namespace Argus.Monitor;

using System.Threading.Channels;
using Argus.Core.Events;
using Argus.Core.Monitoring;
using Argus.Core.Paths;
using Argus.Core.Processes;

/// <summary>
/// The monitor's public surface: one ordered, scope-filtered channel of
/// <see cref="RawEvent"/>. ETW is primary; polling repairs process and TCP
/// attribution. Volume throttling and read sampling happen here, before events
/// reach the analysis pipeline or storage.
/// </summary>
public sealed class MonitorEventSource : IAsyncDisposable
{
    private readonly MonitorOptions _options;
    private readonly MonitorStats _stats = new();
    private readonly Channel<RawEvent> _channel;
    private readonly EventNormalizer _normalizer = new(Guid.NewGuid());
    private readonly ProcessScopeTracker _scope;
    private readonly ReadSampler _sampler;
    private readonly VolumeGovernor _volume;
    private readonly EtwEventMapper _mapper;
    private readonly Dictionary<int, DateTimeOffset> _started = [];
    private readonly Dictionary<string, DateTimeOffset> _recentConnections = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _cts = new();
    private readonly object _gate = new();

    private EtwCollector? _etw;
    private Task? _processPoll;
    private Task? _tcpPoll;
    private int _startedFlag;
    private int _stoppedFlag;

    public MonitorEventSource(MonitorOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        _scope = new ProcessScopeTracker(options.RootPid, options.RootImagePath);
        _sampler = new ReadSampler(options.ReadSampleEvery);
        _volume = new VolumeGovernor(options.VolumeThresholdPerSecond);
        _channel = Channel.CreateBounded<RawEvent>(
            new BoundedChannelOptions(options.ChannelCapacity)
            {
                FullMode = BoundedChannelFullMode.DropWrite,
                SingleReader = true,
                SingleWriter = false,
            },
            _ => _stats.OnChannelDropped());

        var volumes = OperatingSystem.IsWindows() ? VolumeMap.Build() : VolumeMap.Empty;
        _mapper = new EtwEventMapper(volumes.Resolve);
    }

    public ChannelReader<RawEvent> Reader => _channel.Reader;

    public MonitorStats Stats => _stats;

    public int RootPid => _options.RootPid;

    public bool Throttled => _volume.Throttled;

    public long CurrentLostEvents => _etw?.LostEvents ?? 0;

    public void Start()
    {
        if (Interlocked.Exchange(ref _startedFlag, 1) != 0)
        {
            throw new InvalidOperationException("The monitor has already been started.");
        }

        if (!OperatingSystem.IsWindows())
        {
            EmitGap("platform-not-windows", "Windows ETW collectors are not available on this host.");
            _channel.Writer.TryComplete();
            return;
        }

        var rootStarted = _options.RootStartedUtc ?? DateTimeOffset.UtcNow;
        var rootEvent = new RawEvent
        {
            Ts = rootStarted,
            Kind = EventKind.ProcessStart,
            Pid = _options.RootPid,
            ImageName = EtwEventMapper.FileNameOf(_options.RootImagePath),
            ImagePath = _options.RootImagePath,
            Observability = Observability.Direct,
            Source = EventSourceKind.Polling,
            Detail = "launch-root",
        };

        _started[_options.RootPid] = rootStarted;
        _scope.Observe(_normalizer.Normalize(rootEvent));
        Write(rootEvent);

        _etw = new EtwCollector(_options, _stats, Accept, _mapper);
        if (!_etw.TryStart(out var kernelError, out var dnsError))
        {
            EmitGap("etw-unavailable", kernelError ?? "The kernel provider could not be enabled.");
        }

        if (dnsError is not null)
        {
            EmitGap("dns-provider-unavailable", dnsError);
        }

        if (_options.ProcessPollingRepair)
        {
            var poller = new ProcessPollingCollector(
                _options.RootPid,
                IsInScope,
                Accept,
                _options.PollInterval);

            _processPoll = Task.Run(() => poller.RunAsync(_cts.Token), CancellationToken.None);
        }

        if (_options.NetworkEvents)
        {
            try
            {
                _ = TcpTableReader.Read();
                _stats.TcpTableAvailable = true;
            }
            catch (Exception exception) when (exception is InvalidOperationException or ArgumentException)
            {
                _stats.TcpTableAvailable = false;
            }

            var tcp = new TcpPollingCollector(IsInScope, Accept, _options.PollInterval);
            _tcpPoll = Task.Run(() => tcp.RunAsync(_cts.Token), CancellationToken.None);
        }
    }

    private void Accept(RawEvent rawEvent)
    {
        _stats.OnSeen();

        RawEvent? routed;
        lock (_gate)
        {
            routed = Route(rawEvent);
        }

        if (routed is null)
        {
            return;
        }

        _stats.OnForwarded();
        switch (routed.CategoryOrKind())
        {
            case EventCategory.Process:
                if (routed.Kind == EventKind.ProcessStart)
                {
                    _stats.OnProcessStart();
                }

                break;
            case EventCategory.File:
                _stats.OnFile();
                break;
            case EventCategory.Network:
                _stats.OnNetwork();
                break;
            case EventCategory.Dns:
                _stats.OnDns();
                break;
            case EventCategory.Registry:
                _stats.OnRegistry();
                break;
            default:
                break;
        }

        Write(routed);
    }

    private RawEvent? Route(RawEvent rawEvent)
    {
        if (rawEvent.Kind == EventKind.MonitorGap)
        {
            return rawEvent;
        }

        var change = _volume.Observe(rawEvent.Ts);
        if (change is not null)
        {
            _sampler.SetSampleEvery(change.SampleEvery);
            if (change.Throttled)
            {
                _stats.OnThrottled();
            }

            EmitGap(change.Reason, string.Create(
                System.Globalization.CultureInfo.InvariantCulture,
                $"{change.EventsPerSecond} events/s; read sample 1:{change.SampleEvery}"));
        }

        if (rawEvent.Kind == EventKind.ProcessStart)
        {
            if (_started.TryGetValue(rawEvent.Pid, out var firstSeen))
            {
                if ((rawEvent.Ts - firstSeen).Duration() < TimeSpan.FromSeconds(5))
                {
                    return null;
                }

                _started[rawEvent.Pid] = rawEvent.Ts;
            }
            else
            {
                _started[rawEvent.Pid] = rawEvent.Ts;
            }

            _scope.Observe(_normalizer.Normalize(rawEvent));
            return rawEvent;
        }

        if (rawEvent.Kind == EventKind.ProcessStop)
        {
            return _scope.ClassifyPid(rawEvent.Pid).InScope ? rawEvent : null;
        }

        if (!_scope.ClassifyPid(rawEvent.Pid).InScope)
        {
            _stats.OnOutsideScope();
            return null;
        }

        if (rawEvent.Kind == EventKind.NetConnect && IsDuplicateConnection(rawEvent))
        {
            return null;
        }

        if (rawEvent.Kind == EventKind.FileRead)
        {
            var pathKey = PathKey.Canonicalize(rawEvent.Target);
            var sensitive = _options.Catalog.TryMatch(pathKey, out _);
            if (!_sampler.ShouldKeep(rawEvent.Pid, pathKey, sensitive))
            {
                _stats.OnSampledRead();
                return null;
            }
        }

        return rawEvent;
    }

    private bool IsDuplicateConnection(RawEvent rawEvent)
    {
        var key = string.Concat(
            rawEvent.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture), "|",
            rawEvent.RemoteIp ?? string.Empty, "|",
            rawEvent.RemotePort?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);

        if (_recentConnections.TryGetValue(key, out var seen)
            && (rawEvent.Ts - seen).Duration() < TimeSpan.FromSeconds(10))
        {
            return true;
        }

        _recentConnections[key] = rawEvent.Ts;

        if (_recentConnections.Count > 10_000)
        {
            var cutoff = rawEvent.Ts - TimeSpan.FromMinutes(1);
            foreach (var (stale, timestamp) in _recentConnections.ToArray())
            {
                if (timestamp < cutoff)
                {
                    _recentConnections.Remove(stale);
                }
            }
        }

        return false;
    }

    private bool IsInScope(int pid) => _scope.ClassifyPid(pid).InScope;

    private void EmitGap(string reason, string message)
    {
        var gap = new RawEvent
        {
            Ts = DateTimeOffset.UtcNow,
            Kind = EventKind.MonitorGap,
            Pid = 0,
            Target = reason,
            Detail = message,
            Observability = Observability.Partial,
            Source = EventSourceKind.Polling,
        };

        _stats.OnForwarded();
        Write(gap);
    }

    private void Write(RawEvent rawEvent)
    {
        if (!_channel.Writer.TryWrite(rawEvent))
        {
            _stats.OnChannelDropped();
        }
    }

    public async Task StopAsync()
    {
        if (Interlocked.Exchange(ref _stoppedFlag, 1) != 0)
        {
            return;
        }

        _cts.Cancel();

        if (_etw is not null)
        {
            _stats.EtwLostEvents = _etw.LostEvents;
            _etw.Dispose();

            // A pump that died (session closed underneath us, provider failure) used to
            // be recorded only in stats. A session that stopped collecting silently is a
            // monitoring gap and must be reported as one.
            if (_etw.PumpError is { } pumpError)
            {
                _stats.EtwError ??= pumpError;
                EmitGap("etw-pump-failed", pumpError);
            }
        }

        foreach (var task in new[] { _processPoll, _tcpPoll })
        {
            if (task is null)
            {
                continue;
            }

            try
            {
                await task.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected on stop.
            }
        }

        _channel.Writer.TryComplete();
        _cts.Dispose();
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);
}

internal static class RawEventCategoryExtensions
{
    public static EventCategory CategoryOrKind(this RawEvent rawEvent) => EventKinds.CategoryOf(rawEvent.Kind);
}
