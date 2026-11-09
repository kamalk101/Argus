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
    private ProcessPollingCollector? _processPoller;
    private Task? _tcpPoll;
    private int _startedFlag;
    private int _stoppedFlag;
    private int _rootPid;
    private int _rootAttached;
    private int _captureStartReported;
    private long _gaps;
    private readonly List<RawEvent> _preAttach = [];
    private bool _preAttachOverflowed;

    /// <summary>
    /// Cap on events held before the root pid is known. The window is milliseconds; the cap
    /// exists so a caller that starts a monitor and never attaches a root cannot grow this
    /// list without bound on a busy machine.
    /// </summary>
    private const int PreAttachCapacity = 20_000;

    /// <summary>
    /// How late the root may be attached after it started before the silence counts as a
    /// monitoring gap. With capture running first this is measured against ETW already
    /// being live, so a real value here means something went wrong on the launch path.
    /// </summary>
    public static readonly TimeSpan CaptureStartTolerance = TimeSpan.FromMilliseconds(100);

    public MonitorEventSource(MonitorOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        _rootPid = options.RootPid;

        // The tracker starts without a root even when a pid was supplied: SeedRoot attaches
        // it, so there is exactly one code path that names the root.
        _scope = new ProcessScopeTracker(0, options.RootImagePath);
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

    public int RootPid => Volatile.Read(ref _rootPid);

    /// <summary>True once the monitored root process is known.</summary>
    public bool HasRoot => Volatile.Read(ref _rootAttached) != 0;

    public bool Throttled => _volume.Throttled;

    public long CurrentLostEvents => _etw?.LostEvents ?? 0;

    public void Start()
    {
        if (Interlocked.Exchange(ref _startedFlag, 1) != 0)
        {
            // The agent enables capture before launching the target (so the launch is not
            // inside a blind window) and LiveSession.Start starts the monitor again. Enabling
            // the session twice is meaningless, so this is idempotent rather than an error.
            return;
        }

        if (!OperatingSystem.IsWindows())
        {
            EmitGap("platform-not-windows", "Windows ETW collectors are not available on this host.");
            _channel.Writer.TryComplete();
            return;
        }

        // Two supported orders. With a root pid the caller launched the target already and
        // this session starts slightly late (reported as a capture-start gap). With no root
        // pid - the agent's path - capture runs first and the root is attached the moment
        // the process exists, so nothing the target does is missed.
        if (RootPid > 0)
        {
            SeedRoot(RootPid, _options.RootImagePath, _options.RootStartedUtc ?? DateTimeOffset.UtcNow);
        }

        _etw = new EtwCollector(_options, _stats, Accept, _mapper);
        if (!_etw.TryStart(out var kernelError, out var dnsError))
        {
            EmitGap("etw-unavailable", kernelError ?? "The kernel provider could not be enabled.");
        }
        else if (_options.RootStartedUtc is { } launchTime)
        {
            ReportCaptureStart(launchTime);
        }

        if (dnsError is not null)
        {
            EmitGap("dns-provider-unavailable", dnsError);
        }

        if (_options.ProcessPollingRepair)
        {
            var poller = new ProcessPollingCollector(
                RootPid,
                IsInScope,
                Accept,
                _options.PollInterval);

            _processPoller = poller;
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

    /// <summary>
    /// Waits until ETW is actually delivering, then returns true.
    ///
    /// Enabling the session returns before its pump thread has dispatched anything, so
    /// launching the target immediately after <see cref="Start"/> still raced the pump.
    /// Waiting for the first kernel callback (any process on the machine produces one
    /// quickly) removes that race; a timeout is reported as a gap rather than silently
    /// launching into a dead sensor.
    /// </summary>
    public bool WaitForDelivery(TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (_stats.EtwCallbacks > 0)
            {
                return true;
            }

            if (_etw is null)
            {
                return false;
            }

            Thread.Sleep(5);
        }

        EmitGap(
            "capture-not-delivering",
            string.Create(
                System.Globalization.CultureInfo.InvariantCulture,
                $"The ETW session started but delivered no records within {timeout.TotalMilliseconds:0} ms; the monitored application was launched anyway and early events may be missing."));

        return false;
    }

    /// <summary>
    /// Names the root process, which is what makes any event in-scope.
    ///
    /// Called by the agent immediately after the target is launched. Before this, every
    /// event is attributed to no one and dropped as out-of-scope, which is correct: the
    /// only thing running is the machine's own activity.
    /// </summary>
    public bool AttachRoot(int pid, string? imagePath, DateTimeOffset startedUtc)
    {
        if (pid <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(pid), pid, "The root pid must be a real process id.");
        }

        if (Interlocked.Exchange(ref _rootAttached, 1) != 0)
        {
            return false;
        }

        Volatile.Write(ref _rootPid, pid);
        _processPoller?.AttachRoot(pid);
        SeedRoot(pid, imagePath ?? _options.RootImagePath, startedUtc);

        // Anything the target did between Process.Start returning and this call was held
        // rather than dropped, so there is no unobserved window to report. The
        // capture-start gap belongs to the other ordering, where the caller launched the
        // target before the session existed.
        ReplayPreAttach();

        if (_preAttachOverflowed)
        {
            EmitGap(
                "pre-attach-buffer-overflow",
                string.Create(
                    System.Globalization.CultureInfo.InvariantCulture,
                    $"More than {PreAttachCapacity} events arrived before the root process was known; the excess was dropped and is missing from this session."));
        }

        return true;
    }

    /// <summary>
    /// Waits for the ETW session to go quiet so records still in flight are delivered.
    ///
    /// ETW delivers asynchronously, so a target that exits immediately still has its last
    /// records queued. The session used to stop the instant the root process exited and threw
    /// them away: a probe whose whole tree lived about 80 ms recorded only the synthetic root
    /// event, while the same tree living 2 s recorded 37 events. Records for a tree that dies
    /// instantly can arrive hundreds of milliseconds late, so this waits for a floor as well
    /// as for quiet.
    /// </summary>
    public async Task DrainAsync(
        TimeSpan quiet,
        TimeSpan maxWait,
        TimeSpan? minimumWait = null,
        CancellationToken cancellationToken = default)
    {
        var started = DateTimeOffset.UtcNow;
        var deadline = started + maxWait;
        var floor = minimumWait ?? TimeSpan.Zero;
        var last = _stats.EtwCallbacks;
        var quietSince = DateTimeOffset.UtcNow;

        while (DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(20), cancellationToken).ConfigureAwait(false);

            var callbacks = _stats.EtwCallbacks;
            if (callbacks != last)
            {
                last = callbacks;
                quietSince = DateTimeOffset.UtcNow;
                continue;
            }

            // A short target's records can arrive later than one quiet window, so never
            // conclude before the floor has passed.
            if (DateTimeOffset.UtcNow - quietSince >= quiet && DateTimeOffset.UtcNow - started >= floor)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Records the root as in-scope and emits its synthetic launch event.
    ///
    /// Also flips <see cref="HasRoot"/>: this is the single place a root becomes known, so both
    /// orderings (root supplied up front, root attached after launch) end up here. Forgetting
    /// that made every event on the legacy path sit in the pre-attach buffer forever - caught by
    /// <c>--self-test</c>, which starts the monitor with its own pid.
    /// </summary>
    private void SeedRoot(int pid, string? imagePath, DateTimeOffset startedUtc)
    {
        Volatile.Write(ref _rootAttached, 1);
        var rootEvent = new RawEvent
        {
            Ts = startedUtc,
            Kind = EventKind.ProcessStart,
            Pid = pid,
            ImageName = EtwEventMapper.FileNameOf(imagePath),
            ImagePath = imagePath,
            // The root is launched by us, so its image is on disk and can be checked once,
            // synchronously, before the session is live. Without this the monitored application
            // itself has no provenance fact at all: measured 2026-11-09, every root record carried
            // no signature, so no rule could ask whether the subject of the session was signed.
            Signature = RootSignature(imagePath),
            Observability = Observability.Direct,
            Source = EventSourceKind.Polling,
            Detail = "launch-root",
        };

        lock (_gate)
        {
            _scope.AttachRoot(pid, imagePath);
            _started[pid] = startedUtc;
            _scope.Observe(_normalizer.Normalize(rootEvent));
        }

        Write(rootEvent);
    }

    private static SignatureStatus? RootSignature(string? imagePath)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrEmpty(imagePath))
        {
            return null;
        }

        try
        {
            return ImageSignature.Verify(imagePath);
        }
        catch (Exception)
        {
            // A provenance check that could not run is not a claim about the file.
            return SignatureStatus.Unknown;
        }
    }

    private void Accept(RawEvent rawEvent)
    {
        _stats.OnSeen();

        RawEvent? routed;
        lock (_gate)
        {
            if (!HasRoot)
            {
                BufferPreAttach(rawEvent);
                return;
            }

            routed = Route(rawEvent);
        }

        Forward(routed);
    }

    /// <summary>
    /// Holds events that arrive before the root pid is known.
    ///
    /// Capture runs before the target is launched, so the session spends a few milliseconds
    /// with no root, during which nothing can be in scope. Those events used to be dropped:
    /// a batch whose whole life was inside that window was invisible (a probe creating,
    /// renaming and deleting 40 files in ~50 ms recorded only the root start). They are
    /// buffered and re-attributed once the root arrives - the tracker then picks out the
    /// root and anything whose parent chain reaches it, exactly as it does for live events.
    /// </summary>
    private void BufferPreAttach(RawEvent rawEvent)
    {
        if (_preAttach.Count >= PreAttachCapacity)
        {
            if (!_preAttachOverflowed)
            {
                _preAttachOverflowed = true;
                _stats.OnDroppedBeforeRoot();
            }

            return;
        }

        _preAttach.Add(rawEvent);
    }

    private void ReplayPreAttach()
    {
        RawEvent[] pending;
        lock (_gate)
        {
            pending = _preAttach.ToArray();
            _preAttach.Clear();
        }

        foreach (var rawEvent in pending.OrderBy(static e => e.Ts))
        {
            RawEvent? routed;
            lock (_gate)
            {
                routed = Route(rawEvent);
            }

            Forward(routed);
        }
    }

    private void Forward(RawEvent? routed)
    {
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

    /// <summary>
    /// Records the window between the target starting and observation beginning.
    ///
    /// With the agent's ordering (capture first, then launch, then attach) this should
    /// measure microseconds. It is kept because the other supported ordering - a caller
    /// that launches first and hands over a root pid - still has a real blind window, and a
    /// silent loss of those first ~150 ms is exactly what this must not hide. Measured
    /// live before the reorder: 142-156 ms, and a probe's first `reg add` was lost.
    /// </summary>
    private void ReportCaptureStart(DateTimeOffset launchTime)
    {
        if (Interlocked.Exchange(ref _captureStartReported, 1) != 0)
        {
            return;
        }

        var latency = DateTimeOffset.UtcNow - launchTime;
        if (latency <= CaptureStartTolerance)
        {
            return;
        }

        EmitGap(
            "capture-start-latency",
            string.Create(
                System.Globalization.CultureInfo.InvariantCulture,
                $"ETW capture was enabled {latency.TotalMilliseconds:0} ms after the monitored application started; anything it did in that window was not observed."),
            launchTime);
    }

    private RawEvent? Route(RawEvent rawEvent)
    {
        if (rawEvent.Kind == EventKind.MonitorGap)
        {
            return rawEvent;
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
            ObserveVolume(rawEvent.Ts);
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

        ObserveVolume(rawEvent.Ts);

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

    /// <summary>
    /// Feeds the volume fuse, which measures what this session actually processes.
    ///
    /// It used to observe every ETW record before the scope check. Measured live, unrelated
    /// system activity pushed the counter to 10 675 events/s, which throttled - and reported a
    /// gap in - a session whose own target was doing very little, marking a clean run
    /// incomplete. Machine-wide volume is not this session's problem; its own volume is.
    /// </summary>
    private void ObserveVolume(DateTimeOffset timestamp)
    {
        var change = _volume.Observe(timestamp);
        if (change is null)
        {
            return;
        }

        _sampler.SetSampleEvery(change.SampleEvery);
        if (change.Throttled)
        {
            _stats.OnThrottled();
        }

        EmitGap(change.Reason, string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{change.EventsPerSecond} events/s; read sample 1:{change.SampleEvery}"));
    }

    private void EmitGap(string reason, string message, DateTimeOffset? timestamp = null)
    {
        var gap = new RawEvent
        {
            // The gap starts when observation was missing, not when it was noticed, so the
            // stream stays in time order for the correlation index.
            Ts = timestamp ?? DateTimeOffset.UtcNow,
            Kind = EventKind.MonitorGap,
            Pid = 0,
            Target = reason,
            Detail = message,
            Observability = Observability.Partial,
            Source = EventSourceKind.Polling,
        };

        Interlocked.Increment(ref _gaps);
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
