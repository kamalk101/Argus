namespace Argus.Monitor;

using Argus.Core.Events;
using Argus.Core.Monitoring;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

/// <summary>
/// Primary Windows sensor. It enables the kernel process/file/network/registry
/// keywords plus the DNS client provider, then hands each record to the pure
/// mapper. It does not filter here: the monitor's scope gate does that, because
/// it also needs to see out-of-scope process starts to attribute children
/// correctly.
/// </summary>
public sealed class EtwCollector : IDisposable
{
    public static readonly Guid DnsClientProvider = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    private readonly MonitorOptions _options;
    private readonly MonitorStats _stats;
    private readonly Action<RawEvent> _emit;
    private readonly EtwEventMapper _mapper;
    private readonly object _gate = new();

    private TraceEventSession? _session;
    private Task? _pump;
    private bool _disposed;
    private string? _pumpError;

    public EtwCollector(
        MonitorOptions options,
        MonitorStats stats,
        Action<RawEvent> emit,
        EtwEventMapper mapper)
    {
        _options = options;
        _stats = stats;
        _emit = emit;
        _mapper = mapper;
    }

    public string? PumpError => _pumpError;

    public bool TryStart(out string? kernelError, out string? dnsError)
    {
        kernelError = null;
        dnsError = null;

        if (!OperatingSystem.IsWindows())
        {
            kernelError = "ETW is only available on Windows.";
            return false;
        }

        try
        {
            lock (_gate)
            {
                var name = _options.SessionName ?? "Argus-" + Guid.NewGuid().ToString("N");
                _session = new TraceEventSession(name)
                {
                    StopOnDispose = true,
                };

                var keywords = KernelTraceEventParser.Keywords.Process
                    | KernelTraceEventParser.Keywords.FileIO
                    | KernelTraceEventParser.Keywords.FileIOInit
                    | KernelTraceEventParser.Keywords.NetworkTCPIP;

                if (_options.RegistryEvents)
                {
                    keywords |= KernelTraceEventParser.Keywords.Registry;
                }

                _session.EnableKernelProvider(keywords);

                if (_options.DnsEvents)
                {
                    try
                    {
                        _session.EnableProvider(DnsClientProvider, TraceEventLevel.Informational, ulong.MaxValue);
                        _stats.DnsProviderEnabled = true;
                    }
                    catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or UnauthorizedAccessException)
                    {
                        dnsError = exception.Message;
                        _stats.DnsError = dnsError;
                    }
                }

                _session.Source.AllEvents += OnAllEvents;
                _pump = Task.Factory.StartNew(
                    Pump,
                    CancellationToken.None,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default);
            }

            _stats.EtwStarted = true;
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or UnauthorizedAccessException or IOException)
        {
            kernelError = exception.Message;
            _stats.EtwError = kernelError;
            Dispose();
            return false;
        }
    }

    private void Pump()
    {
        try
        {
            _session?.Source.Process();
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            _pumpError = exception.Message;
            _stats.EtwError = _pumpError;
        }
    }

    private void OnAllEvents(TraceEvent data)
    {
        if (data is null || _disposed)
        {
            return;
        }

        var name = data.EventName;
        if (string.IsNullOrEmpty(name))
        {
            return;
        }

        if (!IsEnabled(data, name))
        {
            return;
        }

        try
        {
            var pid = data.ProcessID;
            var record = new EtwRecord
            {
                TimestampUtc = ToUtc(data.TimeStamp),
                Provider = data.ProviderName ?? string.Empty,
                EventName = name,
                EventId = (int)data.ID,
                Pid = pid,
                Tid = data.ThreadID,
                Payload = ReadPayload(data),
            };

            ProcessMetadata? metadata = null;
            if (name.Contains("Process", StringComparison.OrdinalIgnoreCase) && pid > 0)
            {
                metadata = WindowsProcessMetadata.TryGet(pid);
            }

            var rawEvent = _mapper.Map(record, metadata);
            if (rawEvent is null)
            {
                _stats.OnMappingFailure();
                return;
            }

            _emit(rawEvent);
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or NotSupportedException or FormatException)
        {
            _stats.OnMappingFailure();
        }
    }

    private bool IsEnabled(TraceEvent data, string name)
    {
        if (name.Contains("Process", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (name.Contains("FileIO", StringComparison.OrdinalIgnoreCase))
        {
            return _options.FileEvents;
        }

        if (name.Contains("TcpIp", StringComparison.OrdinalIgnoreCase))
        {
            return _options.NetworkEvents;
        }

        if (name.Contains("Registry", StringComparison.OrdinalIgnoreCase))
        {
            return _options.RegistryEvents;
        }

        return _options.DnsEvents
            && (data.ProviderName?.Contains("DNS-Client", StringComparison.OrdinalIgnoreCase) == true
                || ((int)data.ID is 3006 or 3008));
    }

    private static System.Collections.Generic.IReadOnlyDictionary<string, object?> ReadPayload(TraceEvent data)
    {
        var payload = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        var names = data.PayloadNames;
        if (names is null)
        {
            return payload;
        }

        foreach (var name in names)
        {
            try
            {
                payload[name] = data.PayloadByName(name);
            }
            catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or NotSupportedException or IndexOutOfRangeException)
            {
                payload[name] = null;
            }
        }

        return payload;
    }

    private static DateTimeOffset ToUtc(DateTime timestamp) => timestamp.Kind switch
    {
        DateTimeKind.Utc => new DateTimeOffset(timestamp),
        DateTimeKind.Local => new DateTimeOffset(timestamp).ToUniversalTime(),
        _ => new DateTimeOffset(DateTime.SpecifyKind(timestamp, DateTimeKind.Utc)),
    };

    public long LostEvents
    {
        get
        {
            try
            {
                return _session?.Source.EventsLost ?? 0;
            }
            catch (ObjectDisposedException)
            {
                return 0;
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        try
        {
            _session?.Stop();
        }
        catch (Exception exception) when (exception is InvalidOperationException or ObjectDisposedException)
        {
            // Already stopped.
        }

        try
        {
            _pump?.Wait(TimeSpan.FromSeconds(3));
        }
        catch (AggregateException)
        {
            // Pump errors are surfaced through PumpError/stats.
        }

        _session?.Dispose();
        _session = null;
        _pump = null;
    }
}
