namespace Argus.Monitor;

using Argus.Core.Diagnostics;
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

    /// <summary>
    /// Stops kernel sessions this agent created in an earlier run and never got to stop — a killed
    /// process, a crashed run. Only <c>Argus-*</c> names are touched: another product's session and the
    /// classic "NT Kernel Logger" are not ours to stop. Returns the names actually reclaimed so the
    /// agent can say what it did instead of silently changing machine state.
    /// </summary>
    public static IReadOnlyList<string> ReclaimStaleSessions()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<string>();
        }

        IReadOnlyList<string> names;
        try
        {
            names = EtwStartFailure.Reclaimable(TraceEventSession.GetActiveSessionNames());
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            return Array.Empty<string>();
        }

        var stopped = new List<string>();
        foreach (var name in names)
        {
            try
            {
                using var stale = TraceEventSession.GetActiveSession(name);
                if (stale is null)
                {
                    continue;
                }

                stale.Stop();
                stopped.Add(name);
            }
            catch (Exception exception) when (exception is InvalidOperationException or IOException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
            {
                // A session that cannot be stopped is not a reason to refuse to start: TryStart will
                // report the real outcome, and that message now names this exact condition.
            }
        }

        return stopped;
    }

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

                // A named session (anything other than the classic "NT Kernel Logger")
                // does not decode kernel records by itself. Without a registered kernel
                // parser every record arrives as "Task(<guid>)/Opcode(n)", which matches
                // no mapper branch, so the session reports "started" while delivering
                // nothing usable. Registering the parser is what turns those records into
                // FileIO/Create, TcpIp/Connect, Registry/SetValue and so on.
                _session.Source.Kernel.All += static _ => { };

                // The classic Registry keyword reports opens, queries and the kernel's own
                // key-cache traffic, but its writes carry a handle that never matches a handle
                // an Open reported (measured: Opens report 0 or an unrelated value). The
                // manifest provider is the one that names a key and the object a value write
                // went to, so registry writes need it as well.
                if (_options.RegistryEvents)
                {
                    try
                    {
                        _session.EnableProvider(
                            EtwEventMapper.RegistryManifestProvider,
                            TraceEventLevel.Verbose,
                            ulong.MaxValue);
                        _stats.RegistryProviderEnabled = true;
                    }
                    catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or UnauthorizedAccessException)
                    {
                        _stats.RegistryProviderError = exception.GetType().Name;
                    }
                }

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

                // Manifest providers (DNS-Client) deliver no named payload fields until a
                // dynamic parser decodes them; without this the DNS records arrive with an
                // empty payload and map to nothing (QueryName would always be missing).
                _session.Source.Dynamic.All += static _ => { };

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
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or UnauthorizedAccessException or IOException or System.Runtime.InteropServices.COMException or System.ComponentModel.Win32Exception)
        {
            // Two ETW failures are worth naming: a full session table (usually this agent's own
            // sessions, left behind by a killed run) and a missing elevation. Everything else keeps
            // its own message.
            var hresult = exception is System.Runtime.InteropServices.COMException com
                ? com.HResult
                : exception is System.ComponentModel.Win32Exception win32
                    ? win32.NativeErrorCode is 0 ? null : unchecked((int)0x80070000) | (win32.NativeErrorCode & 0xFFFF)
                    : (int?)null;
            kernelError = EtwStartFailure.Explain(hresult, exception.Message);
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

        // Counted before any filtering: "no callbacks at all" (provider or session
        // problem) and "every callback filtered" (configuration problem) are
        // different failures and must not be reported as the same thing.
        _stats.OnEtwCallback();

        var name = data.EventName;
        if (string.IsNullOrEmpty(name))
        {
            _stats.OnEtwFiltered();
            return;
        }

        if (!IsEnabled(data, name))
        {
            _stats.OnEtwFiltered();
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
                // A record the mapper deliberately ignores (FileIO/Close, TcpIp/Send,
                // thread and system-config events) is not a failure. Reporting those as
                // failures buried the real ones under six figures of noise.
                _stats.OnUnmapped();
                return;
            }

            _emit(rawEvent);
        }
        catch (Exception exception)
        {
            // The mapper deliberately has no catch-all so that a malformed payload is
            // distinguishable from an ignored kind. That makes this method the boundary:
            // it must stay total, because an exception escaping here can stop ETW
            // dispatch for the rest of the session and silently end capture. A type that
            // slips past a narrower filter (IndexOutOfRange, NullReference, ...) is still
            // a decode failure, so it is counted as one.
            _stats.OnMappingFailure(DescribeFailure(name, (int)data.ID, exception));
        }
    }

    private static string DescribeFailure(string eventName, int eventId, Exception exception) =>
        string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{eventName}#{eventId} {exception.GetType().Name}");

    private bool IsEnabled(TraceEvent data, string name)
    {
        if (name.Contains("Process", StringComparison.OrdinalIgnoreCase))
        {
            // Event IDs 3/4 are DCStart/DCEnd rundown records for processes that
            // already existed when the session started. They are not new starts;
            // treating them as such floods the session with every process on the
            // machine (including Idle/System) before the target does anything.
            return (int)data.ID is not (3 or 4)
                && !name.Contains("DCStart", StringComparison.OrdinalIgnoreCase)
                && !name.Contains("DCEnd", StringComparison.OrdinalIgnoreCase);
        }

        if (name.Contains("FileIO", StringComparison.OrdinalIgnoreCase))
        {
            return _options.FileEvents;
        }

        if (name.Contains("TcpIp", StringComparison.OrdinalIgnoreCase))
        {
            return _options.NetworkEvents;
        }

        if (data.ProviderName == EtwEventMapper.RegistryManifestProvider)
        {
            return _options.RegistryEvents;
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
