namespace Argus.Monitor;

using Argus.Core.Paths;

public sealed record MonitorOptions
{
    /// <summary>
    /// Pid of the monitored root. **0 means "not attached yet"**: the monitor enables
    /// capture first and learns the pid once the target exists (see
    /// <c>MonitorEventSource.AttachRoot</c>), so no event is missed between launch and
    /// collection.
    /// </summary>
    public required int RootPid { get; init; }

    public string? RootImagePath { get; init; }

    public DateTimeOffset? RootStartedUtc { get; init; }

    public SensitivePathCatalog Catalog { get; init; } = SensitivePathCatalog.Empty;

    public bool FileEvents { get; init; } = true;

    public bool NetworkEvents { get; init; } = true;

    public bool RegistryEvents { get; init; } = true;

    public bool DnsEvents { get; init; } = true;

    public bool ProcessPollingRepair { get; init; } = true;

    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(1);

    public int ReadSampleEvery { get; init; } = 50;

    public int VolumeThresholdPerSecond { get; init; } = 8_000;

    public int ChannelCapacity { get; init; } = 100_000;

    /// <summary>Optional ETW session name; a unique name avoids clashing with PerfView/Procmon.</summary>
    public string? SessionName { get; init; }
}

public sealed class MonitorStats
{
    private long _etwCallbacks;
    private long _etwFiltered;
    private long _eventsSeen;
    private long _eventsForwarded;
    private long _outsideScope;
    private long _sampledReads;
    private long _throttledEvents;
    private long _channelDropped;
    private long _droppedBeforeRoot;
    private long _mappingFailures;
    private long _unmapped;
    private long _processStarts;
    private long _fileEvents;
    private long _networkEvents;
    private long _dnsEvents;
    private long _registryEvents;
    private readonly object _failureGate = new();
    private readonly Queue<string> _mappingFailureSamples = new();

    private const int MaxMappingFailureSamples = 5;

    /// <summary>Raw ETW callbacks received, before the collector's own filtering.</summary>
    public long EtwCallbacks => Interlocked.Read(ref _etwCallbacks);

    /// <summary>Callbacks the collector dropped as not interesting (rundown, disabled category).</summary>
    public long EtwFiltered => Interlocked.Read(ref _etwFiltered);

    public long EventsSeen => Interlocked.Read(ref _eventsSeen);
    public long EventsForwarded => Interlocked.Read(ref _eventsForwarded);
    public long OutsideScope => Interlocked.Read(ref _outsideScope);
    public long SampledReads => Interlocked.Read(ref _sampledReads);
    public long ThrottledEvents => Interlocked.Read(ref _throttledEvents);
    public long ChannelDropped => Interlocked.Read(ref _channelDropped);

    /// <summary>Events dropped because they arrived before the root process was known.</summary>
    public long DroppedBeforeRoot => Interlocked.Read(ref _droppedBeforeRoot);
    /// <summary>Records with a malformed payload: a real sensor-side failure.</summary>
    public long MappingFailures => Interlocked.Read(ref _mappingFailures);

    /// <summary>Records the mapper deliberately ignores (kinds Argus does not model).</summary>
    public long Unmapped => Interlocked.Read(ref _unmapped);
    public long ProcessStarts => Interlocked.Read(ref _processStarts);
    public long FileEvents => Interlocked.Read(ref _fileEvents);
    public long NetworkEvents => Interlocked.Read(ref _networkEvents);
    public long DnsEvents => Interlocked.Read(ref _dnsEvents);
    public long RegistryEvents => Interlocked.Read(ref _registryEvents);

    public long EtwLostEvents { get; set; }

    /// <summary>
    /// Short descriptors of the most recent payload decode failures, newest last.
    /// They name the record and the exception type only: payload values (file paths,
    /// registry keys, DNS names) are captured data and must not be surfaceable in
    /// agent logs or session JSON.
    /// </summary>
    public IReadOnlyList<string> MappingFailureSamples
    {
        get
        {
            lock (_failureGate)
            {
                return _mappingFailureSamples.ToArray();
            }
        }
    }
    public bool EtwStarted { get; set; }
    public bool DnsProviderEnabled { get; set; }
    public bool TcpTableAvailable { get; set; }
    public string? EtwError { get; set; }
    public string? DnsError { get; set; }

    public void OnSeen() => Interlocked.Increment(ref _eventsSeen);

    public void OnEtwCallback() => Interlocked.Increment(ref _etwCallbacks);

    public void OnEtwFiltered() => Interlocked.Increment(ref _etwFiltered);

    public void OnForwarded()
    {
        Interlocked.Increment(ref _eventsForwarded);
    }

    public void OnOutsideScope() => Interlocked.Increment(ref _outsideScope);

    public void OnSampledRead() => Interlocked.Increment(ref _sampledReads);

    public void OnThrottled() => Interlocked.Increment(ref _throttledEvents);

    public void OnChannelDropped() => Interlocked.Increment(ref _channelDropped);

    public void OnDroppedBeforeRoot() => Interlocked.Increment(ref _droppedBeforeRoot);

    public void OnMappingFailure(string? sample = null)
    {
        Interlocked.Increment(ref _mappingFailures);

        if (string.IsNullOrWhiteSpace(sample))
        {
            return;
        }

        lock (_failureGate)
        {
            while (_mappingFailureSamples.Count >= MaxMappingFailureSamples)
            {
                _mappingFailureSamples.Dequeue();
            }

            _mappingFailureSamples.Enqueue(sample);
        }
    }

    public void OnUnmapped() => Interlocked.Increment(ref _unmapped);

    public void OnProcessStart() => Interlocked.Increment(ref _processStarts);

    public void OnFile() => Interlocked.Increment(ref _fileEvents);

    public void OnNetwork() => Interlocked.Increment(ref _networkEvents);

    public void OnDns() => Interlocked.Increment(ref _dnsEvents);

    public void OnRegistry() => Interlocked.Increment(ref _registryEvents);
}
