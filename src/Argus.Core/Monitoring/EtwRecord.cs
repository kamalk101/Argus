namespace Argus.Core.Monitoring;

/// <summary>
/// A single ETW record in a platform-neutral shape. The Windows collector turns
/// <c>TraceEvent</c> into this record; the mapper below is pure data
/// transformation and is therefore unit-tested on Linux.
/// </summary>
public sealed record EtwRecord
{
    public required DateTimeOffset TimestampUtc { get; init; }

    /// <summary>Provider name as reported by ETW (for example Microsoft-Windows-Kernel-File).</summary>
    public required string Provider { get; init; }

    public required string EventName { get; init; }

    public required int EventId { get; init; }

    /// <summary>Header process id: the process that performed the action.</summary>
    public required int Pid { get; init; }

    public int? Tid { get; init; }

    public IReadOnlyDictionary<string, object?> Payload { get; init; } =
        new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Facts the OS can supply about a live process but ETW does not always carry:
/// full image path, command line and parent. Values are best-effort and may be
/// null for protected processes.
/// </summary>
public sealed record ProcessMetadata(
    int Pid,
    string? ImagePath = null,
    string? CommandLine = null,
    int? ParentPid = null,
    string? IntegrityLevel = null);
