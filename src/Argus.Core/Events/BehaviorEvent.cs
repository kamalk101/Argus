namespace Argus.Core.Events;

using Argus.Core.Sessions;

/// <summary>
/// A normalised, immutable behaviour event. This is the contract every layer
/// agrees on: sensors produce it, rules read it, storage persists it, the UI
/// renders it.
/// </summary>
public sealed record BehaviorEvent
{
    /// <summary>Monotonic, assigned at ingest; the ordering key for replay.</summary>
    public long Seq { get; init; }

    public required Guid SessionId { get; init; }

    /// <summary>Event time from the sensor, never the arrival time.</summary>
    public required DateTimeOffset TimestampUtc { get; init; }

    public required EventKind Kind { get; init; }

    public required EventCategory Category { get; init; }

    /// <summary>The process that performed the action.</summary>
    public required int Pid { get; init; }

    public int? Tid { get; init; }

    public int? ParentPid { get; init; }

    public string? ImageName { get; init; }

    public string? ImagePath { get; init; }

    public string? CommandLine { get; init; }

    /// <summary>Target process for process-to-process events (e.g. injection).</summary>
    public int? TargetPid { get; init; }

    /// <summary>Path, endpoint, registry key or domain, as reported by the sensor.</summary>
    public string? Target { get; init; }

    /// <summary>Canonicalised directory/file key for path events (see <see cref="Paths.PathKey"/>).</summary>
    public string? PathKey { get; init; }

    public string? RemoteIp { get; init; }

    public int? RemotePort { get; init; }

    public string? Protocol { get; init; }

    public string? HostName { get; init; }

    public long? BytesOut { get; init; }

    public long? BytesIn { get; init; }

    /// <summary>What the file operation did, when the sensor could tell (see <see cref="FileEffect"/>).</summary>
    public FileEffect? FileEffect { get; init; }

    /// <summary>Source path of a <see cref="EventKind.FileRename"/>; null when the sensor could not pair it.</summary>
    public string? PreviousPath { get; init; }

    /// <summary>Kind-specific extras as JSON; never the only place a fact lives.</summary>
    public string? Detail { get; init; }

    public required Observability Observability { get; init; }

    /// <summary>0..1 confidence in the observation itself, not in the intent.</summary>
    public required double Confidence { get; init; }

    public required EventSourceKind Source { get; init; }

    /// <summary>Set by the scope stage; excluded events are still stored and counted.</summary>
    public ProcessScopeState Scope { get; init; } = ProcessScopeState.Unknown;

    public string? ScopeReason { get; init; }

    public bool InScope => Scope is ProcessScopeState.Root
        or ProcessScopeState.Confirmed
        or ProcessScopeState.Unconfirmed;
}
