namespace Argus.Core.Events;

/// <summary>
/// Sensor output before normalisation. Every collector (ETW, polling, simulator,
/// replay) produces this shape, which keeps the analysis layer sensor-agnostic
/// and lets recorded sessions replay identically.
/// </summary>
public sealed record RawEvent
{
    public required DateTimeOffset Ts { get; init; }

    public required EventKind Kind { get; init; }

    public required int Pid { get; init; }

    public int? Tid { get; init; }

    public int? ParentPid { get; init; }

    public string? ImageName { get; init; }

    public string? ImagePath { get; init; }

    public string? CommandLine { get; init; }

    public int? TargetPid { get; init; }

    public string? Target { get; init; }

    public string? RemoteIp { get; init; }

    public int? RemotePort { get; init; }

    public string? Protocol { get; init; }

    public string? HostName { get; init; }

    public long? BytesOut { get; init; }

    public long? BytesIn { get; init; }

    /// <summary>
    /// What the file operation did to the file, when the sensor can tell. A
    /// <see cref="EventKind.FileCreate"/> with <see cref="Events.FileEffect.Opened"/> is
    /// an open of an existing file, not a write to it.
    /// </summary>
    public FileEffect? FileEffect { get; init; }

    public string? Detail { get; init; }

    public Observability? Observability { get; init; }

    public double? Confidence { get; init; }

    public EventSourceKind? Source { get; init; }
}
