namespace Argus.Core.Events;

/// <summary>
/// How directly the sensor saw this fact. Requirement 6: the product must never
/// blur observed and inferred evidence, so every event carries this and the UI
/// renders it as text.
/// </summary>
public enum Observability
{
    /// <summary>Captured from an OS event for this process.</summary>
    Direct,

    /// <summary>Captured, but attribution or completeness is limited.</summary>
    Partial,

    /// <summary>Deduced from heuristics rather than observed (e.g. injection).</summary>
    Inferred,

    /// <summary>A rollup of many events; the raw detail has aged out.</summary>
    Aggregated,
}

public enum EventSourceKind
{
    Etw,
    Polling,
    Peb,
    Wmi,
    Simulated,
    Replay,
}
