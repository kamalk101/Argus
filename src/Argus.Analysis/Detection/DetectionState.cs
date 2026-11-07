namespace Argus.Analysis.Detection;

using Argus.Core.Events;
using Argus.Core.Sessions;

/// <summary>
/// One investigation unit: a rule, a process, and all its repeats inside the merge
/// window. The UI shows one card per state, not one per event.
/// </summary>
public sealed record DetectionState
{
    /// <summary>Deterministic key: rule, process and first sequence number.</summary>
    public required string Key { get; init; }

    public required string RuleId { get; init; }

    public required string Title { get; init; }

    public required int Severity { get; init; }

    /// <summary>Confidence in the detection, from the evidence-saturation model.</summary>
    public required double Confidence { get; init; }

    public required double BaseConfidence { get; init; }

    public required EvidenceCategory Categories { get; init; }

    public required int ScopePid { get; init; }

    public required DateTimeOffset FirstSeenUtc { get; init; }

    public required DateTimeOffset LastSeenUtc { get; init; }

    public required int EventCount { get; init; }

    public required DetectionStatus Status { get; init; }

    public required string Reason { get; init; }

    public required string Counterfactual { get; init; }

    public required IReadOnlyList<string> Mitre { get; init; }

    public required IReadOnlyList<long> EvidenceSeq { get; init; }

    public required IReadOnlyList<string> Factors { get; init; }

    public bool HasSubsequentEvidence => EventCount > 1;

    public string StatusText => Status switch
    {
        DetectionStatus.Open => "open",
        DetectionStatus.Escalated => "escalated",
        _ => "closed",
    };
}
