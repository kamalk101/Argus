namespace Argus.Storage;

using Argus.Core.Events;
using Argus.Core.Sessions;

public sealed record SessionRecord
{
    public required Guid Id { get; init; }

    public required string TargetPath { get; init; }

    public string? TargetSha256 { get; init; }

    public string? TargetSigner { get; init; }

    public string Mode { get; init; } = "launch";

    public required DateTimeOffset StartedUtc { get; init; }

    public DateTimeOffset? EndedUtc { get; init; }

    public string Status { get; init; } = "running";

    public string? OsBuild { get; init; }

    public string? AgentVersion { get; init; }

    public bool Elevated { get; init; }

    public double PeakScore { get; init; }

    public double? FinalScore { get; init; }

    public string? Verdict { get; init; }

    public long LossEvents { get; init; }

    public long LossBytes { get; init; }

    public string? ConfigHash { get; init; }
}

public sealed record StoredDetection
{
    public required long Id { get; init; }

    public required string DetectionKey { get; init; }

    public required string RuleId { get; init; }

    public required string Title { get; init; }

    public required int Severity { get; init; }

    public required double Confidence { get; init; }

    public required EvidenceCategory Categories { get; init; }

    public required int ScopePid { get; init; }

    public required DateTimeOffset FirstSeenUtc { get; init; }

    public required DateTimeOffset LastSeenUtc { get; init; }

    public required int EventCount { get; init; }

    public required string Status { get; init; }

    public required string Reason { get; init; }

    public required string Counterfactual { get; init; }

    public required string FactorsJson { get; init; }

    public required string Mitre { get; init; }

    public required double Weight { get; init; }
}

public sealed record EventFilter
{
    public EventCategory? Category { get; init; }

    public EventKind? Kind { get; init; }

    public int? Pid { get; init; }

    public string? Text { get; init; }

    /// <summary>Cursor: return events with seq greater than this.</summary>
    public long? AfterSeq { get; init; }

    public int Limit { get; init; } = 200;

    /// <summary>When true, exclude events that fell outside the monitored tree.</summary>
    public bool InScopeOnly { get; init; } = true;
}

public sealed record RollupResult(int RawEventsRemoved, int RollupRowsWritten, DateTimeOffset? OldestRemainingUtc);
