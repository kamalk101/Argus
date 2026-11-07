namespace Argus.Core.Risk;

/// <summary>
/// Tuning surface for the scoring model. Values are data so profiles can change
/// without a rebuild; the model itself is code and is unit-tested.
/// </summary>
public sealed record RiskOptions
{
    /// <summary>Risk at or above which behaviour is reported as suspicious.</summary>
    public double SuspiciousThreshold { get; init; } = 20;

    /// <summary>Risk at or above which behaviour may be reported as malicious.</summary>
    public double MaliciousThreshold { get; init; } = 65;

    /// <summary>A single rule at this severity is suspicious even below the score threshold.</summary>
    public double CategoryRuleSeverity { get; init; } = 45;

    /// <summary>Age at which a detection's weight halves.</summary>
    public TimeSpan DecayHalfLife { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>Evidence fades but is never forgotten while the session is open.</summary>
    public double DecayFloor { get; init; } = 0.60;

    /// <summary>Score bonus per additional independent evidence category.</summary>
    public double CorroborationStep { get; init; } = 0.08;

    public double CorroborationCap { get; init; } = 1.25;

    /// <summary>Severity that counts as critical for the malicious gate.</summary>
    public double CriticalSeverity { get; init; } = 90;

    public double CriticalConfidence { get; init; } = 0.80;

    public static RiskOptions Default { get; } = new();
}

/// <summary>
/// One aggregated detection as the scorer sees it. Keyed by rule and process so
/// repeats collapse into a single weighted signal.
/// </summary>
public sealed record DetectionSignal(
    string Key,
    string RuleId,
    double Severity,
    double Confidence,
    Events.EvidenceCategory Categories,
    DateTimeOffset LastSeenUtc,
    int EventCount = 1);

public sealed record RiskContribution(
    string Key,
    string RuleId,
    double Severity,
    double Confidence,
    double Weight,
    TimeSpan Age,
    Events.EvidenceCategory Categories);

/// <summary>
/// Result of scoring a session. Contains everything the UI needs to explain the
/// number, so a verdict is never presented without its arithmetic.
/// </summary>
public sealed record RiskAssessment
{
    public required double Score { get; init; }

    public required Sessions.RiskBand Band { get; init; }

    public required double PeakScore { get; init; }

    public required IReadOnlyList<RiskContribution> Contributions { get; init; }

    public required Events.EvidenceCategory Categories { get; init; }

    public required string Explanation { get; init; }

    public static RiskAssessment Empty { get; } = new()
    {
        Score = 0,
        Band = Sessions.RiskBand.Benign,
        PeakScore = 0,
        Contributions = [],
        Categories = Events.EvidenceCategory.None,
        Explanation = "No events analysed yet.",
    };
}
