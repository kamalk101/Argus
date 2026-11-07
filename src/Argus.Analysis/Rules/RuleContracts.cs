namespace Argus.Analysis.Rules;

using Argus.Analysis.Correlation;
using Argus.Core.Events;
using Argus.Core.Paths;
using Argus.Core.Processes;

/// <summary>
/// Identity and intent of a rule. Mitre ids are recorded so reports can map
/// behaviour to ATT&CK without interpretation at render time.
/// </summary>
public sealed record RuleMetadata(
    string Id,
    string Title,
    int Severity,
    EvidenceCategory Categories,
    IReadOnlyList<string> Mitre,
    string Description,
    double BaseConfidence = 0.90);

/// <summary>
/// A single rule hit. The reason and counterfactual are required: a detection
/// that cannot explain itself is a bug, not a finding.
/// </summary>
public sealed record RuleFinding
{
    public required RuleMetadata Rule { get; init; }

    public required string Reason { get; init; }

    public required string Counterfactual { get; init; }

    /// <summary>Machine-readable inputs that produced the finding, for the evidence panel.</summary>
    public IReadOnlyList<string> Factors { get; init; } = [];

    public int? TargetPid { get; init; }

    /// <summary>
    /// Process this detection is attributed to for grouping. A spawned shell is
    /// grouped under the application that spawned it, not under the shell, so
    /// repeats from one parent collapse into a single detection.
    /// </summary>
    public int? GroupPid { get; init; }

    public string? Target { get; init; }
}

/// <summary>Everything a rule may consult. Read-only by contract.</summary>
public sealed class RuleContext
{
    public required BehaviorEvent Event { get; init; }

    /// <summary>Stream time: the event's timestamp, so replay is deterministic.</summary>
    public required DateTimeOffset Now { get; init; }

    public required ProcessTable Processes { get; init; }

    public required CorrelationIndex Correlation { get; init; }

    public required SensitivePathCatalog Catalog { get; init; }

    public required int RootPid { get; init; }
}

public interface IRule
{
    RuleMetadata Metadata { get; }
}

/// <summary>Evaluated for every in-scope event.</summary>
public interface IEventRule : IRule
{
    IEnumerable<RuleFinding> Evaluate(RuleContext context);
}

/// <summary>Looks across recent events (e.g. persistence then network).</summary>
public interface ICorrelatedRule : IRule
{
    IEnumerable<RuleFinding> Evaluate(RuleContext context);
}
