namespace Argus.Simulator;

using System.Globalization;
using System.Text;
using Argus.Analysis.Pipeline;
using Argus.Core.Events;
using Argus.Core.Paths;
using Argus.Core.Risk;
using Argus.Core.Sessions;

public sealed record ScenarioRun
{
    public required ScenarioFile Scenario { get; init; }

    public required Guid SessionId { get; init; }

    public required SessionSnapshot Snapshot { get; init; }

    public required IReadOnlyList<BehaviorEvent> Events { get; init; }

    public required IReadOnlyList<(DateTimeOffset Ts, RiskAssessment Risk)> ScoreSamples { get; init; }

    public IReadOnlyList<string> RuleIds =>
        [.. Snapshot.Detections.Select(d => d.RuleId).Distinct(StringComparer.Ordinal).OrderBy(id => id, StringComparer.Ordinal)];
}

public sealed record ScenarioAssertion(IReadOnlyList<string> Failures)
{
    public bool Passed => Failures.Count == 0;

    public string Describe(string scenarioName)
    {
        if (Passed)
        {
            return "pass";
        }

        var builder = new StringBuilder();
        builder.Append("FAIL ").Append(scenarioName);
        foreach (var failure in Failures)
        {
            builder.Append("\n    - ").Append(failure);
        }

        return builder.ToString();
    }
}

/// <summary>
/// Runs a recorded scenario through the exact production pipeline. Deterministic:
/// the same file produces the same detections, counts and scores, so a rule change
/// that alters a verdict fails the assertion.
/// </summary>
public static class ScenarioRunner
{
    /// <summary>
    /// Deterministic catalog for replay. Environment-dependent entries are skipped
    /// (no environment map), leaving literal Windows paths plus the fixture root, so
    /// results never depend on the machine running the test.
    /// </summary>
    public static SensitivePathCatalog DefaultCatalog { get; } =
        SensitivePathCatalog.Default(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

    public static ScenarioRun Run(ScenarioFile scenario, SensitivePathCatalog? catalog = null, RiskOptions? risk = null)
    {
        ArgumentNullException.ThrowIfNull(scenario);

        var sessionId = scenario.Meta.SessionId is { } text && Guid.TryParse(text, out var parsed)
            ? parsed
            : Guid.NewGuid();

        var pipeline = new SessionPipeline(new SessionPipelineOptions
        {
            SessionId = sessionId,
            RootPid = scenario.Meta.RootPid,
            RootImagePath = scenario.Meta.RootImagePath,
            Catalog = catalog ?? DefaultCatalog,
            Risk = risk ?? RiskOptions.Default,
        });

        var events = new List<BehaviorEvent>(scenario.Events.Count);
        var samples = new List<(DateTimeOffset, RiskAssessment)>();
        var lastScore = double.NaN;

        foreach (var rawEvent in scenario.Events)
        {
            var result = pipeline.Ingest(rawEvent);
            events.Add(result.Event);

            if (double.IsNaN(lastScore) || Math.Abs(result.Risk.Score - lastScore) > 0.0001)
            {
                samples.Add((result.Event.TimestampUtc, result.Risk));
                lastScore = result.Risk.Score;
            }
        }

        return new ScenarioRun
        {
            Scenario = scenario,
            SessionId = sessionId,
            Snapshot = pipeline.Snapshot(),
            Events = events,
            ScoreSamples = samples,
        };
    }

    public static ScenarioAssertion Verify(ScenarioRun run)
    {
        ArgumentNullException.ThrowIfNull(run);

        var failures = new List<string>();
        var expect = run.Scenario.Meta.Expect;
        var rules = run.RuleIds;

        foreach (var required in expect.Rules)
        {
            if (!rules.Contains(required, StringComparer.Ordinal))
            {
                failures.Add($"expected rule {required} did not fire (fired: {Describe(rules)})");
            }
        }

        foreach (var forbidden in expect.AbsentRules)
        {
            if (rules.Contains(forbidden, StringComparer.Ordinal))
            {
                failures.Add($"rule {forbidden} fired but was expected to stay quiet");
            }
        }

        if (expect.Band is { } band
            && !string.Equals(run.Snapshot.Risk.Band.ToString(), band, StringComparison.OrdinalIgnoreCase))
        {
            failures.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"expected band {band}, got {run.Snapshot.Risk.Band} (risk {run.Snapshot.Risk.Score:0.0})"));
        }

        if (expect.MinScore is { } min && run.Snapshot.Risk.Score < min)
        {
            failures.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"expected risk >= {min:0.0}, got {run.Snapshot.Risk.Score:0.0}"));
        }

        if (expect.MaxScore is { } max && run.Snapshot.Risk.Score > max)
        {
            failures.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"expected risk <= {max:0.0}, got {run.Snapshot.Risk.Score:0.0}"));
        }

        if (expect.MaxDetections is { } maxDetections && run.Snapshot.Detections.Count > maxDetections)
        {
            failures.Add($"expected at most {maxDetections} detections, got {run.Snapshot.Detections.Count}");
        }

        if (expect.ExpectGaps && run.Snapshot.Gaps.Count == 0)
        {
            failures.Add("expected a monitoring gap, none recorded");
        }

        if (!expect.ExpectGaps && run.Snapshot.Gaps.Count > 0)
        {
            failures.Add($"unexpected monitoring gap: {run.Snapshot.Gaps[0].Reason}");
        }

        return new ScenarioAssertion(failures);
    }

    private static string Describe(IReadOnlyList<string> rules) =>
        rules.Count == 0 ? "none" : string.Join(", ", rules);
}
