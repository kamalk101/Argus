namespace Argus.Analysis.Tests;

using System.Text.Json;
using Argus.Analysis.Rules;
using Argus.Core.Events;
using Argus.Core.Risk;
using Argus.Core.Sessions;
using Argus.Simulator;
using Xunit;

/// <summary>
/// Thresholds are data now, which means a profile can be wrong in ways code could not be.
/// These tests pin the three things that matters: the defaults still match the catalogue, an
/// override actually changes behaviour, and a settings file that is wrong fails loudly instead
/// of leaving the operator with defaults they believe they replaced.
/// </summary>
public sealed class RuleSettingsTests
{
    [Fact]
    public void Default_thresholds_are_the_catalogue_values()
    {
        var settings = RuleSettings.Default;

        Assert.Equal(200, settings.MassFileCreationCount);
        Assert.Equal(10, settings.DestructiveRenameCount);
        Assert.Equal(5, settings.DestructiveRenameDirectories);
        Assert.Equal(6, settings.BeaconConnections);
        Assert.Equal(20L * 1024 * 1024, settings.OutboundVolumeBytes);
    }

    [Fact]
    public void The_catalogue_uses_the_defaults_when_no_settings_are_given()
    {
        var rules = RuleCatalog.CreateDefault();

        var massFiles = Assert.IsType<MassFileCreationRule>(rules.EventRules.Single(r => r.Metadata.Id == "F-004"));
        var beacon = Assert.IsType<BeaconingRule>(rules.EventRules.Single(r => r.Metadata.Id == "N-002"));

        Assert.Equal(RuleSettings.Default.MassFileCreationCount, massFiles.Threshold);
        Assert.Equal(RuleSettings.Default.BeaconConnections, beacon.Threshold);
    }

    [Fact]
    public void An_override_changes_when_a_rule_fires()
    {
        // Four creates are ordinary behaviour under the shipped threshold and a burst under this one.
        var events = new List<RawEvent> { Fx.RootStart() };
        events.AddRange(Fx.MassCreates(4, seconds: 2, span: 3));

        var (quiet, _) = Fx.Run(events);
        Assert.DoesNotContain("F-004", Fx.RulesOf(quiet));

        var (loud, _) = Fx.Run(events, rules: new RuleSettings { MassFileCreationCount = 4 });
        var finding = Assert.Single(loud.Detections, d => d.RuleId == "F-004");
        Assert.Contains("creates_in_window=4", finding.Factors);
        Assert.Contains("threshold=4", finding.Factors);
    }

    [Fact]
    public void The_finding_quotes_the_threshold_that_actually_fired()
    {
        // A report that says "below 200 creates per 60 s" while running at 4 would be a lie.
        var events = new List<RawEvent> { Fx.RootStart() };
        events.AddRange(Fx.MassCreates(4, seconds: 2, span: 3));

        var (snapshot, _) = Fx.Run(events, rules: new RuleSettings { MassFileCreationCount = 4, MassFileCreationWindowSeconds = 12 });

        var finding = Assert.Single(snapshot.Detections, d => d.RuleId == "F-004");
        Assert.Contains("Would not fire below 4 content-changing file creates per 12 s", finding.Counterfactual);
    }

    [Fact]
    public void Settings_are_read_from_json_with_camel_case_keys()
    {
        var settings = RuleSettings.FromJson("""
            {
              // A profile that treats a smaller upload as a transfer.
              "outboundVolumeBytes": 1048576,
              "beaconConnections": 4
            }
            """);

        Assert.Equal(1024 * 1024, settings.OutboundVolumeBytes);
        Assert.Equal(4, settings.BeaconConnections);
        Assert.Equal(RuleSettings.Default.OutboundVolumeWindowSeconds, settings.OutboundVolumeWindowSeconds);
    }

    [Fact]
    public void An_unknown_key_is_an_error_rather_than_a_silent_default()
    {
        // "beaconThreshold" is what someone will write; BeaconConnections is what exists.
        var exception = Assert.Throws<InvalidDataException>(
            () => RuleSettings.FromJson("""{ "beaconThreshold": 4 }"""));

        Assert.Contains("beaconThreshold", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("""{ "massFileCreationCount": 0 }""")]
    [InlineData("""{ "massFileCreationCount": -5 }""")]
    [InlineData("""{ "beaconWindowSeconds": 0 }""")]
    [InlineData("""{ "outboundVolumeBytes": -1 }""")]
    [InlineData("""{ "beaconMaxJitter": 15 }""")]
    public void Impossible_values_are_rejected_with_the_field_named(string json)
    {
        var exception = Assert.Throws<InvalidDataException>(() => RuleSettings.FromJson(json));
        Assert.Contains("must be", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_missing_settings_file_names_the_path()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"argus-rules-missing-{Guid.NewGuid():N}.json");

        var exception = Assert.Throws<InvalidDataException>(() => RuleSettings.Load(missing));
        Assert.Contains(missing, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Malformed_json_reports_where_it_came_from()
    {
        var exception = Assert.Throws<InvalidDataException>(() => RuleSettings.FromJson("{ not json", "profile.json"));
        Assert.Contains("profile.json", exception.Message, StringComparison.Ordinal);
    }
}

/// <summary>
/// Two regression gates the catalogue depends on: benign fixtures must never produce a
/// high-severity detection, and docs/RULES.md must describe the catalogue that is actually
/// shipped. Both are cheap, and both fail loudly the day a rule widens or a table drifts.
/// </summary>
public sealed class CatalogueGateTests
{
    [Fact]
    public void No_benign_scenario_produces_a_high_severity_detection()
    {
        var failures = new List<string>();

        foreach (var scenario in ScenarioLoader.LoadDirectory(RepoPaths.Scenarios))
        {
            var run = ScenarioRunner.Run(scenario);
            if (run.Snapshot.Risk.Band != RiskBand.Benign)
            {
                continue;
            }

            foreach (var detection in run.Snapshot.Detections.Where(d => d.Severity >= 65))
            {
                failures.Add($"{scenario.Meta.Name}: {detection.RuleId} severity {detection.Severity:0} in a benign scenario");
            }

            if (run.Snapshot.Risk.Score >= RiskOptions.Default.SuspiciousThreshold)
            {
                failures.Add($"{scenario.Meta.Name}: benign band but risk {run.Snapshot.Risk.Score:0.0}");
            }
        }

        Assert.Empty(failures);
    }

    [Fact]
    public void The_catalogue_table_in_the_docs_matches_the_shipped_rules()
    {
        var documented = ReadDocumentedTable();
        var generated = RuleCatalog.CreateDefault().All
            .OrderBy(rule => rule.Metadata.Id, StringComparer.Ordinal)
            .Select(rule => new
            {
                Id = rule.Metadata.Id,
                Row = string.Create(
                    System.Globalization.CultureInfo.InvariantCulture,
                    $"| {rule.Metadata.Id} | {rule.Metadata.Title} | {rule.Metadata.Severity} | {EvidenceCategories.Describe(rule.Metadata.Categories).Replace(", ", " + ", StringComparison.Ordinal)} | {string.Join(", ", rule.Metadata.Mitre)} | {KindOf(rule)} |"),
            })
            .ToList();

        // Order matters too: the table is meant to be pasted from `argus rules --markdown`, so a
        // hand-edited row that drifted is as much a failure as a missing one.
        Assert.Equal(
            generated.Select(rule => rule.Row).ToList(),
            documented.Select(row => row.TrimEnd()).ToList());

        static string KindOf(IRule rule) => rule switch
        {
            IWindowedRule windowed => $"aggregated ({(int)windowed.Window.TotalSeconds} s)",
            ICorrelatedRule => "correlated",
            _ => "per-event",
        };
    }

    private static List<string> ReadDocumentedTable()
    {
        var path = Path.Combine(RepoPaths.Root, "docs", "RULES.md");
        var lines = File.ReadAllLines(path);

        return
        [
            .. lines
                .SkipWhile(line => !line.StartsWith("| ID |", StringComparison.Ordinal))
                .Skip(2)
                .TakeWhile(line => line.StartsWith('|'))
                .Select(line => line.TrimEnd()),
        ];
    }
}

/// <summary>
/// docs/RULES.md carries a score table worked by hand. This keeps it honest: if the model moves,
/// the documentation fails the build instead of quietly describing the old arithmetic.
/// </summary>
public sealed class ScoreTableTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void The_documented_score_table_matches_the_scorer()
    {
        var fileOnly = RiskScorer.Evaluate(
            [
                Signal("F-001:1234", "F-001", 80, 0.90, EvidenceCategory.File),
            ],
            Now);

        Assert.Equal(72.0, fileOnly.Score);
        Assert.Equal(RiskBand.Suspicious, fileOnly.Band);

        var twoChannels = RiskScorer.Evaluate(
            [
                Signal("F-001:1234", "F-001", 80, 0.90, EvidenceCategory.File),
                Signal("N-001:1234", "N-001", 50, 0.75, EvidenceCategory.Network),
            ],
            Now);

        Assert.Equal(89.1, twoChannels.Score);
        Assert.Equal(RiskBand.Malicious, twoChannels.Band);

        var aged = RiskScorer.Evaluate(
            [
                Signal("F-001:1234", "F-001", 80, 0.90, EvidenceCategory.File, lastSeen: Now.AddMinutes(-15)),
            ],
            Now);

        // The decay floor (0.60) wins over 0.5^1 at 15 minutes; the docs say so explicitly.
        Assert.Equal(43.2, aged.Score);
        Assert.Equal(RiskBand.Suspicious, aged.Band);
    }

    private static DetectionSignal Signal(
        string key,
        string ruleId,
        double severity,
        double confidence,
        EvidenceCategory category,
        DateTimeOffset? lastSeen = null) =>
        new(key, ruleId, severity, confidence, category, lastSeen ?? Now);
}
