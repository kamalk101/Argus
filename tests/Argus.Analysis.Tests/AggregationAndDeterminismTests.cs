namespace Argus.Analysis.Tests;

using Argus.Core.Events;
using Argus.Core.Sessions;
using Argus.Simulator;
using Xunit;

public sealed class AggregationAndDeterminismTests
{
    [Fact]
    public void Repeats_inside_the_window_collapse_into_one_detection()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5120, Fx.RootPid, "cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd.exe /c dir", 1),
            Fx.ProcessStart(5220, Fx.RootPid, "cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami", 3),
        ]);

        var detection = Assert.Single(snapshot.Detections);
        Assert.Equal("P-002", detection.RuleId);
        Assert.Equal(2, detection.EventCount);
        Assert.Equal(DetectionStatus.Open, detection.Status);
        Assert.Equal(2, detection.EvidenceSeq.Count);
    }

    [Fact]
    public void Repeats_after_the_window_open_a_second_detection()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5120, Fx.RootPid, "cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd.exe /c dir", 1),
            Fx.ProcessStart(5220, Fx.RootPid, "cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami", 900),
        ]);

        Assert.Equal(2, snapshot.Detections.Count);
        Assert.All(snapshot.Detections, detection => Assert.Equal(1, detection.EventCount));
    }

    [Fact]
    public void Repeats_raise_confidence()
    {
        var single = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5120, Fx.RootPid, "cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd.exe /c dir", 1),
        ]);

        var repeated = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5120, Fx.RootPid, "cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd.exe /c dir", 1),
            Fx.ProcessStart(5220, Fx.RootPid, "cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami", 3),
        ]);

        Assert.True(repeated.Snapshot.Risk.Score > single.Snapshot.Risk.Score);
        Assert.True(Assert.Single(repeated.Snapshot.Detections).Confidence
            > Assert.Single(single.Snapshot.Detections).Confidence);
    }

    [Fact]
    public void Replay_is_deterministic()
    {
        var scenario = ScenarioLoader.Load(Path.Combine(RepoPaths.Scenarios, "06-persistence-then-c2.jsonl"));

        var first = ScenarioRunner.Run(scenario);
        var second = ScenarioRunner.Run(scenario);

        Assert.Equal(first.Snapshot.Risk.Score, second.Snapshot.Risk.Score, 3);
        Assert.Equal(first.Snapshot.Risk.Band, second.Snapshot.Risk.Band);
        Assert.Equal(first.RuleIds, second.RuleIds);
        Assert.Equal(
            first.Snapshot.Detections.Select(d => d.Key).OrderBy(k => k, StringComparer.Ordinal),
            second.Snapshot.Detections.Select(d => d.Key).OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(first.Snapshot.Counters.EventsInScope, second.Snapshot.Counters.EventsInScope);
    }

    [Fact]
    public void Every_fixture_matches_its_expectation()
    {
        var scenarios = ScenarioLoader.LoadDirectory(RepoPaths.Scenarios);

        Assert.True(scenarios.Count >= 14, $"expected at least 14 fixtures, found {scenarios.Count}");

        var failures = new List<string>();
        foreach (var scenario in scenarios)
        {
            var run = ScenarioRunner.Run(scenario);
            var assertion = ScenarioRunner.Verify(run);
            if (!assertion.Passed)
            {
                failures.Add(assertion.Describe(scenario.Meta.Name));
            }
        }

        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    [Fact]
    public void Monitoring_gap_is_recorded_not_hidden()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            new RawEvent
            {
                Ts = Fx.T0.AddSeconds(1),
                Kind = EventKind.MonitorGap,
                Pid = Fx.RootPid,
                ImageName = "etw",
                Detail = "event buffer overflow, 42 events lost",
                Target = "etw:file",
                Source = EventSourceKind.Replay,
            },
        ]);

        var gap = Assert.Single(snapshot.Gaps);

        // The sensor sends the reason in Target and the prose in Detail; the gap log used to read
        // them the other way round, so reports named gaps by their description.
        Assert.Equal("etw:file", gap.Reason);
        Assert.Contains("buffer overflow", gap.Detail);
        Assert.Equal(1, snapshot.Counters.Gaps);
    }
}
