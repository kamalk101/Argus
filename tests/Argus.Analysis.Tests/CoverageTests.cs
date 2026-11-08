namespace Argus.Analysis.Tests;

using Argus.Core.Events;
using Argus.Core.Sessions;
using Xunit;

/// <summary>
/// Gaps are not a penalty on the score — a dropped event is not evidence of anything. What they
/// forbid is the other direction: reading "no detections" as "nothing happened". These tests pin
/// that the coverage travels with the verdict and says so in a sentence.
/// </summary>
public sealed class CoverageTests
{
    [Fact]
    public void A_session_without_gaps_reports_complete_coverage()
    {
        var (snapshot, _) = Fx.Run([Fx.RootStart()]);

        Assert.True(snapshot.Coverage.Complete);
        Assert.Equal(0, snapshot.Coverage.Gaps);
        Assert.Empty(snapshot.Coverage.Reasons);
        Assert.DoesNotContain("coverage was incomplete", snapshot.Risk.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_quiet_session_with_a_gap_is_not_an_all_clear()
    {
        // Nothing fired, and the sensor lost events. The band stays Benign — we have no evidence of
        // anything — but the report may not present the absence as a clean bill.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Gap("volume-fuse", "in-scope event rate exceeded the fuse", 3),
        ]);

        Assert.Equal(RiskBand.Benign, snapshot.Risk.Band);
        Assert.Equal(0, snapshot.Risk.Score);
        Assert.False(snapshot.Coverage.Complete);
        Assert.Contains("not an all-clear", snapshot.Coverage.Statement, StringComparison.Ordinal);
        Assert.Contains("not an all-clear", snapshot.Risk.Explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void A_gap_does_not_change_a_score_but_does_qualify_it()
    {
        // The same detection, once with a clean stream and once with a hole in it. The score is
        // identical on purpose: invented penalties would make the number mean less, not more.
        RawEvent[] events =
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updater.lnk", 2, effect: FileEffect.CreatedOrTruncated),
        ];

        var (clean, _) = Fx.Run(events);
        var (gapped, _) = Fx.Run([.. events, Gap("etw-lost-events", "the kernel provider reported lost records", 40)]);

        Assert.Equal(clean.Risk.Score, gapped.Risk.Score);
        Assert.True(clean.Coverage.Complete);
        Assert.False(gapped.Coverage.Complete);
        Assert.Contains("may understate", gapped.Risk.Explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void Distinct_gap_reasons_are_listed_once_each_in_first_seen_order()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Gap("etw-lost-events", "lost records", 5),
            Gap("volume-fuse", "rate fuse", 10),
            Gap("etw-lost-events", "lost records again", 20),
        ]);

        Assert.Equal(3, snapshot.Coverage.Gaps);
        Assert.Equal(["etw-lost-events", "volume-fuse"], snapshot.Coverage.Reasons);
        Assert.Contains("3 collection gap(s)", snapshot.Coverage.Statement, StringComparison.Ordinal);
    }

    private static RawEvent Gap(string reason, string detail, double seconds) => new()
    {
        Ts = Fx.T0.AddSeconds(seconds),
        Kind = EventKind.MonitorGap,
        Pid = 0,
        Target = reason,
        Detail = detail,
        Source = EventSourceKind.Replay,
    };
}
