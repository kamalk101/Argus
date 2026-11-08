namespace Argus.Analysis.Tests;

using Argus.Analysis.Rules;
using Argus.Core.Events;
using Argus.Core.Paths;
using Xunit;

/// <summary>
/// N-005 and X-002. N-005 has to tell a program walking generated names from a resolver having a bad
/// day; X-002 has to tell a planted payload from an installer that writes a helper and starts it.
/// </summary>
public sealed class CorrelationRuleTests
{
    private const string StartupDir = @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup";

    [Fact]
    public void Many_names_that_do_not_exist_are_a_storm()
    {
        var events = new List<RawEvent> { Fx.RootStart() };
        for (var i = 0; i < 15; i++)
        {
            events.Add(Fx.Dns(Fx.RootPid, $"candidate{i:D2}.example.invalid", 1 + i * 0.5, EventKind.DnsResponse, DnsStatus.NameDoesNotExist));
        }

        var (snapshot, _) = Fx.Run(events);

        var finding = Assert.Single(snapshot.Detections, d => d.RuleId == "N-005");
        Assert.Contains("distinct_failed_names=15", finding.Factors);
        Assert.Equal(50, finding.Severity);
    }

    [Fact]
    public void Repeated_failures_for_one_name_are_not_a_storm()
    {
        // A single dead host retried is a broken endpoint, not a candidate list: the rule counts
        // distinct names, so repetition adds nothing.
        var events = new List<RawEvent> { Fx.RootStart() };
        for (var i = 0; i < 40; i++)
        {
            events.Add(Fx.Dns(Fx.RootPid, "update.contoso.invalid", 1 + i * 0.5, EventKind.DnsResponse, DnsStatus.NameDoesNotExist));
        }

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("N-005", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Successful_lookups_of_many_names_are_not_a_storm()
    {
        var events = new List<RawEvent> { Fx.RootStart() };
        for (var i = 0; i < 20; i++)
        {
            events.Add(Fx.Dns(Fx.RootPid, $"cdn{i:D2}.contoso.com", 1 + i * 0.5, EventKind.DnsResponse, DnsStatus.Success));
        }

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("N-005", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Timeouts_are_not_counted_because_they_say_nothing_about_the_name()
    {
        var events = new List<RawEvent> { Fx.RootStart() };
        for (var i = 0; i < 20; i++)
        {
            events.Add(Fx.Dns(Fx.RootPid, $"host{i:D2}.contoso.com", 1 + i * 0.5, EventKind.DnsResponse, DnsStatus.NoAnswer));
        }

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("N-005", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Only_the_lookups_of_one_process_are_counted()
    {
        // Machine-wide noise must not assemble a storm out of several unrelated programs.
        var events = new List<RawEvent> { Fx.RootStart() };
        for (var i = 0; i < 10; i++)
        {
            events.Add(Fx.Dns(Fx.RootPid, $"a{i:D2}.example.invalid", 1 + i * 0.5, EventKind.DnsResponse, DnsStatus.NameDoesNotExist));
            events.Add(Fx.Dns(7777, $"b{i:D2}.example.invalid", 1.2 + i * 0.5, EventKind.DnsResponse, DnsStatus.NameDoesNotExist));
        }

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("N-005", Fx.RulesOf(snapshot));
    }

    [Theory]
    [InlineData("9003", DnsStatus.NameDoesNotExist)]
    [InlineData("NXDOMAIN", DnsStatus.NameDoesNotExist)]
    [InlineData("nxdomain", DnsStatus.NameDoesNotExist)]
    [InlineData("0", DnsStatus.Success)]
    [InlineData("NOERROR", DnsStatus.Success)]
    [InlineData("1460", DnsStatus.NoAnswer)]
    [InlineData("9005", DnsStatus.NoAnswer)]
    [InlineData("9501", DnsStatus.NoAnswer)]
    [InlineData("REFUSED", DnsStatus.NoAnswer)]
    [InlineData(null, DnsStatus.Unknown)]
    [InlineData("", DnsStatus.Unknown)]
    public void Dns_status_parses_the_codes_the_resolver_reports(string? raw, DnsStatus expected) =>
        Assert.Equal(expected, DnsStatuses.Parse(raw));

    [Fact]
    public void An_unrecognised_status_is_unknown_rather_than_a_failed_lookup()
    {
        // Measured on Windows: every A (QueryType 1) response carries QueryStatus=87, including for
        // names that resolve — example.com answered with its addresses through the AAAA query while
        // its A record carried 87 and no results. Mapping unknown non-zero codes to NoAnswer invented
        // a failure for lookups that had succeeded. Only codes with a known meaning may be mapped.
        Assert.Equal(DnsStatus.Unknown, DnsStatuses.Parse("87"));
        Assert.Equal(DnsStatus.Unknown, DnsStatuses.Parse("12345"));
    }

    [Fact]
    public void A_payload_written_into_startup_and_then_run_correlates()
    {
        var planted = $@"{StartupDir}\payload.exe";
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileWrite, Fx.RootPid, planted, 1, bytesOut: 4096, effect: FileEffect.CreatedOrTruncated),
            Fx.ProcessStart(8000, Fx.RootPid, "payload.exe", planted, $"\"{planted}\"", 3),
        ]);

        var finding = Assert.Single(snapshot.Detections, d => d.RuleId == "X-002");
        Assert.Contains($"executed_path={PathKey.Canonicalize(planted)}", finding.Factors);
        Assert.Contains("match_basis=path", finding.Factors);
        Assert.Equal(85, finding.Severity);
    }

    [Fact]
    public void A_launch_with_no_resolved_path_still_correlates_when_the_writer_is_its_parent()
    {
        // Measured live: a short-lived payload started from Startup arrives with imagePath=null and
        // observability=partial, because the metadata lookup loses the race with a process that exits
        // in milliseconds. Requiring a resolved path meant the rule could never fire for the common
        // case, so the fallback is the written file's name plus the writer being the parent.
        var planted = $@"{StartupDir}\payload.exe";
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, planted, 1, effect: FileEffect.CreatedOrTruncated),
            Fx.ProcessStart(8000, Fx.RootPid, "payload.exe", path: null, commandLine: null, seconds: 3),
        ]);

        var finding = Assert.Single(snapshot.Detections, d => d.RuleId == "X-002");
        Assert.Contains("match_basis=name-and-parent", finding.Factors);
        Assert.Contains("executed_path=(unresolved)", finding.Factors);
    }

    [Fact]
    public void A_name_match_without_the_writer_as_parent_stays_quiet()
    {
        // Name alone is not a match: a differently parented process with the same file name could be
        // any program on the machine, which is the false positive the path check exists to avoid.
        var planted = $@"{StartupDir}\payload.exe";
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, planted, 1, effect: FileEffect.CreatedOrTruncated),
            Fx.ProcessStart(8100, 9999, "payload.exe", path: null, commandLine: null, seconds: 3),
        ]);

        Assert.DoesNotContain("X-002", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void A_same_named_program_elsewhere_does_not_correlate()
    {
        // The whole point: matching must be on the path, not the file name, or every install where a
        // helper shares a name with something in Startup would look like this.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileWrite, Fx.RootPid, $@"{StartupDir}\notes.exe", 1, bytesOut: 4096, effect: FileEffect.CreatedOrTruncated),
            Fx.ProcessStart(8000, Fx.RootPid, "notes.exe", @"C:\Program Files\Contoso\notes.exe", "notes.exe", 3),
        ]);

        Assert.DoesNotContain("X-002", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Running_a_file_from_startup_that_was_not_written_is_not_correlated()
    {
        // Started from Startup, but nothing wrote it in this session: F-001's business, not X-002's.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(8000, Fx.RootPid, "old.exe", $@"{StartupDir}\old.exe", "old.exe", 3),
        ]);

        Assert.DoesNotContain("X-002", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Opening_an_existing_file_in_startup_then_running_it_is_not_a_plant()
    {
        // A create-or-open is not evidence that content was written, so it cannot be the write half.
        var planted = $@"{StartupDir}\existing.exe";
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, planted, 1, effect: FileEffect.Opened),
            Fx.ProcessStart(8000, Fx.RootPid, "existing.exe", planted, "existing.exe", 3),
        ]);

        Assert.DoesNotContain("X-002", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void A_write_followed_by_a_launch_outside_the_window_does_not_correlate()
    {
        var planted = $@"{StartupDir}\payload.exe";
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileWrite, Fx.RootPid, planted, 1, bytesOut: 4096, effect: FileEffect.CreatedOrTruncated),
            Fx.ProcessStart(8000, Fx.RootPid, "payload.exe", planted, "payload.exe", 200),
        ]);

        Assert.DoesNotContain("X-002", Fx.RulesOf(snapshot));
    }
}
