namespace Argus.Analysis.Tests;

using Argus.Analysis.Rules;
using Argus.Core.Events;
using Xunit;

/// <summary>
/// P-004, P-006 and P-007: three rules whose whole job is telling an ordinary act from its abusive
/// twin — an installed helper from a staged one, administration from enumeration, a backup from a
/// wiper. Each pair below is that distinction, not a restatement of the threshold.
/// </summary>
public sealed class ProcessChannelRuleTests
{
    private const string System32 = @"C:\Windows\System32";

    [Fact]
    public void A_helper_launched_from_temp_is_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5200, Fx.RootPid, "stage2.exe", @"C:\Users\kamal\AppData\Local\Temp\stage2.exe", "\"C:\\Users\\kamal\\AppData\\Local\\Temp\\stage2.exe\" /quiet", 2),
        ]);

        var finding = Assert.Single(snapshot.Detections, d => d.RuleId == "P-004");
        Assert.Contains("location=a temporary directory", finding.Factors);
        Assert.Equal(45, finding.Severity);
    }

    [Fact]
    public void An_installed_helper_is_not_flagged()
    {
        // Same binary name, same arguments, installed location: the rule is about where, only.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5200, Fx.RootPid, "stage2.exe", @"C:\Program Files\Contoso\stage2.exe", "\"C:\\Program Files\\Contoso\\stage2.exe\" /quiet", 2),
            Fx.ProcessStart(5210, Fx.RootPid, "notes.exe", @"C:\Users\kamal\Documents\notes.exe", "notes.exe", 3),
        ]);

        Assert.DoesNotContain("P-004", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void A_launch_without_a_reported_path_is_not_judged()
    {
        // A bare image name says nothing about location; guessing one would make this rule fire on
        // every process whose path the sensor failed to resolve.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5200, Fx.RootPid, "mystery.exe", path: null, commandLine: "mystery.exe /run", seconds: 2),
        ]);

        Assert.DoesNotContain("P-004", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void One_tool_driven_with_different_switches_is_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5400, Fx.RootPid, "whoami.exe", $@"{System32}\whoami.exe", "whoami /priv", 2),
            Fx.ProcessStart(5410, Fx.RootPid, "whoami.exe", $@"{System32}\whoami.exe", "whoami /groups", 4),
            Fx.ProcessStart(5420, Fx.RootPid, "whoami.exe", $@"{System32}\whoami.exe", "whoami /all", 6),
        ]);

        var finding = Assert.Single(snapshot.Detections, d => d.RuleId == "P-006");
        Assert.Contains("launches=3", finding.Factors);
        Assert.Contains("distinct_flags=3", finding.Factors);
    }

    [Fact]
    public void Two_invocations_with_proper_arguments_are_not_enumeration()
    {
        // Fixture 20 in miniature: querying and then deleting a task uses five switches across two
        // launches, which is administration, not discovery.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5130, Fx.RootPid, "schtasks.exe", $@"{System32}\schtasks.exe", "schtasks /query /fo LIST", 2),
            Fx.ProcessStart(5131, Fx.RootPid, "schtasks.exe", $@"{System32}\schtasks.exe", "schtasks /delete /tn \"Old Vendor Task\" /f", 3),
        ]);

        Assert.DoesNotContain("P-006", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Command_interpreters_are_not_counted_as_discovery()
    {
        // `cmd /c …` repeats constantly in ordinary sessions and P-002 already speaks about it.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5500, 9999, "cmd.exe", $@"{System32}\cmd.exe", "cmd /c dir", 2),
            Fx.ProcessStart(5501, 9999, "cmd.exe", $@"{System32}\cmd.exe", "cmd /c set", 3),
            Fx.ProcessStart(5502, 9999, "cmd.exe", $@"{System32}\cmd.exe", "cmd /c ver", 4),
        ]);

        Assert.DoesNotContain("P-006", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Switch_extraction_keeps_names_and_drops_values_and_numbers()
    {
        var flags = RepeatedFlagsRule.ExtractFlags("tool /user:alice /user:bob -x=1 --long /2 \"--quoted\"");

        Assert.Equal(["user", "x", "long", "quoted"], flags);
    }

    [Fact]
    public void Deleting_shadow_copies_is_recovery_tampering()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5300, Fx.RootPid, "vssadmin.exe", $@"{System32}\vssadmin.exe", "vssadmin  delete shadows /all /quiet", 2),
        ]);

        var finding = Assert.Single(snapshot.Detections, d => d.RuleId == "P-007");
        Assert.Contains("shadow copies", finding.Reason, StringComparison.Ordinal);
        Assert.Equal(80, finding.Severity);
    }

    [Fact]
    public void Listing_shadow_copies_is_not_tampering()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5300, Fx.RootPid, "vssadmin.exe", $@"{System32}\vssadmin.exe", "vssadmin list shadows", 2),
            Fx.ProcessStart(5310, Fx.RootPid, "vssadmin.exe", $@"{System32}\vssadmin.exe", "vssadmin create shadow /for=C:", 3),
        ]);

        Assert.DoesNotContain("P-007", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Disabling_recovery_is_tampering()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5310, Fx.RootPid, "bcdedit.exe", $@"{System32}\bcdedit.exe", "bcdedit /set {default} recoveryenabled No", 2),
        ]);

        Assert.Contains("P-007", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Wmi_shadowcopy_deletion_is_the_same_act()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5320, Fx.RootPid, "wmic.exe", $@"{System32}\wbem\wmic.exe", "wmic shadowcopy delete /nointeractive", 2),
        ]);

        Assert.Contains("P-007", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void A_backup_start_is_not_recovery_tampering()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5330, Fx.RootPid, "wbadmin.exe", $@"{System32}\wbadmin.exe", "wbadmin start backup -backupTarget:E: -allCritical", 2),
            Fx.ProcessStart(5340, Fx.RootPid, "bcdedit.exe", $@"{System32}\bcdedit.exe", "bcdedit /enum {default}", 3),
        ]);

        Assert.DoesNotContain("P-007", Fx.RulesOf(snapshot));
    }
}
