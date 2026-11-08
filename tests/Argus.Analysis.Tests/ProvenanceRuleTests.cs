namespace Argus.Analysis.Tests;

using Argus.Analysis.Rules;
using Argus.Core.Events;
using Xunit;

/// <summary>
/// P-001, P-005 and P-008. Each pair separates the act from its ordinary twin: an application that
/// runs an interpreter from a shell that does, provenance from a binary nobody vouched for, and
/// creation across a process boundary from delegation by the operating system.
/// </summary>
public sealed class ProvenanceRuleTests
{
    private const string System32 = @"C:\Windows\System32";
    private const string CustomApp = @"C:\Program Files\Contoso\contoso.exe";

    [Fact]
    public void An_interpreter_in_the_tree_with_no_observed_creator_is_flagged()
    {
        // An interpreter whose image sits under the root's own directory but whose creator was never
        // recorded. P-002 cannot speak here, because there is no parent to name; this is the case
        // P-001 exists for.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(6010, 9999, "cmd.exe", @"C:\argus-test\cmd.exe", "cmd.exe /c whoami /priv", 2),
        ]);

        var finding = Assert.Single(snapshot.Detections, d => d.RuleId == "P-001");
        Assert.Contains("child=cmd.exe", finding.Factors);
        Assert.Contains("basis=no-observed-creator", finding.Factors);
        Assert.Equal(60, finding.Severity);
    }

    [Fact]
    public void A_named_non_shell_parent_is_left_to_P_002_so_one_launch_is_counted_once()
    {
        // The two rules are disjoint by construction: where a creator was observed, P-002 speaks and
        // P-001 stands aside. Otherwise one shell would be scored as two independent findings.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(6000, Fx.RootPid, "contoso.exe", CustomApp, "contoso.exe", 1),
            Fx.ProcessStart(6010, 6000, "cmd.exe", $@"{System32}\cmd.exe", "cmd.exe /c whoami /priv", 2),
        ]);

        Assert.Contains("P-002", Fx.RulesOf(snapshot));
        Assert.DoesNotContain("P-001", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void A_shell_spawning_a_shell_is_not_reported()
    {
        // The whole point of a shell is to start other interpreters, and P-002 covers the parents
        // where the act is genuinely unexpected.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(6000, 9999, "explorer.exe", $@"C:\Windows\explorer.exe", "explorer.exe", 1),
            Fx.ProcessStart(6010, 6000, "cmd.exe", $@"{System32}\cmd.exe", "cmd.exe /c dir", 2),
            Fx.ProcessStart(6020, 6010, "powershell.exe", $@"{System32}\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoProfile", 3),
        ]);

        Assert.DoesNotContain("P-001", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void A_document_viewer_is_left_to_P_002_so_one_launch_is_counted_once()
    {
        // winword spawning cmd is exactly P-002. P-001 must stand aside or the scorer adds the same
        // behaviour twice and the event reads as two independent findings.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(6100, Fx.RootPid, "winword.exe", @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "WINWORD.EXE /n \"invoice.docx\"", 1),
            Fx.ProcessStart(6110, 6100, "cmd.exe", $@"{System32}\cmd.exe", "cmd.exe /c calc.exe", 2),
        ]);

        Assert.Contains("P-002", Fx.RulesOf(snapshot));
        Assert.DoesNotContain("P-001", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void An_unsigned_child_of_the_tree_is_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(6200, Fx.RootPid, "helper.exe", @"C:\Program Files\Contoso\helper.exe", "helper.exe", 1, SignatureStatus.Invalid),
        ]);

        var finding = Assert.Single(snapshot.Detections, d => d.RuleId == "P-005");
        Assert.Contains("signature=Invalid", finding.Factors);
        Assert.Equal(30, finding.Severity);
    }

    [Fact]
    public void A_binary_whose_signature_could_not_be_read_is_not_called_unsigned()
    {
        // This is the whole reason the status is three-way. "Unknown" is an absence of evidence and
        // reporting it would accuse every protected process in the tree.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(6200, Fx.RootPid, "opaque.exe", @"C:\Program Files\Contoso\opaque.exe", "opaque.exe", 1, signature: null),
            Fx.ProcessStart(6210, Fx.RootPid, "trusted.exe", @"C:\Program Files\Contoso\trusted.exe", "trusted.exe", 2, SignatureStatus.Valid),
        ]);

        Assert.DoesNotContain("P-005", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void A_process_in_the_app_directory_with_no_observed_creator_is_inferred_injection()
    {
        // The scope tracker attributes this by location alone: the image sits under the root's own
        // directory, yet no parent link to the root was observed. That is the process-table
        // footprint of a remote thread, and the only shape the sensor can actually prove.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(7100, 9999, "payload.exe", @"C:\argus-test\payload.exe", "payload.exe", 2),
        ]);

        var finding = Assert.Single(snapshot.Detections, d => d.RuleId == "P-008");
        Assert.Contains("basis=inferred-from-process-table", finding.Factors);
        Assert.Contains("inferred", finding.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Ordinary_parent_child_launches_are_not_injection()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(7200, Fx.RootPid, "child.exe", @"C:\Program Files\Contoso\child.exe", "child.exe", 1),
            Fx.ProcessStart(7210, 7200, "grandchild.exe", @"C:\Program Files\Contoso\grandchild.exe", "grandchild.exe", 2),
        ]);

        Assert.DoesNotContain("P-008", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void A_process_from_a_shared_directory_proves_nothing_about_its_creator()
    {
        // System32 is shared by the whole machine, so its location is no evidence that the application
        // created this process, and none that it did not.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(7300, 9999, "regsvr32.exe", $@"{System32}\regsvr32.exe", "regsvr32.exe /s foo.dll", 2),
        ]);

        Assert.DoesNotContain("P-008", Fx.RulesOf(snapshot));
    }
}
