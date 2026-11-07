namespace Argus.Analysis.Tests;

using Argus.Core.Events;
using Argus.Core.Sessions;
using Xunit;

public sealed class RuleTests
{
    [Fact]
    public void Unexpected_shell_from_application_is_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5120, Fx.RootPid, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -nop", 2),
        ]);

        Assert.Contains("P-002", Fx.RulesOf(snapshot));
        Assert.Equal(RiskBand.Suspicious, snapshot.Risk.Band);
        Assert.Contains("powershell.exe", snapshot.Detections[0].Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Shell_spawned_by_an_ide_is_not_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(4400, Fx.RootPid, "Code.exe", @"C:\Program Files\Microsoft VS Code\Code.exe", seconds: 1),
            Fx.ProcessStart(4401, 4400, "cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd.exe /c dir", 2),
        ]);

        Assert.DoesNotContain("P-002", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Non_shell_child_is_not_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(4400, Fx.RootPid, "helper.exe", @"C:\argus-test\helper.exe", seconds: 1),
        ]);

        Assert.Empty(snapshot.Detections);
    }

    [Fact]
    public void Encoded_payload_argument_is_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5120, Fx.RootPid, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -w hidden -enc SQBFAFgA", 1),
        ]);

        Assert.Contains("P-003", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Plain_interpreter_argument_is_not_flagged_as_encoded()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5120, Fx.RootPid, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -NoProfile", 1),
        ]);

        Assert.DoesNotContain("P-003", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Startup_write_is_flagged_and_system_write_uses_its_own_rule()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, Fx.StartupDir + @"\run.lnk", 2),
            Fx.FileOp(EventKind.FileWrite, Fx.RootPid, @"C:\Windows\System32\drivers\evil.sys", 3),
        ]);

        var rules = Fx.RulesOf(snapshot);
        Assert.Contains("F-001", rules);
        Assert.Contains("F-005", rules);
        Assert.DoesNotContain("F-007", rules);
    }

    [Fact]
    public void Ordinary_build_output_is_not_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileWrite, Fx.RootPid, @"C:\argus-test\build\a.o", 2),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\argus-test\build\b.o", 3),
        ]);

        Assert.Empty(snapshot.Detections);
    }

    [Fact]
    public void Executable_dropped_in_temp_is_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Users\public\AppData\Local\Temp\stage2.exe", 2),
        ]);

        Assert.Contains("F-007", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Text_file_in_temp_is_not_flagged_as_payload()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Users\public\AppData\Local\Temp\notes.txt", 2),
        ]);

        Assert.DoesNotContain("F-007", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Risky_port_on_public_address_is_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.NetConnect(Fx.RootPid, "198.51.100.10", 3389, 3),
        ]);

        Assert.Contains("N-001", Fx.RulesOf(snapshot));
        Assert.Contains("Remote Desktop", snapshot.Detections[0].Reason);
    }

    [Theory]
    [InlineData("127.0.0.1", 4444)]
    [InlineData("203.0.113.9", 443)]
    [InlineData("203.0.113.9", 8080)]
    public void Loopback_and_ordinary_ports_are_not_flagged(string ip, int port)
    {
        var (snapshot, _) = Fx.Run([Fx.RootStart(), Fx.NetConnect(Fx.RootPid, ip, port, 3)]);

        Assert.DoesNotContain("N-001", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Persistence_then_external_connection_is_correlated()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, Fx.StartupDir + @"\updater.lnk", 2),
            Fx.NetConnect(Fx.RootPid, "203.0.113.7", 443, 8),
        ]);

        Assert.Contains("X-001", Fx.RulesOf(snapshot));
        Assert.Contains("install-then-call-home", snapshot.Detections.First(d => d.RuleId == "X-001").Reason);
    }

    [Fact]
    public void External_connection_long_after_persistence_is_not_correlated()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, Fx.StartupDir + @"\updater.lnk", 2),
            Fx.NetConnect(Fx.RootPid, "203.0.113.7", 443, 180),
        ]);

        Assert.DoesNotContain("X-001", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Internal_connection_after_persistence_is_not_correlated()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, Fx.StartupDir + @"\updater.lnk", 2),
            Fx.NetConnect(Fx.RootPid, "10.0.0.5", 443, 8),
        ]);

        Assert.DoesNotContain("X-001", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Every_detection_explains_itself()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, Fx.StartupDir + @"\updater.lnk", 2),
            Fx.ProcessStart(5120, Fx.RootPid, "cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami", 3),
            Fx.NetConnect(5120, "203.0.113.7", 4444, 5),
        ]);

        Assert.NotEmpty(snapshot.Detections);
        Assert.All(snapshot.Detections, detection =>
        {
            Assert.False(string.IsNullOrWhiteSpace(detection.Reason));
            Assert.False(string.IsNullOrWhiteSpace(detection.Counterfactual));
            Assert.False(string.IsNullOrWhiteSpace(detection.Title));
            Assert.NotEmpty(detection.Mitre);
            Assert.NotEmpty(detection.Factors);
        });

        Assert.Contains("Risk", snapshot.Risk.Explanation);
        Assert.NotEmpty(snapshot.Risk.Contributions);
    }

    [Fact]
    public void Out_of_scope_processes_are_counted_but_not_analysed()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5000, 777, "unrelated.exe", @"C:\Program Files\Other\unrelated.exe", seconds: 1),
            Fx.FileOp(EventKind.FileCreate, 5000, @"C:\Windows\System32\unrelated.dll", 2),
        ]);

        Assert.Empty(snapshot.Detections);
        Assert.True(snapshot.Counters.EventsOutsideScope > 0);
        Assert.Equal(1, snapshot.Counters.EventsInScope);
    }
}
