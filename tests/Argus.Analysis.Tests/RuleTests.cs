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
    public void Signed_installer_named_setup_is_not_flagged_for_spawning_a_shell()
    {
        // Measured live 2026-11-09: a catalog-signed parent named contoso-setup-x64.exe spawning
        // PowerShell was reported by P-002 at 85. Real installers are named arbitrarily, so the
        // exemption is name *shape* plus a verified signature.
        var (snapshot, _) = Fx.Run(
        [
            Fx.ProcessStart(Fx.RootPid, 9999, "VSCodeUserSetup-x64-1.90.exe", @"C:\Users\kamal\Downloads\VSCodeUserSetup-x64-1.90.exe", signature: SignatureStatus.Valid),
            Fx.ProcessStart(5120, Fx.RootPid, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoProfile -Command Get-Date", 2),
        ]);

        Assert.DoesNotContain("P-002", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Unsigned_setup_named_program_still_flags_its_shell()
    {
        // The signature half is what stops "setup.exe" from being a free pass.
        var (snapshot, _) = Fx.Run(
        [
            Fx.ProcessStart(Fx.RootPid, 9999, "contoso-setup-x64.exe", @"C:\Users\kamal\Downloads\contoso-setup-x64.exe", signature: SignatureStatus.Invalid),
            Fx.ProcessStart(5120, Fx.RootPid, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoProfile -Command Get-Date", 2),
        ]);

        Assert.Contains("P-002", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Signed_program_without_an_installer_name_still_flags_its_shell()
    {
        // A valid publisher certificate alone is not permission to run shells: the name marker
        // is the half that says "this is a setup program", and it is required as well.
        var (snapshot, _) = Fx.Run(
        [
            Fx.ProcessStart(Fx.RootPid, 9999, "Git-2.56.0.4-64-bit.exe", @"C:\Users\kamal\Downloads\Git-2.56.0.4-64-bit.exe", signature: SignatureStatus.Valid),
            Fx.ProcessStart(5120, Fx.RootPid, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoProfile -Command Get-Date", 2),
        ]);

        Assert.Contains("P-002", Fx.RulesOf(snapshot));
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
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, Fx.StartupDir + @"\run.lnk", 2, bytesOut: 2048),
            Fx.FileOp(EventKind.FileWrite, Fx.RootPid, @"C:\Windows\System32\drivers\evil.sys", 3, bytesOut: 4096),
        ]);

        var rules = Fx.RulesOf(snapshot);
        Assert.Contains("F-001", rules);
        Assert.Contains("F-005", rules);
        Assert.DoesNotContain("F-007", rules);
    }

    // ETW's FileIO/Create is create-or-open. These tests pin the resulting contract:
    // a bare create is a touch, not a write, and only byte-backed creates or a
    // following FileWrite may back a "write to a sensitive location" detection.
    [Fact]
    public void Bare_create_in_system32_is_not_a_system_write()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Windows\System32\PING.EXE", 2),
            Fx.FileOp(EventKind.FileRead, Fx.RootPid, @"C:\Windows\System32\PING.EXE", 3),
        ]);

        Assert.Empty(snapshot.Detections);
    }

    [Fact]
    public void Opening_a_system_binary_is_not_a_system_write()
    {
        // The live shape: cmd opens System32\PING.EXE to run it. ETW reports
        // CreateDisposition=OPEN_EXISTING, which must never read as a system write.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Windows\System32\PING.EXE", 2, effect: FileEffect.Opened),
            Fx.FileOp(EventKind.FileRead, Fx.RootPid, @"C:\Windows\System32\PING.EXE", 3),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Windows\System32\kernel32.dll", 4, effect: FileEffect.Opened),
        ]);

        Assert.Empty(snapshot.Detections);
    }

    [Fact]
    public void Create_always_in_system32_is_a_system_write()
    {
        // The live shape of a drop: CREATE_ALWAYS, with no FileWrite event at all
        // (a same-volume copy duplicates extents and emits no writes).
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Windows\System32\evil.dll", 2, effect: FileEffect.CreatedOrTruncated),
        ]);

        var f005 = snapshot.Detections.Where(d => d.RuleId == "F-005").ToList();
        Assert.Single(f005);
        Assert.Contains("evidence=create", f005[0].Factors);
    }

    [Fact]
    public void Create_with_bytes_in_system32_is_a_system_write()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Windows\System32\evil.dll", 2, bytesOut: 8192),
        ]);

        Assert.Contains("F-005", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Create_then_write_in_system32_produces_one_detection()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Windows\System32\evil.dll", 2),
            Fx.FileOp(EventKind.FileWrite, Fx.RootPid, @"C:\Windows\System32\evil.dll", 3, bytesOut: 8192),
        ]);

        var f005 = snapshot.Detections.Where(d => d.RuleId == "F-005").ToList();
        Assert.Single(f005);
        Assert.Contains("evidence=write", f005[0].Factors);
    }

    [Fact]
    public void Deleting_from_a_system_location_is_a_system_write()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileDelete, Fx.RootPid, @"C:\Windows\System32\drivers\etc\hosts", 2),
        ]);

        Assert.Contains("F-005", Fx.RulesOf(snapshot));
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
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Users\public\AppData\Local\Temp\stage2.exe", 2, bytesOut: 53248),
        ]);

        Assert.Contains("F-007", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Opening_an_existing_executable_in_temp_is_not_a_drop()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Users\public\AppData\Local\Temp\stage2.exe", 2),
        ]);

        Assert.DoesNotContain("F-007", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Executable_written_to_temp_after_a_bare_create_is_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Users\public\AppData\Local\Temp\stage2.exe", 2),
            Fx.FileOp(EventKind.FileWrite, Fx.RootPid, @"C:\Users\public\AppData\Local\Temp\stage2.exe", 3, bytesOut: 53248),
        ]);

        var f007 = snapshot.Detections.Where(d => d.RuleId == "F-007").ToList();
        Assert.Single(f007);
        Assert.Contains("modified", f007[0].Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Copy_style_drop_without_a_write_event_is_still_flagged()
    {
        // A same-volume copy emits a create (CREATE_ALWAYS) and no write at all, so
        // gating a drop on FileWrite alone would hide the most common drop method.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Users\public\AppData\Local\Temp\stage2.exe", 2, effect: FileEffect.CreatedOrTruncated),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Users\public\AppData\Local\Temp\stage2.exe", 3, effect: FileEffect.Opened),
        ]);

        Assert.Single(snapshot.Detections, d => d.RuleId == "F-007");
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
    public void PowerShell_policy_scratch_file_is_not_a_dropped_payload()
    {
        // Measured live: `cmd /c powershell -NoProfile -Command Get-Date` writes
        // __PSScriptPolicyTest_<random>.ps1 into %TEMP% on every invocation.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(6020, Fx.RootPid, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoProfile -Command Get-Date", 1),
            Fx.FileOp(EventKind.FileCreate, 6020, @"C:\Users\kamal\AppData\Local\Temp\__PSScriptPolicyTest_tq2ri1id.wvs.ps1", 2, effect: FileEffect.CreatedOrTruncated),
            Fx.FileOp(EventKind.FileWrite, 6020, @"C:\Users\kamal\AppData\Local\Temp\__PSScriptPolicyTest_tq2ri1id.wvs.ps1", 3, bytesOut: 128),
        ]);

        Assert.DoesNotContain("F-007", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void PowerShell_scratch_name_written_by_another_process_still_fires()
    {
        // The exclusion is scoped to the interpreter itself: a non-PowerShell writer using
        // the same name is exactly the evasion the narrow predicate has to keep catching.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, @"C:\Users\kamal\AppData\Local\Temp\__PSScriptPolicyTest_tq2ri1id.wvs.ps1", 2, effect: FileEffect.CreatedOrTruncated),
            Fx.FileOp(EventKind.FileWrite, Fx.RootPid, @"C:\Users\kamal\AppData\Local\Temp\__PSScriptPolicyTest_tq2ri1id.wvs.ps1", 3, bytesOut: 4096),
        ]);

        Assert.Contains("F-007", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void PowerShell_writing_its_own_named_script_in_temp_still_fires()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(6020, Fx.RootPid, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -Command iwr", 1),
            Fx.FileOp(EventKind.FileCreate, 6020, @"C:\Users\kamal\AppData\Local\Temp\stage.ps1", 2, effect: FileEffect.CreatedOrTruncated),
            Fx.FileOp(EventKind.FileWrite, 6020, @"C:\Users\kamal\AppData\Local\Temp\stage.ps1", 3, bytesOut: 2048),
        ]);

        Assert.Contains("F-007", Fx.RulesOf(snapshot));
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
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, Fx.StartupDir + @"\updater.lnk", 2, bytesOut: 2048),
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
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, Fx.StartupDir + @"\updater.lnk", 2, bytesOut: 2048),
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
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, Fx.StartupDir + @"\updater.lnk", 2, bytesOut: 2048),
            Fx.NetConnect(Fx.RootPid, "10.0.0.5", 443, 8),
        ]);

        Assert.DoesNotContain("X-001", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Opening_a_persistence_file_without_writing_it_is_not_correlated()
    {
        // Reading an existing shortcut in the Startup folder is not a persistence write,
        // even when an external connection follows: a bare create is create-or-open.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, Fx.StartupDir + @"\updater.lnk", 2),
            Fx.NetConnect(Fx.RootPid, "203.0.113.7", 443, 8),
        ]);

        var rules = Fx.RulesOf(snapshot);
        Assert.DoesNotContain("F-001", rules);
        Assert.DoesNotContain("X-001", rules);
    }

    [Fact]
    public void Every_detection_explains_itself()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, Fx.StartupDir + @"\updater.lnk", 2, bytesOut: 2048),
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

    private const string RunKey =
        @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

    [Fact]
    public void Run_key_write_is_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.RegistryOp(Fx.RootPid, RunKey + @"\Updater", 2),
        ]);

        var f002 = snapshot.Detections.Single(d => d.RuleId == "F-002");
        Assert.Contains("evidence=registry-write", f002.Factors);
        Assert.Contains("updater", f002.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Run_once_delete_is_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.RegistryOp(Fx.RootPid, RunKey + "Once\\Payload", 2, EventKind.RegistryDeleteValue),
        ]);

        Assert.Contains("F-002", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Run_mru_is_not_an_autostart_key()
    {
        // Explorer\RunMRU records what the user typed into the Run dialog. It begins with
        // "Run" but Windows never executes it, so matching on a prefix would be a false
        // positive on every Start-menu search.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.RegistryOp(Fx.RootPid, @"\REGISTRY\CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\a", 2),
            Fx.RegistryOp(Fx.RootPid, @"\REGISTRY\CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackDocs", 3),
        ]);

        Assert.DoesNotContain("F-002", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Reg_add_of_a_run_value_is_flagged_from_the_command_line()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5120, Fx.RootPid, "reg.exe", @"C:\Windows\System32\reg.exe",
                @"reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Run"" /v Updater /d C:\argus-test\stage2.exe", 2),
        ]);

        var f002 = snapshot.Detections.Single(d => d.RuleId == "F-002");
        Assert.Contains("evidence=command-line", f002.Factors);
        Assert.Contains("reg.exe", f002.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Reg_query_of_a_run_value_is_not_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5120, Fx.RootPid, "reg.exe", @"C:\Windows\System32\reg.exe",
                @"reg query ""HKCU\Software\Microsoft\Windows\CurrentVersion\Run""", 2),
        ]);

        Assert.DoesNotContain("F-002", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Scheduled_task_registration_is_flagged()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5130, Fx.RootPid, "schtasks.exe", @"C:\Windows\System32\schtasks.exe",
                @"schtasks /create /tn ""Argus Updater"" /tr C:\argus-test\stage2.exe /sc onlogon", 2),
        ]);

        var f003 = snapshot.Detections.Single(d => d.RuleId == "F-003");
        Assert.Contains("Argus Updater", f003.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Scheduling_tool_administration_is_not_a_task_registration()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStart(5130, Fx.RootPid, "schtasks.exe", @"C:\Windows\System32\schtasks.exe",
                @"schtasks /query /tn ""Argus Updater""", 2),
            Fx.ProcessStart(5131, Fx.RootPid, "schtasks.exe", @"C:\Windows\System32\schtasks.exe",
                @"schtasks /delete /tn ""Argus Updater"" /f", 3),
            Fx.ProcessStart(5132, Fx.RootPid, "schtasks.exe", @"C:\Windows\System32\schtasks.exe",
                @"schtasks /end /tn ""Argus Updater""", 4),
        ]);

        Assert.DoesNotContain("F-003", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Task_registration_is_recognised_without_the_exe_extension()
    {
        // Live ETW reported ImageFileName="schtasks" for schtasks /query; matching only on
        // "schtasks.exe" silently missed every such child.
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStartWithImage(5140, Fx.RootPid, "schtasks",
                @"schtasks /create /tn ArgusProbe /tr C:\argus-test\stage2.exe /sc once /st 23:59", 2),
        ]);

        Assert.Contains("F-003", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Unexpected_shell_is_recognised_without_the_exe_extension()
    {
        var (snapshot, _) = Fx.Run(
        [
            Fx.RootStart(),
            Fx.ProcessStartWithImage(5150, Fx.RootPid, "powershell", "powershell -nop -w hidden -enc SQBFAFgA", 2),
        ]);

        Assert.Contains("P-002", Fx.RulesOf(snapshot));
        Assert.Contains("P-003", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Regular_callbacks_to_one_endpoint_are_flagged()
    {
        var events = new List<RawEvent> { Fx.RootStart() };
        events.AddRange(Fx.Beacon(count: 12, startSeconds: 1, intervalSeconds: 30));

        var (snapshot, _) = Fx.Run(events);

        var n002 = snapshot.Detections.Single(d => d.RuleId == "N-002");
        Assert.Equal(2, n002.EventCount);

        // Factors describe the latest crossing: the twelfth callback.
        Assert.Contains("connections=12", n002.Factors);
        Assert.Contains("mean_interval_seconds=30", n002.Factors);
        Assert.Contains("jitter_percent=0", n002.Factors);
    }

    [Fact]
    public void Irregular_connections_to_one_endpoint_are_not_beacons()
    {
        // Same endpoint, same count: only the spacing differs, which is the whole signal.
        var events = new List<RawEvent> { Fx.RootStart() };
        events.AddRange(Fx.Beacon(count: 12, startSeconds: 1, intervalSeconds: 30, jitter: i => (i % 3) * 17));

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("N-002", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void A_fast_burst_is_not_a_beacon()
    {
        // Ten connections in one second is a page load, not a timer.
        var events = new List<RawEvent> { Fx.RootStart() };
        events.AddRange(Fx.Beacon(count: 12, startSeconds: 1, intervalSeconds: 0.1));

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("N-002", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void A_large_upload_to_one_public_address_is_flagged()
    {
        var events = new List<RawEvent> { Fx.RootStart() };
        for (var i = 0; i < 12; i++)
        {
            events.Add(Fx.Flow(Fx.RootPid, "203.0.113.9", 2 * 1024 * 1024, 1 + i));
        }

        var (snapshot, _) = Fx.Run(events);

        // One finding, at the crossing: the tenth 2 MB send reaches 20 MB exactly and is the
        // only finding in the transfer — the two sends after it are not a second crossing.
        var n003 = snapshot.Detections.Single(d => d.RuleId == "N-003");
        Assert.Contains("crossings=1", n003.Factors);
        Assert.Contains("megabytes=20", n003.Factors);
        Assert.Contains("remote_ip=203.0.113.9", n003.Factors);
    }

    [Fact]
    public void Volume_spread_over_several_addresses_is_not_one_transfer()
    {
        var events = new List<RawEvent> { Fx.RootStart() };
        for (var i = 0; i < 12; i++)
        {
            events.Add(Fx.Flow(Fx.RootPid, $"203.0.113.{10 + i}", 2 * 1024 * 1024, 1 + i));
        }

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("N-003", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Volume_to_a_private_address_is_not_exfiltration_evidence()
    {
        var events = new List<RawEvent> { Fx.RootStart() };
        for (var i = 0; i < 12; i++)
        {
            events.Add(Fx.Flow(Fx.RootPid, "10.0.0.5", 3 * 1024 * 1024, 1 + i));
        }

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("N-003", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Connecting_to_a_bare_public_address_is_flagged()
    {
        var (snapshot, _) = Fx.Run([
            Fx.RootStart(),
            Fx.NetConnect(Fx.RootPid, "198.51.100.20", 4443, 5),
        ]);

        var n004 = snapshot.Detections.Single(d => d.RuleId == "N-004");
        Assert.Contains("dns_queries_in_window=0", n004.Factors);
    }

    [Fact]
    public void A_name_lookup_before_connecting_suppresses_the_bare_address_finding()
    {
        var (snapshot, _) = Fx.Run([
            Fx.RootStart(),
            Fx.Dns(Fx.RootPid, "example.test", 2),
            Fx.NetConnect(Fx.RootPid, "198.51.100.20", 4443, 3),
        ]);

        Assert.DoesNotContain("N-004", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Private_addresses_are_not_bare_public_connections()
    {
        var (snapshot, _) = Fx.Run([
            Fx.RootStart(),
            Fx.NetConnect(Fx.RootPid, "10.1.2.3", 445, 2),
        ]);

        Assert.DoesNotContain("N-004", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Reading_another_programs_credential_store_is_flagged()
    {
        var loginData = @"C:\Users\kamal\AppData\Local\Google\Chrome\User Data\Default\Login Data";
        var key = @"C:\Users\kamal\.ssh\id_rsa";

        var (snapshot, _) = Fx.Run([
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileRead, Fx.RootPid, loginData, 1),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, key, 2, effect: FileEffect.Opened),
        ]);

        var f008 = snapshot.Detections.Single(d => d.RuleId == "F-008");
        Assert.Equal(2, f008.EventCount);

        // Factors describe the latest finding, which is the key read.
        Assert.Contains("store=SSH private key", f008.Factors);
        Assert.Contains("operation=opened", f008.Factors);
    }

    [Fact]
    public void A_browser_reading_its_own_login_data_is_not_flagged()
    {
        var loginData = @"C:\Users\kamal\AppData\Local\Google\Chrome\User Data\Default\Login Data";

        var (snapshot, _) = Fx.Run([
            Fx.ProcessStart(Fx.RootPid, 9999, "chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            Fx.FileOp(EventKind.FileRead, Fx.RootPid, loginData, 1),
        ], rootImagePath: @"C:\Program Files\Google\Chrome\Application\chrome.exe");

        Assert.DoesNotContain("F-008", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void The_ssh_client_reading_its_own_key_is_not_flagged()
    {
        var key = @"C:\Users\kamal\.ssh\id_ed25519";

        var (snapshot, _) = Fx.Run([
            Fx.ProcessStartWithImage(5150, Fx.RootPid, "ssh", "ssh git@example.com", 1),
            Fx.FileOp(EventKind.FileRead, 5150, key, 2),
        ]);

        Assert.DoesNotContain("F-008", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Writing_a_credential_store_is_not_credential_access()
    {
        // Writes to these paths belong to the write rules; F-008 is about reading them.
        var loginData = @"C:\Users\kamal\AppData\Local\Google\Chrome\User Data\Default\Login Data";

        var (snapshot, _) = Fx.Run([
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileCreate, Fx.RootPid, loginData, 1, effect: FileEffect.CreatedOrTruncated),
            Fx.FileOp(EventKind.FileWrite, Fx.RootPid, loginData, 2, bytesOut: 512),
        ]);

        Assert.DoesNotContain("F-008", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Ordinary_files_are_not_credential_stores()
    {
        var (snapshot, _) = Fx.Run([
            Fx.RootStart(),
            Fx.FileOp(EventKind.FileRead, Fx.RootPid, @"C:\argus-test\docs\report.docx", 1),
            Fx.FileOp(EventKind.FileRead, Fx.RootPid, @"C:\Users\kamal\Documents\notes.txt", 2),
        ]);

        Assert.DoesNotContain("F-008", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Marker_rename_burst_across_directories_is_flagged()
    {
        var events = new List<Core.Events.RawEvent> { Fx.RootStart() };
        events.AddRange(Fx.MarkerRenames(20, seconds: 1, span: 30, directories: 8));

        var (snapshot, r) = Fx.Run(events, risk: null);

        var f006 = snapshot.Detections.Single(d => d.RuleId == "F-006");
        Assert.Equal(2, f006.EventCount);

        // Factors describe the latest crossing (20 renames), not the first.
        Assert.Contains("marker_renames_in_window=20", f006.Factors);
        Assert.Contains("distinct_directories=8", f006.Factors);
        Assert.Contains("appended_suffix=locked", f006.Factors);

        _ = r;
    }

    [Fact]
    public void Renaming_inside_one_directory_is_not_the_ransomware_shape()
    {
        // A batch renamer or an unpacker works in one folder. Breadth is part of the shape.
        var events = new List<Core.Events.RawEvent> { Fx.RootStart() };
        events.AddRange(Fx.MarkerRenames(30, seconds: 1, span: 20, directories: 1));

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("F-006", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Finishing_a_download_is_not_a_marker_rename()
    {
        // "movie.mp4.part" -> "movie.mp4" removes an intermediate extension. It is the
        // commonest extension change on a desktop and must never count.
        var events = new List<Core.Events.RawEvent> { Fx.RootStart() };
        for (var i = 0; i < 30; i++)
        {
            var root = $@"C:\argus-test\downloads\d{i % 8}\";
            events.Add(Fx.Rename(Fx.RootPid, root + $"file{i}.mp4.part", root + $"file{i}.mp4", 1 + i));
        }

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("F-006", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Rename_below_the_threshold_is_not_flagged()
    {
        var events = new List<Core.Events.RawEvent> { Fx.RootStart() };
        events.AddRange(Fx.MarkerRenames(9, seconds: 1, span: 10, directories: 8));

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("F-006", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Mass_file_creation_is_flagged_once_per_threshold()
    {
        var events = new List<Core.Events.RawEvent> { Fx.RootStart() };
        events.AddRange(Fx.MassCreates(250, seconds: 1, span: 30));

        var (snapshot, _) = Fx.Run(events, risk: null);

        var f004 = snapshot.Detections.Single(d => d.RuleId == "F-004");
        Assert.Equal(1, f004.EventCount);
        Assert.Contains("creates_in_window=200", f004.Factors);
    }

    [Fact]
    public void Write_burst_is_not_mass_file_creation()
    {
        // A build tool rewriting existing objects is volume, not files appearing.
        var events = new List<Core.Events.RawEvent> { Fx.RootStart() };
        events.AddRange(Fx.MassCreates(250, seconds: 1, span: 30, kind: EventKind.FileWrite));

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("F-004", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Creation_below_the_threshold_is_not_flagged()
    {
        var events = new List<Core.Events.RawEvent> { Fx.RootStart() };
        events.AddRange(Fx.MassCreates(199, seconds: 1, span: 30));

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("F-004", Fx.RulesOf(snapshot));
    }

    [Fact]
    public void Opens_do_not_count_as_file_creation()
    {
        var events = new List<Core.Events.RawEvent> { Fx.RootStart() };
        events.AddRange(Fx.MassCreates(250, seconds: 1, span: 30, effect: FileEffect.Opened));

        var (snapshot, _) = Fx.Run(events);

        Assert.DoesNotContain("F-004", Fx.RulesOf(snapshot));
    }
}
