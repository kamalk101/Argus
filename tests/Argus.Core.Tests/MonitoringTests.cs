namespace Argus.Core.Tests;

using Argus.Core.Events;
using Argus.Core.Monitoring;
using Xunit;

public sealed class MonitoringTests
{
    private static readonly DateTimeOffset T0 = new(2026, 5, 1, 10, 0, 0, TimeSpan.Zero);

    private static EtwRecord Record(string eventName, int eventId, int pid, params (string Key, object? Value)[] payload) =>
        new()
        {
            TimestampUtc = T0,
            Provider = "Microsoft-Windows-Kernel-Process",
            EventName = eventName,
            EventId = eventId,
            Pid = pid,
            Tid = 7,
            Payload = payload.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase),
        };

    [Fact]
    public void Process_start_uses_payload_and_metadata_fallbacks()
    {
        var mapper = new EtwEventMapper();
        var record = Record("ProcessStart", 1, 5000,
            ("ParentID", 4312),
            ("ImageFileName", "powershell.exe"),
            ("CommandLine", "powershell.exe -nop -enc AAAA"));

        var raw = mapper.Map(record);

        Assert.NotNull(raw);
        Assert.Equal(EventKind.ProcessStart, raw.Kind);
        Assert.Equal(5000, raw.Pid);
        Assert.Equal(4312, raw.ParentPid);
        Assert.Equal("powershell.exe", raw.ImageName);
        Assert.Equal("powershell.exe -nop -enc AAAA", raw.CommandLine);
        Assert.Equal(EventSourceKind.Etw, raw.Source);
    }

    [Fact]
    public void Process_start_fills_path_and_command_line_from_metadata()
    {
        var mapper = new EtwEventMapper();
        var record = Record("ProcessStart", 1, 5000, ("ParentID", 4312), ("ImageFileName", "powershell.exe"));
        var metadata = new ProcessMetadata(5000, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -enc AAAA", 4312);

        var raw = mapper.Map(record, metadata);

        Assert.NotNull(raw);
        Assert.Equal(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", raw.ImagePath);
        Assert.Equal("powershell.exe -enc AAAA", raw.CommandLine);
        Assert.Equal(Observability.Direct, raw.Observability);
    }

    [Fact]
    public void File_create_remembers_file_key_for_later_write()
    {
        var mapper = new EtwEventMapper(path => path.Replace(@"\Device\HarddiskVolume3", "C:", StringComparison.OrdinalIgnoreCase));
        var create = Record("FileIOCreate", 12, 5000, ("FileName", @"\Device\HarddiskVolume3\argus-test\dropped.exe"), ("FileKey", 42UL));

        var created = mapper.Map(create);
        Assert.NotNull(created);
        Assert.Equal(EventKind.FileCreate, created.Kind);
        Assert.Equal(@"C:\argus-test\dropped.exe", created.Target);

        var write = Record("FileIOWrite", 16, 5000, ("FileKey", 42UL), ("IoSize", 128UL));
        var written = mapper.Map(write);

        Assert.NotNull(written);
        Assert.Equal(EventKind.FileWrite, written.Kind);
        Assert.Equal(@"C:\argus-test\dropped.exe", written.Target);
        Assert.Equal(128, written.BytesOut);
        Assert.Equal(1, mapper.CachedFileKeys);
    }

    [Fact]
    public void File_create_is_marked_as_create_or_open_and_keeps_its_size()
    {
        // Kernel FileIO/Create covers create and open. The mapper must say so, and it
        // must put the byte count in BytesOut where rules can see it.
        var mapper = new EtwEventMapper();
        var create = Record("FileIOCreate", 12, 5000, ("FileName", @"C:\Windows\System32\x.dll"), ("IoSize", 4096UL));

        var raw = mapper.Map(create);

        Assert.NotNull(raw);
        Assert.Equal(EventKind.FileCreate, raw.Kind);
        Assert.Contains("createOrOpen", raw.Detail, StringComparison.Ordinal);
        Assert.Equal(4096, raw.BytesOut);

        var bareOpen = mapper.Map(Record("FileIOCreate", 12, 5001, ("FileName", @"C:\Windows\System32\kernel32.dll")));

        Assert.NotNull(bareOpen);
        Assert.Null(bareOpen.BytesOut);
    }

    [Theory]
    [InlineData("CREATE_ALWAYS", FileEffect.CreatedOrTruncated)]
    [InlineData("CREATE_NEW", FileEffect.CreatedOrTruncated)]
    [InlineData("TRUNCATE_EXISTING", FileEffect.CreatedOrTruncated)]
    [InlineData("OPEN_EXISTING", FileEffect.Opened)]
    [InlineData("OPEN_ALWAYS", FileEffect.Unknown)]
    public void Create_disposition_decides_whether_content_changed(string disposition, FileEffect expected)
    {
        // TraceEvent decodes CreateDisposition for us; without it an open and a write
        // are the same record. Values observed live on the Windows VM.
        var mapper = new EtwEventMapper();
        var record = Record("FileIOCreate", 12, 5000,
            ("FileName", @"C:\Windows\System32\PING.EXE"),
            ("CreateDisposition", disposition));

        var raw = mapper.Map(record);

        Assert.NotNull(raw);
        Assert.Equal(expected, raw.FileEffect);
        Assert.Contains(disposition, raw.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_without_a_disposition_has_no_effect_verdict()
    {
        var mapper = new EtwEventMapper();

        var raw = mapper.Map(Record("FileIOCreate", 12, 5000, ("FileName", @"C:\Windows\System32\x.dll")));

        Assert.NotNull(raw);
        Assert.Null(raw.FileEffect);
    }

    [Fact]
    public void Directory_create_is_not_a_file_write()
    {
        // Windows recreates System32\CatRoot2 while verifying signatures. It arrives as
        // a Create with FileAttributes=Normal and FILE_DIRECTORY_FILE in the options
        // (observed live: CreateOptions=2113569 = 0x204021), so FileAttributes alone is
        // not enough to tell it from a file create.
        var mapper = new EtwEventMapper();

        var raw = mapper.Map(Record("FileIOCreate", 12, 5000,
            ("FileName", @"C:\Windows\system32\catroot2"),
            ("CreateDisposition", "CREATE_NEW"),
            ("CreateOptions", 2113569),
            ("FileAttributes", "Normal")));

        Assert.NotNull(raw);
        Assert.Equal(FileEffect.Unknown, raw.FileEffect);
        Assert.Contains("directory", raw.Detail, StringComparison.Ordinal);

        // A file create in the same directory context is still a content change.
        var file = mapper.Map(Record("FileIOCreate", 12, 5000,
            ("FileName", @"C:\Windows\System32\evil.dll"),
            ("CreateDisposition", "CREATE_NEW"),
            ("CreateOptions", 2113536),
            ("FileAttributes", "Normal")));

        Assert.NotNull(file);
        Assert.Equal(FileEffect.CreatedOrTruncated, file.FileEffect);

        // A trailing separator is a directory even without the option flag.
        var trailing = mapper.Map(Record("FileIOCreate", 12, 5000,
            ("FileName", @"C:\Windows\system32\CatRoot2\"),
            ("CreateDisposition", "OPEN_EXISTING")));

        Assert.NotNull(trailing);
        Assert.Equal(FileEffect.Unknown, trailing.FileEffect);
    }

    [Fact]
    public void Rename_records_new_target_and_old_path()
    {
        var mapper = new EtwEventMapper();
        var record = Record("FileIORename", 19, 5000, ("FileName", @"C:\temp\a.tmp"), ("FileName2", @"C:\temp\b.exe"));

        var raw = mapper.Map(record);

        Assert.NotNull(raw);
        Assert.Equal(EventKind.FileRename, raw.Kind);
        Assert.Equal(@"C:\temp\b.exe", raw.Target);

        // Both halves are contract fields: a rule has to compare the old and the new name,
        // and a fact that only exists in a JSON blob is not something rules can use.
        Assert.Equal(@"C:\temp\a.tmp", raw.PreviousPath);
        Assert.Equal(Observability.Direct, raw.Observability);
    }

    [Fact]
    public void Rename_source_and_destination_records_are_paired()
    {
        // Live shape: FileIO/Rename carries the source, FileIo/RenamePath the destination,
        // both with the same FileKey. Two records, one rename.
        var mapper = new EtwEventMapper();
        var source = Record("FileIORename", 19, 5000, ("FileName", @"C:\docs\report.docx"), ("FileKey", 77UL));
        var destination = Record("FileIoRenamePath", 19, 5000, ("FileName", @"C:\docs\report.docx.locked"), ("FileKey", 77UL));

        var first = mapper.Map(source);
        var second = mapper.Map(destination);

        Assert.Null(first);
        Assert.NotNull(second);
        Assert.Equal(EventKind.FileRename, second.Kind);
        Assert.Equal(@"C:\docs\report.docx.locked", second.Target);
        Assert.Equal(@"C:\docs\report.docx", second.PreviousPath);
        Assert.Equal(Observability.Direct, second.Observability);
    }

    [Fact]
    public void Rename_destination_without_a_source_is_partial()
    {
        var mapper = new EtwEventMapper();
        var raw = mapper.Map(Record("FileIoRenamePath", 19, 5000, ("FileName", @"C:\docs\x.docx.locked"), ("FileKey", 99UL)));

        Assert.NotNull(raw);
        Assert.Equal(EventKind.FileRename, raw.Kind);
        Assert.Null(raw.PreviousPath);
        Assert.Equal(Observability.Partial, raw.Observability);
    }

    [Fact]
    public void Tcp_connect_maps_address_and_port()
    {
        var mapper = new EtwEventMapper();
        var record = Record("TcpIpConnect", 12, 5000, ("daddr", 0x0100007Fu), ("dport", 443), ("saddr", 0x0100007Fu), ("sport", 50000));

        var raw = mapper.Map(record);

        Assert.NotNull(raw);
        Assert.Equal(EventKind.NetConnect, raw.Kind);
        Assert.Equal("127.0.0.1", raw.RemoteIp);
        Assert.Equal(443, raw.RemotePort);
        Assert.Equal("tcp", raw.Protocol);
    }

    [Fact]
    public void Dns_query_and_response_are_partial()
    {
        var mapper = new EtwEventMapper();
        var query = new EtwRecord
        {
            TimestampUtc = T0,
            Provider = "Microsoft-Windows-DNS-Client",
            EventName = "Query",
            EventId = 3006,
            Pid = 5000,
            Payload = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["QueryName"] = "example.test",
                ["QueryType"] = 1,
            },
        };

        var raw = mapper.Map(query);

        Assert.NotNull(raw);
        Assert.Equal(EventKind.DnsQuery, raw.Kind);
        Assert.Equal("example.test", raw.HostName);
        Assert.Equal(Observability.Partial, raw.Observability);
    }

    [Fact]
    public void Registry_write_resolves_the_key_from_the_open_handle()
    {
        // Live measurement: Registry/SetValue arrives with an empty KeyName and only a
        // KeyHandle, so a write could not be attributed to a key and the registry channel
        // produced nothing at all. The key name comes from the preceding Registry/Open.
        var mapper = new EtwEventMapper();
        const string Key = @"\REGISTRY\USER\S-1\Software\Microsoft\Windows\CurrentVersion\Run";

        Assert.Null(mapper.Map(Record("Registry/Open", 0, 4380, ("KeyName", Key), ("KeyHandle", 0x1A2BUL), ("ValueName", ""))));

        var raw = mapper.Map(Record("Registry/SetValue", 0, 4380,
            ("KeyName", string.Empty),
            ("KeyHandle", 0x1A2BUL),
            ("ValueName", "ArgusProbe")));

        Assert.NotNull(raw);
        Assert.Equal(EventKind.RegistrySetValue, raw.Kind);
        Assert.Equal(Key + @"\ArgusProbe", raw.Target);
        Assert.Equal(4380, raw.Pid);

        // The key name was not in this record, so the attribution is inferred from the
        // handle table and must not be presented as a directly observed path.
        Assert.Equal(Observability.Inferred, raw.Observability);
    }

    [Fact]
    public void Registry_write_without_a_known_handle_is_ignored()
    {
        // Opening the key happened before capture started: the write cannot be attributed
        // to a key, and guessing one would be worse than dropping it.
        var mapper = new EtwEventMapper();

        var raw = mapper.Map(Record("Registry/SetValue", 0, 4380,
            ("KeyName", string.Empty),
            ("KeyHandle", 0x9999UL),
            ("ValueName", "X")));

        Assert.Null(raw);
    }

    [Fact]
    public void Kernel_registry_cache_events_are_not_value_writes()
    {
        // Registry/KCBCreate and Registry/KCBDelete are the kernel's own key-control-block
        // traffic. Their header process id is whichever process triggered a cache
        // operation, so substring matching turned them into writes "by the target": a
        // session that only ran `echo hello` recorded 104 registryDeleteValue events
        // against HKLM\SYSTEM\...\SafeBoot. They are not process activity and are ignored.
        var mapper = new EtwEventMapper();

        Assert.Null(mapper.Map(Record("Registry/KCBDelete", 0, 4380,
            ("KeyName", @"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\SafeBoot"),
            ("KeyHandle", 0x5555UL),
            ("ValueName", ""))));

        Assert.Null(mapper.Map(Record("Registry/KCBCreate", 0, 4380,
            ("KeyName", @"\REGISTRY\MACHINE\HARDWARE\DESCRIPTION"),
            ("KeyHandle", 0x6666UL))));

        // The kernel cache must not populate the handle table either: a later write must
        // not inherit a key name it never opened.
        mapper.Map(Record("Registry/KCBCreate", 0, 4380,
            ("KeyName", @"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\SafeBoot"),
            ("KeyHandle", 0x7777UL)));

        Assert.Null(mapper.Map(Record("Registry/SetValue", 0, 4380, ("KeyHandle", 0x7777UL), ("ValueName", "X"))));
    }

    [Fact]
    public void User_level_registry_delete_is_still_mapped()
    {
        var mapper = new EtwEventMapper();

        var raw = mapper.Map(Record("Registry/DeleteValue", 0, 4380,
            ("KeyName", @"\REGISTRY\USER\S-1\Software\Microsoft\Windows\CurrentVersion\Run"),
            ("ValueName", "Updater")));

        Assert.NotNull(raw);
        Assert.Equal(EventKind.RegistryDeleteValue, raw.Kind);
    }

    [Fact]
    public void Registry_close_forgets_the_handle()
    {
        var mapper = new EtwEventMapper();

        mapper.Map(Record("Registry/Open", 0, 4380, ("KeyName", @"\REGISTRY\MACHINE\X"), ("KeyHandle", 0x10UL)));
        mapper.Map(Record("Registry/Close", 0, 4380, ("KeyHandle", 0x10UL)));

        var raw = mapper.Map(Record("Registry/SetValue", 0, 4380, ("KeyHandle", 0x10UL), ("ValueName", "Y")));

        Assert.Null(raw);
    }

    [Fact]
    public void Registry_delete_resolves_the_key_from_the_open_handle()
    {
        var mapper = new EtwEventMapper();

        mapper.Map(Record("Registry/Open", 0, 4380, ("KeyName", @"\REGISTRY\MACHINE\X"), ("KeyHandle", 0x20UL)));

        var raw = mapper.Map(Record("Registry/DeleteValue", 0, 4380, ("KeyHandle", 0x20UL), ("ValueName", "Old")));

        Assert.NotNull(raw);
        Assert.Equal(EventKind.RegistryDeleteValue, raw.Kind);
        Assert.Equal(@"\REGISTRY\MACHINE\X\Old", raw.Target);
    }

    [Fact]
    public void Registry_set_includes_value_name()
    {
        var mapper = new EtwEventMapper();
        // Live records are named with a slash; the name used here was invented by an
        // earlier test and never matched a real provider, which exact matching exposed.
        var record = Record("Registry/SetValue", 5, 5000,
            ("KeyName", @"\REGISTRY\USER\S-1\Software\Microsoft\Windows\CurrentVersion\Run"),
            ("ValueName", "Updater"));

        var raw = mapper.Map(record);

        Assert.NotNull(raw);
        Assert.Equal(EventKind.RegistrySetValue, raw.Kind);
        Assert.EndsWith("Run\\Updater", raw.Target, StringComparison.Ordinal);
    }

    [Fact]
    public void File_event_without_resolvable_path_is_partial_not_dropped()
    {
        // No FileName/OpenPath and no cached FileKey: the path is unknowable, but the
        // event still happened. It must reach the session as partial evidence instead of
        // being counted as a deliberately ignored kind.
        var mapper = new EtwEventMapper();
        var record = Record("FileIOWrite", 16, 5000, ("FileKey", 99UL), ("IoSize", 16UL));

        var raw = mapper.Map(record);

        Assert.NotNull(raw);
        Assert.Equal(EventKind.FileWrite, raw.Kind);
        Assert.Null(raw.Target);
        Assert.Equal(Observability.Partial, raw.Observability);
        Assert.Contains("pathUnresolved", raw.Detail, StringComparison.Ordinal);
        Assert.Contains("99", raw.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Rename_without_resolvable_paths_is_partial_not_dropped()
    {
        var mapper = new EtwEventMapper();

        var raw = mapper.Map(Record("FileIORename", 19, 5000));

        Assert.NotNull(raw);
        Assert.Equal(EventKind.FileRename, raw.Kind);
        Assert.Null(raw.Target);
        Assert.Equal(Observability.Partial, raw.Observability);
    }

    [Fact]
    public void Unknown_event_is_ignored()
    {
        var mapper = new EtwEventMapper();
        Assert.Null(mapper.Map(Record("SomethingElse", 999, 1)));
    }

    // The mapper's contract has two distinct "no event" cases, and the collector
    // counts them differently: null means "deliberately ignored" (Unmapped), a throw
    // means "malformed payload" (MappingFailures). These tests pin that boundary so a
    // future catch-all cannot silently turn sensor bugs back into noise.
    [Fact]
    public void Malformed_payload_throws_instead_of_returning_null()
    {
        var mapper = new EtwEventMapper();
        var record = Record("TcpIpConnect", 12, 5000, ("daddr", 0x0100007Fu), ("dport", "not-a-port"));

        Assert.ThrowsAny<Exception>(() => mapper.Map(record));
    }

    [Fact]
    public void Malformed_process_payload_throws_instead_of_returning_null()
    {
        var mapper = new EtwEventMapper();
        var record = Record("ProcessStart", 1, 5000, ("ParentID", "not-a-pid"));

        Assert.ThrowsAny<Exception>(() => mapper.Map(record));
    }

    [Theory]
    [InlineData("FileIOClose", 14)]
    [InlineData("TcpIpSend", 10)]
    [InlineData("ThreadStart", 3)]
    [InlineData("SystemConfigCPU", 31)]
    public void Known_but_ignored_record_returns_null(string eventName, int eventId)
    {
        var mapper = new EtwEventMapper();

        Assert.Null(mapper.Map(Record(eventName, eventId, 5000, ("FileName", @"C:\temp\a.txt"))));
    }

    [Fact]
    public void Valid_kernel_process_start_maps_after_parser_registration()
    {
        // Regression for the Source.Kernel registration change: a named session only
        // decodes kernel records once a kernel parser is registered, and the decoded
        // shape must still map to a process start with its identity fields intact.
        var mapper = new EtwEventMapper();
        var record = Record("Process/Start", 1, 5000,
            ("ImagePath", @"C:\Windows\System32\notepad.exe"),
            ("ImageFileName", "notepad.exe"),
            ("ParentID", 4312));

        var raw = mapper.Map(record);

        Assert.NotNull(raw);
        Assert.Equal(EventKind.ProcessStart, raw.Kind);
        Assert.Equal(5000, raw.Pid);
        Assert.Equal(7, raw.Tid);
        Assert.Equal(4312, raw.ParentPid);
        Assert.Equal(@"C:\Windows\System32\notepad.exe", raw.ImagePath);
        Assert.Equal("notepad.exe", raw.ImageName);
        Assert.Equal(T0, raw.Ts);
        Assert.Equal(Observability.Direct, raw.Observability);
        Assert.Equal(EventSourceKind.Etw, raw.Source);
    }

    [Fact]
    public void Read_sampler_keeps_first_read_and_samples_repeats()
    {
        var sampler = new ReadSampler(sampleEvery: 5);

        Assert.True(sampler.ShouldKeep(1, @"c:\a.txt", sensitive: false));
        Assert.False(sampler.ShouldKeep(1, @"c:\a.txt", sensitive: false));
        Assert.True(sampler.ShouldKeep(1, @"c:\a.txt", sensitive: true));
        Assert.True(sampler.ShouldKeep(1, @"c:\b.txt", sensitive: false));
        Assert.True(sampler.ShouldKeep(2, @"c:\a.txt", sensitive: false));

        for (var i = 0; i < 3; i++)
        {
            sampler.ShouldKeep(1, @"c:\a.txt", sensitive: false);
        }

        Assert.True(sampler.ShouldKeep(1, @"c:\a.txt", sensitive: false));
    }

    [Fact]
    public void Volume_governor_opens_and_closes_the_fuse()
    {
        var governor = new VolumeGovernor(thresholdPerSecond: 2, sustainedSeconds: 1, coolSeconds: 1);

        Assert.Null(governor.Observe(T0));
        Assert.Null(governor.Observe(T0.AddMilliseconds(10)));
        var opened = governor.Observe(T0.AddMilliseconds(1100));

        Assert.NotNull(opened);
        Assert.True(opened.Throttled);
        Assert.True(governor.Throttled);

        var closed = governor.Observe(T0.AddMilliseconds(2300));

        Assert.NotNull(closed);
        Assert.False(closed.Throttled);
        Assert.False(governor.Throttled);
    }
}
