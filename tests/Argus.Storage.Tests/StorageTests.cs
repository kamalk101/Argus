namespace Argus.Storage.Tests;

using Argus.Analysis.Detection;
using Argus.Analysis.Pipeline;
using Argus.Core.Events;
using Argus.Core.Processes;
using Argus.Core.Risk;
using Argus.Core.Sessions;
using Xunit;

public sealed class StorageTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 5, 1, 10, 0, 0, TimeSpan.Zero);
    private static readonly Guid Session = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    private readonly SessionDatabase _database = SessionDatabase.CreateTemporary();
    private readonly SessionRepository _sessions;
    private readonly EventRepository _events;
    private readonly ProcessRepository _processes;
    private readonly DetectionRepository _detections;
    private readonly ScoreRepository _scores;
    private readonly GapRepository _gaps;
    private readonly RollupService _rollups;

    public StorageTests()
    {
        _sessions = new SessionRepository(_database);
        _events = new EventRepository(_database);
        _processes = new ProcessRepository(_database);
        _detections = new DetectionRepository(_database);
        _scores = new ScoreRepository(_database);
        _gaps = new GapRepository(_database);
        _rollups = new RollupService(_database);

        _sessions.Create(new SessionRecord
        {
            Id = Session,
            TargetPath = @"C:\argus-test\sample.exe",
            StartedUtc = T0,
            AgentVersion = "test",
        });
    }

    [Fact]
    public void Initialize_is_idempotent()
    {
        _database.Initialize();

        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        Assert.Equal(1L, Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void Session_round_trips_and_completes()
    {
        var loaded = _sessions.Get(Session);
        Assert.NotNull(loaded);
        Assert.Equal("running", loaded.Status);
        Assert.Single(_sessions.List());

        var risk = new RiskAssessment
        {
            Score = 71.5,
            Band = RiskBand.Malicious,
            PeakScore = 88,
            Contributions = [],
            Categories = EvidenceCategory.File | EvidenceCategory.Network,
            Explanation = "test",
        };

        _sessions.Complete(Session, T0.AddMinutes(5), risk, lossEvents: 2);

        var completed = _sessions.Get(Session);
        Assert.NotNull(completed);
        Assert.Equal("stopped", completed.Status);
        Assert.Equal(71.5, completed.FinalScore!.Value, 3);
        Assert.Equal("Malicious", completed.Verdict);
        Assert.Equal(2, completed.LossEvents);
        Assert.NotNull(completed.EndedUtc);
    }

    [Fact]
    public void Events_are_paged_and_filtered()
    {
        _events.AppendBatch(Session, [
            Event(1, EventKind.ProcessStart, 4312, category: EventCategory.Process),
            Event(2, EventKind.FileWrite, 4312, @"C:\ProgramData\Startup\run.lnk", EventCategory.File),
            Event(3, EventKind.NetConnect, 4312, "203.0.113.7:443", EventCategory.Network),
            Event(4, EventKind.FileWrite, 5000, @"C:\Temp\other.txt", EventCategory.File, ProcessScopeState.Excluded),
        ]);

        Assert.Equal(4, _events.Count(Session));

        var files = _events.Page(Session, new EventFilter { Category = EventCategory.File });
        Assert.Single(files);

        var after = _events.Page(Session, new EventFilter { AfterSeq = 2, InScopeOnly = false });
        Assert.Equal(new long[] { 3, 4 }, after.Select(e => e.Seq));

        var all = _events.Page(Session, new EventFilter { InScopeOnly = false });
        Assert.Equal(4, all.Count);
    }

    [Fact]
    public void Full_text_search_finds_paths_and_hosts()
    {
        _events.AppendBatch(Session, [
            Event(1, EventKind.FileCreate, 4312, @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updater.lnk", EventCategory.File),
            Event(2, EventKind.NetConnect, 4312, "203.0.113.7:443", EventCategory.Network),
        ]);

        var hits = _events.Search(Session, "updater.lnk");
        Assert.Single(hits);
        Assert.Equal(EventKind.FileCreate, hits[0].Kind);
    }

    [Fact]
    public void Detection_upsert_updates_in_place_and_replaces_evidence()
    {
        var detection = Detection(2, [1, 2]);
        var firstId = _detections.Upsert(Session, detection, 0.25);

        var updated = detection with
        {
            EventCount = 3,
            Confidence = 0.61,
            EvidenceSeq = [1, 2, 3],
        };

        var secondId = _detections.Upsert(Session, updated, 0.4);

        Assert.Equal(firstId, secondId);
        var stored = Assert.Single(_detections.List(Session));
        Assert.Equal(3, stored.EventCount);
        Assert.Equal(0.4, stored.Weight, 3);
        Assert.Equal(new long[] { 1, 2, 3 }, _detections.EvidenceFor(secondId));
    }

    [Fact]
    public void Scores_and_gaps_persist()
    {
        var risk = new RiskAssessment
        {
            Score = 42,
            Band = RiskBand.Suspicious,
            PeakScore = 42,
            Contributions = [],
            Categories = EvidenceCategory.Process,
            Explanation = "test arithmetic",
        };

        _scores.Append(Session, T0, risk);
        _scores.Append(Session, T0.AddSeconds(1), risk with { Score = 55 });

        var history = _scores.History(Session);
        Assert.Equal(2, history.Count);
        Assert.Equal(42, history[0].Score, 3);
        Assert.Equal(55, history[1].Score, 3);

        _gaps.AddRange(Session, [
            new GapEntry(T0, "etw", "event buffer overflow", 42, "etw:file"),
        ]);

        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM gaps WHERE session_id = $s;";
        command.Parameters.AddWithValue("$s", Session.ToString());
        Assert.Equal(1L, Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void Processes_upsert_and_list()
    {
        var record = new ProcessRecord(4312, 9999, "sample.exe", @"C:\argus-test\sample.exe", "sample.exe", T0, ProcessScopeState.Root);
        _processes.Upsert(Session, record);
        _processes.Upsert(Session, record with { CommandLine = "sample.exe --run" });

        var rows = _processes.List(Session);
        var row = Assert.Single(rows);
        Assert.Equal("sample.exe --run", row.CommandLine);
        Assert.Equal(ProcessScopeState.Root, row.Scope);

        _processes.MarkExited(Session, 4312, T0, T0.AddMinutes(1), 0);

        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT exit_code FROM processes WHERE session_id = $s AND pid = 4312;";
        command.Parameters.AddWithValue("$s", Session.ToString());
        Assert.Equal(0L, Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void Rollup_compresses_old_events_and_removes_raw_rows()
    {
        var events = Enumerable.Range(0, 12)
            .Select(i => Event(
                100 + i,
                EventKind.FileWrite,
                4312,
                $@"C:\argus-test\logs\file-{i}.log",
                EventCategory.File,
                timestamp: T0.AddSeconds(i)))
            .ToList();

        _events.AppendBatch(Session, events);
        Assert.Equal(12, _events.Count(Session));

        var result = _rollups.Rollup(Session, T0.AddSeconds(20), TimeSpan.FromSeconds(5));

        Assert.Equal(12, result.RawEventsRemoved);
        Assert.Equal(0, _events.Count(Session));
        Assert.True(result.RollupRowsWritten >= 2);

        var rollups = _rollups.List(Session);
        Assert.Equal(12, rollups.Sum(r => r.Count));
        Assert.Empty(_events.Search(Session, "file-0.log"));
    }

    [Fact]
    public void Rollup_keeps_events_newer_than_the_cutoff()
    {
        _events.AppendBatch(Session, [
            Event(1, EventKind.FileWrite, 4312, @"C:\argus-test\old.txt", EventCategory.File, timestamp: T0),
            Event(2, EventKind.FileWrite, 4312, @"C:\argus-test\new.txt", EventCategory.File, timestamp: T0.AddMinutes(10)),
        ]);

        _rollups.Rollup(Session, T0.AddMinutes(5), TimeSpan.FromMinutes(1));

        var remaining = _events.Page(Session, new EventFilter { InScopeOnly = false });
        var single = Assert.Single(remaining);
        Assert.Equal(2, single.Seq);
    }

    [Fact]
    public void Reader_sees_committed_rows_while_writer_holds_a_transaction()
    {
        using var writer = _database.Open();
        using var transaction = writer.BeginTransaction();
        using var insert = writer.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO events (session_id, seq, ts_utc, kind, category, pid, observability, confidence, source, scope_state)
            VALUES ($s, 99, $ts, 'FileWrite', 'File', 4312, 'Direct', 0.9, 'Replay', 'Root');
            """;
        insert.Parameters.AddWithValue("$s", Session.ToString());
        insert.Parameters.AddWithValue("$ts", T0.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        insert.ExecuteNonQuery();

        // WAL: the uncommitted row is invisible to the reader, and the read does not block.
        Assert.Equal(0, _events.Count(Session));

        transaction.Commit();
        Assert.Equal(1, _events.Count(Session));
    }

    public void Dispose()
    {
        var path = _database.Path;
        _database.Dispose();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            var file = path + suffix;
            if (File.Exists(file))
            {
                File.Delete(file);
            }
        }
    }

    private static BehaviorEvent Event(
        long seq,
        EventKind kind,
        int pid,
        string? target = null,
        EventCategory category = EventCategory.Process,
        ProcessScopeState scope = ProcessScopeState.Root,
        DateTimeOffset? timestamp = null) => new()
    {
        SessionId = Session,
        Seq = seq,
        TimestampUtc = timestamp ?? T0,
        Kind = kind,
        Category = category,
        Pid = pid,
        Target = target,
        PathKey = target is not null && category == EventCategory.File ? Argus.Core.Paths.PathKey.Canonicalize(target) : null,
        Observability = Observability.Direct,
        Confidence = 0.9,
        Source = EventSourceKind.Replay,
        Scope = scope,
    };

    private static DetectionState Detection(int count, IReadOnlyList<long> evidence) => new()
    {
        Key = "P-002#4312#7",
        RuleId = "P-002",
        Title = "Unexpected command interpreter",
        Severity = 85,
        Confidence = 0.5,
        BaseConfidence = 0.9,
        Categories = EvidenceCategory.Process,
        ScopePid = 4312,
        FirstSeenUtc = T0,
        LastSeenUtc = T0.AddSeconds(2),
        EventCount = count,
        Status = DetectionStatus.Open,
        Reason = "sample.exe spawned cmd.exe",
        Counterfactual = "Would not fire for a GUI child.",
        Mitre = ["T1059"],
        EvidenceSeq = evidence,
        Factors = ["parent=sample.exe", "child=cmd.exe"],
    };
}
