namespace Argus.Cli;

using Argus.Core.Risk;
using Argus.Simulator;
using Argus.Storage;

/// <summary>
/// Persists a replay through the same repositories the agent uses, so the UI can
/// be exercised against real stored sessions before the Windows sensor exists.
/// </summary>
internal sealed class SessionWriter : IDisposable
{
    private readonly SessionDatabase _database;
    private readonly SessionRepository _sessions;
    private readonly EventRepository _events;
    private readonly ProcessRepository _processes;
    private readonly DetectionRepository _detections;
    private readonly ScoreRepository _scores;
    private readonly GapRepository _gaps;

    public SessionWriter(string path)
    {
        _database = new SessionDatabase(path);
        _database.Initialize();
        _sessions = new SessionRepository(_database);
        _events = new EventRepository(_database);
        _processes = new ProcessRepository(_database);
        _detections = new DetectionRepository(_database);
        _scores = new ScoreRepository(_database);
        _gaps = new GapRepository(_database);
    }

    public void Persist(ScenarioRun run)
    {
        ArgumentNullException.ThrowIfNull(run);

        var snapshot = run.Snapshot;
        var started = run.Events.Count > 0 ? run.Events[0].TimestampUtc : DateTimeOffset.UtcNow;
        var ended = run.Events.Count > 0 ? run.Events[^1].TimestampUtc : started;

        _sessions.Create(new SessionRecord
        {
            Id = run.SessionId,
            TargetPath = run.Scenario.Meta.RootImagePath ?? $@"C:\argus-test\{run.Scenario.Meta.Name}.exe",
            Mode = "launch",
            StartedUtc = started,
            Status = "stopped",
            AgentVersion = "0.1.0-replay",
            PeakScore = snapshot.Risk.PeakScore,
            FinalScore = snapshot.Risk.Score,
            Verdict = snapshot.Risk.Band.ToString(),
            ConfigHash = "replay",
        });

        _events.AppendBatch(run.SessionId, run.Events);

        foreach (var process in snapshot.Processes.All)
        {
            _processes.Upsert(run.SessionId, process);
        }

        var weights = snapshot.Risk.Contributions.ToDictionary(c => c.Key, c => c.Weight, StringComparer.Ordinal);
        foreach (var detection in snapshot.Detections)
        {
            _detections.Upsert(run.SessionId, detection, weights.GetValueOrDefault(detection.Key));
        }

        foreach (var (timestamp, assessment) in run.ScoreSamples)
        {
            _scores.Append(run.SessionId, timestamp, assessment);
        }

        if (snapshot.Gaps.Count > 0)
        {
            _gaps.AddRange(run.SessionId, snapshot.Gaps);
        }

        _sessions.Complete(run.SessionId, ended, snapshot.Risk, snapshot.Counters.Gaps);
    }

    public void Dispose() => _database.Dispose();
}
