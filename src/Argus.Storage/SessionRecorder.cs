namespace Argus.Storage;

using Argus.Analysis.Detection;
using Argus.Analysis.Pipeline;
using Argus.Core.Events;
using Argus.Core.Processes;
using Argus.Core.Risk;

/// <summary>
/// The persistence facade used by the live agent and by replay tooling. It keeps
/// the write policy (batch events, upsert detections, sample scores, record gaps)
/// in one place so a live session and a replayed session produce the same rows.
/// </summary>
public sealed class SessionRecorder
{
    private readonly SessionRepository _sessions;
    private readonly EventRepository _events;
    private readonly ProcessRepository _processes;
    private readonly DetectionRepository _detections;
    private readonly ScoreRepository _scores;
    private readonly GapRepository _gaps;
    private bool _completed;

    public SessionRecorder(SessionDatabase database, SessionRecord session)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(session);

        _sessions = new SessionRepository(database);
        _events = new EventRepository(database);
        _processes = new ProcessRepository(database);
        _detections = new DetectionRepository(database);
        _scores = new ScoreRepository(database);
        _gaps = new GapRepository(database);

        _sessions.Create(session);
    }

    public void AppendEvents(IReadOnlyList<BehaviorEvent> events)
    {
        if (events.Count == 0)
        {
            return;
        }

        _events.AppendBatch(events[0].SessionId, events);
    }

    public void UpsertProcess(Guid sessionId, ProcessRecord process) =>
        _processes.Upsert(sessionId, process);

    public void UpsertDetection(Guid sessionId, DetectionState detection, double weight) =>
        _detections.Upsert(sessionId, detection, weight);

    public void AppendScore(Guid sessionId, DateTimeOffset timestampUtc, RiskAssessment risk) =>
        _scores.Append(sessionId, timestampUtc, risk);

    public void AddGaps(Guid sessionId, IEnumerable<GapEntry> gaps)
    {
        var list = gaps as IReadOnlyCollection<GapEntry> ?? [.. gaps];
        if (list.Count > 0)
        {
            _gaps.AddRange(sessionId, list);
        }
    }

    public void Complete(Guid sessionId, DateTimeOffset endedUtc, RiskAssessment risk, long lossEvents = 0, string status = "stopped")
    {
        if (_completed)
        {
            return;
        }

        _completed = true;
        _sessions.Complete(sessionId, endedUtc, risk, lossEvents, status);
    }
}
