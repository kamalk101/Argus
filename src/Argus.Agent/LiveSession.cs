namespace Argus.Agent;

using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Argus.Analysis.Detection;
using Argus.Analysis.Pipeline;
using Argus.Analysis.Rules;
using Argus.Core.Events;
using Argus.Core.Paths;
using Argus.Core.Processes;
using Argus.Core.Risk;
using Argus.Core.Sessions;
using Argus.Monitor;
using Argus.Storage;

/// <summary>
/// One monitoring session: target process, monitor channel, analysis pipeline,
/// SQLite recorder, JSONL recording and SSE fan-out. Live and replay sessions use
/// the same pipeline and storage code, so a recorded session can be re-run on
/// Linux with identical results.
/// </summary>
public sealed class LiveSession : IAsyncDisposable
{
    private static readonly TimeSpan BatchDelay = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Minimum time to keep collecting after the root process exits.
    ///
    /// Measured on the VM: a tree that lives ~20 ms can have its records delivered later than
    /// 600 ms, and a 20 ms probe that renamed a file recorded nothing at all. Waiting longer
    /// is cheap and the alternative is a silently empty session.
    /// </summary>
    private static readonly TimeSpan PostExitDrainFloor = TimeSpan.FromMilliseconds(1500);

    /// <summary>How long the pump may take to persist what is queued when the session stops.</summary>
    private static readonly TimeSpan DrainPumpTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ScoreSampleInterval = TimeSpan.FromSeconds(1);
    private const int MaxBatch = 500;

    private readonly SseHub _hub;
    private readonly SessionRecorder _recorder;
    private readonly SessionRepository _sessions;
    private readonly EventRepository _events;
    private readonly ProcessRepository _processes;
    private readonly DetectionRepository _detections;
    private readonly ScoreRepository _scores;
    private readonly SessionPipeline _pipeline;
    private readonly MonitorEventSource _monitor;
    private readonly Process _process;
    private readonly StreamWriter _jsonl;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _stopGate = new(1, 1);

    private Task? _pump;
    private Task? _watch;
    private string _status = "running";
    private DateTimeOffset? _endedUtc;
    private RiskAssessment _risk = RiskAssessment.Empty;
    private DateTimeOffset _lastScoreSample;
    private int _gapsRecorded;

    public LiveSession(
        Guid id,
        string targetPath,
        Process process,
        SessionDatabase database,
        SessionRecorder recorder,
        MonitorEventSource monitor,
        string databasePath,
        string recordPath,
        SseHub hub,
        SensitivePathCatalog catalog,
        RuleSettings? ruleSettings = null)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(recorder);
        ArgumentNullException.ThrowIfNull(monitor);
        ArgumentNullException.ThrowIfNull(hub);

        Id = id;
        TargetPath = targetPath;
        RootPid = process.Id;
        StartedUtc = DateTimeOffset.UtcNow;
        DatabasePath = databasePath;
        RecordPath = recordPath;
        _process = process;
        _recorder = recorder;
        _monitor = monitor;
        _hub = hub;

        _sessions = new SessionRepository(database);
        _events = new EventRepository(database);
        _processes = new ProcessRepository(database);
        _detections = new DetectionRepository(database);
        _scores = new ScoreRepository(database);

        _pipeline = new SessionPipeline(new SessionPipelineOptions
        {
            SessionId = id,
            RootPid = process.Id,
            RootImagePath = targetPath,
            Catalog = catalog,
            Risk = RiskOptions.Default,
            Rules = RuleCatalog.CreateDefault(ruleSettings),
        });

        var directory = Path.GetDirectoryName(recordPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _jsonl = new StreamWriter(recordPath, append: false, Encoding.UTF8);
        WriteMeta();
    }

    public Guid Id { get; }

    public string TargetPath { get; }

    public int RootPid { get; }

    public DateTimeOffset StartedUtc { get; }

    public string DatabasePath { get; }

    public string RecordPath { get; }

    public Process Process => _process;

    public string Status => _status;

    public RiskAssessment Risk => _risk;

    public void Start()
    {
        _monitor.Start();
        _pump = Task.Run(PumpAsync);
        _watch = Task.Run(WatchAsync);
    }

    public SessionStateDto State()
    {
        var coverage = _pipeline.Snapshot().Coverage;
        return new SessionStateDto(
            Id,
            TargetPath,
            RootPid,
            _status,
            StartedUtc,
            _endedUtc,
            _risk.Band.ToString(),
            _risk.Score,
            _risk.PeakScore,
            DatabasePath,
            RecordPath,
            new CoverageDto(coverage.Complete, coverage.Gaps, coverage.Reasons, coverage.Statement));
    }

    public HealthDto Health()
    {
        var stats = _monitor.Stats;
        return new HealthDto(
            "ok",
            AgentInfo.Version,
            AgentInfo.IsElevated,
            Environment.ProcessId,
            Environment.OSVersion.VersionString,
            stats.EtwStarted,
            stats.DnsProviderEnabled,
            stats.RegistryProviderEnabled,
            stats.TcpTableAvailable,
            _monitor.CurrentLostEvents,
            stats.EtwError,
            stats.DnsError,
            stats.RegistryProviderError,
            new MonitorCountersDto(
                stats.EventsSeen,
                stats.EventsForwarded,
                stats.OutsideScope,
                stats.SampledReads,
                stats.ThrottledEvents,
                stats.ChannelDropped,
                stats.MappingFailures,
                stats.ProcessStarts,
                stats.FileEvents,
                stats.NetworkEvents,
                stats.DnsEvents,
                stats.RegistryEvents,
                _monitor.Throttled),
            State());
    }

    public SessionRecord? Record() => _sessions.Get(Id);

    public IReadOnlyList<ProcessRecord> ProcessList() => _processes.List(Id);

    public IReadOnlyList<ProcessDto> ProcessDtos() =>
        [.. ProcessList().Select(process => new ProcessDto(
            process.Pid,
            process.ParentPid,
            process.ImageName,
            process.ImagePath,
            process.CommandLine,
            process.StartedUtc,
            process.Scope.ToString(),
            process.ScopeReason))];

    public IReadOnlyList<BehaviorEvent> EventsPage(EventFilter filter) => _events.Page(Id, filter);

    public IReadOnlyList<BehaviorEvent> EventsByIds(IEnumerable<long> sequenceNumbers) =>
        _events.BySequence(Id, sequenceNumbers);

    public IReadOnlyList<EventDto> ToDtoList(IEnumerable<BehaviorEvent> behaviorEvents) =>
        [.. behaviorEvents.Select(ToDto)];

    public IReadOnlyList<BehaviorEvent> Search(string text, int limit = 100) => _events.Search(Id, text, limit);

    public IReadOnlyList<StoredDetection> DetectionList() => _detections.List(Id);

    public StoredDetection? Detection(string key) => _detections.Get(Id, key);

    public IReadOnlyList<long> Evidence(long detectionId) => _detections.EvidenceFor(detectionId);

    public IReadOnlyList<(DateTimeOffset Ts, double Score, double Peak, string Band)> ScoreHistory() =>
        _scores.History(Id);

    public IReadOnlyList<GapEntry> Gaps() => _pipeline.Snapshot().Gaps;

    public EventDto ToDto(BehaviorEvent behaviorEvent) => new(
        behaviorEvent.Seq,
        behaviorEvent.TimestampUtc,
        behaviorEvent.Kind.ToString(),
        behaviorEvent.Category.ToString(),
        behaviorEvent.Pid,
        behaviorEvent.ParentPid,
        behaviorEvent.ImageName,
        behaviorEvent.ImagePath,
        behaviorEvent.Target,
        behaviorEvent.RemoteIp,
        behaviorEvent.RemotePort,
        behaviorEvent.Protocol,
        behaviorEvent.HostName,
        behaviorEvent.Scope.ToString(),
        behaviorEvent.ScopeReason,
        behaviorEvent.Observability.ToString(),
        behaviorEvent.Confidence,
        behaviorEvent.Source.ToString());

    public DetectionDto ToDto(DetectionState detection) => new(
        detection.Key,
        detection.RuleId,
        detection.Title,
        detection.Severity,
        detection.Confidence,
        EvidenceCategories.Describe(detection.Categories),
        detection.ScopePid,
        detection.FirstSeenUtc,
        detection.LastSeenUtc,
        detection.EventCount,
        detection.StatusText,
        detection.Reason,
        detection.Counterfactual,
        detection.Factors,
        detection.Mitre,
        detection.EvidenceSeq);

    private void WriteMeta()
    {
        var meta = new Dictionary<string, object?>
        {
            ["$meta"] = new
            {
                name = "live-" + Id.ToString("N")[..12],
                description = "Recorded live session for " + TargetPath,
                rootPid = RootPid,
                rootImagePath = TargetPath,
                sessionId = Id.ToString(),
                expect = new { },
            },
        };

        _jsonl.WriteLine(JsonSerializer.Serialize(meta, RawEventJson.Options));
    }

    private async Task PumpAsync()
    {
        try
        {
            while (true)
            {
                if (!await _monitor.Reader.WaitToReadAsync(_cts.Token).ConfigureAwait(false))
                {
                    break;
                }

                var batch = new List<RawEvent>(MaxBatch);
                while (batch.Count < MaxBatch && _monitor.Reader.TryRead(out var rawEvent))
                {
                    batch.Add(rawEvent);
                }

                if (batch.Count > 0 && batch.Count < MaxBatch)
                {
                    try
                    {
                        await Task.Delay(BatchDelay, _cts.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        // Stop was requested; drain and persist what we have.
                    }

                    while (batch.Count < MaxBatch && _monitor.Reader.TryRead(out var more))
                    {
                        batch.Add(more);
                    }
                }

                if (batch.Count > 0)
                {
                    ProcessBatch(batch);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during stop.
        }
        finally
        {
            var remaining = new List<RawEvent>(MaxBatch);
            while (remaining.Count < MaxBatch && _monitor.Reader.TryRead(out var rawEvent))
            {
                remaining.Add(rawEvent);
            }

            if (remaining.Count > 0)
            {
                ProcessBatch(remaining);
            }
        }
    }

    private void ProcessBatch(List<RawEvent> rawEvents)
    {
        var events = new List<BehaviorEvent>(rawEvents.Count);
        var touched = new Dictionary<string, DetectionState>(StringComparer.Ordinal);
        var risk = _risk;

        foreach (var rawEvent in rawEvents)
        {
            var result = _pipeline.Ingest(rawEvent);
            events.Add(result.Event);
            risk = result.Risk;

            foreach (var detection in result.Detections)
            {
                touched[detection.Key] = detection;
            }
        }

        if (events.Count == 0)
        {
            return;
        }

        _recorder.AppendEvents(events);
        _jsonl.Write(string.Concat(rawEvents.Select(RawEventJson.Serialize).Select(line => line + "\n")));
        _jsonl.Flush();

        foreach (var behaviorEvent in events)
        {
            if (behaviorEvent.Kind != EventKind.ProcessStart)
            {
                continue;
            }

            _recorder.UpsertProcess(Id, new ProcessRecord(
                behaviorEvent.Pid,
                behaviorEvent.ParentPid,
                behaviorEvent.ImageName,
                behaviorEvent.ImagePath,
                behaviorEvent.CommandLine,
                behaviorEvent.TimestampUtc,
                behaviorEvent.Scope,
                behaviorEvent.ScopeReason));
        }

        var weights = risk.Contributions.ToDictionary(c => c.Key, c => c.Weight, StringComparer.Ordinal);
        foreach (var detection in touched.Values)
        {
            _recorder.UpsertDetection(Id, detection, weights.GetValueOrDefault(detection.Key));
        }

        var lastTimestamp = events[^1].TimestampUtc;
        if (_lastScoreSample == default
            || (lastTimestamp - _lastScoreSample).Duration() >= ScoreSampleInterval
            || Math.Abs(risk.Score - _risk.Score) > 0.0001)
        {
            _recorder.AppendScore(Id, lastTimestamp, risk);
            _lastScoreSample = lastTimestamp;
        }

        var allGaps = _pipeline.Snapshot().Gaps;
        if (allGaps.Count > _gapsRecorded)
        {
            var newGaps = allGaps.Skip(_gapsRecorded).ToArray();
            _recorder.AddGaps(Id, newGaps);
            _gapsRecorded = allGaps.Count;
            foreach (var gap in newGaps)
            {
                _hub.Publish("gap", new
                {
                    timestamp = gap.TimestampUtc,
                    source = gap.Source,
                    reason = gap.Reason,
                    lost = gap.LostCount,
                    detail = gap.Detail,
                });
            }
        }

        _risk = risk;

        _hub.Publish("events", events.Select(ToDto).ToArray());
        foreach (var detection in touched.Values)
        {
            _hub.Publish("detection", ToDto(detection));
        }

        _hub.Publish("score", new
        {
            timestamp = lastTimestamp,
            score = risk.Score,
            peak = risk.PeakScore,
            band = risk.Band.ToString(),
            explanation = risk.Explanation,
        });
        _hub.Publish("stats", MonitorStatsDto());
    }

    private MonitorCountersDto MonitorStatsDto()
    {
        var stats = _monitor.Stats;
        return new MonitorCountersDto(
            stats.EventsSeen,
            stats.EventsForwarded,
            stats.OutsideScope,
            stats.SampledReads,
            stats.ThrottledEvents,
            stats.ChannelDropped,
            stats.MappingFailures,
            stats.ProcessStarts,
            stats.FileEvents,
            stats.NetworkEvents,
            stats.DnsEvents,
            stats.RegistryEvents,
            _monitor.Throttled);
    }

    private async Task WatchAsync()
    {
        try
        {
            await _process.WaitForExitAsync(_cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (InvalidOperationException)
        {
            return;
        }

        // The target exiting does not mean its events have arrived: ETW delivers
        // asynchronously and the last records are still in flight. Give them a moment before
        // the session stops, otherwise a short-lived target looks like it did nothing.
        try
        {
            await _monitor
                .DrainAsync(
                    TimeSpan.FromMilliseconds(250),
                    TimeSpan.FromSeconds(3),
                    minimumWait: PostExitDrainFloor)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException)
        {
            // Stopping anyway is better than hanging on a session that will not quiesce.
        }

        await StopAsync("target-exited", terminateTarget: false).ConfigureAwait(false);
    }

    public async Task StopAsync(string reason, bool terminateTarget)
    {
        await _stopGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_status is "stopped" or "incomplete" or "crashed")
            {
                return;
            }

            _status = "stopping";

            try
            {
                await _monitor.StopAsync().ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                // Monitor already stopped.
            }

            if (_pump is not null)
            {
                try
                {
                    // The monitor completes the channel when it stops, so the pump drains what
                    // is queued and ends by itself. Cancelling first would discard exactly the
                    // records the drain above waited for, so only cancel as a fallback.
                    await _pump.WaitAsync(DrainPumpTimeout).ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    _cts.Cancel();
                    await _pump.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Expected.
                }
            }

            // Background loops (watch, score sampling) still hold the token.
            _cts.Cancel();

            if (terminateTarget)
            {
                try
                {
                    if (!_process.HasExited)
                    {
                        _process.Kill(entireProcessTree: true);
                    }
                }
                catch (Exception exception) when (exception is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
                {
                    // The process may have exited between the check and the kill.
                }
            }

            // Everything the target did has been persisted by now, so this verdict is final.
            // A session whose only in-scope event is the root says nothing about behaviour:
            // present that as a gap, not as a quiet, clean run.
            if (reason == "target-exited" && _pipeline.Snapshot().Counters.EventsInScope <= 1)
            {
                _pipeline.Ingest(new RawEvent
                {
                    Ts = DateTimeOffset.UtcNow,
                    Kind = EventKind.MonitorGap,
                    Pid = 0,
                    Target = "target-exited-immediately",
                    Detail = "The monitored application exited before any activity beyond its own start was captured; this session says almost nothing about what it did.",
                    Observability = Observability.Partial,
                    Source = EventSourceKind.Polling,
                });
            }

            var snapshot = _pipeline.Snapshot();
            var stats = _monitor.Stats;
            var loss = stats.EtwLostEvents + stats.ChannelDropped;
            _endedUtc = DateTimeOffset.UtcNow;
            _risk = snapshot.Risk;
            _status = loss > 0 ? "incomplete" : "stopped";

            var lateGaps = snapshot.Gaps.Skip(_gapsRecorded).ToArray();
            if (lateGaps.Length > 0)
            {
                _recorder.AddGaps(Id, lateGaps);
                _gapsRecorded = snapshot.Gaps.Count;
            }

            _recorder.Complete(
                Id,
                _endedUtc.Value,
                snapshot.Risk,
                loss,
                _status);

            _jsonl.Dispose();

            _hub.Publish("state", new
            {
                id = Id,
                status = _status,
                reason,
                endedUtc = _endedUtc,
                verdict = snapshot.Risk.Band.ToString(),
                score = snapshot.Risk.Score,
                peak = snapshot.Risk.PeakScore,
                // Published with the verdict so a consumer cannot render "clean" while the sensor
                // had holes; the statement is ready to show as-is.
                coverage = new
                {
                    complete = snapshot.Coverage.Complete,
                    gaps = snapshot.Coverage.Gaps,
                    reasons = snapshot.Coverage.Reasons,
                    statement = snapshot.Coverage.Statement,
                },
            });
        }
        finally
        {
            _stopGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync("agent-shutdown", terminateTarget: false).ConfigureAwait(false);
        await _monitor.DisposeAsync().ConfigureAwait(false);
        _stopGate.Dispose();
        _cts.Dispose();
    }
}

public static class AgentInfo
{
    public const string Version = "0.2.0-phase2";

    public static bool IsElevated
    {
        get
        {
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
    }
}
