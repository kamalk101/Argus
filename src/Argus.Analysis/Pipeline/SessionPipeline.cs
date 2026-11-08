namespace Argus.Analysis.Pipeline;

using Argus.Analysis.Correlation;
using Argus.Analysis.Detection;
using Argus.Analysis.Rules;
using Argus.Core.Events;
using Argus.Core.Paths;
using Argus.Core.Processes;
using Argus.Core.Risk;
using Argus.Core.Sessions;

public sealed record SessionPipelineOptions
{
    public required Guid SessionId { get; init; }

    public required int RootPid { get; init; }

    public string? RootImagePath { get; init; }

    public SensitivePathCatalog Catalog { get; init; } = SensitivePathCatalog.Empty;

    public RiskOptions Risk { get; init; } = RiskOptions.Default;

    public int CorrelationCapacity { get; init; } = 200_000;

    public TimeSpan MergeWindow { get; init; } = TimeSpan.FromMinutes(5);

    public RuleCatalog? Rules { get; init; }
}

public sealed record PipelineIngestResult
{
    public required BehaviorEvent Event { get; init; }

    public required ScopeDecision Scope { get; init; }

    /// <summary>Detections created or updated by this event.</summary>
    public required IReadOnlyList<DetectionState> Detections { get; init; }

    public required RiskAssessment Risk { get; init; }

    public required bool Evaluated { get; init; }
}

public sealed record GapEntry(
    DateTimeOffset TimestampUtc,
    string Source,
    string Reason,
    long? LostCount,
    string? Detail);

public sealed record SessionCounters
{
    public long EventsSeen { get; init; }

    public long EventsInScope { get; init; }

    public long EventsOutsideScope { get; init; }

    public long ProcessStarts { get; init; }

    public long FileOperations { get; init; }

    public long NetworkConnections { get; init; }

    public long FindingsRaised { get; init; }

    public long Detections { get; init; }

    public long Gaps { get; init; }

    public IReadOnlyDictionary<EventCategory, long> ByCategory { get; init; } =
        new Dictionary<EventCategory, long>();
}

public sealed record SessionSnapshot
{
    public required RiskAssessment Risk { get; init; }

    public required IReadOnlyList<DetectionState> Detections { get; init; }

    public required SessionCounters Counters { get; init; }

    public required IReadOnlyList<GapEntry> Gaps { get; init; }

    /// <summary>
    /// What the sensor could not see. A verdict is published with its coverage, so "no detections"
    /// can never be rendered as "nothing happened" while gaps exist.
    /// </summary>
    public required CoverageAssessment Coverage { get; init; }

    public required ProcessTable Processes { get; init; }
}

/// <summary>
/// Normalise → scope → rules → aggregate → score, in one deterministic pass.
/// Time is the stream's time (the event timestamp), never the wall clock, so the
/// same recorded session always produces the same detections and scores.
/// </summary>
public sealed class SessionPipeline
{
    private readonly SessionPipelineOptions _options;
    private readonly EventNormalizer _normalizer;
    private readonly ProcessScopeTracker _scope;
    private readonly ProcessTable _processes = new();
    private readonly CorrelationIndex _correlation;
    private readonly DetectionAggregator _detections;
    private readonly RuleCatalog _rules;
    private readonly Dictionary<EventCategory, long> _byCategory = [];

    private long _eventsSeen;
    private long _eventsInScope;
    private long _eventsOutsideScope;
    private long _processStarts;
    private long _fileOperations;
    private long _networkConnections;
    private long _findingsRaised;
    private long _gaps;
    private double _peak;
    private RiskAssessment _risk = RiskAssessment.Empty;
    private readonly List<GapEntry> _gapLog = [];

    public SessionPipeline(SessionPipelineOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        _normalizer = new EventNormalizer(options.SessionId);
        _scope = new ProcessScopeTracker(options.RootPid, options.RootImagePath);
        _correlation = new CorrelationIndex(options.CorrelationCapacity);
        _detections = new DetectionAggregator(options.MergeWindow);
        _rules = options.Rules ?? RuleCatalog.CreateDefault();
    }

    public Guid SessionId => _options.SessionId;

    public int RootPid => _options.RootPid;

    public PipelineIngestResult Ingest(RawEvent raw)
    {
        ArgumentNullException.ThrowIfNull(raw);

        var behaviorEvent = _normalizer.Normalize(raw);
        var decision = _scope.Observe(behaviorEvent);
        behaviorEvent = behaviorEvent with
        {
            Scope = decision.State,
            ScopeReason = decision.Reason,
        };

        _eventsSeen++;
        _byCategory[behaviorEvent.Category] = _byCategory.GetValueOrDefault(behaviorEvent.Category) + 1;

        if (behaviorEvent.Kind == EventKind.MonitorGap)
        {
            _gaps++;
            // Target carries the machine-readable reason and Detail the prose (see the sensor's
            // EmitGap). Reading them the other way round put the sentence in the reason column and
            // the reason in the detail column, which is how the report ended up naming gaps by
            // their description.
            _gapLog.Add(new GapEntry(
                behaviorEvent.TimestampUtc,
                behaviorEvent.ImageName ?? "sensor",
                behaviorEvent.Target is { Length: > 0 } reason ? reason : "collection-gap",
                null,
                behaviorEvent.Detail));
        }

        if (!behaviorEvent.InScope)
        {
            _eventsOutsideScope++;
            return new PipelineIngestResult
            {
                Event = behaviorEvent,
                Scope = decision,
                Detections = [],
                Risk = _risk,
                Evaluated = false,
            };
        }

        _eventsInScope++;

        if (behaviorEvent.Kind == EventKind.ProcessStart)
        {
            _processStarts++;
            _processes.Record(new ProcessRecord(
                behaviorEvent.Pid,
                behaviorEvent.ParentPid,
                behaviorEvent.ImageName,
                behaviorEvent.ImagePath,
                behaviorEvent.CommandLine,
                behaviorEvent.TimestampUtc,
                decision.State,
                decision.Reason));
        }
        else if (behaviorEvent.Category == EventCategory.File)
        {
            _fileOperations++;
        }
        else if (behaviorEvent.Kind == EventKind.NetConnect)
        {
            _networkConnections++;
        }

        _correlation.Add(behaviorEvent);

        var context = new RuleContext
        {
            Event = behaviorEvent,
            Now = behaviorEvent.TimestampUtc,
            Processes = _processes,
            Correlation = _correlation,
            Catalog = _options.Catalog,
            RootPid = _options.RootPid,
        };

        var findings = new List<RuleFinding>();
        foreach (var rule in _rules.EventRules)
        {
            findings.AddRange(rule.Evaluate(context));
        }

        foreach (var rule in _rules.CorrelatedRules)
        {
            findings.AddRange(rule.Evaluate(context));
        }

        var touched = new List<DetectionState>(findings.Count);
        foreach (var finding in findings)
        {
            var detection = _detections.Apply(finding, behaviorEvent);
            if (detection is not null)
            {
                touched.Add(detection);
            }
        }

        _findingsRaised += findings.Count;

        _risk = RiskScorer.Evaluate(_detections.ToSignals(), behaviorEvent.TimestampUtc, _options.Risk, _peak);
        _peak = _risk.PeakScore;

        return new PipelineIngestResult
        {
            Event = behaviorEvent,
            Scope = decision,
            Detections = touched,
            Risk = _risk,
            Evaluated = true,
        };
    }

    public SessionSnapshot Snapshot()
    {
        var coverage = CoverageAssessment.From(_gapLog);

        return new SessionSnapshot
        {
            Risk = WithCoverage(_risk, coverage),
            Detections = _detections.All,
            Gaps = _gapLog,
            Coverage = coverage,
            Processes = _processes,
            Counters = new SessionCounters
            {
                EventsSeen = _eventsSeen,
                EventsInScope = _eventsInScope,
                EventsOutsideScope = _eventsOutsideScope,
                ProcessStarts = _processStarts,
                FileOperations = _fileOperations,
                NetworkConnections = _networkConnections,
                FindingsRaised = _findingsRaised,
                Detections = _detections.All.Count,
                Gaps = _gaps,
                ByCategory = new Dictionary<EventCategory, long>(_byCategory),
            },
        };
    }

    /// <summary>
    /// The score is left alone; the sentence around it is not. A reader who sees "no significant
    /// indicators" must also see that the sensor had holes, and why.
    /// </summary>
    private static RiskAssessment WithCoverage(RiskAssessment risk, CoverageAssessment coverage)
    {
        if (coverage.Complete)
        {
            return risk;
        }

        var limitation = risk.Score > 0
            ? $" Coverage was incomplete ({coverage.Gaps} gap(s)), so the score may understate what the application did."
            : " No detections were raised, but coverage was incomplete, so this is not an all-clear.";

        return risk with { Explanation = risk.Explanation + limitation };
    }
}
