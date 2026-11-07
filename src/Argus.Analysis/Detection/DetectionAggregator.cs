namespace Argus.Analysis.Detection;

using Argus.Analysis.Rules;
using Argus.Core.Events;
using Argus.Core.Risk;
using Argus.Core.Sessions;

/// <summary>
/// Collapses repeated rule hits into one detection per (rule, process) inside a
/// merge window, and escalates when new evidence channels join. This is why a
/// looping application produces one card with a count instead of thousands.
/// </summary>
public sealed class DetectionAggregator
{
    private const int MaxEvidenceRefs = 200;

    private readonly Dictionary<string, DetectionState> _byKey = [];
    private readonly Dictionary<string, string> _slotToKey = [];
    private readonly TimeSpan _mergeWindow;

    public DetectionAggregator(TimeSpan? mergeWindow = null)
    {
        _mergeWindow = mergeWindow ?? TimeSpan.FromMinutes(5);
    }

    public IReadOnlyList<DetectionState> All =>
        [.. _byKey.Values.OrderBy(d => d.FirstSeenUtc).ThenBy(d => d.Key, StringComparer.Ordinal)];

    public IReadOnlyList<DetectionState> Active =>
        [.. _byKey.Values
            .Where(d => d.Status != DetectionStatus.Closed)
            .OrderBy(d => d.FirstSeenUtc)
            .ThenBy(d => d.Key, StringComparer.Ordinal)];

    public DetectionState? Apply(RuleFinding finding, BehaviorEvent behaviorEvent)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(behaviorEvent);

        var groupPid = finding.GroupPid ?? behaviorEvent.Pid;
        var slot = $"{finding.Rule.Id}|{groupPid}";

        if (_slotToKey.TryGetValue(slot, out var existingKey)
            && _byKey.TryGetValue(existingKey, out var existing)
            && behaviorEvent.TimestampUtc - existing.LastSeenUtc <= _mergeWindow)
        {
            var count = existing.EventCount + 1;
            var categories = existing.Categories | finding.Rule.Categories;
            var escalated = categories != existing.Categories;
            var lastSeen = behaviorEvent.TimestampUtc > existing.LastSeenUtc
                ? behaviorEvent.TimestampUtc
                : existing.LastSeenUtc;

            var updated = existing with
            {
                LastSeenUtc = lastSeen,
                EventCount = count,
                Confidence = ConfidenceModel.ForEvidence(existing.BaseConfidence, count),
                Categories = categories,
                Status = escalated ? DetectionStatus.Escalated : existing.Status,
                Reason = finding.Reason,
                Counterfactual = finding.Counterfactual,
                Mitre = [.. existing.Mitre.Union(finding.Rule.Mitre, StringComparer.Ordinal)],
                EvidenceSeq = AppendEvidence(existing.EvidenceSeq, behaviorEvent.Seq),
                Factors = finding.Factors,
            };

            _byKey[existingKey] = updated;
            return updated;
        }

        var key = $"{finding.Rule.Id}#{groupPid}#{behaviorEvent.Seq}";
        var created = new DetectionState
        {
            Key = key,
            RuleId = finding.Rule.Id,
            Title = finding.Rule.Title,
            Severity = finding.Rule.Severity,
            Confidence = ConfidenceModel.ForEvidence(finding.Rule.BaseConfidence, 1),
            BaseConfidence = finding.Rule.BaseConfidence,
            Categories = finding.Rule.Categories,
            ScopePid = groupPid,
            FirstSeenUtc = behaviorEvent.TimestampUtc,
            LastSeenUtc = behaviorEvent.TimestampUtc,
            EventCount = 1,
            Status = DetectionStatus.Open,
            Reason = finding.Reason,
            Counterfactual = finding.Counterfactual,
            Mitre = finding.Rule.Mitre,
            EvidenceSeq = [behaviorEvent.Seq],
            Factors = finding.Factors,
        };

        _byKey[key] = created;
        _slotToKey[slot] = key;
        return created;
    }

    public IReadOnlyList<DetectionSignal> ToSignals() =>
        [.. Active.Select(d => new DetectionSignal(
            d.Key,
            d.RuleId,
            d.Severity,
            d.Confidence,
            d.Categories,
            d.LastSeenUtc,
            d.EventCount))];

    private static IReadOnlyList<long> AppendEvidence(IReadOnlyList<long> existing, long seq)
    {
        if (existing.Count >= MaxEvidenceRefs)
        {
            return existing;
        }

        var copy = new List<long>(existing.Count + 1);
        copy.AddRange(existing);
        copy.Add(seq);
        return copy;
    }
}
