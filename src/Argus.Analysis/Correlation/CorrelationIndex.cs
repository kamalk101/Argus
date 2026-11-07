namespace Argus.Analysis.Correlation;

using Argus.Core.Events;

/// <summary>
/// Time-ordered index of in-scope events used by correlated rules. Events arrive
/// in timestamp order (ETW and replay both do) so "recent" queries can scan
/// backwards and stop at the window edge instead of filtering the whole session.
/// </summary>
public sealed class CorrelationIndex
{
    private readonly List<BehaviorEvent> _events;
    private readonly int _capacity;

    public CorrelationIndex(int capacity = 200_000)
    {
        _capacity = Math.Max(64, capacity);
        _events = new List<BehaviorEvent>(Math.Min(_capacity, 4096));
    }

    public int Count => _events.Count;

    public void Add(BehaviorEvent behaviorEvent)
    {
        ArgumentNullException.ThrowIfNull(behaviorEvent);

        if (_events.Count >= _capacity)
        {
            var drop = Math.Max(1, _events.Count / 10);
            _events.RemoveRange(0, drop);
        }

        _events.Add(behaviorEvent);
    }

    /// <summary>Events of one category within [since, until], oldest first.</summary>
    public IReadOnlyList<BehaviorEvent> Recent(
        EventCategory category,
        DateTimeOffset since,
        DateTimeOffset until,
        int? pid = null)
    {
        var matches = new List<BehaviorEvent>();

        for (var i = _events.Count - 1; i >= 0; i--)
        {
            var candidate = _events[i];
            if (candidate.TimestampUtc < since)
            {
                break;
            }

            if (candidate.TimestampUtc > until || candidate.Category != category)
            {
                continue;
            }

            if (pid is not null && candidate.Pid != pid)
            {
                continue;
            }

            matches.Add(candidate);
        }

        matches.Reverse();
        return matches;
    }

    public IReadOnlyList<BehaviorEvent> Recent(DateTimeOffset since, DateTimeOffset until, Func<BehaviorEvent, bool> predicate)
    {
        ArgumentNullException.ThrowIfNull(predicate);

        var matches = new List<BehaviorEvent>();
        for (var i = _events.Count - 1; i >= 0; i--)
        {
            var candidate = _events[i];
            if (candidate.TimestampUtc < since)
            {
                break;
            }

            if (candidate.TimestampUtc <= until && predicate(candidate))
            {
                matches.Add(candidate);
            }
        }

        matches.Reverse();
        return matches;
    }
}
