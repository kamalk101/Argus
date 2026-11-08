namespace Argus.Analysis.Rules;

using Argus.Core.Events;

/// <summary>
/// N-005: many distinct names failed to resolve in a short window.
///
/// This is the signature of a domain-generation algorithm: a program walks a list of candidate
/// names, most of which were never registered, until one answers. It is also what a typo'd spell
/// checker, a busted search-suffix in a corporate resolver, or a machine with a dead VPN looks like
/// from the wire — which is why the rule counts *distinct* names rather than queries, and why the
/// finding reports the window and the names instead of asserting intent.
///
/// Only an authoritative "no such name" counts. A timeout or a refused query says something about
/// the path to the resolver, not about the name, and lumping the two together would let a flaky
/// network look exactly like a DGA.
///
/// Severity 50: real but not damning, and rarely alone in a report that also shows what the
/// program did with the answer.
/// </summary>
public sealed class FailedLookupStormRule : IEventRule, IWindowedRule
{
    private readonly RuleSettings _settings;

    public FailedLookupStormRule(RuleSettings? settings = null) => _settings = settings ?? RuleSettings.Default;

    public TimeSpan Window => TimeSpan.FromSeconds(_settings.FailedLookupWindowSeconds);

    /// <summary>Distinct names that must fail before the storm is worth mentioning.</summary>
    public int Threshold => _settings.FailedLookupCount;

    public RuleMetadata Metadata { get; } = new(
        "N-005",
        "Storm of lookups for names that do not exist",
        50,
        EvidenceCategory.Network,
        ["T1568.002"],
        "Many distinct hostnames failed to resolve within a short window, the shape of a domain-generation algorithm walking candidate names.",
        BaseConfidence: 0.75);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind is not (EventKind.DnsQuery or EventKind.DnsResponse))
        {
            yield break;
        }

        // Only an authoritative negative counts; a timeout says nothing about the name.
        if (current.DnsStatus != DnsStatus.NameDoesNotExist)
        {
            yield break;
        }

        var name = (current.HostName ?? current.Target ?? string.Empty).Trim().TrimEnd('.');
        if (name.Length == 0)
        {
            yield break;
        }

        var since = context.Now - Window;
        var failed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { name };
        var pid = current.Pid;

        foreach (var candidate in context.Correlation.Recent(
            since,
            context.Now,
            e => e.Kind is EventKind.DnsQuery or EventKind.DnsResponse
                && e.DnsStatus == DnsStatus.NameDoesNotExist
                && e.Pid == pid))
        {
            var candidateName = (candidate.HostName ?? candidate.Target ?? string.Empty).Trim().TrimEnd('.');
            if (candidateName.Length > 0)
            {
                failed.Add(candidateName);
            }
        }

        var distinct = failed.Count;
        if (distinct < Threshold)
        {
            yield break;
        }

        // One detection per threshold crossing (15, 30, 45 …), not one per query.
        if (distinct % Threshold != 0)
        {
            yield break;
        }

        var sample = string.Join(", ", failed.OrderBy(n => n, StringComparer.Ordinal).Take(5));
        var image = ProcessNames.Normalize(current.ImageName ?? current.PathKey ?? string.Empty);
        var who = string.IsNullOrEmpty(image) ? $"PID {pid}" : $"{ProcessNames.Display(image)} (PID {pid})";

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{who} asked for {distinct} distinct names in {Window.TotalSeconds:0} s and every one was answered \"no such name\" ({sample}{(distinct > 5 ? ", …" : string.Empty)}), which is how a program walks a list of generated candidates.",
            Counterfactual = $"Would not fire below {Threshold} distinct failing names within {Window.TotalSeconds:0} s, counts each name once however often it is repeated, counts only an authoritative \"no such name\" (a timeout or refused query says nothing about the name), and keeps to the one process that made the lookups. A misspelled search suffix, a dead VPN or a typo'd updater host produces the same shape; the finding reports the window and the names so that can be checked in one look.",
            Factors =
            [
                $"distinct_failed_names={distinct}",
                $"threshold={Threshold}",
                $"window_seconds={(int)Window.TotalSeconds}",
                $"pid={pid}",
                $"sample={sample}",
            ],
            TargetPid = pid,
            GroupPid = pid,
            Target = name,
        };
    }
}
