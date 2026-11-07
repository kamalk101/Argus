namespace Argus.Analysis.Rules;

using Argus.Core.Events;
using Argus.Core.Network;

/// <summary>
/// X-001: a persistence write followed by an external connection inside the
/// correlation window. Neither half is conclusive; together they describe the
/// install-then-call-home shape, so this is the one rule that can reach the
/// malicious band on its own.
/// </summary>
public sealed class PersistenceThenNetworkRule : ICorrelatedRule
{
    public static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(60);

    public RuleMetadata Metadata { get; } = new(
        "X-001",
        "Persistence write followed by external connection",
        90,
        EvidenceCategory.File | EvidenceCategory.Network,
        ["T1105", "T1547"],
        "A persistence-location write and an external network connection occurred within the correlation window.",
        BaseConfidence: 0.85);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind is not (EventKind.NetConnect or EventKind.NetAccept))
        {
            yield break;
        }

        if (!IpAddressClassifier.IsExternal(current.RemoteIp))
        {
            yield break;
        }

        var since = context.Now - CorrelationWindow;
        var recentFiles = context.Correlation.Recent(EventCategory.File, since, context.Now);

        BehaviorEvent? persistenceWrite = null;
        string? label = null;

        for (var i = recentFiles.Count - 1; i >= 0; i--)
        {
            var candidate = recentFiles[i];
            if (candidate.Kind is not (EventKind.FileCreate or EventKind.FileWrite or EventKind.FileRename)
                || string.IsNullOrEmpty(candidate.PathKey))
            {
                continue;
            }

            if (context.Catalog.TryMatch(candidate.PathKey, out var entry)
                && string.Equals(entry.Group, "persistence", StringComparison.OrdinalIgnoreCase))
            {
                persistenceWrite = candidate;
                label = entry.Label;
                break;
            }
        }

        if (persistenceWrite is null)
        {
            yield break;
        }

        var delta = context.Now - persistenceWrite.TimestampUtc;
        var endpoint = $"{current.RemoteIp}:{current.RemotePort}";

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"The application wrote {persistenceWrite.Target} into {label} and then connected to {endpoint} {delta.TotalSeconds:0.0} s later — the install-then-call-home pattern.",
            Counterfactual = "Would not fire if the connection were internal or loopback, or if no persistence-location write preceded it within 60 seconds.",
            Factors =
            [
                $"persistence_path={persistenceWrite.PathKey}",
                $"persistence_seq={persistenceWrite.Seq}",
                $"network_seq={current.Seq}",
                $"delta_seconds={delta.TotalSeconds:0.0}",
                $"remote={endpoint}",
            ],
            Target = endpoint,
        };
    }
}
