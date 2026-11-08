namespace Argus.Analysis.Rules;

using System.Globalization;
using Argus.Core.Events;
using Argus.Core.Network;

/// <summary>
/// N-002: repeated connections to the same endpoint at a steady interval — the shape of a
/// periodic callback.
///
/// The signal is regularity, not count: a browser opens dozens of connections and a chat client
/// holds one open, but only a program that wakes up on a timer connects *again and again at the
/// same spacing*. Jitter is measured as the coefficient of variation of the intervals (standard
/// deviation over mean), so a beacon sleeping 30 s with a 2 s spread reads as 6.7 % and a user
/// clicking around reads far higher.
///
/// Counted from the correlation index rather than hidden rule state, so replay of a recording
/// produces the same verdict and a rule change is visible in the fixture suite.
/// </summary>
public sealed class BeaconingRule : IEventRule
{
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(10);

    /// <summary>Six callbacks is the smallest sample where "regular" means anything.</summary>
    public const int Threshold = 6;

    /// <summary>Below this mean interval, a burst of connections is load, not a timer.</summary>
    public const double MinMeanIntervalSeconds = 5;

    /// <summary>Intervals within ±15 % of their mean: the catalogue's low-jitter criterion.</summary>
    public const double MaxJitter = 0.15;

    public RuleMetadata Metadata { get; } = new(
        "N-002",
        "Periodic callbacks to one endpoint",
        60,
        EvidenceCategory.Network,
        ["T1071"],
        "The application connected to the same endpoint repeatedly at a nearly constant interval, which is how a periodic callback behaves.",
        BaseConfidence: 0.75);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind is not (EventKind.NetConnect or EventKind.NetAccept)
            || string.IsNullOrEmpty(current.RemoteIp)
            || IpAddressClassifier.Classify(current.RemoteIp) is IpScope.Loopback or IpScope.Invalid)
        {
            yield break;
        }

        var since = context.Now - Window;
        var recent = context.Correlation.Recent(EventCategory.Network, since, context.Now, current.Pid);

        var times = new List<DateTimeOffset>(Threshold + 4);
        foreach (var candidate in recent)
        {
            if (candidate.Kind is not (EventKind.NetConnect or EventKind.NetAccept)
                || !string.Equals(candidate.RemoteIp, current.RemoteIp, StringComparison.Ordinal)
                || candidate.RemotePort != current.RemotePort)
            {
                continue;
            }

            times.Add(candidate.TimestampUtc);
        }

        // The current event is already in the index when the rule runs; if a pipeline feeds
        // rules before indexing, this keeps the count honest either way.
        if (times.Count == 0 || times[^1] != current.TimestampUtc)
        {
            times.Add(current.TimestampUtc);
        }

        if (times.Count < Threshold || times.Count % Threshold != 0)
        {
            // Fires once per Threshold callbacks rather than on every further connection.
            yield break;
        }

        var intervals = new double[times.Count - 1];
        for (var i = 1; i < times.Count; i++)
        {
            intervals[i - 1] = (times[i] - times[i - 1]).TotalSeconds;
        }

        var mean = intervals.Average();
        if (mean < MinMeanIntervalSeconds)
        {
            yield break;
        }

        var variance = intervals.Select(value => (value - mean) * (value - mean)).Average();
        var jitter = Math.Sqrt(variance) / mean;
        if (jitter > MaxJitter)
        {
            yield break;
        }

        var endpoint = $"{current.RemoteIp}:{current.RemotePort}";
        var span = (times[^1] - times[0]).TotalSeconds;

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"The application connected to {endpoint} {times.Count} times over {span:0} s with intervals of {mean:0.#} s ± {jitter * 100:0.#}% — a periodic callback rather than user-driven traffic.",
            Counterfactual = "Would not fire for connections spread at irregular intervals, for a burst of traffic faster than one connection per five seconds, or for loopback and private endpoints used by ordinary background services.",
            Factors =
            [
                $"remote={endpoint}",
                $"connections={times.Count}",
                $"span_seconds={span.ToString("0", CultureInfo.InvariantCulture)}",
                $"mean_interval_seconds={mean.ToString("0.##", CultureInfo.InvariantCulture)}",
                $"jitter_percent={(jitter * 100).ToString("0.#", CultureInfo.InvariantCulture)}",
                $"window_seconds={(int)Window.TotalSeconds}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.Pid,
            Target = endpoint,
        };
    }
}
