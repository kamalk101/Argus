namespace Argus.Analysis.Rules;

using System.Globalization;
using Argus.Core.Events;
using Argus.Core.Network;

/// <summary>
/// N-003: a large volume leaving to one public address inside a minute.
///
/// Volume alone is ordinary — uploads, backups and video calls all move megabytes — which is why
/// this rule is about *concentration*: one destination, one minute, more than 20 MB, from a
/// single process. It is the collection half of exfiltration (T1041), and it is deliberately
/// crude; it belongs in the report as an ingredient next to what was written and where, never as
/// a verdict on its own.
///
/// Summed from the send records in the correlation index, so the count is reproducible from a
/// recording and there is no rule-side accumulator to drift.
/// </summary>
public sealed class OutboundVolumeRule : IEventRule
{
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(60);

    public const long ThresholdBytes = 20L * 1024 * 1024;

    public RuleMetadata Metadata { get; } = new(
        "N-003",
        "Large outbound transfer to one address",
        65,
        EvidenceCategory.Network,
        ["T1041"],
        "The application sent more than 20 MB to a single public address within a minute.",
        BaseConfidence: 0.70);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind != EventKind.NetFlow
            || current.BytesOut is not { } currentBytes
            || currentBytes <= 0
            || string.IsNullOrEmpty(current.RemoteIp)
            || !IpAddressClassifier.IsExternal(current.RemoteIp))
        {
            yield break;
        }

        var since = context.Now - Window;
        var recent = context.Correlation.Recent(EventCategory.Network, since, context.Now, current.Pid);

        long total = 0;
        var records = 0;
        var counted = false;
        foreach (var candidate in recent)
        {
            if (candidate.Kind != EventKind.NetFlow
                || !string.Equals(candidate.RemoteIp, current.RemoteIp, StringComparison.Ordinal)
                || candidate.BytesOut is not { } sent
                || sent <= 0)
            {
                continue;
            }

            total += sent;
            records++;
            counted |= candidate.Seq == current.Seq;
        }

        if (!counted)
        {
            total += currentBytes;
            records++;
        }

        if (total < ThresholdBytes)
        {
            yield break;
        }

        // One finding per 20 MB: a 60 MB upload is three crossings, not a finding per send.
        var crossings = total / ThresholdBytes;
        var previous = (total - currentBytes) / ThresholdBytes;
        if (crossings == previous)
        {
            yield break;
        }

        var megabytes = total / (1024.0 * 1024.0);

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"The application sent {megabytes:0.#} MB to {current.RemoteIp} within {Window.TotalSeconds:0} s across {records} send records — one destination, one minute, far above ordinary application traffic.",
            Counterfactual = "Would not fire for private or loopback addresses, for volume spread across several destinations, or for a single transfer below 20 MB.",
            Factors =
            [
                $"remote_ip={current.RemoteIp}",
                $"bytes_out={total}",
                $"megabytes={megabytes.ToString("0.#", CultureInfo.InvariantCulture)}",
                $"send_records={records}",
                $"crossings={crossings}",
                $"window_seconds={(int)Window.TotalSeconds}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.Pid,
            Target = current.RemoteIp,
        };
    }
}
