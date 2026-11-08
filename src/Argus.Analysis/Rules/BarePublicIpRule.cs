namespace Argus.Analysis.Rules;

using Argus.Core.Events;
using Argus.Core.Network;

/// <summary>
/// N-004: a connection to a public address by a process that looked nothing up.
///
/// Ordinary applications reach the network through a name: they resolve it and then connect to
/// whatever it resolved to. A program that dials a bare public address without asking anyone has
/// an address baked into it, which is what a hardcoded callback or a direct-to-IP implant looks
/// like. Severity is low on purpose — a program with its own resolver, a cached address, or an
/// address reached over DNS-over-HTTPS looks identical, and this rule may only ever be an
/// ingredient in a larger picture.
///
/// The sensor records DNS queries, not DNS answers, so this cannot check whether *that* address
/// was resolved: it checks whether the process asked anything at all in the last two minutes.
/// </summary>
public sealed class BarePublicIpRule : IEventRule
{
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(2);

    public RuleMetadata Metadata { get; } = new(
        "N-004",
        "Connection to a bare public address",
        35,
        EvidenceCategory.Network,
        ["T1095"],
        "The application connected to a public address without resolving any name beforehand, which is how a hardcoded callback behaves.",
        BaseConfidence: 0.60);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind != EventKind.NetConnect
            || string.IsNullOrEmpty(current.RemoteIp)
            || !IpAddressClassifier.IsExternal(current.RemoteIp))
        {
            yield break;
        }

        var since = context.Now - Window;
        var recent = context.Correlation.Recent(since, context.Now, candidate =>
            candidate.Pid == current.Pid
            && candidate.Kind is EventKind.DnsQuery or EventKind.DnsResponse
                or EventKind.NetConnect or EventKind.NetAccept);

        var earlierConnections = 0;
        foreach (var candidate in recent)
        {
            if (candidate.Kind is EventKind.DnsQuery or EventKind.DnsResponse)
            {
                // The process asked for a name, so this connection may well be the answer.
                yield break;
            }

            if (candidate.Kind is EventKind.NetConnect or EventKind.NetAccept
                && string.Equals(candidate.RemoteIp, current.RemoteIp, StringComparison.Ordinal))
            {
                earlierConnections++;
            }
        }

        if (earlierConnections > 1)
        {
            // Already reported on the first connection to this address in the window.
            yield break;
        }

        var endpoint = $"{current.RemoteIp}:{current.RemotePort}";

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"The application connected to {endpoint} without resolving any name in the previous {Window.TotalMinutes:0} minutes — the address came from inside the program rather than from the system resolver.",
            Counterfactual = "Would not fire for private or loopback addresses, for a process that looked up any name in the window (its own or a library's), or for repeat connections to an address it has already been seen using.",
            Factors =
            [
                $"remote={endpoint}",
                $"ip_scope=public",
                $"dns_queries_in_window=0",
                $"window_seconds={(int)Window.TotalSeconds}",
                $"protocol={current.Protocol ?? "unknown"}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.Pid,
            Target = endpoint,
        };
    }
}
