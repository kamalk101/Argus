namespace Argus.Analysis.Rules;

using Argus.Core.Events;
using Argus.Core.Network;

/// <summary>
/// N-001: a connection to a service port a desktop application has no ordinary
/// reason to use. Port choice is a signal, never a verdict.
/// </summary>
public sealed class RiskyPortRule : IEventRule
{
    private static readonly Dictionary<int, (string Service, bool Elevated)> Ports = new()
    {
        [21] = ("FTP control", false),
        [23] = ("Telnet", true),
        [25] = ("SMTP", false),
        [139] = ("NetBIOS session", false),
        [445] = ("SMB file sharing", false),
        [1337] = ("commonly used by tooling and implants", true),
        [3389] = ("Remote Desktop", false),
        [4444] = ("commonly used by reverse shells", true),
        [5900] = ("VNC remote desktop", false),
        [6667] = ("IRC", false),
    };

    public RuleMetadata Metadata { get; } = new(
        "N-001",
        "Connection to a risky service port",
        45,
        EvidenceCategory.Network,
        ["T1021"],
        "The application connected to a port associated with remote administration, file sharing or implants.",
        BaseConfidence: 0.80);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind is not (EventKind.NetConnect or EventKind.NetAccept))
        {
            yield break;
        }

        if (current.RemotePort is not { } port || !Ports.TryGetValue(port, out var info))
        {
            yield break;
        }

        if (IpAddressClassifier.Classify(current.RemoteIp) == IpScope.Loopback)
        {
            yield break;
        }

        var target = $"{current.RemoteIp}:{port}";
        var external = IpAddressClassifier.IsExternal(current.RemoteIp);

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"The application connected to {target} ({info.Service}), {(external ? "a public" : "a private")} address with no legitimate desktop use for that service.",
            Counterfactual = "Would not fire for loopback connections, or for outbound traffic on ordinary web and messaging ports.",
            Factors =
            [
                $"remote={target}",
                $"service={info.Service}",
                $"ip_scope={(external ? "public" : "private")}",
                $"protocol={current.Protocol ?? "unknown"}",
            ],
            Target = target,
        };
    }
}
