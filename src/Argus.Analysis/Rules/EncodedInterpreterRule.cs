namespace Argus.Analysis.Rules;

using System.Text.RegularExpressions;
using Argus.Core.Events;

/// <summary>
/// P-003: an interpreter launched with an encoded payload, a remote URL or a
/// script-host container. Legitimate software rarely needs these argument shapes.
/// </summary>
public sealed partial class EncodedInterpreterRule : IEventRule
{
    public RuleMetadata Metadata { get; } = new(
        "P-003",
        "Interpreter with encoded or remote payload",
        75,
        EvidenceCategory.Process,
        ["T1218", "T1027"],
        "A script interpreter or loader was started with encoded, remote or script-host arguments.",
        BaseConfidence: 0.90);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind != EventKind.ProcessStart)
        {
            yield break;
        }

        var image = ProcessNames.Normalize(current.ImageName ?? current.ImagePath);
        if (!ProcessNames.Interpreters.Contains(image))
        {
            yield break;
        }

        var commandLine = current.CommandLine;
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            yield break;
        }

        var match = SuspiciousArguments().Match(commandLine);
        if (!match.Success)
        {
            yield break;
        }

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{image} (PID {current.Pid}) was started with the argument pattern \"{match.Value}\", which is used to run hidden or remotely supplied code.",
            Counterfactual = "Would not fire for an ordinary invocation without encoded, URL or script-host arguments.",
            Factors =
            [
                $"image={image}",
                $"matched={match.Value}",
                $"arguments={Trim(commandLine)}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.ParentPid,
            Target = commandLine,
        };
    }

    private static string Trim(string value) => value.Length <= 160 ? value : value[..160] + "…";

    [GeneratedRegex(
        @"(-enc(odedcommand)?\b|frombase64string\b|javascript:|\.hta\b|https?://)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SuspiciousArguments();
}
