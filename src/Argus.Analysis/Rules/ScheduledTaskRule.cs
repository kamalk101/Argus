namespace Argus.Analysis.Rules;

using System.Text.RegularExpressions;
using Argus.Core.Events;

/// <summary>
/// F-003: a scheduled task was registered. Task registration is how a program arranges
/// to run again later without a Run key, and it survives the deletion of the original
/// file. The evidence is the scheduling tool being launched with a create verb.
///
/// The task definition file itself (under <c>System32\Tasks</c>) is already covered by
/// F-005 as a system write; this rule names the persistence act rather than the file.
/// </summary>
public sealed partial class ScheduledTaskRule : IEventRule
{
    private static readonly HashSet<string> SchedulingTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "schtasks.exe", "at.exe",
    };

    public RuleMetadata Metadata { get; } = new(
        "F-003",
        "Scheduled task created",
        70,
        EvidenceCategory.Process,
        ["T1053.005"],
        "A task scheduler was used to register a task that will run later without the user.",
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
        if (!ProcessNames.IsOneOf(image, SchedulingTools))
        {
            yield break;
        }

        var commandLine = current.CommandLine;

        // schtasks /query, /run, /end, /delete are ordinary administration; only
        // registration creates something that will execute later.
        var registration = CreateVerb().Match(commandLine ?? string.Empty);
        var isAt = image.Equals("at.exe", StringComparison.OrdinalIgnoreCase)
            || image.Equals("at", StringComparison.OrdinalIgnoreCase);

        if (!registration.Success && !isAt)
        {
            yield break;
        }

        var taskName = NamedTask(commandLine);
        var tool = isAt
            ? "at.exe, the legacy scheduler"
            : "schtasks.exe with a /create verb";        var named = taskName.Length > 0 ? $" \"{taskName}\"" : string.Empty;

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{tool} (PID {current.Pid}) registered the scheduled task{named}; the task will run later without the user starting it.",
            Counterfactual = "Would not fire for a listing or one-off execution (`schtasks /query`, `/run`, `/end`, `/delete`), or if the tool had only been read without a create verb.",
            Factors =
            [
                $"image={image}",
                $"evidence=command-line",
                $"task={taskName}",
                $"arguments={Trim(commandLine)}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.ParentPid,
            Target = commandLine,
        };
    }

    private static string NamedTask(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return string.Empty;
        }

        var match = TaskNameArgument().Match(commandLine);
        if (!match.Success)
        {
            return string.Empty;
        }

        // Two alternatives: a quoted name that may contain spaces, or a bare token.
        return (match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value).Trim();
    }

    private static string Trim(string? value) => value is null
        ? string.Empty
        : value.Length <= 160 ? value : value[..160] + "…";

    [GeneratedRegex(@"(\s/|\s-)create\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CreateVerb();

    [GeneratedRegex(@"/tn\s+""([^""]+)""|/tn\s+(\S+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TaskNameArgument();
}
