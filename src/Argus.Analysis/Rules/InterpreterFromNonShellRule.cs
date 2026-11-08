namespace Argus.Analysis.Rules;

using Argus.Core.Events;
using Argus.Core.Sessions;

/// <summary>
/// P-001: an interpreter was started by a process the sensor never saw.
///
/// P-002 asks a question the process table can answer — "which non-shell parent started this shell?" —
/// and it asks it well, at severity 85. This rule covers the one case P-002 structurally cannot reach:
/// an interpreter whose creator was never recorded at all, yet which belongs to the monitored tree
/// because its image lives in the application's own directory. The tree started it somehow, and the
/// link that would say how is missing.
///
/// The two rules are therefore disjoint by construction rather than by a list of exceptions: where a
/// parent record exists P-002 speaks, and this rule stays silent, so one launch is never scored twice.
/// Severity 60 is below P-002 because missing evidence is weaker than a named parent.
/// </summary>
public sealed class InterpreterFromNonShellRule : IEventRule
{
    public RuleMetadata Metadata { get; } = new(
        "P-001",
        "Shell or interpreter spawned by a non-shell parent",
        60,
        EvidenceCategory.Process,
        ["T1059"],
        "A command interpreter belongs to the monitored tree but no process record explains who started it, so its arguments were not typed by the user and the creating parent is unknown.",
        BaseConfidence: 0.70);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind != EventKind.ProcessStart)
        {
            yield break;
        }

        var child = ProcessNames.Normalize(current.ImageName ?? current.ImagePath);
        if (!ProcessNames.IsOneOf(child, ProcessNames.Interpreters))
        {
            yield break;
        }

        // Attribution the sensor could not make: the process is in the tree by location alone.
        if (current.Scope != ProcessScopeState.Unconfirmed)
        {
            yield break;
        }

        // A recorded creator means P-002 owns this launch. Yielding here is what keeps the two rules
        // disjoint, so a shell is never reported as two independent findings.
        if (current.ParentPid is { } parentPid && context.Processes.TryGet(parentPid, out _))
        {
            yield break;
        }

        var arguments = ShortArguments(current.CommandLine);
        var creator = current.ParentPid is { } recorded
            ? $"PID {recorded}, which never appeared in the process table"
            : "no recorded parent";

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = arguments.Length > 0
                ? $"{ProcessNames.Display(child)} (PID {current.Pid}) ran with arguments \"{arguments}\" and belongs to the monitored tree, but it was not started by any observed parent ({creator}). An interpreter that the application's tree produced without a visible creator ran commands nobody typed."
                : $"{ProcessNames.Display(child)} (PID {current.Pid}) belongs to the monitored tree, but it was not started by any observed parent ({creator}). An interpreter that the application's tree produced without a visible creator ran commands nobody typed.",
            Counterfactual = "Would not fire when the creator was observed — a named non-shell parent is P-002's finding at a higher severity, so this rule stands aside rather than scoring the same launch twice. Would not fire for a process attributed by an observed parent chain, or for an image in a shared directory such as System32, where location alone does not place it in the tree.",
            Factors =
            [
                $"child={child}",
                $"pid={current.Pid}",
                $"parent_pid={current.ParentPid}",
                $"scope_reason={current.ScopeReason ?? "unconfirmed"}",
                $"arguments={arguments}",
                $"basis=no-observed-creator",
            ],
            TargetPid = current.Pid,
            GroupPid = context.RootPid,
            Target = current.CommandLine,
        };
    }

    private static string ShortArguments(string? commandLine) =>
        string.IsNullOrWhiteSpace(commandLine)
            ? string.Empty
            : commandLine.Length <= 160 ? commandLine : commandLine[..160] + "…";
}
