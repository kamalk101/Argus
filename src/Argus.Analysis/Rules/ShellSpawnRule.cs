namespace Argus.Analysis.Rules;

using Argus.Core.Events;

/// <summary>
/// P-002: an application that is not a shell, terminal, IDE, installer or service
/// host spawned a command interpreter. This is the canonical "unexpected command
/// execution" signal.
/// </summary>
public sealed class ShellSpawnRule : IEventRule
{
    public RuleMetadata Metadata { get; } = new(
        "P-002",
        "Unexpected command interpreter",
        85,
        EvidenceCategory.Process,
        ["T1059"],
        "A non-shell parent process spawned a command interpreter.",
        BaseConfidence: 0.90);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind != EventKind.ProcessStart)
        {
            yield break;
        }

        var child = ProcessNames.Normalize(current.ImageName ?? current.ImagePath);
        if (string.IsNullOrEmpty(child) || !ProcessNames.Interpreters.Contains(child))
        {
            yield break;
        }

        if (current.ParentPid is not { } parentPid)
        {
            yield break;
        }

        if (!context.Processes.TryGet(parentPid, out var parent))
        {
            // Without a parent record the relationship is unproven; report it as
            // inferred rather than claiming something the sensor did not see.
            yield break;
        }

        var parentName = ProcessNames.Normalize(parent.ImageName ?? parent.ImagePath);
        if (string.IsNullOrEmpty(parentName) || ProcessNames.ExpectedInterpreterParents.Contains(parentName))
        {
            yield break;
        }

        if (string.Equals(parentName, child, StringComparison.OrdinalIgnoreCase))
        {
            yield break;
        }

        var arguments = ShortArguments(current.CommandLine);
        var reason = arguments.Length > 0
            ? $"{parentName} (PID {parent.Pid}), which is not a shell, terminal, IDE, installer or service host, spawned {child} (PID {current.Pid}) with arguments \"{arguments}\"."
            : $"{parentName} (PID {parent.Pid}), which is not a shell, terminal, IDE, installer or service host, spawned {child} (PID {current.Pid}).";

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = reason,
            Counterfactual = "Would not fire if the child were a signed GUI application, or if the parent were a shell, terminal, IDE, installer or service host.",
            Factors =
            [
                $"parent={parentName}",
                $"child={child}",
                $"pid={current.Pid}",
                $"arguments={arguments}",
            ],
            TargetPid = current.Pid,
            GroupPid = parentPid,
            Target = current.CommandLine,
        };
    }

    private static string ShortArguments(string? commandLine) =>
        string.IsNullOrWhiteSpace(commandLine)
            ? string.Empty
            : commandLine.Length <= 160 ? commandLine : commandLine[..160] + "…";
}
