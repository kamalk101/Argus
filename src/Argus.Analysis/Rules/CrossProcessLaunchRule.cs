namespace Argus.Analysis.Rules;

using Argus.Core.Events;
using Argus.Core.Sessions;

/// <summary>
/// P-008: a process lives in the application's own directory without the application having created it.
///
/// This is the observable footprint of remote-thread or cross-process creation. The sensor cannot see
/// <c>CreateRemoteThread</c> or an <c>APC</c> injection directly — the kernel provider the monitor
/// enables has no thread-injection keyword, and the product says so in its own limitations ("injection
/// indicators are inferred") — so the rule reads what the scope tracker can prove instead.
///
/// The pipeline marks a process <see cref="ProcessScopeState.Unconfirmed"/> when its image sits under the
/// root application's directory but no observed parent link explains how it got there. For a single-tenant
/// application directory that is a real contradiction: the image is the application's own code, yet no
/// link from the application to it was ever observed. Established injection named it.
///
/// Interpreters are excluded: an unattributed shell is <see cref="InterpreterFromNonShellRule"/>'s
/// finding, which says more about the act than a bare attribution gap does.
///
/// Confidence is 0.60 and the finding is labelled inferred, because benign explanations exist: the parent
/// exited before its start was captured, so the link was lost rather than absent. Severity 65 keeps the
/// claim below the behavioural process rules that see the act itself.
/// </summary>
public sealed class CrossProcessLaunchRule : IEventRule
{
    public RuleMetadata Metadata { get; } = new(
        "P-008",
        "Process in the application's directory with no observed creator",
        65,
        EvidenceCategory.Process,
        ["T1055"],
        "A process image inside the application's own directory appeared without any observed parent link to the application, which is the shape of remote-thread or cross-process creation.",
        BaseConfidence: 0.60);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind != EventKind.ProcessStart)
        {
            yield break;
        }

        // The root is the user's own launch; only an unattributed sibling is a contradiction.
        if (current.Pid == context.RootPid || current.Scope != ProcessScopeState.Unconfirmed)
        {
            yield break;
        }

        var image = ProcessNames.Normalize(current.ImageName ?? current.ImagePath);
        if (string.IsNullOrEmpty(image))
        {
            yield break;
        }

        // An interpreter with no observed creator is P-001's finding, which names the act rather than
        // merely the gap. Yielding here keeps the two rules from reporting one launch twice.
        if (ProcessNames.IsOneOf(image, ProcessNames.Interpreters))
        {
            yield break;
        }

        var scopeReason = current.ScopeReason ?? "unconfirmed";

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{ProcessNames.Display(image)} (PID {current.Pid}) was launched from inside the application's own directory, but no parent link to the application was observed for it: the process is attributed by its location alone ({scopeReason}). A process that is the application's own code and yet was not started by it is inferred to have been created from across a process boundary.",
            Counterfactual = "Would not fire when the creator was observed inside the tree, or when the process was launched from a shared directory such as System32 or Program Files, where location proves nothing. The finding is inferred from the process table rather than observed, and a parent that exited before its launch was captured produces the same shape; the reason states which inference was made and keeps the claim at severity 65.",
            Factors =
            [
                $"image={image}",
                $"path={current.ImagePath}",
                $"pid={current.Pid}",
                $"parent_pid={current.ParentPid}",
                $"scope_reason={scopeReason}",
                $"basis=inferred-from-process-table",
            ],
            TargetPid = current.Pid,
            GroupPid = context.RootPid,
            Target = current.ImagePath ?? image,
        };
    }
}
