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
        if (!ProcessNames.IsOneOf(child, ProcessNames.Interpreters))
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
        if (string.IsNullOrEmpty(parentName) || ProcessNames.IsOneOf(parentName, ProcessNames.ExpectedInterpreterParents))
        {
            yield break;
        }

        if (IsSignedInstaller(parent, parentName))
        {
            yield break;
        }

        if (string.Equals(parentName, child, StringComparison.OrdinalIgnoreCase))
        {
            yield break;
        }

        var arguments = ShortArguments(current.CommandLine);
        var reason = arguments.Length > 0
            ? $"{ProcessNames.Display(parentName)} (PID {parent.Pid}), which is not a shell, terminal, IDE, installer or service host, spawned {ProcessNames.Display(child)} (PID {current.Pid}) with arguments \"{arguments}\"."
            : $"{ProcessNames.Display(parentName)} (PID {parent.Pid}), which is not a shell, terminal, IDE, installer or service host, spawned {ProcessNames.Display(child)} (PID {current.Pid}).";

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

    /// <summary>
    /// This rule's own description exempts installers and updaters, but a name list cannot: measured
    /// 2026-11-09, the four real installers on the test machine were named <c>ChromeSetup.exe</c>,
    /// <c>Git-2.56.0.4-64-bit.exe</c>, <c>python-3.12.10-amd64.exe</c> and
    /// <c>node-v22.23.4-x64.msi</c>, so only one of them would ever match a fixed set. A signed image
    /// whose name carries an installer or updater marker is the shape a setup program has: it was
    /// verified live that a catalog-signed parent named <c>contoso-setup-x64.exe</c> spawning
    /// PowerShell scored <c>P-002</c> at 85 before this check existed.
    ///
    /// Both halves are required. A name alone is a free pass for malware called <c>setup.exe</c> —
    /// measured live, an unsigned copy with the same name still fires — so only a publisher-verified
    /// image gets the exemption, and installers whose names carry no marker
    /// (<c>Git-2.56.0.4-64-bit.exe</c>) are still reported rather than guessed about.
    /// </summary>
    private static bool IsSignedInstaller(Core.Processes.ProcessRecord parent, string parentName)
    {
        if (parent.Signature != SignatureStatus.Valid)
        {
            return false;
        }

        return ProcessNames.InstallerMarkers.Any(marker =>
            parentName.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }
}
