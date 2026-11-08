namespace Argus.Analysis.Rules;

using Argus.Core.Events;

/// <summary>
/// P-005: a program launched inside the tree has no trusted publisher signature.
///
/// Unsigned is not malicious — half the small utilities on a workstation are unsigned — so this rule
/// is deliberately the quietest process signal in the catalogue (severity 30). What it contributes is
/// independence: it says nothing about behaviour, only about provenance, so when it appears next to a
/// behavioural rule the corroboration is real rather than a second reading of the same event.
///
/// It fires only on <see cref="SignatureStatus.Invalid"/>. A launch whose signature the sensor could
/// not establish is not evidence of anything, and treating "unknown" as "unsigned" would accuse every
/// protected process and every binary that exited before it could be read.
/// </summary>
public sealed class UnsignedImageRule : IEventRule
{
    public RuleMetadata Metadata { get; } = new(
        "P-005",
        "Unsigned image launched in the monitored tree",
        30,
        EvidenceCategory.Process,
        ["T1553"],
        "A program started inside the monitored tree whose Authenticode chain does not lead to a trusted publisher.",
        BaseConfidence: 0.70);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind != EventKind.ProcessStart)
        {
            yield break;
        }

        // A root process the user deliberately started is their choice, not an indicator.
        if (current.Pid == context.RootPid)
        {
            yield break;
        }

        if (current.Signature != SignatureStatus.Invalid)
        {
            yield break;
        }

        var image = ProcessNames.Normalize(current.ImageName ?? current.ImagePath);
        if (string.IsNullOrEmpty(image))
        {
            yield break;
        }

        // Software the operating system ships is signed by design; if the chain did not verify for
        // something in System32, the sensor misread it rather than the binary being forged.
        var pathKey = current.ImagePath ?? string.Empty;
        if (pathKey.Contains(@"\windows\system32\", StringComparison.OrdinalIgnoreCase)
            || pathKey.Contains(@"\windows\syswow64\", StringComparison.OrdinalIgnoreCase))
        {
            yield break;
        }

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{ProcessNames.Display(image)} (PID {current.Pid}) was started with {SignatureStatuses.Describe(current.Signature.Value)}, so nothing ties this binary to a publisher who could be held responsible for it.",
            Counterfactual = "Would not fire for a binary whose signature chains to a trusted publisher, nor for one whose signature state the sensor could not establish — unknown provenance is not evidence. Unsigned utilities, in-house tools and freshly compiled builds legitimately land here; the severity is low because provenance alone does not indicate intent.",
            Factors =
            [
                $"image={image}",
                $"path={current.ImagePath}",
                $"signature={current.Signature.Value}",
                $"pid={current.Pid}",
                $"parent_pid={current.ParentPid}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.ParentPid,
            Target = current.ImagePath ?? image,
        };
    }
}
