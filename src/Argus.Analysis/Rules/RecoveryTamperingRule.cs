namespace Argus.Analysis.Rules;

using Argus.Core.Events;

/// <summary>
/// P-007: shadow copies or the recovery environment were deleted.
///
/// This is ransomware's last preparation step before encryption: with the shadow copies gone there
/// is nothing to restore from, and with recovery disabled the machine will not offer a repair boot.
/// The rule looks at the command line, never at the mere presence of the tool — backup software calls
/// `vssadmin delete shadows` on a schedule, which is why the reason quotes the arguments and the
/// counterfactual names the case explicitly.
///
/// Severity 80: this is one of very few behaviours with almost no benign story when it appears in a
/// process tree that the user just started.
/// </summary>
public sealed class RecoveryTamperingRule : IEventRule
{
    public RuleMetadata Metadata { get; } = new(
        "P-007",
        "Shadow copy or recovery tampering",
        80,
        EvidenceCategory.Process,
        ["T1490"],
        "The application deleted shadow copies or disabled Windows recovery, which removes the ability to restore files or the system.",
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
        if (string.IsNullOrEmpty(image) || string.IsNullOrWhiteSpace(current.CommandLine))
        {
            yield break;
        }

        var words = Words(current.CommandLine);
        if (!TryDescribe(image, words, out var describes))
        {
            yield break;
        }

        var arguments = current.CommandLine.Length <= 200
            ? current.CommandLine
            : current.CommandLine[..200] + "…";

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{ProcessNames.Display(image)} (PID {current.Pid}) was started with \"{arguments}\", which {describes}.",
            Counterfactual = "Would not fire for a plain `vssadmin list shadows`, for a backup that creates a shadow copy, or for a `bcdedit` query. Backup software does delete shadow copies on a retention schedule; that is why the finding quotes the arguments rather than the tool name.",
            Factors =
            [
                $"image={image}",
                $"effect={describes}",
                $"pid={current.Pid}",
                $"parent_pid={current.ParentPid}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.ParentPid,
            Target = current.CommandLine,
        };
    }

    /// <summary>
    /// Recognises the destructive forms only. Every branch requires the acting verb *and* its object,
    /// so a listing, a query or a create is not caught by substring luck.
    /// </summary>
    public static bool TryDescribe(string image, IReadOnlyList<string> words, out string describes)
    {
        describes = string.Empty;
        var has = (string word) => words.Any(w => string.Equals(w, word, StringComparison.OrdinalIgnoreCase));
        var hasAny = (params string[] candidates) => candidates.Any(has);

        switch (image.ToLowerInvariant())
        {
            case "vssadmin.exe":
            case "vssadmin":
                if (has("delete") && hasAny("shadows", "shadow"))
                {
                    describes = "deletes the volume shadow copies this machine could restore files from";
                    return true;
                }

                return false;

            case "wbadmin.exe":
            case "wbadmin":
                if (has("delete") && hasAny("catalog", "systemstatebackup", "backup"))
                {
                    describes = "deletes the Windows Server backup catalog";
                    return true;
                }

                return false;

            case "bcdedit.exe":
            case "bcdedit":
                // bcdedit /set {default} recoveryenabled No — the argument order is not fixed, and the
                // braces arrive as separate words.
                if (has("set") && hasAny("recoveryenabled", "bootstatuspolicy")
                    && hasAny("no", "ignoreallfailures", "false"))
                {
                    describes = "disables the Windows recovery environment that would offer a repair boot";
                    return true;
                }

                return false;

            case "wmic.exe":
            case "wmic":
                if (has("shadowcopy") && has("delete"))
                {
                    describes = "deletes the volume shadow copies through WMI, the same act as `vssadmin delete shadows`";
                    return true;
                }

                return false;

            default:
                return false;
        }
    }

    /// <summary>
    /// Words with the switch prefix removed, so `delete`, `/delete` and `-delete` are one verb.
    /// Matching the raw word meant `bcdedit /set ...` missed the exact-word check on "set":
    /// fixture 35 reported one finding where it expects two.
    /// </summary>
    private static string[] Words(string commandLine) =>
        [.. commandLine
            .Split([' ', '\t', '"'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(word => word.Length > 1 && (word[0] == '/' || word[0] == '-') ? word[1..] : word)];
}
