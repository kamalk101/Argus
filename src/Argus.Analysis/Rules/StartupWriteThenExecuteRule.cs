namespace Argus.Analysis.Rules;

using Argus.Core.Events;
using Argus.Core.Paths;

/// <summary>
/// X-002: a file was written into a persistence location, and then that exact file was executed.
///
/// This is the pairing that turns persistence from an intent into an act. Writing `evil.exe` into the
/// Startup folder is worth reporting on its own (F-001); *running that same file* moments later is
/// what proves the write was a payload rather than an installer dropping an icon. Both halves are
/// ordinary alone: installers write to Startup, and programs run.
///
/// The match is on the canonical path, not the file name: `notes.exe` appearing in Startup and a
/// different `notes.exe` running from Program Files must not correlate, or every install would look
/// like this. Severity 85 and two evidence categories, so it reaches the malicious band on the shape
/// alone — which is deliberate, because the act has no benign reading once the paths are equal.
/// </summary>
public sealed class StartupWriteThenExecuteRule : ICorrelatedRule
{
    public static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(120);

    public RuleMetadata Metadata { get; } = new(
        "X-002",
        "Startup write followed by execution of that file",
        85,
        EvidenceCategory.File | EvidenceCategory.Process,
        ["T1547.001"],
        "A file written into a persistence location was then executed, which turns the write into an act rather than an intent.",
        BaseConfidence: 0.85);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind != EventKind.ProcessStart)
        {
            yield break;
        }

        var imagePath = PathKey.Canonicalize(current.ImagePath);
        if (string.IsNullOrEmpty(imagePath))
        {
            // A launch whose path the sensor did not resolve cannot be matched to a write, and
            // guessing by file name is exactly the false positive this rule is built to avoid.
            yield break;
        }

        // The file has to live in a persistence location for this rule to apply at all.
        if (!context.Catalog.TryMatch(imagePath, out var entry)
            || !string.Equals(entry.Group, "persistence", StringComparison.OrdinalIgnoreCase))
        {
            yield break;
        }

        var since = context.Now - CorrelationWindow;
        var recentFiles = context.Correlation.Recent(EventCategory.File, since, context.Now);

        BehaviorEvent? write = null;
        for (var i = recentFiles.Count - 1; i >= 0; i--)
        {
            var candidate = recentFiles[i];
            if (candidate.Kind is not (EventKind.FileCreate or EventKind.FileWrite or EventKind.FileRename)
                || !FileChangeEvidence.IsContentChange(candidate)
                || !string.Equals(candidate.PathKey, imagePath, StringComparison.OrdinalIgnoreCase))
            {
                // A bare create is create-or-open, so it does not prove content was written.
                continue;
            }

            write = candidate;
            break;
        }

        if (write is null)
        {
            yield break;
        }

        var delta = context.Now - write.TimestampUtc;
        var image = ProcessNames.Normalize(current.ImageName ?? imagePath);

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{write.Target} was written into {entry.Label} and then executed as {ProcessNames.Display(image)} (PID {current.Pid}) {delta.TotalSeconds:0.0} s later, so the file that was planted is the file that ran.",
            Counterfactual = "Would not fire if the launched path differs from the written path (only the same canonical file counts, so a same-named program elsewhere does not correlate), if the write was an open of a file that already existed rather than a content change, or if more than 120 seconds passed between them. An installer that writes a helper into Startup and starts it immediately is the benign twin; the finding quotes both paths so the difference is checkable.",
            Factors =
            [
                $"written_path={write.PathKey}",
                $"executed_path={imagePath}",
                $"location={entry.Label}",
                $"write_seq={write.Seq}",
                $"process_seq={current.Seq}",
                $"delta_seconds={delta.TotalSeconds:0.0}",
                $"pid={current.Pid}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.ParentPid,
            Target = imagePath,
        };
    }
}
