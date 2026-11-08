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
/// Matching is on the canonical path where the sensor resolved one, not the file name: `notes.exe`
/// appearing in Startup and a different `notes.exe` running from Program Files must not correlate,
/// or every install would look like this.
///
/// **But the path is frequently unavailable, and requiring it made the rule miss the real thing.**
/// Measured live: a payload started from Startup arrived as <c>observability=partial</c> with
/// <c>imagePath=null</c>, because the kernel process-start record names only the image and the
/// metadata lookup lost the race with a process that exits in milliseconds. Payloads are short-lived
/// by nature, so that is the common case, not the edge. When the path is unknown the rule falls back
/// to a weaker but still specific match — the launched image name equals the written file's name
/// **and** the process that started it is the process that wrote it — and records which basis was
/// used so the evidence panel cannot present an inference as a path equality.
///
/// Severity 85 and two evidence categories, so it reaches the malicious band on the shape alone,
/// which is deliberate: the act has no benign reading once the file is identified.
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
        var image = ProcessNames.Normalize(current.ImageName ?? imagePath);
        if (string.IsNullOrEmpty(image))
        {
            yield break;
        }

        // Cheap exit when the sensor did resolve a path and it is not a persistence location.
        if (!string.IsNullOrEmpty(imagePath)
            && (!context.Catalog.TryMatch(imagePath, out var known)
                || !string.Equals(known.Group, "persistence", StringComparison.OrdinalIgnoreCase)))
        {
            yield break;
        }

        var since = context.Now - CorrelationWindow;
        var recentFiles = context.Correlation.Recent(EventCategory.File, since, context.Now);

        BehaviorEvent? write = null;
        string? matchBasis = null;
        SensitivePathEntry? entry = null;

        for (var i = recentFiles.Count - 1; i >= 0; i--)
        {
            var candidate = recentFiles[i];
            if (candidate.Kind is not (EventKind.FileCreate or EventKind.FileWrite or EventKind.FileRename)
                || !FileChangeEvidence.IsContentChange(candidate)
                || string.IsNullOrEmpty(candidate.PathKey)
                || !context.Catalog.TryMatch(candidate.PathKey, out var candidateEntry)
                || !string.Equals(candidateEntry.Group, "persistence", StringComparison.OrdinalIgnoreCase))
            {
                // A bare create is create-or-open, so it does not prove content was written, and a
                // write somewhere else says nothing about this launch.
                continue;
            }

            if (!string.IsNullOrEmpty(imagePath))
            {
                if (!string.Equals(candidate.PathKey, imagePath, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                write = candidate;
                matchBasis = "path";
                entry = candidateEntry;
                break;
            }

            // No resolved path: the launched image must have the written file's name *and* have been
            // started by the process that wrote it. Name alone would correlate unrelated programs.
            if (!string.Equals(ProcessNames.Normalize(PathKey.FileName(candidate.PathKey)), image, StringComparison.OrdinalIgnoreCase)
                || candidate.Pid != current.ParentPid)
            {
                continue;
            }

            write = candidate;
            matchBasis = "name-and-parent";
            entry = candidateEntry;
            break;
        }

        if (write is null || entry is null || matchBasis is null)
        {
            yield break;
        }

        var delta = context.Now - write.TimestampUtc;
        var basis = matchBasis == "path"
            ? "the same file the sensor watched being written"
            : $"the file named in the write, started by the process that wrote it (no full path was resolved for the launch: PID {current.Pid})";

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{write.Target} was written into {entry.Label} and then executed as {ProcessNames.Display(image)} (PID {current.Pid}) {delta.TotalSeconds:0.0} s later — {basis}. The file that was planted is the file that ran.",
            Counterfactual = "Would not fire if the launched file differs from the written one, if the write was an open of a file that already existed rather than a content change, or if more than 120 seconds passed between them. Where the sensor resolved no path for the launch, the match rests on the image name equalling the written file name and on the writer being the parent, which is why the finding states which basis it used. An installer that writes a helper into Startup and starts it immediately is the benign twin.",
            Factors =
            [
                $"written_path={write.PathKey}",
                $"executed_path={(string.IsNullOrEmpty(imagePath) ? "(unresolved)" : imagePath)}",
                $"executed_image={image}",
                $"match_basis={matchBasis}",
                $"location={entry.Label}",
                $"write_seq={write.Seq}",
                $"process_seq={current.Seq}",
                $"delta_seconds={delta.TotalSeconds:0.0}",
                $"pid={current.Pid}",
                $"writer_pid={write.Pid}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.ParentPid,
            Target = write.PathKey,
        };
    }
}
