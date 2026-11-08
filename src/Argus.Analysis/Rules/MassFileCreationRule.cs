namespace Argus.Analysis.Rules;

using Argus.Core.Events;
using Argus.Core.Paths;

/// <summary>
/// F-004: a burst of file creation. Encrypting ransomware writes thousands of new files
/// in seconds; a dropper unpacks an archive the same way. Volume alone is weak evidence
/// (compilers, package restores, backups), so this rule is deliberately the mildest file
/// rule and reports the measured rate rather than an opinion.
///
/// Counted from the correlation index, never from hidden rule state: replay stays
/// deterministic and the count is the same one the evidence panel can show.
/// </summary>
public sealed class MassFileCreationRule : IEventRule
{
    /// <summary>Creates within the window that make the rate itself worth reporting.</summary>
    public const int Threshold = 200;

    public static readonly TimeSpan Window = TimeSpan.FromSeconds(60);

    public RuleMetadata Metadata { get; } = new(
        "F-004",
        "Mass file creation",
        55,
        EvidenceCategory.File,
        ["T1105", "T1486"],
        "Files were created at a rate consistent with unpacking a payload or encrypting a directory.",
        BaseConfidence: 0.80);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind != EventKind.FileCreate || !FileChangeEvidence.IsContentChange(current))
        {
            // Opens are excluded: a burst of opens is normal scanning, and the rule is
            // about files appearing.
            yield break;
        }

        var since = context.Now - Window;
        var creates = context.Correlation.Recent(
            since,
            context.Now,
            e => e.Kind == EventKind.FileCreate && FileChangeEvidence.IsContentChange(e));

        var count = creates.Count;
        if (count < Threshold || count % Threshold != 0)
        {
            // Fire on each threshold crossing (200, 400, 600 …) instead of on every event
            // past 200: one detection per escalation step, and repeats raise confidence
            // through the normal aggregation path.
            yield break;
        }

        var span = creates.Count > 1
            ? creates[^1].TimestampUtc - creates[0].TimestampUtc
            : TimeSpan.Zero;
        var perSecond = span.TotalSeconds > 0 ? count / span.TotalSeconds : count;
        var directory = PathKey.DirectoryName(current.PathKey);
        var fileName = PathKey.FileName(current.PathKey);

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{count} files were created in {Math.Max(1, (int)Math.Round(Window.TotalSeconds))} s ({perSecond:0} per second), most recently \"{(fileName.Length > 0 ? fileName : current.Target)}\" in {(directory.Length > 0 ? directory : "an unknown directory")}. A user-driven application rarely writes at this rate.",
            Counterfactual = $"Would not fire below {Threshold} content-changing file creates per {Window.TotalSeconds:0} s, and does not fire for file writes to existing files or for opens.",
            Factors =
            [
                $"creates_in_window={count}",
                $"window_seconds={(int)Window.TotalSeconds}",
                $"per_second={perSecond:0.0}",
                $"latest={current.PathKey}",
            ],
            TargetPid = current.Pid,
            Target = current.Target,
        };
    }
}
