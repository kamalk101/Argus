namespace Argus.Analysis.Rules;

using Argus.Core.Events;
using Argus.Core.Paths;

/// <summary>
/// F-006: destructive renaming with an appended marker — the shape of an encryptor.
///
/// The other file rules count one thing at an intensity. This one counts a *pattern*: many
/// files being renamed to a name that still starts with the old one but ends in something
/// else ("report.docx" to "report.docx.locked"), spread across many directories. That is what
/// encryption tooling does after it has rewritten a file, and it is not a shape ordinary
/// software produces in bulk: a build, an unpacker, a download or a backup either keeps the
/// extension or works inside one directory.
///
/// What this rule deliberately does **not** claim: deletions. The kernel file subscription
/// used here does not report <c>del</c>/<c>DeleteFile</c> at all (measured: 26 deletions in a
/// live probe produced zero events), so a wiper that only deletes is invisible to this rule
/// and to the sensor. See docs/RULES.md; do not present a quiet F-006 as "no destruction".
/// </summary>
public sealed class DestructiveRenameBurstRule : IEventRule, IWindowedRule
{
    /// <summary>Marker-appending renames within the window that make the pattern worth reporting.</summary>
    private readonly RuleSettings _settings;

    public DestructiveRenameBurstRule(RuleSettings? settings = null) => _settings = settings ?? RuleSettings.Default;

    public int Threshold => _settings.DestructiveRenameCount;

    /// <summary>How many directories must be involved: one folder of renamed files is a batch tool.</summary>
    public int DirectoryThreshold => _settings.DestructiveRenameDirectories;

    public TimeSpan Window => TimeSpan.FromSeconds(_settings.DestructiveRenameWindowSeconds);

    /// <summary>
    /// Extensions that mean "this file was still being written". Renaming
    /// "movie.mp4.part" to "movie.mp4" is how every downloader finishes a file, and it looks
    /// exactly like a marker-appending rename if you only compare names.
    /// </summary>
    private static readonly HashSet<string> Intermediate = new(StringComparer.OrdinalIgnoreCase)
    {
        "part", "partial", "tmp", "temp", "crdownload", "download", "filepart", "opdownload", "!ut",
    };

    public RuleMetadata Metadata { get; } = new(
        "F-006",
        "Destructive rename burst (ransomware shape)",
        85,
        EvidenceCategory.File,
        ["T1486"],
        "Many files were renamed to a new name appended to the original across many directories, the pattern left by encryption tooling.",
        BaseConfidence: 0.85);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind != EventKind.FileRename || !IsMarkerRename(current))
        {
            yield break;
        }

        var since = context.Now - Window;
        var renames = context.Correlation.Recent(
            since,
            context.Now,
            e => e.Kind == EventKind.FileRename && IsMarkerRename(e));

        var count = renames.Count;

        // Fire on each crossing (10, 20, 30 …) rather than on every rename past the
        // threshold, so one detection per escalation step.
        if (count < Threshold || count % Threshold != 0)
        {
            yield break;
        }

        var directories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var suffixes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var workedInPlace = 0;

        foreach (var rename in renames)
        {
            var directory = PathKey.DirectoryName(rename.PathKey ?? string.Empty);
            if (directory.Length > 0)
            {
                directories.Add(directory);
            }

            if (rename.PreviousPath is { } previous
                && string.Equals(
                    PathKey.DirectoryName(rename.PathKey ?? string.Empty),
                    PathKey.DirectoryName(PathKey.Canonicalize(previous)),
                    StringComparison.OrdinalIgnoreCase))
            {
                workedInPlace++;
            }

            var suffix = SuffixOf(rename.PathKey ?? string.Empty, rename.PreviousPath);
            if (suffix.Length > 0)
            {
                suffixes[suffix] = suffixes.GetValueOrDefault(suffix) + 1;
            }
        }

        if (directories.Count < DirectoryThreshold)
        {
            // A single directory of renamed files is a batch renamer or an unpacker. The
            // breadth is part of the shape, so this stays quiet instead of guessing.
            yield break;
        }

        var topSuffix = suffixes.OrderByDescending(pair => pair.Value).ThenBy(pair => pair.Key, StringComparer.Ordinal).FirstOrDefault();
        var latest = PathKey.FileName(current.PathKey ?? string.Empty);

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{count} files were renamed to a name appended to the original in {Window.TotalSeconds:0} s, across {directories.Count} directories, most recently \"{(latest.Length > 0 ? latest : current.Target)}\". Encryption tooling renames what it has rewritten; ordinary software keeps the extension or stays inside one folder.",
            Counterfactual = $"Would not fire below {Threshold} marker-appending renames of files spread over {DirectoryThreshold}+ directories in {Window.TotalSeconds:0} s, does not count a rename that only removes an intermediate extension (.part, .crdownload, .tmp), and cannot see pure deletions at all.",
            Factors =
            [
                $"marker_renames_in_window={count}",
                $"distinct_directories={directories.Count}",
                $"threshold={Threshold}",
                $"window_seconds={(int)Window.TotalSeconds}",
                $"appended_suffix={(topSuffix.Key ?? "unknown")}",
                $"appended_suffix_count={topSuffix.Value}",
                $"renamed_in_place={workedInPlace}",
                $"latest={current.PathKey}",
                $"previous={current.PreviousPath}",
            ],
            TargetPid = current.Pid,
            Target = current.Target,
        };
    }

    /// <summary>
    /// A rename that appends a marker to the existing name, e.g.
    /// <c>report.docx</c> to <c>report.docx.locked</c>.
    /// </summary>
    internal static bool IsMarkerRename(BehaviorEvent rename)
    {
        if (rename.Kind != EventKind.FileRename || string.IsNullOrEmpty(rename.PathKey) || string.IsNullOrEmpty(rename.PreviousPath))
        {
            return false;
        }

        var previous = PathKey.Canonicalize(rename.PreviousPath);
        var current = rename.PathKey;

        var previousExtension = PathKey.Extension(previous).TrimStart('.');
        if (Intermediate.Contains(previousExtension))
        {
            // "x.part" to "x" is a finished download, not encryption.
            return false;
        }

        var previousName = PathKey.FileName(previous);
        var currentName = PathKey.FileName(current);

        return previousName.Length > 0
            && currentName.Length > previousName.Length
            && currentName.StartsWith(previousName, StringComparison.OrdinalIgnoreCase);
    }

    private static string SuffixOf(string currentPathKey, string? previousPath)
    {
        if (string.IsNullOrEmpty(previousPath))
        {
            return string.Empty;
        }

        var previousName = PathKey.FileName(PathKey.Canonicalize(previousPath));
        var currentName = PathKey.FileName(currentPathKey);
        return currentName.StartsWith(previousName, StringComparison.OrdinalIgnoreCase)
            ? currentName[previousName.Length..].TrimStart('.')
            : string.Empty;
    }
}
