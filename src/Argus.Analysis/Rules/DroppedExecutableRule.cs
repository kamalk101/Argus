namespace Argus.Analysis.Rules;

using Argus.Core.Events;
using Argus.Core.Paths;

/// <summary>
/// F-007: an executable or script payload appeared in a location an application
/// can write to without elevation. Dropping and then running a payload is a
/// standard staging step; on its own it is only suspicious.
/// </summary>
public sealed class DroppedExecutableRule : IEventRule
{
    private static readonly HashSet<string> PayloadExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".lnk",
    };

    private static readonly string[] WritableMarkers =
    [
        @"\temp\", @"\tmp\", @"\downloads\", @"\appdata\local\", @"\appdata\roaming\", @"\public\",
    ];

    public RuleMetadata Metadata { get; } = new(
        "F-007",
        "Executable payload dropped in a writable location",
        50,
        EvidenceCategory.File,
        ["T1105"],
        "An executable or script file was created in a user-writable directory.",
        BaseConfidence: 0.80);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind is not (EventKind.FileCreate or EventKind.FileWrite or EventKind.FileRename))
        {
            yield break;
        }

        if (!FileChangeEvidence.IsContentChange(current))
        {
            // A bare create is create-or-open: opening an existing .cmd/.ps1 in a temp
            // directory is not the same act as dropping one.
            yield break;
        }

        var pathKey = current.PathKey;
        if (string.IsNullOrEmpty(pathKey))
        {
            yield break;
        }

        var extension = PathKey.Extension(pathKey);
        if (!PayloadExtensions.Contains(extension))
        {
            yield break;
        }

        var writable = context.Catalog.TryMatch(pathKey, out var entry)
            && entry.Group is "userdata" or "test";

        if (!writable)
        {
            writable = WritableMarkers.Any(marker => pathKey.Contains(marker, StringComparison.Ordinal));
        }

        if (!writable)
        {
            yield break;
        }

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"The application {FileChangeEvidence.Operation(current.Kind)} {extension} payload \"{PathKey.FileName(pathKey)}\" in a user-writable directory ({PathKey.DirectoryName(pathKey)}).",
            Counterfactual = "Would not fire for a download or installer writing to a user-selected folder only if the extension were not executable, and would not fire for a payload that was only opened (create disposition OPEN_EXISTING) rather than dropped.",
            Factors =
            [
                $"path={pathKey}",
                $"extension={extension}",
                $"writable_location=true",
                $"evidence={FileChangeEvidence.Evidence(current)}",
            ],
            Target = current.Target,
        };
    }
}
