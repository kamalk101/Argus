namespace Argus.Analysis.Rules;

using Argus.Core.Events;
using Argus.Core.Paths;

/// <summary>
/// P-004: an executable was launched from a directory anything running as the user can write to.
///
/// The signal is the location, not the binary: a program started out of `%TEMP%`, `Downloads` or
/// `%APPDATA%` is either something the user just received or something that unpacked itself there,
/// and neither is how installed software normally starts. It is deliberately mild (severity 45)
/// because plenty of legitimate software does exactly this — updaters, portable apps, installers
/// that stage a helper in temp — and because the same act is already reported from the file side by
/// `F-007` when the payload first appears.
///
/// Matched by path shape rather than through the catalog: the catalog's replay entries skip
/// `%APPDATA%`/`%USERPROFILE%` for determinism (see `F-008`), and the fixture root `C:\argus-test`
/// must not count as user-writable or every fixture would fire.
/// </summary>
public sealed class UserWritableLaunchRule : IEventRule
{
    private static readonly string[] WritableMarkers =
    [
        @"\temp\", @"\tmp\", @"\downloads\", @"\appdata\local\", @"\appdata\roaming\",
        @"\users\public\", @"\inetcache\", @"\d3dscache\",
    ];

    /// <summary>Images that are executable payloads rather than data files opened by a handler.</summary>
    private static readonly HashSet<string> LaunchableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".pif",
    };

    public RuleMetadata Metadata { get; } = new(
        "P-004",
        "Executable launched from a user-writable directory",
        45,
        EvidenceCategory.Process,
        ["T1204"],
        "A process started from a directory any program running as the user can write to, such as a temporary or download folder.",
        BaseConfidence: 0.75);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind != EventKind.ProcessStart)
        {
            yield break;
        }

        var pathKey = PathKey.Canonicalize(current.ImagePath);
        if (string.IsNullOrEmpty(pathKey) || !pathKey.Contains('\\'))
        {
            // A bare image name says nothing about where the image lives; guessing a location would
            // turn this rule into "some process started".
            yield break;
        }

        if (!LaunchableExtensions.Contains(PathKey.Extension(pathKey)))
        {
            yield break;
        }

        var marker = Array.Find(WritableMarkers, m => pathKey.Contains(m, StringComparison.Ordinal));
        if (marker is null)
        {
            yield break;
        }

        var image = ProcessNames.Normalize(current.ImageName ?? pathKey);
        var location = WritableLocation(marker);

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{ProcessNames.Display(image)} (PID {current.Pid}) was launched from {location}: \"{current.ImagePath}\", a directory any program running as the user can write to.",
            Counterfactual = "Would not fire if the image were started from its installed directory (Program Files, System32 or the user's own program folder). Updaters, portable applications and installers that stage a helper in a temporary directory legitimately do this, which is why the severity is low and the finding is about the location only.",
            Factors =
            [
                $"image={image}",
                $"path={current.ImagePath}",
                $"location={location}",
                $"parent_pid={current.ParentPid}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.ParentPid,
            Target = current.ImagePath,
        };
    }

    private static string WritableLocation(string marker) => marker switch
    {
        @"\temp\" or @"\tmp\" => "a temporary directory",
        @"\downloads\" => "a downloads directory",
        @"\appdata\local\" => "the local application-data directory",
        @"\appdata\roaming\" => "the roaming application-data directory",
        @"\users\public\" => "the public user directory",
        _ => "a browser or shader cache directory",
    };
}
