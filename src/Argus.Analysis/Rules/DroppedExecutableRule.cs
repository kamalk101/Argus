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

        if (IsInterpreterScratch(context, pathKey))
        {
            yield break;
        }

        if (IsCompilerCache(pathKey, extension))
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

    /// <summary>
    /// PowerShell touches <c>%TEMP%\__PSScriptPolicyTest_&lt;random&gt;.ps1</c> (and a
    /// <c>.psm1</c> companion) on every invocation while it probes execution policy.
    /// Measured live: a monitored <c>cmd.exe /c powershell -NoProfile -Command "Get-Date"</c>
    /// produced one <c>createdOrTruncated</c> create of that file, and this rule reported it,
    /// so a benign one-liner scored Suspicious 19.4 on nothing else. The exclusion is kept
    /// narrow on purpose — the file name must match the interpreter's own scratch pattern,
    /// it must sit in a temp directory, and the process writing it must itself be a PowerShell
    /// host — so a payload dropped anywhere else, or under any other name, still fires.
    /// </summary>
    private static bool IsInterpreterScratch(RuleContext context, string pathKey)
    {
        var fileName = PathKey.FileName(pathKey);
        if (!fileName.StartsWith("__PSScriptPolicyTest_", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!pathKey.Contains(@"\temp\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return ProcessNames.IsOneOf(
            ProcessNames.Normalize(context.Processes.ImageNameOf(context.Event.Pid)),
            ProcessNames.PowerShellHosts);
    }

    /// <summary>
    /// The C# compiler server unpacks the analyzers it loads into
    /// <c>%TEMP%\VBCSCompiler\AnalyzerAssemblyLoader\&lt;hash&gt;\&lt;guid&gt;\*.dll</c> on every build.
    /// Measured in the benign corpus (2026-11-09): one `dotnet run` of a console project created
    /// eight such DLLs and this rule reported them, so an ordinary build reached Suspicious 37.1.
    /// Only the DLLs in that cache are excluded — an executable or script dropped in the same
    /// directory still fires, because only a loader cache looks like this.
    /// </summary>
    private static bool IsCompilerCache(string pathKey, string extension) =>
        extension.Equals(".dll", StringComparison.OrdinalIgnoreCase)
        && pathKey.Contains(@"\vbcscompiler\", StringComparison.OrdinalIgnoreCase);
}
