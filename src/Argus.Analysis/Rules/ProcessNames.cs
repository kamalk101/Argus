namespace Argus.Analysis.Rules;

/// <summary>
/// Curated name sets. Kept explicit and small so the rules stay readable and the
/// false-positive baseline stays explainable.
/// </summary>
internal static class ProcessNames
{
    /// <summary>Programs that execute other programs by design.</summary>
    public static readonly HashSet<string> Interpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe",
    };

    /// <summary>PowerShell hosts, which write their own execution-policy scratch file.</summary>
    public static readonly HashSet<string> PowerShellHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe",
    };

    /// <summary>
    /// Parents for which spawning an interpreter is ordinary: shells, terminals,
    /// IDEs, installers and service hosts.
    /// </summary>
    public static readonly HashSet<string> ExpectedInterpreterParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "wt.exe",
        "windowsterminal.exe", "devenv.exe", "code.exe", "idea64.exe", "pycharm64.exe",
        "python.exe", "pythonw.exe", "node.exe", "java.exe", "dotnet.exe",
        "msiexec.exe", "setup.exe", "install.exe", "installer.exe", "update.exe",
        "services.exe", "svchost.exe", "taskhostw.exe", "taskeng.exe", "sihost.exe",
        "bash.exe", "wsl.exe", "ssms.exe", "rclone.exe",
    };

    public static string Normalize(string? imageNameOrPath)
    {
        if (string.IsNullOrWhiteSpace(imageNameOrPath))
        {
            return string.Empty;
        }

        var value = imageNameOrPath.Trim();
        var index = value.LastIndexOfAny(['\\', '/']);
        return index < 0 ? value : value[(index + 1)..];
    }

    /// <summary>
    /// True when the reported image name is in <paramref name="names"/>.
    ///
    /// The kernel process provider does not always report the extension: a live capture
    /// of <c>schtasks /query</c> arrived as <c>ImageFileName="schtasks"</c>, and
    /// <c>PING.EXE</c> arrived in full. Comparing the literal name against a set of
    /// "x.exe" names silently missed every child whose name came without it, so both
    /// spellings are accepted.
    /// </summary>
    public static bool IsOneOf(string image, IReadOnlySet<string> names)
    {
        if (string.IsNullOrEmpty(image))
        {
            return false;
        }

        if (names.Contains(image))
        {
            return true;
        }

        return !image.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            && names.Contains(image + ".exe");
    }

    /// <summary>Name for reason text: always with the extension, whichever form arrived.</summary>
    public static string Display(string image) =>
        string.IsNullOrEmpty(image) || image.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? image
            : image + ".exe";
}
