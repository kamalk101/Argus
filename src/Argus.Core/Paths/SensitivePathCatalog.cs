namespace Argus.Core.Paths;

/// <summary>
/// Catalog of locations worth extra attention (persistence, system integrity,
/// credentials, user data). It is configuration, not a constant: the behaviour
/// simulator points the same catalog at a temporary root so tests never touch a
/// real startup folder.
/// </summary>
public sealed class SensitivePathCatalog
{
    public static readonly string[] KnownGroups = ["persistence", "system", "credentials", "userdata", "test"];

    private readonly List<SensitivePathEntry> _entries;

    public SensitivePathCatalog(IEnumerable<SensitivePathEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        // Longest prefix first so a specific entry always wins over a broader one.
        _entries = [.. entries
            .Where(e => !string.IsNullOrEmpty(e.CanonicalPrefix))
            .OrderByDescending(e => e.CanonicalPrefix.Length)];
    }

    public IReadOnlyList<SensitivePathEntry> Entries => _entries;

    public static SensitivePathCatalog Empty { get; } = new([]);

    /// <summary>Shipped defaults; entries whose environment variable cannot be resolved are skipped.</summary>
    public static SensitivePathCatalog Default(IReadOnlyDictionary<string, string>? environment = null)
    {
        var definitions = new (string Group, string Label, string Path)[]
        {
            ("persistence", "User Startup folder", @"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            ("persistence", "Machine Startup folder", @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),
            ("system", "System32", @"C:\Windows\System32"),
            ("system", "SysWOW64", @"C:\Windows\SysWOW64"),
            ("system", "Kernel drivers", @"C:\Windows\System32\drivers"),
            ("system", "Program Files", @"C:\Program Files"),
            ("system", "Program Files (x86)", @"C:\Program Files (x86)"),
            ("credentials", "Chrome login data", @"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"),
            ("credentials", "Windows credentials", @"%APPDATA%\Microsoft\Credentials"),
            ("credentials", "User SSH keys", @"%USERPROFILE%\.ssh"),
            ("userdata", "Documents", @"%USERPROFILE%\Documents"),
            ("userdata", "Desktop", @"%USERPROFILE%\Desktop"),
            ("userdata", "Downloads", @"%USERPROFILE%\Downloads"),
            ("test", "Replay fixture root", @"C:\argus-test"),
        };

        var entries = new List<SensitivePathEntry>(definitions.Length);
        foreach (var (group, label, template) in definitions)
        {
            var expanded = Expand(template, environment);
            if (expanded is null)
            {
                continue;
            }

            entries.Add(new SensitivePathEntry(group, label, expanded));
        }

        return new SensitivePathCatalog(entries);
    }

    public bool TryMatch(string? canonicalPathKey, out SensitivePathEntry entry)
    {
        entry = null!;
        if (string.IsNullOrEmpty(canonicalPathKey))
        {
            return false;
        }

        foreach (var candidate in _entries)
        {
            if (PathKey.IsUnder(canonicalPathKey, candidate.CanonicalPrefix))
            {
                entry = candidate;
                return true;
            }
        }

        return false;
    }

    public bool TryMatchGroup(string? canonicalPathKey, out SensitivePathEntry entry, out string group)
    {
        if (TryMatch(canonicalPathKey, out entry))
        {
            group = entry.Group;
            return true;
        }

        group = string.Empty;
        return false;
    }

    /// <summary>Expands <c>%VAR%</c> tokens; returns null when any variable is unknown.</summary>
    public static string? Expand(string template, IReadOnlyDictionary<string, string>? environment = null)
    {
        ArgumentNullException.ThrowIfNull(template);

        var result = template;
        var start = result.IndexOf('%');
        while (start >= 0)
        {
            var end = result.IndexOf('%', start + 1);
            if (end < 0)
            {
                return null;
            }

            var name = result[(start + 1)..end];
            string? value = null;
            if (environment is not null && environment.TryGetValue(name, out var fromMap))
            {
                value = fromMap;
            }
            else if (environment is null)
            {
                value = Environment.GetEnvironmentVariable(name);
            }

            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            result = string.Concat(result.AsSpan(0, start), value, result.AsSpan(end + 1));
            start = result.IndexOf('%', start + value.Length);
        }

        return result;
    }
}

public sealed record SensitivePathEntry(string Group, string Label, string Prefix)
{
    public string CanonicalPrefix { get; } = PathKey.Canonicalize(Prefix);
}
