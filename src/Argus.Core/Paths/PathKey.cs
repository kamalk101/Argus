namespace Argus.Core.Paths;

/// <summary>
/// Canonical path form used for every comparison, catalog match and grouping.
/// Windows paths are case-insensitive and separator-inconsistent (ETW reports
/// device paths, the shell reports drive letters), so all comparisons happen on
/// this normalised key and never on the raw string.
/// </summary>
public static class PathKey
{
    /// <summary>
    /// Lower-cases, unifies separators, strips quotes and trailing separators, and
    /// collapses duplicate separators without destroying a UNC prefix.
    /// </summary>
    public static string Canonicalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        var value = path.Trim().Trim('"');
        if (value.Length == 0)
        {
            return string.Empty;
        }

        value = value.Replace('/', '\\');

        var unc = value.StartsWith(@"\\", StringComparison.Ordinal);
        if (unc)
        {
            value = value[2..];
        }

        while (value.Contains(@"\\", StringComparison.Ordinal))
        {
            value = value.Replace(@"\\", @"\", StringComparison.Ordinal);
        }

        if (unc)
        {
            value = @"\\" + value;
        }

        if (value.Length > 1)
        {
            value = value.TrimEnd('\\');
        }

        return value.ToLowerInvariant();
    }

    /// <summary>True when <paramref name="canonicalPath"/> equals or lives below a prefix.</summary>
    public static bool IsUnder(string? canonicalPath, string? canonicalPrefix)
    {
        if (string.IsNullOrEmpty(canonicalPath) || string.IsNullOrEmpty(canonicalPrefix))
        {
            return false;
        }

        // An unresolved dot segment would let "c:\windows\system32\..\..\evil"
        // match a system directory. Such a path is treated as unmatched rather
        // than guessed at.
        if (HasDotSegment(canonicalPath))
        {
            return false;
        }

        if (string.Equals(canonicalPath, canonicalPrefix, StringComparison.Ordinal))
        {
            return true;
        }

        var prefix = canonicalPrefix.EndsWith('\\') ? canonicalPrefix : canonicalPrefix + @"\";
        return canonicalPath.StartsWith(prefix, StringComparison.Ordinal);
    }

    private static bool HasDotSegment(string canonicalPath)
    {
        var span = canonicalPath.AsSpan();
        var start = 0;
        while (start < span.Length)
        {
            var end = span[start..].IndexOf('\\');
            if (end < 0)
            {
                end = span.Length - start;
            }

            var segment = span.Slice(start, end);
            if (segment is ".." or ".")
            {
                return true;
            }

            start += end + 1;
        }

        return false;
    }

    /// <summary>File name without directory, from a canonical key.</summary>
    public static string FileName(string? canonicalPath)
    {
        if (string.IsNullOrEmpty(canonicalPath))
        {
            return string.Empty;
        }

        var index = canonicalPath.LastIndexOf('\\');
        return index < 0 ? canonicalPath : canonicalPath[(index + 1)..];
    }

    /// <summary>Lower-case extension including the dot, or empty.</summary>
    public static string Extension(string? canonicalPath)
    {
        var name = FileName(canonicalPath);
        var index = name.LastIndexOf('.');
        return index <= 0 ? string.Empty : name[index..];
    }

    /// <summary>Directory containing the canonical path (empty when it has no separator).</summary>
    public static string DirectoryName(string? canonicalPath)
    {
        if (string.IsNullOrEmpty(canonicalPath))
        {
            return string.Empty;
        }

        var index = canonicalPath.LastIndexOf('\\');
        return index <= 0 ? string.Empty : canonicalPath[..index];
    }

    /// <summary>
    /// Maps an ETW device path (<c>\Device\HarddiskVolume3\Windows\...</c>) to a
    /// drive-letter path using a caller-supplied map. Unknown volumes are returned
    /// unchanged so the UI can still show what the sensor saw.
    /// </summary>
    public static string FromDevicePath(string path, IReadOnlyDictionary<string, string> volumeMap)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(volumeMap);

        // Longest device name first: \Device\HarddiskVolume1 is a prefix of
        // \Device\HarddiskVolume10 and must not win by dictionary order.
        foreach (var (device, drive) in volumeMap.OrderByDescending(pair => pair.Key.Length))
        {
            if (path.StartsWith(device, StringComparison.OrdinalIgnoreCase))
            {
                return drive.TrimEnd('\\') + path[device.Length..];
            }
        }

        return path;
    }
}
