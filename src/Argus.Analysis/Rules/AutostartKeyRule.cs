namespace Argus.Analysis.Rules;

using System.Text.RegularExpressions;
using Argus.Core.Events;

/// <summary>
/// F-002: an autostart registry value was written. Windows executes values under
/// <c>CurrentVersion\Run</c> and its variants at every sign-in, so a program that
/// adds one has arranged to run again without the user asking.
///
/// Two observations back this, both direct:
/// <list type="bullet">
/// <item>the registry write itself (kernel registry events), when the sensor delivers it;</item>
/// <item>a <c>reg.exe add|import</c> launch whose arguments name such a key. That is the
/// command line, not a guess about what the command did — the finding says so.</item>
/// </list>
///
/// The channel is Registry because the finding is about a registry autostart value.
/// A detection that is only a command line does not claim the value exists; the
/// factor <c>evidence=command-line</c> keeps that distinction visible.
/// </summary>
public sealed partial class AutostartKeyRule : IEventRule
{
    /// <summary>
    /// Value names under <c>CurrentVersion</c> that Windows runs at sign-in. Matched as
    /// whole segments: <c>runmru</c> (the most-recently-used list) starts with "run" and
    /// must not match.
    /// </summary>
    private static readonly HashSet<string> AutostartValueNames = new(StringComparer.Ordinal)
    {
        "run", "runonce", "runservices", "runonceex", "runservicesonce",
    };

    public RuleMetadata Metadata { get; } = new(
        "F-002",
        "Write to a Run/RunOnce autostart key",
        75,
        EvidenceCategory.Registry,
        ["T1547.001"],
        "A registry value was created or changed under a key Windows executes at sign-in.",
        BaseConfidence: 0.90);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;

        var finding = current.Kind switch
        {
            EventKind.RegistrySetValue or EventKind.RegistryDeleteValue when IsAutostartKey(current.PathKey)
                => FromRegistry(current),
            EventKind.ProcessStart when IsAutostartCommand(current)
                => FromCommandLine(current),
            _ => null,
        };

        if (finding is not null)
        {
            yield return finding;
        }
    }

    private RuleFinding FromRegistry(BehaviorEvent current)
    {
        var verb = current.Kind == EventKind.RegistryDeleteValue ? "deleted" : "created or changed";
        var valueName = KeySuffix(current.PathKey);

        return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"The application {verb} the autostart value \"{valueName}\" under {KeyPath(current.PathKey)} — Windows runs this value at every sign-in.",
            Counterfactual = "Would not fire if the value were written under a key Windows does not execute at sign-in (for example the installer's own product key or the Explorer settings), or if the key were only read.",
            Factors =
            [
                $"operation={current.Kind}",
                $"evidence=registry-write",
                $"key={current.PathKey}",
                $"value={valueName}",
            ],
            TargetPid = current.Pid,
            Target = current.Target,
        };
    }

    private RuleFinding FromCommandLine(BehaviorEvent current)
    {
        var image = ProcessNames.Normalize(current.ImageName ?? current.ImagePath);

        return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{ProcessNames.Display(image)} (PID {current.Pid}) was started with arguments that write an autostart value under {DescribeAutostartTarget(current.CommandLine)} — Windows runs such a value at every sign-in.",
            Counterfactual = "Would not fire for a registry read or delete (`reg query`, `reg delete`), or for a write to a key Windows does not execute at sign-in.",
            Factors =
            [
                $"operation=registry-write",
                $"evidence=command-line",
                $"image={image}",
                $"arguments={Trim(current.CommandLine)}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.ParentPid,
            Target = current.CommandLine,
        };
    }

    private static bool IsAutostartCommand(BehaviorEvent current)
    {
        var image = ProcessNames.Normalize(current.ImageName ?? current.ImagePath);
        if (!image.Equals("reg.exe", StringComparison.OrdinalIgnoreCase)
            && !image.Equals("reg", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var commandLine = current.CommandLine;
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return false;
        }

        if (!WriteVerb().IsMatch(commandLine) || !AutostartArgument().IsMatch(commandLine))
        {
            return false;
        }

        return true;
    }

    private static bool IsAutostartKey(string? canonicalKey)
    {
        if (string.IsNullOrEmpty(canonicalKey))
        {
            return false;
        }

        var segments = canonicalKey.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < segments.Length - 1; i++)
        {
            if (segments[i].Equals("currentversion", StringComparison.Ordinal)
                && AutostartValueNames.Contains(segments[i + 1]))
            {
                return true;
            }
        }

        return false;
    }

    private static string DescribeAutostartTarget(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return "an autostart key";
        }

        var match = AutostartArgument().Match(commandLine);
        return match.Success ? match.Value.Trim('"', ' ') : "an autostart key";
    }

    /// <summary>Key path through the autostart value name, for reason text.</summary>
    private static string KeyPath(string? canonicalKey)
    {
        if (string.IsNullOrEmpty(canonicalKey))
        {
            return string.Empty;
        }

        var segments = canonicalKey.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < segments.Length - 1; i++)
        {
            if (segments[i].Equals("currentversion", StringComparison.Ordinal)
                && AutostartValueNames.Contains(segments[i + 1]))
            {
                // Stop after the autostart segment: everything past it is the value name.
                return "\\" + string.Join('\\', segments[..(i + 2)]);
            }
        }

        return canonicalKey;
    }

    private static string KeySuffix(string? canonicalKey)
    {
        if (string.IsNullOrEmpty(canonicalKey))
        {
            return string.Empty;
        }

        var segments = canonicalKey.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        return segments.Length > 0 ? segments[^1] : canonicalKey;
    }

    private static string Trim(string? value) => value is null
        ? string.Empty
        : value.Length <= 160 ? value : value[..160] + "…";

    [GeneratedRegex(@"\b(add|import)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex WriteVerb();

    /// <summary>
    /// A <c>CurrentVersion\Run</c>-family key inside a command line. The lookahead keeps
    /// <c>RunMRU</c> and other longer names from matching while still accepting
    /// <c>RunOnce</c>, <c>RunOnceEx</c> and <c>RunServices</c> as their own tokens.
    /// </summary>
    [GeneratedRegex(
        @"currentversion[\\/]+(runonceex|runservicesonce|runservices|runonce|run)(?=[\\/""\s]|$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AutostartArgument();
}
