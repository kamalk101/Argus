namespace Argus.Analysis.Rules;

using Argus.Core.Events;

/// <summary>
/// P-006: the same program was started again and again with different switches.
///
/// That is what a discovery script looks like from the process side: one binary, many invocations,
/// a different switch each time — `net /user`, `net /group`, `net /share`. A person opening an
/// application twice does not change the switches, and a program that legitimately takes switches
/// (a package manager, an installer) usually varies arguments *and* subcommands rather than cycling
/// through short flags.
///
/// Severity 25 and counted from the correlation index, so replay reproduces the verdict. Interpreters
/// are excluded: `cmd.exe /c …` appears constantly in ordinary sessions and is already covered by
/// P-002, which says something much more specific about it.
/// </summary>
public sealed class RepeatedFlagsRule : IEventRule, IWindowedRule
{
    private readonly RuleSettings _settings;

    public RepeatedFlagsRule(RuleSettings? settings = null) => _settings = settings ?? RuleSettings.Default;

    public TimeSpan Window => TimeSpan.FromSeconds(_settings.RepeatedFlagsWindowSeconds);

    /// <summary>Distinct switches on one image before the pattern is worth mentioning.</summary>
    public int Threshold => _settings.RepeatedFlagsThreshold;

    public RuleMetadata Metadata { get; } = new(
        "P-006",
        "Repeated launches of one program with different switches",
        25,
        EvidenceCategory.Process,
        ["T1082"],
        "One program was started repeatedly with a different command-line switch each time, the shape of a script enumerating information.",
        BaseConfidence: 0.60);

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (current.Kind != EventKind.ProcessStart)
        {
            yield break;
        }

        var image = ProcessNames.Normalize(current.ImageName ?? current.ImagePath);
        if (string.IsNullOrEmpty(image) || ProcessNames.IsOneOf(image, ProcessNames.Interpreters))
        {
            yield break;
        }

        var currentFlags = ExtractFlags(current.CommandLine);
        if (currentFlags.Length == 0)
        {
            // A launch without switches adds nothing to a count of switches.
            yield break;
        }

        // A process started by a copy of itself with a switch is how multi-process applications are
        // built, not how information is enumerated. Measured in the benign corpus (2026-11-09):
        // chrome.exe spawning chrome.exe --type=renderer/gpu-process/utility produced four findings
        // in one 25 s session, and the Electron IDE did the same twice. Distinct-parent launches
        // (the discovery shape this rule is for) are unaffected.
        if (current.ParentPid is { } parentPid
            && context.Processes.TryGet(parentPid, out var parent)
            && string.Equals(
                ProcessNames.Normalize(parent.ImageName ?? parent.ImagePath),
                image,
                StringComparison.OrdinalIgnoreCase))
        {
            yield break;
        }

        var since = context.Now - Window;
        var earlier = context.Correlation.Recent(
            since,
            context.Now,
            e => e.Kind == EventKind.ProcessStart
                && e.Pid != current.Pid
                && string.Equals(ProcessNames.Normalize(e.ImageName ?? e.ImagePath), image, StringComparison.OrdinalIgnoreCase));

        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in earlier)
        {
            foreach (var flag in ExtractFlags(candidate.CommandLine))
            {
                flags.Add(flag);
            }
        }

        var before = flags.Count;
        foreach (var flag in currentFlags)
        {
            flags.Add(flag);
        }

        var distinct = flags.Count;

        // Two conditions, because either alone is ordinary. One tool used twice with proper arguments
        // (`schtasks /query /fo LIST`, then `/delete /tn … /f`) reaches five switches without being
        // discovery — that is what fixture 20 is for. Enumeration is the same tool used again and
        // again, each time with a different switch.
        var launches = earlier.Count + 1;
        if (launches < Threshold)
        {
            yield break;
        }

        // Fire when the distinct count crosses a multiple of the threshold (3, 6, 9 …): one
        // detection per escalation step, not one per invocation.
        if (distinct / Threshold == before / Threshold)
        {
            yield break;
        }

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"{ProcessNames.Display(image)} was started {launches} times in {Window.TotalSeconds:0} s with {distinct} different switches between them ({string.Join(", ", flags.OrderBy(f => f, StringComparer.Ordinal).Take(6))}), which is how a script enumerates information rather than how a person uses a program.",
            Counterfactual = $"Would not fire below {Threshold} launches of one image carrying {Threshold} distinct switches within {Window.TotalSeconds:0} s, does not count launches without switches, and excludes command interpreters, whose switches are covered by P-002.",
            Factors =
            [
                $"image={image}",
                $"launches={launches}",
                $"distinct_flags={distinct}",
                $"threshold={Threshold}",
                $"window_seconds={(int)Window.TotalSeconds}",
                $"flags={string.Join(",", flags.OrderBy(f => f, StringComparer.Ordinal))}",
                $"latest_flag={currentFlags[0]}",
            ],
            TargetPid = current.Pid,
            GroupPid = current.Pid,
            Target = current.CommandLine,
        };
    }

    /// <summary>
    /// Switches in the two Windows spellings (`/name`, `-name`) plus the Unix one (`--name`), without
    /// the value: `net /user:foo` and `net /user:bar` are the same switch used twice.
    /// </summary>
    public static string[] ExtractFlags(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return [];
        }

        var flags = new List<string>();
        foreach (var word in commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var token = word.Trim('"', '\'');
            var prefixLength = token.StartsWith("--", StringComparison.Ordinal) ? 2
                : token.Length > 1 && (token[0] == '/' || token[0] == '-') ? 1
                : 0;

            if (prefixLength == 0 || token.Length == prefixLength)
            {
                continue;
            }

            var name = token[prefixLength..];
            var separator = name.IndexOfAny([':', '=']);
            if (separator > 0)
            {
                name = name[..separator];
            }

            if (name.Length == 0 || name.All(char.IsDigit))
            {
                // `/2` in `schtasks /run /2` is not a switch name worth counting as discovery.
                continue;
            }

            if (!flags.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                flags.Add(name);
            }
        }

        return [.. flags];
    }
}
