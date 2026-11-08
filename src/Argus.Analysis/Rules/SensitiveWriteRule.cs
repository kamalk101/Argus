namespace Argus.Analysis.Rules;

using Argus.Core.Events;

/// <summary>
/// Fires when a process writes into a catalogued location. One class, two
/// configured instances (persistence, system integrity): identical logic, distinct
/// metadata, so the reason text can name the risk the location carries.
/// </summary>
public sealed class SensitiveWriteRule : IEventRule
{
    private static readonly HashSet<EventKind> WriteKinds =
    [
        EventKind.FileCreate, EventKind.FileWrite, EventKind.FileRename, EventKind.FileDelete,
    ];

    private static readonly Dictionary<string, string> GroupPurpose = new(StringComparer.OrdinalIgnoreCase)
    {
        ["persistence"] = "a location Windows executes automatically at sign-in",
        ["system"] = "a location that determines system and program integrity",
        ["credentials"] = "credential and secret storage",
        ["userdata"] = "user document storage",
        ["test"] = "the replay fixture root",
    };

    private readonly string _group;

    public SensitiveWriteRule(RuleMetadata metadata, string group)
    {
        Metadata = metadata;
        _group = group;
    }

    public RuleMetadata Metadata { get; }

    public IEnumerable<RuleFinding> Evaluate(RuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = context.Event;
        if (!WriteKinds.Contains(current.Kind) || string.IsNullOrEmpty(current.PathKey))
        {
            yield break;
        }

        if (!FileChangeEvidence.IsContentChange(current))
        {
            // A bare create is create-or-open in ETW: opening a system binary must not
            // read as writing it. See FileChangeEvidence for the reasoning.
            yield break;
        }

        if (!context.Catalog.TryMatch(current.PathKey, out var entry)
            || !string.Equals(entry.Group, _group, StringComparison.OrdinalIgnoreCase))
        {
            yield break;
        }

        var operation = FileChangeEvidence.Operation(current.Kind);

        var purpose = GroupPurpose.TryGetValue(entry.Group, out var text) ? text : "a sensitive location";

        yield return new RuleFinding
        {
            Rule = Metadata,
            Reason = $"The application {operation} {current.Target}, inside {entry.Label} — {purpose}.",
            Counterfactual = $"Would not fire if the path were outside the catalogued {entry.Group} locations, or if the file had only been opened (create disposition OPEN_EXISTING) rather than created or truncated.",
            Factors =
            [
                $"operation={current.Kind}",
                $"evidence={FileChangeEvidence.Evidence(current)}",
                $"path={current.PathKey}",
                $"catalog_group={entry.Group}",
                $"catalog_label={entry.Label}",
            ],
            Target = current.Target,
        };
    }
}
