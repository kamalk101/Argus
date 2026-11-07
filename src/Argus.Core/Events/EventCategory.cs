using System.Numerics;

namespace Argus.Core.Events;

public enum EventCategory
{
    Process,
    File,
    Registry,
    Network,
    Dns,
    Meta,
}

/// <summary>
/// Independent evidence channels. Corroboration is counted across these, never
/// across repeats of the same channel (see <see cref="Risk.RiskScorer"/>).
/// </summary>
[Flags]
public enum EvidenceCategory
{
    None = 0,
    Process = 1,
    File = 2,
    Registry = 4,
    Network = 8,
    Dns = 16,
}

public static class EventKinds
{
    public static EventCategory CategoryOf(EventKind kind) => kind switch
    {
        EventKind.SessionStart or EventKind.SessionStop or EventKind.MonitorGap => EventCategory.Meta,
        EventKind.ProcessStart or EventKind.ProcessStop or EventKind.ImageLoad => EventCategory.Process,
        EventKind.FileCreate or EventKind.FileWrite or EventKind.FileRead or EventKind.FileDelete
            or EventKind.FileRename => EventCategory.File,
        EventKind.RegistrySetValue or EventKind.RegistryDeleteValue => EventCategory.Registry,
        EventKind.NetConnect or EventKind.NetAccept or EventKind.NetClose or EventKind.NetFlow => EventCategory.Network,
        EventKind.DnsQuery or EventKind.DnsResponse => EventCategory.Dns,
        _ => EventCategory.Meta,
    };
}

public static class EvidenceCategories
{
    public static EvidenceCategory FromEventCategory(EventCategory category) => category switch
    {
        EventCategory.Process => EvidenceCategory.Process,
        EventCategory.File => EvidenceCategory.File,
        EventCategory.Registry => EvidenceCategory.Registry,
        EventCategory.Network => EvidenceCategory.Network,
        EventCategory.Dns => EvidenceCategory.Dns,
        _ => EvidenceCategory.None,
    };

    public static int DistinctCount(EvidenceCategory categories) =>
        BitOperations.PopCount((uint)categories);

    /// <summary>Human-readable, stable ordering used in explanations and reports.</summary>
    public static string Describe(EvidenceCategory categories)
    {
        if (categories == EvidenceCategory.None)
        {
            return "none";
        }

        var parts = new List<string>(5);
        if (categories.HasFlag(EvidenceCategory.Process)) parts.Add("process");
        if (categories.HasFlag(EvidenceCategory.File)) parts.Add("file");
        if (categories.HasFlag(EvidenceCategory.Registry)) parts.Add("registry");
        if (categories.HasFlag(EvidenceCategory.Network)) parts.Add("network");
        if (categories.HasFlag(EvidenceCategory.Dns)) parts.Add("dns");
        return string.Join(", ", parts);
    }
}
