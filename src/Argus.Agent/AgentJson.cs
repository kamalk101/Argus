namespace Argus.Agent;

using System.Text.Json;
using System.Text.Json.Serialization;

public static class AgentJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        WriteIndented = false,
    };

    public static JsonSerializerOptions Pretty { get; } = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        WriteIndented = true,
    };
}

public sealed record StartSessionRequest(string Path, string? Args = null, string? Mode = "launch");

public sealed record SessionStateDto(
    Guid Id,
    string TargetPath,
    int RootPid,
    string Status,
    DateTimeOffset StartedUtc,
    DateTimeOffset? EndedUtc,
    string? Verdict,
    double Score,
    double PeakScore,
    string? DatabasePath,
    string? RecordPath,
    CoverageDto Coverage);

/// <summary>
/// What the sensor could not see, published beside every verdict. A consumer that renders the
/// score without this can present an incomplete session as a clean one.
/// </summary>
public sealed record CoverageDto(bool Complete, int Gaps, IReadOnlyList<string> Reasons, string Statement);

public sealed record DetectionDto(
    string Key,
    string RuleId,
    string Title,
    int Severity,
    double Confidence,
    string Categories,
    int ScopePid,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    int EventCount,
    string Status,
    string Reason,
    string Counterfactual,
    IReadOnlyList<string> Factors,
    IReadOnlyList<string> Mitre,
    IReadOnlyList<long> EvidenceSeq);

public sealed record EventDto(
    long Seq,
    DateTimeOffset TimestampUtc,
    string Kind,
    string Category,
    int Pid,
    int? ParentPid,
    string? ImageName,
    string? ImagePath,
    string? Target,
    string? RemoteIp,
    int? RemotePort,
    string? Protocol,
    string? HostName,
    string Scope,
    string? ScopeReason,
    string Observability,
    double Confidence,
    string Source);

public sealed record ProcessDto(
    int Pid,
    int? ParentPid,
    string? ImageName,
    string? ImagePath,
    string? CommandLine,
    DateTimeOffset StartedUtc,
    string Scope,
    string? ScopeReason);

public sealed record HealthDto(
    string Status,
    string Version,
    bool Elevated,
    int AgentPid,
    string Os,
    bool EtwStarted,
    bool DnsProviderEnabled,
    bool RegistryProviderEnabled,
    bool TcpTableAvailable,
    long EtwLostEvents,
    string? EtwError,
    string? DnsError,
    string? RegistryProviderError,
    MonitorCountersDto? Monitor,
    SessionStateDto? Session);

public sealed record MonitorCountersDto(
    long EventsSeen,
    long EventsForwarded,
    long OutsideScope,
    long SampledReads,
    long ThrottledEvents,
    long ChannelDropped,
    long MappingFailures,
    long ProcessStarts,
    long FileEvents,
    long NetworkEvents,
    long DnsEvents,
    long RegistryEvents,
    bool Throttled);
