namespace Argus.Core.Events;

using Argus.Core.Paths;

/// <summary>
/// Assigns sequence numbers, derives categories and path keys, and applies
/// confidence defaults. Deterministic: the same input sequence always produces
/// the same output, which is what makes replay assertions meaningful.
/// </summary>
public sealed class EventNormalizer
{
    private readonly Guid _sessionId;
    private long _seq;

    public EventNormalizer(Guid sessionId)
    {
        _sessionId = sessionId;
    }

    public long LastSeq => _seq;

    public BehaviorEvent Normalize(RawEvent raw)
    {
        ArgumentNullException.ThrowIfNull(raw);

        var seq = ++_seq;
        var category = EventKinds.CategoryOf(raw.Kind);
        var observability = raw.Observability ?? DefaultObservability(raw.Source);
        var source = raw.Source ?? EventSourceKind.Replay;

        return new BehaviorEvent
        {
            Seq = seq,
            SessionId = _sessionId,
            TimestampUtc = raw.Ts,
            Kind = raw.Kind,
            Category = category,
            Pid = raw.Pid,
            Tid = raw.Tid,
            ParentPid = raw.ParentPid,
            ImageName = raw.ImageName,
            ImagePath = raw.ImagePath,
            CommandLine = raw.CommandLine,
            TargetPid = raw.TargetPid,
            Target = raw.Target,
            PathKey = DerivePathKey(category, raw.Target),
            RemoteIp = raw.RemoteIp,
            RemotePort = raw.RemotePort,
            Protocol = raw.Protocol,
            HostName = raw.HostName,
            DnsStatus = raw.DnsStatus,
            BytesOut = raw.BytesOut,
            BytesIn = raw.BytesIn,
            FileEffect = raw.FileEffect,
            PreviousPath = raw.PreviousPath,
            Detail = raw.Detail,
            Signature = raw.Signature,
            Observability = observability,
            Confidence = raw.Confidence ?? DefaultConfidence(observability),
            Source = source,
        };
    }

    public static Observability DefaultObservability(EventSourceKind? source) => source switch
    {
        EventSourceKind.Simulated or EventSourceKind.Replay => Observability.Direct,
        EventSourceKind.Polling => Observability.Partial,
        EventSourceKind.Wmi => Observability.Partial,
        _ => Observability.Direct,
    };

    public static double DefaultConfidence(Observability observability) => observability switch
    {
        Observability.Direct => 0.90,
        Observability.Partial => 0.70,
        Observability.Inferred => 0.50,
        Observability.Aggregated => 0.60,
        _ => 0.60,
    };

    private static string? DerivePathKey(EventCategory category, string? target)
    {
        if (target is null)
        {
            return null;
        }

        return category is EventCategory.File or EventCategory.Registry
            ? PathKey.Canonicalize(target)
            : null;
    }
}
