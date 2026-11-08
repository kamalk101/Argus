namespace Argus.Core.Events;

/// <summary>
/// What the OS could establish about the Authenticode chain of a launched image.
///
/// This is deliberately three-way rather than a boolean. A file with no publisher is not the same
/// finding as a file whose signature is present but forged, and neither is a file the sensor could
/// not inspect at all — a protected process, or a path that vanished before it was read. The
/// difference matters because "unsigned" is the suspicious state and "unknown" must never be
/// reported as if it were evidence.
/// </summary>
public enum SignatureStatus
{
    /// <summary>The sensor did not establish a trust result; never treat as unsigned.</summary>
    Unknown,

    /// <summary>A publisher certificate chained to a trusted root.</summary>
    Valid,

    /// <summary>Present but not trusted: unsigned by a publisher, or the chain did not verify.</summary>
    Invalid,
}

public static class SignatureStatuses
{
    public static string Describe(SignatureStatus status) => status switch
    {
        SignatureStatus.Valid => "a valid publisher signature",
        SignatureStatus.Invalid => "no trusted publisher signature",
        _ => "a signature state the sensor could not establish",
    };
}
