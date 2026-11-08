namespace Argus.Core.Events;

/// <summary>
/// Outcome of a name lookup, reduced to the only distinction the analysis layer acts on.
///
/// The resolver reports dozens of codes, and most of them say nothing about whether a name exists:
/// a timeout, a refused query or a server failure are problems with the path to the resolver, not
/// evidence about the name. Collapsing them into "failed" would let a flaky network look like a
/// domain-generation algorithm, so the failure type is kept separate from the non-answer type.
/// </summary>
public enum DnsStatus
{
    /// <summary>The sensor reported no status, or the record carried none.</summary>
    Unknown,

    /// <summary>The name resolved (or the lookup succeeded without an address record).</summary>
    Success,

    /// <summary>The resolver answered authoritatively that the name does not exist (NXDOMAIN).</summary>
    NameDoesNotExist,

    /// <summary>The lookup did not return a usable answer: timeout, refused, server failure, or no records of the requested type. Not evidence about the name.</summary>
    NoAnswer,
}

public static class DnsStatuses
{
    /// <summary>
    /// Windows <c>DNS_QUERY_STATUS</c> codes, plus the textual spellings a manifest provider may
    /// carry. Only the two NXDOMAIN codes map to <see cref="DnsStatus.NameDoesNotExist"/>.
    ///
    /// An unrecognised numeric code becomes <see cref="DnsStatus.Unknown"/>, never
    /// <see cref="DnsStatus.NoAnswer"/>. That is deliberate: the DNS-Client provider reports
    /// <c>QueryStatus=87</c> on every <c>A</c> (QueryType 1) response, including for names that
    /// resolve — measured on this machine, where `example.com` answered with its addresses through
    /// the AAAA query while the A record carried 87 and no results. Treating every non-zero code as
    /// "the lookup did not complete" recorded a false fact for lookups that had in fact succeeded,
    /// and a rule reading it would have been reasoning from a fiction. Only codes whose meaning is
    /// known are mapped; the rest are honestly unknown.
    /// </summary>
    public static DnsStatus Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return DnsStatus.Unknown;
        }

        var text = value.Trim().Trim('"');

        // 9003 is DNS_ERROR_RCODE_NAME_ERROR, the NXDOMAIN code ETW reports as QueryStatus.
        if (text is "9003" or "0x232B" or "0x232b")
        {
            return DnsStatus.NameDoesNotExist;
        }

        switch (text.ToUpperInvariant())
        {
            case "NXDOMAIN":
            case "NAMEERROR":
            case "NAME_ERROR":
            case "DNS_ERROR_RCODE_NAME_ERROR":
                return DnsStatus.NameDoesNotExist;

            case "0":
            case "NOERROR":
            case "SUCCESS":
                return DnsStatus.Success;

            case "1460":    // DNS_ERROR_RCODE_SERVER_FAILURE
            case "9005":    // DNS_ERROR_RCODE_REFUSED
            case "9501":    // DNS_INFO_NO_RECORDS: completed, but no records of that type
            case "TIMEOUT":
            case "REFUSED":
            case "SERVFAIL":
            case "SERVER_FAILURE":
            case "NODATA":
                return DnsStatus.NoAnswer;
        }

        return DnsStatus.Unknown;
    }

    public static string Describe(DnsStatus status) => status switch
    {
        DnsStatus.Success => "the name resolved",
        DnsStatus.NameDoesNotExist => "the name does not exist",
        DnsStatus.NoAnswer => "the lookup did not complete",
        _ => "the lookup result was not reported",
    };
}
