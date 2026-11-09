namespace Argus.Agent;

using System.Collections.Concurrent;
using System.Security.Cryptography;

/// <summary>
/// Single-use tickets for the SSE endpoint. <c>EventSource</c> cannot set an <c>Authorization</c>
/// header, and the bearer token must not travel in a URL that ends up in history, a log or a
/// Referer — so the dashboard exchanges its token for a short-lived ticket over an ordinary
/// authorised request and puts only that ticket in the stream URL. A ticket is bound to one session,
/// expires in seconds, and is consumed on first use, so a leaked URL is worth at most one connection
/// to the session it was issued for.
/// </summary>
public sealed class StreamTickets
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<string, (Guid SessionId, DateTimeOffset ExpiresUtc)> _tickets = new(StringComparer.Ordinal);

    public (string Ticket, DateTimeOffset ExpiresUtc) Issue(Guid sessionId)
    {
        Prune();
        var ticket = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        var expires = DateTimeOffset.UtcNow.Add(Lifetime);
        _tickets[ticket] = (sessionId, expires);
        return (ticket, expires);
    }

    /// <summary>Consume a ticket. Returns false for unknown, expired, already used or wrong-session.</summary>
    public bool Consume(string ticket, Guid sessionId)
    {
        if (!_tickets.TryRemove(ticket, out var entry))
        {
            return false;
        }

        return entry.SessionId == sessionId && entry.ExpiresUtc > DateTimeOffset.UtcNow;
    }

    private void Prune()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var (ticket, entry) in _tickets)
        {
            if (entry.ExpiresUtc <= now)
            {
                _tickets.TryRemove(ticket, out _);
            }
        }
    }
}
