namespace Argus.Monitor;

using System.Text.Json;
using Argus.Core.Events;

/// <summary>
/// Polls the TCP owner table and turns new/closed sockets into Partial network
/// events. It is deliberately a repair source: ETW sees short-lived connections
/// this poller cannot, while the owner table fixes ETW attribution when the
/// reporting thread is not the socket owner.
/// </summary>
public sealed class TcpPollingCollector
{
    private readonly Func<int, bool> _isInScope;
    private readonly Action<RawEvent> _emit;
    private readonly TimeSpan _interval;
    private readonly Dictionary<string, TrackedConnection> _seen = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private bool _baselineCaptured;

    public TcpPollingCollector(Func<int, bool> isInScope, Action<RawEvent> emit, TimeSpan interval)
    {
        _isInScope = isInScope;
        _emit = emit;
        _interval = interval;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_interval);
        do
        {
            try
            {
                Poll();
            }
            catch (Exception exception) when (exception is InvalidOperationException or ArgumentException)
            {
                // The table can change underneath the snapshot; next tick retries.
            }
        }
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false));
    }

    public void Poll()
    {
        IReadOnlyList<TcpConnection> connections;
        try
        {
            connections = TcpTableReader.Read();
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        var present = new HashSet<string>(StringComparer.Ordinal);

        lock (_gate)
        {
            foreach (var connection in connections)
            {
                if (!_isInScope(connection.Pid))
                {
                    continue;
                }

                var key = KeyOf(connection);
                present.Add(key);

                if (_seen.TryGetValue(key, out var tracked))
                {
                    tracked.LastSeenUtc = now;
                    continue;
                }

                _seen[key] = new TrackedConnection(connection, now);
                _emit(new RawEvent
                {
                    Ts = now,
                    Kind = EventKind.NetConnect,
                    Pid = connection.Pid,
                    RemoteIp = connection.RemoteAddress,
                    RemotePort = connection.RemotePort,
                    Protocol = "tcp",
                    Detail = JsonSerializer.Serialize(new Dictionary<string, string>
                    {
                        ["localIp"] = connection.LocalAddress,
                        ["localPort"] = connection.LocalPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        ["family"] = connection.AddressFamily,
                        ["state"] = connection.State.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        ["attribution"] = "tcp-owner-table",
                        ["preexisting"] = (!_baselineCaptured).ToString(),
                    }),
                    Observability = Observability.Partial,
                    Source = EventSourceKind.Polling,
                });
            }

            _baselineCaptured = true;

            foreach (var (key, tracked) in _seen.ToArray())
            {
                if (present.Contains(key)
                    || now - tracked.LastSeenUtc < _interval + TimeSpan.FromSeconds(2))
                {
                    continue;
                }

                _seen.Remove(key);
                _emit(new RawEvent
                {
                    Ts = now,
                    Kind = EventKind.NetClose,
                    Pid = tracked.Connection.Pid,
                    RemoteIp = tracked.Connection.RemoteAddress,
                    RemotePort = tracked.Connection.RemotePort,
                    Protocol = "tcp",
                    Observability = Observability.Partial,
                    Source = EventSourceKind.Polling,
                });
            }
        }
    }

    private static string KeyOf(TcpConnection connection) =>
        string.Concat(
            connection.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture), "|",
            connection.LocalAddress, "|",
            connection.LocalPort.ToString(System.Globalization.CultureInfo.InvariantCulture), "|",
            connection.RemoteAddress, "|",
            connection.RemotePort.ToString(System.Globalization.CultureInfo.InvariantCulture), "|",
            connection.AddressFamily);

    private sealed class TrackedConnection(TcpConnection connection, DateTimeOffset firstSeenUtc)
    {
        public TcpConnection Connection { get; } = connection;

        public DateTimeOffset FirstSeenUtc { get; } = firstSeenUtc;

        public DateTimeOffset LastSeenUtc { get; set; } = firstSeenUtc;
    }
}
