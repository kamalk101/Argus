namespace Argus.Storage;

using System.Globalization;
using System.Text;
using Argus.Core.Events;
using Argus.Core.Sessions;
using Microsoft.Data.Sqlite;

/// <summary>
/// Event persistence. Writes are batched inside one transaction because the
/// sensor produces thousands of events per second; a per-event transaction would
/// dominate the CPU budget.
/// </summary>
public sealed class EventRepository(SessionDatabase database)
{
    private const string Columns = """
        e.seq, e.ts_utc, e.kind, e.category, e.pid, e.tid, e.parent_pid, e.image_name, e.image_path,
        e.target, e.path_key, e.remote_ip, e.remote_port, e.protocol, e.host_name,
        e.bytes_out, e.bytes_in, e.detail, e.observability, e.confidence, e.source, e.scope_state
        """;

    private readonly SessionDatabase _database = database;

    public int AppendBatch(Guid sessionId, IEnumerable<BehaviorEvent> events)
    {
        ArgumentNullException.ThrowIfNull(events);

        using var connection = _database.Open();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO events (
                session_id, seq, ts_utc, kind, category, pid, tid, parent_pid, image_name, image_path,
                target, path_key, remote_ip, remote_port, protocol, host_name, bytes_out, bytes_in,
                detail, detail_text, observability, confidence, source, scope_state)
            VALUES (
                $session, $seq, $ts, $kind, $category, $pid, $tid, $parent, $image, $imagePath,
                $target, $pathKey, $remoteIp, $remotePort, $protocol, $host, $bytesOut, $bytesIn,
                $detail, $detailText, $observability, $confidence, $source, $scope);
            """;

        foreach (var name in new[]
                 {
                     "$session", "$seq", "$ts", "$kind", "$category", "$pid", "$tid", "$parent",
                     "$image", "$imagePath", "$target", "$pathKey", "$remoteIp", "$remotePort",
                     "$protocol", "$host", "$bytesOut", "$bytesIn", "$detail", "$detailText",
                     "$observability", "$confidence", "$source", "$scope",
                 })
        {
            command.Parameters.AddWithValue(name, DBNull.Value);
        }

        var count = 0;
        foreach (var behaviorEvent in events)
        {
            command.Parameters["$session"].Value = sessionId.ToString();
            command.Parameters["$seq"].Value = behaviorEvent.Seq;
            command.Parameters["$ts"].Value = Db.Text(behaviorEvent.TimestampUtc);
            command.Parameters["$kind"].Value = behaviorEvent.Kind.ToString();
            command.Parameters["$category"].Value = behaviorEvent.Category.ToString();
            command.Parameters["$pid"].Value = behaviorEvent.Pid;
            command.Parameters["$tid"].Value = (object?)behaviorEvent.Tid ?? DBNull.Value;
            command.Parameters["$parent"].Value = (object?)behaviorEvent.ParentPid ?? DBNull.Value;
            command.Parameters["$image"].Value = (object?)behaviorEvent.ImageName ?? DBNull.Value;
            command.Parameters["$imagePath"].Value = (object?)behaviorEvent.ImagePath ?? DBNull.Value;
            command.Parameters["$target"].Value = (object?)behaviorEvent.Target ?? DBNull.Value;
            command.Parameters["$pathKey"].Value = (object?)behaviorEvent.PathKey ?? DBNull.Value;
            command.Parameters["$remoteIp"].Value = (object?)behaviorEvent.RemoteIp ?? DBNull.Value;
            command.Parameters["$remotePort"].Value = (object?)behaviorEvent.RemotePort ?? DBNull.Value;
            command.Parameters["$protocol"].Value = (object?)behaviorEvent.Protocol ?? DBNull.Value;
            command.Parameters["$host"].Value = (object?)behaviorEvent.HostName ?? DBNull.Value;
            command.Parameters["$bytesOut"].Value = (object?)behaviorEvent.BytesOut ?? DBNull.Value;
            command.Parameters["$bytesIn"].Value = (object?)behaviorEvent.BytesIn ?? DBNull.Value;
            command.Parameters["$detail"].Value = (object?)behaviorEvent.Detail ?? DBNull.Value;
            command.Parameters["$detailText"].Value = (object?)BuildDetailText(behaviorEvent) ?? DBNull.Value;
            command.Parameters["$observability"].Value = behaviorEvent.Observability.ToString();
            command.Parameters["$confidence"].Value = behaviorEvent.Confidence;
            command.Parameters["$source"].Value = behaviorEvent.Source.ToString();
            command.Parameters["$scope"].Value = behaviorEvent.Scope.ToString();

            command.ExecuteNonQuery();
            count++;
        }

        transaction.Commit();
        return count;
    }

    public IReadOnlyList<BehaviorEvent> Page(Guid sessionId, EventFilter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);

        var sql = new StringBuilder($"SELECT {Columns} FROM events e WHERE e.session_id = $session");
        using var connection = _database.Open();
        using var command = connection.CreateCommand();

        command.Parameters.AddWithValue("$session", sessionId.ToString());

        if (filter.Category is { } category)
        {
            sql.Append(" AND e.category = $category");
            command.Parameters.AddWithValue("$category", category.ToString());
        }

        if (filter.Kind is { } kind)
        {
            sql.Append(" AND e.kind = $kind");
            command.Parameters.AddWithValue("$kind", kind.ToString());
        }

        if (filter.Pid is { } pid)
        {
            sql.Append(" AND e.pid = $pid");
            command.Parameters.AddWithValue("$pid", pid);
        }

        if (!string.IsNullOrWhiteSpace(filter.Text))
        {
            sql.Append(" AND (e.target LIKE $text OR e.detail LIKE $text OR e.host_name LIKE $text)");
            command.Parameters.AddWithValue("$text", $"%{filter.Text}%");
        }

        if (filter.InScopeOnly)
        {
            sql.Append(" AND e.scope_state IN ('Root', 'Confirmed', 'Unconfirmed')");
        }

        if (filter.AfterSeq is { } afterSeq)
        {
            sql.Append(" AND e.seq > $after");
            command.Parameters.AddWithValue("$after", afterSeq);
        }

        sql.Append(" ORDER BY e.seq LIMIT $limit;");
        command.Parameters.AddWithValue("$limit", Math.Clamp(filter.Limit, 1, 5000));
        command.CommandText = sql.ToString();

        using var reader = command.ExecuteReader();
        var results = new List<BehaviorEvent>();
        while (reader.Read())
        {
            results.Add(Map(reader, sessionId));
        }

        return results;
    }

    /// <summary>FTS5 phrase search over paths, hosts and detail text.</summary>
    public IReadOnlyList<BehaviorEvent> Search(Guid sessionId, string text, int limit = 100)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return [];
        }

        // Quote the input as a single FTS phrase so user text can contain
        // operators without breaking the query.
        var phrase = "\"" + text.Trim().Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";

        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT {Columns}
            FROM events e
            WHERE e.session_id = $session
              AND e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH $q)
            ORDER BY e.ts_utc DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        command.Parameters.AddWithValue("$q", phrase);
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));

        using var reader = command.ExecuteReader();
        var results = new List<BehaviorEvent>();
        while (reader.Read())
        {
            results.Add(Map(reader, sessionId));
        }

        return results;
    }

    public IReadOnlyDictionary<EventCategory, long> CountByCategory(Guid sessionId)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT category, COUNT(*) FROM events
            WHERE session_id = $session
              AND scope_state IN ('Root', 'Confirmed', 'Unconfirmed')
            GROUP BY category;
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());

        using var reader = command.ExecuteReader();
        var results = new Dictionary<EventCategory, long>();
        while (reader.Read())
        {
            results[Db.ParseEnum<EventCategory>(reader.GetValue(0))] = reader.GetInt64(1);
        }

        return results;
    }

    public long Count(Guid sessionId)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM events WHERE session_id = $session;";
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static string? BuildDetailText(BehaviorEvent behaviorEvent)
    {
        var parts = new[] { behaviorEvent.Target, behaviorEvent.HostName, behaviorEvent.Detail }
            .Where(static part => !string.IsNullOrWhiteSpace(part));

        var text = string.Join(' ', parts);
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    private static BehaviorEvent Map(SqliteDataReader reader, Guid sessionId) => new()
    {
        SessionId = sessionId,
        Seq = reader.GetInt64(0),
        TimestampUtc = Db.ParseTime(reader.GetValue(1)),
        Kind = Db.ParseEnum<EventKind>(reader.GetValue(2)),
        Category = Db.ParseEnum<EventCategory>(reader.GetValue(3)),
        Pid = reader.GetInt32(4),
        Tid = reader.IsDBNull(5) ? null : reader.GetInt32(5),
        ParentPid = reader.IsDBNull(6) ? null : reader.GetInt32(6),
        ImageName = reader.IsDBNull(7) ? null : reader.GetString(7),
        ImagePath = reader.IsDBNull(8) ? null : reader.GetString(8),
        Target = reader.IsDBNull(9) ? null : reader.GetString(9),
        PathKey = reader.IsDBNull(10) ? null : reader.GetString(10),
        RemoteIp = reader.IsDBNull(11) ? null : reader.GetString(11),
        RemotePort = reader.IsDBNull(12) ? null : reader.GetInt32(12),
        Protocol = reader.IsDBNull(13) ? null : reader.GetString(13),
        HostName = reader.IsDBNull(14) ? null : reader.GetString(14),
        BytesOut = reader.IsDBNull(15) ? null : reader.GetInt64(15),
        BytesIn = reader.IsDBNull(16) ? null : reader.GetInt64(16),
        Detail = reader.IsDBNull(17) ? null : reader.GetString(17),
        Observability = Db.ParseEnum<Observability>(reader.GetValue(18)),
        Confidence = reader.GetDouble(19),
        Source = Db.ParseEnum<EventSourceKind>(reader.GetValue(20)),
        Scope = Db.ParseEnum<ProcessScopeState>(reader.GetValue(21)),
    };
}
