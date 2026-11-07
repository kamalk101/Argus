namespace Argus.Storage;

using Argus.Core.Events;
using Argus.Core.Paths;

/// <summary>
/// Compresses aged raw events into per-window counts. Volume evidence survives
/// ("12,431 files written in System32"), individual rows do not, and the UI marks
/// such evidence as aggregated rather than pretending the detail is still there.
/// </summary>
public sealed class RollupService(SessionDatabase database)
{
    private readonly SessionDatabase _database = database;

    public RollupResult Rollup(
        Guid sessionId,
        DateTimeOffset olderThanUtc,
        TimeSpan window,
        int maxEvents = 50_000)
    {
        if (window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(window), "Rollup window must be positive.");
        }

        using var connection = _database.Open();
        using var select = connection.CreateCommand();
        select.CommandText = """
            SELECT id, seq, ts_utc, kind, category, pid, path_key, target, bytes_out, bytes_in
            FROM events
            WHERE session_id = $session AND ts_utc < $cutoff
            ORDER BY seq ASC
            LIMIT $limit;
            """;
        select.Parameters.AddWithValue("$session", sessionId.ToString());
        select.Parameters.AddWithValue("$cutoff", Db.Text(olderThanUtc));
        select.Parameters.AddWithValue("$limit", Math.Clamp(maxEvents, 1, 500_000));

        var rows = new List<RawRow>();
        using (var reader = select.ExecuteReader())
        {
            while (reader.Read())
            {
                rows.Add(new RawRow(
                    reader.GetInt64(0),
                    reader.GetInt64(1),
                    Db.ParseTime(reader.GetValue(2)),
                    Db.ParseEnum<EventKind>(reader.GetValue(3)),
                    Db.ParseEnum<EventCategory>(reader.GetValue(4)),
                    reader.GetInt32(5),
                    reader.IsDBNull(6) ? null : reader.GetString(6),
                    reader.IsDBNull(7) ? null : reader.GetString(7),
                    reader.IsDBNull(8) ? 0 : reader.GetInt64(8),
                    reader.IsDBNull(9) ? 0 : reader.GetInt64(9)));
            }
        }

        if (rows.Count == 0)
        {
            return new RollupResult(0, 0, null);
        }

        var groups = rows
            .GroupBy(row => new
            {
                Bucket = Bucket(row.TimestampUtc, window),
                row.Category,
                row.Kind,
                row.Pid,
                Prefix = PrefixOf(row),
            })
            .Select(group => new
            {
                group.Key.Bucket,
                group.Key.Category,
                group.Key.Kind,
                group.Key.Pid,
                group.Key.Prefix,
                Count = group.Count(),
                BytesOut = group.Sum(r => r.BytesOut),
                BytesIn = group.Sum(r => r.BytesIn),
                SampleSeq = group.Min(r => r.Seq),
            })
            .ToList();

        using var transaction = connection.BeginTransaction();

        using (var upsert = connection.CreateCommand())
        {
            upsert.Transaction = transaction;
            upsert.CommandText = """
                INSERT INTO event_rollups (
                    session_id, window_start_utc, window_end_utc, category, kind, pid,
                    target_prefix, count, bytes_out, bytes_in, sample_seq)
                VALUES ($session, $start, $end, $category, $kind, $pid,
                        $prefix, $count, $bytesOut, $bytesIn, $sample)
                ON CONFLICT(session_id, window_start_utc, category, kind, pid, target_prefix)
                DO UPDATE SET
                    count = event_rollups.count + excluded.count,
                    bytes_out = event_rollups.bytes_out + excluded.bytes_out,
                    bytes_in = event_rollups.bytes_in + excluded.bytes_in,
                    sample_seq = COALESCE(event_rollups.sample_seq, excluded.sample_seq);
                """;

            upsert.Parameters.AddWithValue("$session", sessionId.ToString());
            upsert.Parameters.AddWithValue("$start", DBNull.Value);
            upsert.Parameters.AddWithValue("$end", DBNull.Value);
            upsert.Parameters.AddWithValue("$category", DBNull.Value);
            upsert.Parameters.AddWithValue("$kind", DBNull.Value);
            upsert.Parameters.AddWithValue("$pid", DBNull.Value);
            upsert.Parameters.AddWithValue("$prefix", DBNull.Value);
            upsert.Parameters.AddWithValue("$count", DBNull.Value);
            upsert.Parameters.AddWithValue("$bytesOut", DBNull.Value);
            upsert.Parameters.AddWithValue("$bytesIn", DBNull.Value);
            upsert.Parameters.AddWithValue("$sample", DBNull.Value);

            foreach (var group in groups)
            {
                upsert.Parameters["$start"].Value = Db.Text(group.Bucket);
                upsert.Parameters["$end"].Value = Db.Text(group.Bucket + window);
                upsert.Parameters["$category"].Value = group.Category.ToString();
                upsert.Parameters["$kind"].Value = group.Kind.ToString();
                upsert.Parameters["$pid"].Value = group.Pid;
                upsert.Parameters["$prefix"].Value = (object?)group.Prefix ?? DBNull.Value;
                upsert.Parameters["$count"].Value = group.Count;
                upsert.Parameters["$bytesOut"].Value = group.BytesOut;
                upsert.Parameters["$bytesIn"].Value = group.BytesIn;
                upsert.Parameters["$sample"].Value = group.SampleSeq;
                upsert.ExecuteNonQuery();
            }
        }

        var removed = 0;
        foreach (var chunk in rows.Chunk(400))
        {
            using var delete = connection.CreateCommand();
            delete.Transaction = transaction;
            var names = new string[chunk.Length];
            for (var i = 0; i < chunk.Length; i++)
            {
                names[i] = "$id" + i.ToString(System.Globalization.CultureInfo.InvariantCulture);
                delete.Parameters.AddWithValue(names[i], chunk[i].Id);
            }

            delete.CommandText = $"DELETE FROM events WHERE id IN ({string.Join(',', names)});";
            removed += delete.ExecuteNonQuery();
        }

        transaction.Commit();

        DateTimeOffset? oldest = null;
        using (var remaining = connection.CreateCommand())
        {
            remaining.CommandText = "SELECT MIN(ts_utc) FROM events WHERE session_id = $session;";
            remaining.Parameters.AddWithValue("$session", sessionId.ToString());
            var value = remaining.ExecuteScalar();
            if (value is not null and not DBNull)
            {
                oldest = Db.ParseTime(value);
            }
        }

        return new RollupResult(removed, groups.Count, oldest);
    }

    public IReadOnlyList<RollupRow> List(Guid sessionId)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT window_start_utc, window_end_utc, category, kind, pid, target_prefix,
                   count, bytes_out, bytes_in, sample_seq
            FROM event_rollups WHERE session_id = $session
            ORDER BY window_start_utc ASC;
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());

        using var reader = command.ExecuteReader();
        var results = new List<RollupRow>();
        while (reader.Read())
        {
            results.Add(new RollupRow(
                Db.ParseTime(reader.GetValue(0)),
                Db.ParseTime(reader.GetValue(1)),
                Db.ParseEnum<EventCategory>(reader.GetValue(2)),
                Db.ParseEnum<EventKind>(reader.GetValue(3)),
                reader.GetInt32(4),
                reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.GetInt32(6),
                reader.GetInt64(7),
                reader.GetInt64(8),
                reader.IsDBNull(9) ? null : reader.GetInt64(9)));
        }

        return results;
    }

    private static DateTimeOffset Bucket(DateTimeOffset timestamp, TimeSpan window)
    {
        var ticks = timestamp.UtcTicks - (timestamp.UtcTicks % window.Ticks);
        return new DateTimeOffset(ticks, TimeSpan.Zero);
    }

    private static string? PrefixOf(RawRow row) =>
        row.PathKey is not null ? PathKey.DirectoryName(row.PathKey) : row.Target;

    private sealed record RawRow(
        long Id,
        long Seq,
        DateTimeOffset TimestampUtc,
        EventKind Kind,
        EventCategory Category,
        int Pid,
        string? PathKey,
        string? Target,
        long BytesOut,
        long BytesIn);
}

public sealed record RollupRow(
    DateTimeOffset WindowStartUtc,
    DateTimeOffset WindowEndUtc,
    EventCategory Category,
    EventKind Kind,
    int Pid,
    string? TargetPrefix,
    int Count,
    long BytesOut,
    long BytesIn,
    long? SampleSeq);
