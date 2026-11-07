namespace Argus.Storage;

using System.Text.Json;
using Argus.Analysis.Detection;
using Argus.Analysis.Pipeline;
using Argus.Core.Events;
using Argus.Core.Risk;
using Microsoft.Data.Sqlite;

public sealed class DetectionRepository(SessionDatabase database)
{
    private readonly SessionDatabase _database = database;

    /// <summary>
    /// Upserts by deterministic detection key and replaces its evidence links.
    /// Evidence is rebuilt rather than appended so a replayed session converges to
    /// exactly the same rows.
    /// </summary>
    public long Upsert(Guid sessionId, DetectionState detection, double weight = 0)
    {
        ArgumentNullException.ThrowIfNull(detection);

        using var connection = _database.Open();
        using var transaction = connection.BeginTransaction();

        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO detections (
                session_id, detection_key, rule_id, title, severity, base_confidence, confidence,
                categories, scope_pid, first_ts, last_ts, event_count, status, reason,
                counterfactual, factors_json, mitre, weight)
            VALUES (
                $session, $key, $rule, $title, $severity, $baseConfidence, $confidence,
                $categories, $pid, $first, $last, $count, $status, $reason,
                $counterfactual, $factors, $mitre, $weight)
            ON CONFLICT(session_id, detection_key) DO UPDATE SET
                confidence = excluded.confidence,
                categories = excluded.categories,
                last_ts = excluded.last_ts,
                event_count = excluded.event_count,
                status = excluded.status,
                reason = excluded.reason,
                counterfactual = excluded.counterfactual,
                factors_json = excluded.factors_json,
                mitre = excluded.mitre,
                weight = excluded.weight;
            """;

        command.Parameters.AddWithValue("$session", sessionId.ToString());
        command.Parameters.AddWithValue("$key", detection.Key);
        command.Parameters.AddWithValue("$rule", detection.RuleId);
        command.Parameters.AddWithValue("$title", detection.Title);
        command.Parameters.AddWithValue("$severity", detection.Severity);
        command.Parameters.AddWithValue("$baseConfidence", detection.BaseConfidence);
        command.Parameters.AddWithValue("$confidence", detection.Confidence);
        command.Parameters.AddWithValue("$categories", (int)detection.Categories);
        command.Parameters.AddWithValue("$pid", detection.ScopePid);
        command.Parameters.AddWithValue("$first", Db.Text(detection.FirstSeenUtc));
        command.Parameters.AddWithValue("$last", Db.Text(detection.LastSeenUtc));
        command.Parameters.AddWithValue("$count", detection.EventCount);
        command.Parameters.AddWithValue("$status", detection.Status.ToString());
        command.Parameters.AddWithValue("$reason", detection.Reason);
        command.Parameters.AddWithValue("$counterfactual", detection.Counterfactual);
        command.Parameters.AddWithValue("$factors", JsonSerializer.Serialize(detection.Factors));
        command.Parameters.AddWithValue("$mitre", string.Join(',', detection.Mitre));
        command.Parameters.AddWithValue("$weight", weight);
        command.ExecuteNonQuery();

        long id;
        using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = "SELECT id FROM detections WHERE session_id = $session AND detection_key = $key;";
            select.Parameters.AddWithValue("$session", sessionId.ToString());
            select.Parameters.AddWithValue("$key", detection.Key);
            id = Convert.ToInt64(select.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
        }

        using (var clear = connection.CreateCommand())
        {
            clear.Transaction = transaction;
            clear.CommandText = "DELETE FROM detection_evidence WHERE detection_id = $id;";
            clear.Parameters.AddWithValue("$id", id);
            clear.ExecuteNonQuery();
        }

        using (var evidence = connection.CreateCommand())
        {
            evidence.Transaction = transaction;
            evidence.CommandText = """
                INSERT OR IGNORE INTO detection_evidence (detection_id, seq, role)
                VALUES ($id, $seq, 'observed');
                """;
            var seqParameter = evidence.Parameters.AddWithValue("$seq", 0L);
            evidence.Parameters.AddWithValue("$id", id);

            foreach (var seq in detection.EvidenceSeq)
            {
                seqParameter.Value = seq;
                evidence.ExecuteNonQuery();
            }
        }

        transaction.Commit();
        return id;
    }

    public IReadOnlyList<StoredDetection> List(Guid sessionId)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, detection_key, rule_id, title, severity, confidence, categories, scope_pid,
                   first_ts, last_ts, event_count, status, reason, counterfactual, factors_json,
                   mitre, weight
            FROM detections WHERE session_id = $session
            ORDER BY severity DESC, first_ts ASC;
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());

        using var reader = command.ExecuteReader();
        var results = new List<StoredDetection>();
        while (reader.Read())
        {
            results.Add(Map(reader));
        }

        return results;
    }

    public StoredDetection? Get(Guid sessionId, string detectionKey)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, detection_key, rule_id, title, severity, confidence, categories, scope_pid,
                   first_ts, last_ts, event_count, status, reason, counterfactual, factors_json,
                   mitre, weight
            FROM detections WHERE session_id = $session AND detection_key = $key;
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        command.Parameters.AddWithValue("$key", detectionKey);

        using var reader = command.ExecuteReader();
        return reader.Read() ? Map(reader) : null;
    }

    public IReadOnlyList<long> EvidenceFor(long detectionId)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT seq FROM detection_evidence WHERE detection_id = $id ORDER BY seq;";
        command.Parameters.AddWithValue("$id", detectionId);

        using var reader = command.ExecuteReader();
        var results = new List<long>();
        while (reader.Read())
        {
            results.Add(reader.GetInt64(0));
        }

        return results;
    }

    private static StoredDetection Map(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt64(0),
        DetectionKey = reader.GetString(1),
        RuleId = reader.GetString(2),
        Title = reader.GetString(3),
        Severity = reader.GetInt32(4),
        Confidence = reader.GetDouble(5),
        Categories = (EvidenceCategory)reader.GetInt32(6),
        ScopePid = reader.GetInt32(7),
        FirstSeenUtc = Db.ParseTime(reader.GetValue(8)),
        LastSeenUtc = Db.ParseTime(reader.GetValue(9)),
        EventCount = reader.GetInt32(10),
        Status = reader.GetString(11),
        Reason = reader.GetString(12),
        Counterfactual = reader.GetString(13),
        FactorsJson = reader.GetString(14),
        Mitre = reader.GetString(15),
        Weight = reader.GetDouble(16),
    };
}

public sealed class ScoreRepository(SessionDatabase database)
{
    private readonly SessionDatabase _database = database;

    public void Append(Guid sessionId, DateTimeOffset timestampUtc, RiskAssessment assessment)
    {
        ArgumentNullException.ThrowIfNull(assessment);

        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO score_history (session_id, ts_utc, score, peak, band, categories, explanation)
            VALUES ($session, $ts, $score, $peak, $band, $categories, $explanation)
            ON CONFLICT(session_id, ts_utc) DO UPDATE SET
                score = excluded.score,
                peak = excluded.peak,
                band = excluded.band,
                categories = excluded.categories,
                explanation = excluded.explanation;
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        command.Parameters.AddWithValue("$ts", Db.Text(timestampUtc));
        command.Parameters.AddWithValue("$score", assessment.Score);
        command.Parameters.AddWithValue("$peak", assessment.PeakScore);
        command.Parameters.AddWithValue("$band", assessment.Band.ToString());
        command.Parameters.AddWithValue("$categories", (int)assessment.Categories);
        command.Parameters.AddWithValue("$explanation", assessment.Explanation);
        command.ExecuteNonQuery();
    }

    public IReadOnlyList<(DateTimeOffset Ts, double Score, double Peak, string Band)> History(Guid sessionId)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ts_utc, score, peak, band FROM score_history
            WHERE session_id = $session ORDER BY ts_utc ASC;
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());

        using var reader = command.ExecuteReader();
        var results = new List<(DateTimeOffset, double, double, string)>();
        while (reader.Read())
        {
            results.Add((Db.ParseTime(reader.GetValue(0)), reader.GetDouble(1), reader.GetDouble(2), reader.GetString(3)));
        }

        return results;
    }
}

public sealed class GapRepository(SessionDatabase database)
{
    private readonly SessionDatabase _database = database;

    public void AddRange(Guid sessionId, IEnumerable<GapEntry> gaps)
    {
        ArgumentNullException.ThrowIfNull(gaps);

        using var connection = _database.Open();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO gaps (session_id, ts_utc, source, reason, lost_count, detail)
            VALUES ($session, $ts, $source, $reason, $lost, $detail);
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        command.Parameters.AddWithValue("$ts", DBNull.Value);
        command.Parameters.AddWithValue("$source", DBNull.Value);
        command.Parameters.AddWithValue("$reason", DBNull.Value);
        command.Parameters.AddWithValue("$lost", DBNull.Value);
        command.Parameters.AddWithValue("$detail", DBNull.Value);

        foreach (var gap in gaps)
        {
            command.Parameters["$ts"].Value = Db.Text(gap.TimestampUtc);
            command.Parameters["$source"].Value = gap.Source;
            command.Parameters["$reason"].Value = gap.Reason;
            command.Parameters["$lost"].Value = (object?)gap.LostCount ?? DBNull.Value;
            command.Parameters["$detail"].Value = (object?)gap.Detail ?? DBNull.Value;
            command.ExecuteNonQuery();
        }

        transaction.Commit();
    }
}
