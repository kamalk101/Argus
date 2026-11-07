namespace Argus.Storage;

using Argus.Core.Risk;
using Argus.Core.Sessions;
using Microsoft.Data.Sqlite;

public sealed class SessionRepository(SessionDatabase database)
{
    private readonly SessionDatabase _database = database;

    public void Create(SessionRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO sessions (
                id, target_path, target_sha256, target_signer, mode, started_utc, ended_utc, status,
                os_build, agent_version, elevated, peak_score, final_score, verdict,
                loss_events, loss_bytes, config_hash)
            VALUES (
                $id, $target, $sha, $signer, $mode, $started, $ended, $status,
                $os, $agent, $elevated, $peak, $final, $verdict, $lossEvents, $lossBytes, $configHash)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                ended_utc = excluded.ended_utc,
                peak_score = excluded.peak_score,
                final_score = excluded.final_score,
                verdict = excluded.verdict,
                loss_events = excluded.loss_events,
                loss_bytes = excluded.loss_bytes;
            """;

        command.Parameters.AddWithValue("$id", record.Id.ToString());
        command.Parameters.AddWithValue("$target", record.TargetPath);
        command.Parameters.AddWithValue("$sha", Db.OrNull(record.TargetSha256));
        command.Parameters.AddWithValue("$signer", Db.OrNull(record.TargetSigner));
        command.Parameters.AddWithValue("$mode", record.Mode);
        command.Parameters.AddWithValue("$started", Db.Text(record.StartedUtc));
        command.Parameters.AddWithValue("$ended", Db.OrNull(Db.TextOrNull(record.EndedUtc)));
        command.Parameters.AddWithValue("$status", record.Status);
        command.Parameters.AddWithValue("$os", Db.OrNull(record.OsBuild));
        command.Parameters.AddWithValue("$agent", Db.OrNull(record.AgentVersion));
        command.Parameters.AddWithValue("$elevated", Db.Bool(record.Elevated));
        command.Parameters.AddWithValue("$peak", record.PeakScore);
        command.Parameters.AddWithValue("$final", Db.OrNull(record.FinalScore));
        command.Parameters.AddWithValue("$verdict", Db.OrNull(record.Verdict));
        command.Parameters.AddWithValue("$lossEvents", record.LossEvents);
        command.Parameters.AddWithValue("$lossBytes", record.LossBytes);
        command.Parameters.AddWithValue("$configHash", Db.OrNull(record.ConfigHash));

        command.ExecuteNonQuery();
    }

    public void Complete(Guid id, DateTimeOffset endedUtc, RiskAssessment risk, long lossEvents = 0)
    {
        ArgumentNullException.ThrowIfNull(risk);

        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE sessions SET
                status = 'stopped',
                ended_utc = $ended,
                peak_score = $peak,
                final_score = $final,
                verdict = $verdict,
                loss_events = $loss
            WHERE id = $id;
            """;

        command.Parameters.AddWithValue("$id", id.ToString());
        command.Parameters.AddWithValue("$ended", Db.Text(endedUtc));
        command.Parameters.AddWithValue("$peak", risk.PeakScore);
        command.Parameters.AddWithValue("$final", risk.Score);
        command.Parameters.AddWithValue("$verdict", risk.Band.ToString());
        command.Parameters.AddWithValue("$loss", lossEvents);
        command.ExecuteNonQuery();
    }

    public SessionRecord? Get(Guid id)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {SelectColumns} FROM sessions WHERE id = $id;";
        command.Parameters.AddWithValue("$id", id.ToString());

        using var reader = command.ExecuteReader();
        return reader.Read() ? Map(reader) : null;
    }

    public IReadOnlyList<SessionRecord> List(int limit = 50)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {SelectColumns} FROM sessions ORDER BY started_utc DESC LIMIT $limit;";
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));

        using var reader = command.ExecuteReader();
        var results = new List<SessionRecord>();
        while (reader.Read())
        {
            results.Add(Map(reader));
        }

        return results;
    }

    private const string SelectColumns = """
        id, target_path, target_sha256, target_signer, mode, started_utc, ended_utc, status,
        os_build, agent_version, elevated, peak_score, final_score, verdict,
        loss_events, loss_bytes, config_hash
        """;

    private static SessionRecord Map(SqliteDataReader reader) => new()
    {
        Id = Guid.Parse(reader.GetString(0)),
        TargetPath = reader.GetString(1),
        TargetSha256 = reader.IsDBNull(2) ? null : reader.GetString(2),
        TargetSigner = reader.IsDBNull(3) ? null : reader.GetString(3),
        Mode = reader.GetString(4),
        StartedUtc = Db.ParseTime(reader.GetValue(5)),
        EndedUtc = Db.ParseTimeOrNull(reader.GetValue(6)),
        Status = reader.GetString(7),
        OsBuild = reader.IsDBNull(8) ? null : reader.GetString(8),
        AgentVersion = reader.IsDBNull(9) ? null : reader.GetString(9),
        Elevated = reader.GetInt64(10) != 0,
        PeakScore = reader.GetDouble(11),
        FinalScore = reader.IsDBNull(12) ? null : reader.GetDouble(12),
        Verdict = reader.IsDBNull(13) ? null : reader.GetString(13),
        LossEvents = reader.GetInt64(14),
        LossBytes = reader.GetInt64(15),
        ConfigHash = reader.IsDBNull(16) ? null : reader.GetString(16),
    };
}
