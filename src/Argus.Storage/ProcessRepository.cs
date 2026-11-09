namespace Argus.Storage;

using Argus.Core.Events;
using Argus.Core.Processes;
using Argus.Core.Sessions;

public sealed class ProcessRepository(SessionDatabase database)
{
    private readonly SessionDatabase _database = database;

    public void Upsert(Guid sessionId, ProcessRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO processes (
                session_id, pid, parent_pid, image_name, image_path, cmdline,
                start_utc, end_utc, exit_code, signer, sha256, integrity, scope_state)
            VALUES (
                $session, $pid, $parent, $image, $imagePath, $cmdline,
                $start, NULL, NULL, $signer, NULL, NULL, $scope)
            ON CONFLICT(session_id, pid, start_utc) DO UPDATE SET
                parent_pid = excluded.parent_pid,
                image_name = excluded.image_name,
                image_path = excluded.image_path,
                cmdline = COALESCE(excluded.cmdline, processes.cmdline),
                signer = COALESCE(excluded.signer, processes.signer),
                scope_state = excluded.scope_state;
            """;

        command.Parameters.AddWithValue("$session", sessionId.ToString());
        command.Parameters.AddWithValue("$pid", record.Pid);
        command.Parameters.AddWithValue("$parent", Db.OrNull(record.ParentPid));
        command.Parameters.AddWithValue("$image", Db.OrNull(record.ImageName));
        command.Parameters.AddWithValue("$imagePath", Db.OrNull(record.ImagePath));
        command.Parameters.AddWithValue("$cmdline", Db.OrNull(record.CommandLine));
        command.Parameters.AddWithValue("$start", Db.Text(record.StartedUtc));
        command.Parameters.AddWithValue("$signer", Db.OrNull(record.Signature?.ToString()));
        command.Parameters.AddWithValue("$scope", record.Scope.ToString());

        command.ExecuteNonQuery();
    }

    public void MarkExited(Guid sessionId, int pid, DateTimeOffset startedUtc, DateTimeOffset endedUtc, int? exitCode)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE processes SET end_utc = $end, exit_code = $code
            WHERE session_id = $session AND pid = $pid AND start_utc = $start;
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());
        command.Parameters.AddWithValue("$pid", pid);
        command.Parameters.AddWithValue("$start", Db.Text(startedUtc));
        command.Parameters.AddWithValue("$end", Db.Text(endedUtc));
        command.Parameters.AddWithValue("$code", Db.OrNull(exitCode));
        command.ExecuteNonQuery();
    }

    public IReadOnlyList<ProcessRecord> List(Guid sessionId)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT pid, parent_pid, image_name, image_path, cmdline, start_utc, scope_state, signer
            FROM processes WHERE session_id = $session
            ORDER BY start_utc ASC, pid ASC;
            """;
        command.Parameters.AddWithValue("$session", sessionId.ToString());

        using var reader = command.ExecuteReader();
        var results = new List<ProcessRecord>();
        while (reader.Read())
        {
            results.Add(new ProcessRecord(
                reader.GetInt32(0),
                reader.IsDBNull(1) ? null : reader.GetInt32(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                Db.ParseTime(reader.GetValue(5)),
                Db.ParseEnum<ProcessScopeState>(reader.GetValue(6)),
                Signature: reader.IsDBNull(7) ? null : Db.ParseEnum<SignatureStatus>(reader.GetValue(7))));
        }

        return results;
    }
}
