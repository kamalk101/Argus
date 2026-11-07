namespace Argus.Storage;

using Microsoft.Data.Sqlite;

/// <summary>
/// Owns the database file, connection settings and schema version. WAL lets the
/// UI read while the agent writes, which is the whole reason a live dashboard can
/// query without blocking collection.
/// </summary>
public sealed class SessionDatabase : IDisposable
{
    private readonly string _path;
    private readonly string _connectionString;

    public SessionDatabase(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        _path = path;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = true,
        }.ToString();

        var directory = System.IO.Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    public string Path => _path;

    public SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;
            PRAGMA synchronous = NORMAL;
            """;
        command.ExecuteNonQuery();

        return connection;
    }

    /// <summary>Creates the schema if absent and verifies the version.</summary>
    public void Initialize()
    {
        using var connection = Open();

        using (var wal = connection.CreateCommand())
        {
            wal.CommandText = "PRAGMA journal_mode = WAL;";
            wal.ExecuteScalar();
        }

        var version = ReadVersion(connection);
        if (version == 0)
        {
            using var create = connection.CreateCommand();
            create.CommandText = Schema.Sql;
            create.ExecuteNonQuery();

            using var stamp = connection.CreateCommand();
            stamp.CommandText = $"PRAGMA user_version = {Schema.Version};";
            stamp.ExecuteNonQuery();
            return;
        }

        if (version != Schema.Version)
        {
            throw new InvalidOperationException(
                $"Session database schema v{version} is not supported by this build (expected v{Schema.Version}).");
        }
    }

    public static SessionDatabase CreateTemporary()
    {
        var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "argus-tests");
        Directory.CreateDirectory(directory);
        var path = System.IO.Path.Combine(directory, $"session-{Guid.NewGuid():N}.db");
        var database = new SessionDatabase(path);
        database.Initialize();
        return database;
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
    }

    private static int ReadVersion(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        var value = command.ExecuteScalar();
        return value is null or DBNull ? 0 : Convert.ToInt32(value, System.Globalization.CultureInfo.InvariantCulture);
    }
}
