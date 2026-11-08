namespace Argus.Agent;

using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Argus.Core.Paths;
using Argus.Monitor;
using Argus.Storage;

/// <summary>
/// Owns the one active live session and the databases behind completed ones.
/// A single active session is deliberate: the agent's ETW kernel session is a
/// machine-wide resource and concurrent targets would make scope attribution
/// ambiguous.
/// </summary>
public sealed class SessionManager : IAsyncDisposable
{
    private readonly SseHub _hub;
    private readonly AgentOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<Guid, LiveSession> _sessions = [];
    private readonly Dictionary<Guid, SessionDatabase> _databases = [];
    private bool _usedFixedPaths;

    public SessionManager(SseHub hub, AgentOptions options)
    {
        _hub = hub;
        _options = options;
    }

    public LiveSession? Active => _sessions.Values.FirstOrDefault(session => session.Status is "running" or "stopping");

    public IReadOnlyList<LiveSession> Sessions => [.. _sessions.Values.OrderByDescending(session => session.StartedUtc)];

    public string DataRoot
    {
        get
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(local))
            {
                local = Path.GetTempPath();
            }

            return Path.Combine(local, "Argus", "sessions");
        }
    }

    public async Task<LiveSession> StartAsync(string targetPath, string? arguments, string mode = "launch")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);
        targetPath = Path.GetFullPath(targetPath);

        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (Active is not null)
            {
                throw new InvalidOperationException("A monitoring session is already active. Stop it first.");
            }

            if (!File.Exists(targetPath))
            {
                throw new FileNotFoundException("Target executable was not found.", targetPath);
            }

            if (!string.Equals(Path.GetExtension(targetPath), ".exe", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Only .exe targets are supported.");
            }

            Directory.CreateDirectory(DataRoot);

            var id = Guid.NewGuid();
            var fixedPaths = !_usedFixedPaths;
            var dbPath = fixedPaths && _options.DatabasePath is not null
                ? _options.DatabasePath
                : Path.Combine(DataRoot, $"{id}.db");
            var recordPath = fixedPaths && _options.RecordPath is not null
                ? _options.RecordPath
                : Path.Combine(DataRoot, $"{id}.jsonl");
            _usedFixedPaths = true;

            var database = new SessionDatabase(dbPath);
            database.Initialize();
            _databases[id] = database;

            var started = DateTimeOffset.UtcNow;
            var recorder = new SessionRecorder(database, new SessionRecord
            {
                Id = id,
                TargetPath = targetPath,
                TargetSha256 = TryHash(targetPath),
                TargetSigner = TrySigner(targetPath),
                Mode = mode,
                StartedUtc = started,
                Status = "running",
                OsBuild = Environment.OSVersion.VersionString,
                AgentVersion = AgentInfo.Version,
                Elevated = AgentInfo.IsElevated,
                ConfigHash = "phase2",
            });

            Process? process = null;
            MonitorEventSource? monitor = null;

            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = targetPath,
                    UseShellExecute = false,
                    WorkingDirectory = Path.GetDirectoryName(targetPath) ?? Environment.CurrentDirectory,

                    // The monitored application must not inherit the agent's console or
                    // stdio handles. If it did, a target that outlives the agent keeps a
                    // caller's captured stdout open and blocks whoever is reading it -
                    // scripts/smoke.ps1 hung exactly that way. The target's own output is
                    // not part of Argus's output, so it is drained and discarded, and
                    // stdin is closed so a console target sees EOF instead of stealing
                    // the agent's console input.
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };

                if (!string.IsNullOrWhiteSpace(arguments))
                {
                    startInfo.Arguments = arguments;
                }

                process = Process.Start(startInfo)
                    ?? throw new InvalidOperationException("Windows did not return a process for the target.");

                DrainTargetStreams(process);

                monitor = new MonitorEventSource(new MonitorOptions
                {
                    RootPid = process.Id,
                    RootImagePath = targetPath,
                    RootStartedUtc = started,
                    Catalog = SensitivePathCatalog.Default(),
                    SessionName = _options.SessionName,
                });

                var session = new LiveSession(
                    id,
                    targetPath,
                    process,
                    database,
                    recorder,
                    monitor,
                    dbPath,
                    recordPath,
                    _hub,
                    SensitivePathCatalog.Default());

                session.Start();
                _sessions[id] = session;
                _hub.Publish("state", session.State());
                return session;
            }
            catch
            {
                monitor?.DisposeAsync().AsTask().GetAwaiter().GetResult();
                if (process is { HasExited: false })
                {
                    process.Kill(entireProcessTree: true);
                }

                process?.Dispose();
                _databases.Remove(id, out _);
                database.Dispose();
                throw;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public LiveSession? Get(Guid id) => _sessions.GetValueOrDefault(id);

    public async Task<bool> StopAsync(Guid id, bool terminate)
    {
        var session = Get(id);
        if (session is null)
        {
            return false;
        }

        await session.StopAsync("api-request", terminate).ConfigureAwait(false);
        return true;
    }

    public async Task StopAllAsync()
    {
        foreach (var session in _sessions.Values)
        {
            await session.StopAsync("agent-shutdown", terminateTarget: false).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAllAsync().ConfigureAwait(false);

        foreach (var session in _sessions.Values)
        {
            await session.DisposeAsync().ConfigureAwait(false);
        }

        foreach (var database in _databases.Values)
        {
            database.Dispose();
        }

        _sessions.Clear();
        _databases.Clear();
        _hub.Complete();
        _gate.Dispose();
    }

    /// <summary>
    /// Closes the target's stdin and reads its stdout/stderr to exhaustion in the
    /// background. Draining matters: a redirected pipe that nobody reads fills up and
    /// would block a chatty target. Errors here are expected once the target exits and
    /// are not surfaced as session failures.
    /// </summary>
    private static void DrainTargetStreams(Process process)
    {
        try
        {
            process.StandardInput.Close();
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or ObjectDisposedException)
        {
            // The target exited before we could close its stdin.
        }

        Drain(process.StandardOutput);
        Drain(process.StandardError);
    }

    private static void Drain(StreamReader reader)
    {
        _ = Task.Run(async () =>
        {
            var buffer = new char[4096];
            try
            {
                while (await reader.ReadAsync(buffer.AsMemory()).ConfigureAwait(false) > 0)
                {
                    // Deliberately discarded: target output is not agent output.
                }
            }
            catch (Exception exception) when (exception is IOException or ObjectDisposedException or InvalidOperationException)
            {
                // The target exited and its pipe was closed.
            }
        });
    }

    private static string? TryHash(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string? TrySigner(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            using var certificate = X509Certificate.CreateFromSignedFile(path);
            return certificate.Subject;
        }
        catch (Exception exception) when (exception is CryptographicException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
