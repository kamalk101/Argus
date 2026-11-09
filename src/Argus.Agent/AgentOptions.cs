namespace Argus.Agent;

using System.Globalization;

public sealed record AgentOptions
{
    public bool SelfTest { get; init; }

    public bool Json { get; init; }

    public bool Elevate { get; init; }

    public bool AllowNonElevated { get; init; }

    public string? TargetPath { get; init; }

    public string? TargetArguments { get; init; }

    public int? DurationSeconds { get; init; }

    public string? RecordPath { get; init; }

    public string? DatabasePath { get; init; }

    /// <summary>Optional JSON file overriding the tunable rule thresholds.</summary>
    public string? RulesPath { get; init; }

    public int Port { get; init; }

    public string? ReadyFile { get; init; }

    public string? Token { get; init; }

    public string? SessionName { get; init; }

    /// <summary>
    /// Directory holding the built dashboard (`web/dist`). Served by the agent so the UI is
    /// same-origin with the API: no CORS, no Origin rewriting, and the bearer token never leaves
    /// loopback. Null means the agent runs headless.
    /// </summary>
    public string? WebRoot { get; init; }

    public static AgentOptions Parse(string[] args)
    {
        var options = new AgentOptions();
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < args.Length; i++)
        {
            var argument = args[i];
            if (argument is "--help" or "-h" or "help")
            {
                throw new UsageException(Usage);
            }

            if (!argument.StartsWith("--", StringComparison.Ordinal))
            {
                throw new UsageException($"Unexpected argument '{argument}'.\n\n{Usage}");
            }

            var name = argument[2..];
            switch (name.ToLowerInvariant())
            {
                case "self-test":
                    options = options with { SelfTest = true };
                    continue;
                case "json":
                    options = options with { Json = true };
                    continue;
                case "elevate":
                    options = options with { Elevate = true };
                    continue;
                case "allow-non-elevated":
                    options = options with { AllowNonElevated = true };
                    continue;
                case "version":
                    throw new VersionRequestedException();
            }

            if (i + 1 >= args.Length)
            {
                throw new UsageException($"Option --{name} requires a value.\n\n{Usage}");
            }

            values[name] = args[++i];
        }

        if (values.TryGetValue("target", out var target))
        {
            options = options with { TargetPath = Path.GetFullPath(target) };
        }

        if (values.TryGetValue("args", out var targetArguments))
        {
            options = options with { TargetArguments = targetArguments };
        }

        if (values.TryGetValue("record", out var record))
        {
            options = options with { RecordPath = Path.GetFullPath(record) };
        }

        if (values.TryGetValue("db", out var database))
        {
            options = options with { DatabasePath = Path.GetFullPath(database) };
        }

        if (values.TryGetValue("rules", out var rules))
        {
            options = options with { RulesPath = Path.GetFullPath(rules) };
        }

        if (values.TryGetValue("port", out var portText))
        {
            options = options with { Port = ParseInt("port", portText) };
        }

        if (values.TryGetValue("duration", out var durationText))
        {
            options = options with { DurationSeconds = ParseInt("duration", durationText) };
        }

        if (values.TryGetValue("ready-file", out var ready))
        {
            options = options with { ReadyFile = Path.GetFullPath(ready) };
        }

        if (values.TryGetValue("token", out var token))
        {
            options = options with { Token = token };
        }

        if (values.TryGetValue("web-root", out var webRoot))
        {
            options = options with { WebRoot = Path.GetFullPath(webRoot) };
        }

        if (values.TryGetValue("session-name", out var sessionName))
        {
            options = options with { SessionName = sessionName };
        }

        // A target is optional: without one the agent waits for the dashboard to start a session, which
        // is the product's real shape (launch Argus, then choose an application on the Sessions screen).
        // `--self-test` returns before this point.

        return options;
    }

    private static int ParseInt(string name, string text)
    {
        if (!int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) || value < 0)
        {
            throw new UsageException($"--{name} expects a non-negative integer.");
        }

        return value;
    }

    public const string Usage = """
        argus-agent — elevated Windows behaviour monitor

        Usage:
          argus-agent [--target <exe>] [options]
          argus-agent --self-test [--json]

        Monitoring options:
          --target <exe>          Application to launch and monitor (omit to wait for the dashboard)
          --args "<arguments>"    Command-line arguments for the target
          --duration <seconds>    Stop the session and exit after this many seconds
          --db <path>             Session SQLite file (default: %LOCALAPPDATA%\Argus\sessions\<id>.db)
          --record <path>         Raw JSONL recording (default: alongside the DB)
          --rules <path>          JSON file overriding the tunable rule thresholds
          --port <number>         Loopback API port (default: 0 = ephemeral)
          --session-name <name>   ETW session name (default: unique)
          --token <token>         Bearer token (normally generated by the launcher)
          --ready-file <path>     Write startup JSON here (used by the elevation launcher)
          --web-root <dir>        Serve the built dashboard from this directory (web/dist)
          --elevate               Relaunch through UAC if not already elevated
          --allow-non-elevated    Continue without administrator rights (degraded)

        Diagnosis:
          --self-test             Check elevation, ETW kernel provider, DNS provider and TCP table
          --json                  Machine-readable self-test output

        Exit codes: 0 ok, 1 check failed, 2 usage error, 3 permission/startup error.
        """;
}

public sealed class UsageException(string message) : Exception(message);

public sealed class VersionRequestedException : Exception;
