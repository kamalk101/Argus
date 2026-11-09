namespace Argus.Desktop;

using System.Diagnostics;
using System.Text.Json;

/// <summary>
/// Starts the elevated agent and hands back what the window needs to reach it.
///
/// The agent is started through its own <c>--elevate</c> path rather than by this process asking for
/// UAC: the launcher mints the bearer token, passes it to the child in its arguments, and prints the
/// ready JSON on stdout. The token therefore never touches a file, and this process stays at normal
/// integrity — the dashboard does not need administrator rights, only the sensor does.
/// </summary>
internal sealed class AgentProcess : IDisposable
{
    private readonly Process _process;

    private AgentProcess(Process process, Uri dashboard, string token)
    {
        _process = process;
        Dashboard = dashboard;
        Token = token;
    }

    public Uri Dashboard { get; }

    public string Token { get; }

    public static async Task<AgentProcess> StartAsync(CancellationToken cancellationToken)
    {
        var (fileName, arguments) = Locate();
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory,
        };

        var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("the agent process could not be started");

        // Read the one ready line, not the whole stream: the elevated child inherits the launcher's
        // stdout handles, so `ReadToEnd` never completes while the agent is alive. That hang was
        // measured — the window sat on "Starting the elevated monitor…" with a healthy agent running.
        var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        string? ready;
        try
        {
            ready = await ReadReadyLineAsync(process, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            process.Dispose();
            throw new InvalidOperationException(
                "the agent did not report readiness within 90 s. If a permission prompt is open, answer it; "
                + "otherwise start the agent by hand to see why it stopped.");
        }

        // What the launcher printed, always: a launch that reported readiness but is then refused as
        // "no valid bearer token" cannot be diagnosed without it.
        TryLog("launcher said: " + (ready ?? "(nothing)"));

        if (string.IsNullOrWhiteSpace(ready))
        {
            process.Dispose();
            var errors = await SafeStderrAsync(stderr).ConfigureAwait(false);
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(errors) ? "the agent exited without a message" : errors);
        }

        using var document = JsonDocument.Parse(ready);
        var root = document.RootElement;
        var port = root.GetProperty("port").GetInt32();
        var token = root.GetProperty("token").GetString()
            ?? throw new InvalidOperationException("the agent did not report a token");

        return new AgentProcess(process, new Uri($"http://127.0.0.1:{port}/"), token);
    }

    internal static void TryLog(string message)
    {
        try
        {
            File.AppendAllText(
                Path.Combine(Path.GetTempPath(), "argus-desktop.log"),
                DateTime.Now.ToString("O") + " " + message + Environment.NewLine);
        }
        catch (IOException)
        {
        }
    }

    /// <summary>
    /// The first stdout line that is the ready JSON. Blank lines are skipped, and the wait is bounded:
    /// a UAC prompt that is dismissed produces no line at all.
    /// </summary>
    private static async Task<string?> ReadReadyLineAsync(Process process, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(90));

        while (true)
        {
            string? line;
            try
            {
                line = await process.StandardOutput.ReadLineAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw new TimeoutException();
            }

            if (line is null)
            {
                return null;
            }

            if (line.TrimStart().StartsWith('{'))
            {
                return line.Trim();
            }
        }
    }

    private static async Task<string> SafeStderrAsync(Task<string> stderr)
    {
        try
        {
            return (await stderr.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false)).Trim();
        }
        catch (Exception exception) when (exception is TimeoutException or OperationCanceledException)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Where the agent lives. Beside this executable first (a published build), then the repository
    /// layout, so `dotnet run --project src/Argus.Desktop` works from a checkout.
    /// </summary>
    private static (string FileName, string Arguments) Locate()
    {
        var beside = Path.Combine(AppContext.BaseDirectory, "argus-agent.exe");
        if (File.Exists(beside))
        {
            return (beside, "--elevate");
        }

        var start = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; depth < 6 && start is not null; depth++, start = start.Parent)
        {
            var dll = Path.Combine(start.FullName, "src", "Argus.Agent", "bin", "Debug", "net8.0-windows", "argus-agent.dll");
            if (File.Exists(dll))
            {
                return ("dotnet", $"\"{dll}\" --elevate");
            }
        }

        throw new FileNotFoundException(
            "argus-agent was not found beside this executable or in src/Argus.Agent/bin. Build the agent first: dotnet build src/Argus.Agent");
    }

    /// <summary>
    /// Ends the agent the way the agent expects: stop the session, then stop the server. A killed
    /// agent leaves its kernel ETW session registered, which is what makes the next launch fail.
    /// </summary>
    public async Task StopAsync()
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", Token);
            using var response = await http.PostAsync(new Uri(Dashboard, "api/shutdown"), null).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            // The agent may already be gone; the process check below is the real answer.
        }
    }

    public void Dispose()
    {
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
        }

        _process.Dispose();
    }
}
