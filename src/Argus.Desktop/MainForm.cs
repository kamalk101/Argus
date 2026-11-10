namespace Argus.Desktop;

using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

/// <summary>
/// The window Argus opens: a WebView2 pointed at the agent's own origin.
///
/// Same-origin is the reason this is not a browser tab: the dashboard reads the API with a bearer
/// token and the stream with a single-use ticket, and the agent refuses foreign Host and Origin
/// headers. Loading the built dashboard from the agent means neither has to be loosened.
/// </summary>
internal sealed class MainForm : Form
{
    private readonly WebView2 _web = new() { Dock = DockStyle.Fill };
    private readonly Label _status = new()
    {
        Dock = DockStyle.Fill,
        TextAlign = ContentAlignment.MiddleCenter,
        Padding = new Padding(24),
        Font = new Font("Segoe UI", 10f),
    };

    private AgentProcess? _agent;

    public MainForm()
    {
        Text = "Argus — behaviour monitoring";
        Width = 1360;
        Height = 900;
        MinimumSize = new Size(960, 640);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(11, 13, 17);
        ForeColor = Color.FromArgb(223, 229, 238);

        // The status label is what the operator sees while UAC is pending, and what they see instead of
        // an empty window if it is refused. A blank frame reads as a hang.
        _status.Text = "Starting the elevated monitor…"
            + Environment.NewLine
            + "Windows will ask for permission; the sensor needs administrator rights, this window does not.";
        Controls.Add(_status);
    }

    protected override async void OnShown(EventArgs e)
    {
        base.OnShown(e);
        await ConnectAsync().ConfigureAwait(true);
    }

    private async Task ConnectAsync()
    {
        try
        {
            _agent = await AgentProcess.StartAsync(CancellationToken.None).ConfigureAwait(true);

            // Before any WebView2 object exists: is the runtime actually installed (not merely present
            // as an Edge binary)? Measured: Edge 92's msedgewebview2.exe exists but the SDK cannot use
            // it, so checking for the ever-green registration is the check that matches reality.
            var runtime = RuntimeLocator.Find();
            if (runtime is null)
            {
                ShowFailure(
                    RuntimeLocator.ExplainMissing(new Uri(_agent.Dashboard, $"?token={_agent.Token}").ToString()),
                    monitoring: true);
                return;
            }

            AgentProcess.TryLog("WebView2 runtime " + runtime.Version + " (" + (runtime.PerUser ? "per user" : "per machine") + ")");

            // The default user-data folder sits beside the executable, which is wrong for a run out of
            // bin/ (a rebuild replaces files under the browser's profile). %LOCALAPPDATA% is also where a
            // per-user runtime keeps its own state.
            var profile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Argus",
                "webview");
            Directory.CreateDirectory(profile);

            var environment = await CoreWebView2Environment.CreateAsync(null, profile).ConfigureAwait(true);
            await _web.EnsureCoreWebView2Async(environment).ConfigureAwait(true);

            // The token is handed to the page the same way a browser would get it from a URL, then the
            // page stores it and the address bar is not part of this app.
            _web.CoreWebView2.Settings.AreDevToolsEnabled = true;
            _web.CoreWebView2.Settings.IsStatusBarEnabled = false;

            // Swap the status label for the browser *before* navigating. Painting the browser is
            // supervised by the window's render loop, and an unrenderable child kept the message on
            // screen even though the agent was up and answering (measured: status text stayed for 10 s
            // while the agent was listening on its port).
            Controls.Remove(_status);
            Controls.Add(_web);
            _web.CreateControl();
            _web.Visible = true;

            _web.CoreWebView2.Navigate(new Uri(_agent.Dashboard, $"?token={_agent.Token}").ToString());
        }
        catch (Exception exception)
        {
            // Every failure type, not just the expected ones: an `async void` handler that lets an
            // exception escape leaves the window on its first status message with no way to tell why.
            string trace;
            try
            {
                trace = exception.ToString();
            }
            catch (Exception)
            {
                trace = exception.Message;
            }

            ShowFailure(trace);
        }
    }

    /// <param name="monitoring">
    /// True when the agent started and only the window could not show it. The help text differs: telling
    /// an operator "nothing is being monitored" while the sensor is running is a false statement about
    /// the machine, and it was on screen until this parameter existed.
    /// </param>
    private void ShowFailure(string message, bool monitoring = false)
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

        _status.Text = (monitoring ? string.Empty : "Argus could not start the monitor." + Environment.NewLine + Environment.NewLine)
            + message
            + (monitoring
                ? string.Empty
                : Environment.NewLine
                    + Environment.NewLine
                    + "Nothing is being monitored. Start the agent by hand to see its console output:"
                    + Environment.NewLine
                    + @"dotnet run --project src\Argus.Agent -- --target ""C:\Windows\System32\notepad.exe""");
    }

    protected override async void OnFormClosing(FormClosingEventArgs e)
    {
        base.OnFormClosing(e);
        if (_agent is not null)
        {
            await _agent.StopAsync().ConfigureAwait(true);
            _agent.Dispose();
            _agent = null;
        }
    }
}
