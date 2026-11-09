namespace Argus.Desktop;

/// <summary>
/// Entry point. No console: this is the double-click experience, and everything it needs to say goes
/// into the window rather than a terminal that vanishes with the first error.
/// </summary>
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();

        // A WinForms exception must never end the process silently: an `async void` handler that throws
        // closes the window with no message at all, which is exactly what happened while the dashboard
        // was being wired up. Both the UI thread and unobserved tasks are reported and kept open.
        Application.ThreadException += (_, e) => Report(e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) => Report(e.ExceptionObject as Exception);
        Application.Run(new MainForm());
    }

    private static void Report(Exception? exception)
    {
        AgentProcess.TryLog("unhandled: " + (exception?.ToString() ?? "no exception object"));
        MessageBox.Show(
            "Argus hit an unexpected error and will stay open." + Environment.NewLine + Environment.NewLine
            + (exception?.Message ?? "The error was not reported.") + Environment.NewLine + Environment.NewLine
            + "Details were written to %TEMP%\argus-desktop.log.",
            "Argus",
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);
    }
}
