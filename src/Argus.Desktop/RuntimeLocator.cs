namespace Argus.Desktop;

/// <summary>
/// Why the WebView2 runtime matters here, and what to say when it cannot be used.
///
/// Measured on Windows 10 21H2 with Edge 92: <c>msedgewebview2.exe</c> exists, so a check for the
/// executable says "installed", but the WebView2 SDK refuses to create an environment and reports only
/// <c>E_NOTIMPL</c> (0x80070032) — the Windows installation has never received the WebView2 runtime
/// that ships separately from Edge. The runtime is therefore reported as absent unless it is the
/// Evergreen installation, and the message says how to get it.
/// </summary>
internal static class RuntimeLocator
{
    private const string ClientKey = @"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";

    /// <summary>The Evergreen runtime's version, when it is registered. Null means it is not installed.</summary>
    public static string? InstalledVersion()
    {
        foreach (var hive in new[] { Microsoft.Win32.Registry.LocalMachine, Microsoft.Win32.Registry.CurrentUser })
        {
            try
            {
                using var key = hive.OpenSubKey(ClientKey, writable: false);
                if (key?.GetValue("pv") is string version && !string.IsNullOrWhiteSpace(version) && version != "0.0.0.0")
                {
                    return version;
                }
            }
            catch (Exception exception) when (exception is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
            }
        }

        return null;
    }

    /// <summary>What the window says instead of a blank frame when the runtime is missing.</summary>
    public static string ExplainMissing(string agentUrl)
    {
        return "The WebView2 runtime is not installed on this machine, so Argus cannot show the dashboard in this window."
            + Environment.NewLine
            + Environment.NewLine
            + "Install it once with the Evergreen bootstrapper (Microsoft's \"WebView2 Runtime\" download page), then start Argus again."
            + Environment.NewLine
            + "Edge being installed is not enough: the runtime is a separate installation."
            + Environment.NewLine
            + Environment.NewLine
            + "The monitor is already running. Its dashboard is available at:"
            + Environment.NewLine
            + agentUrl;
    }
}
