namespace Argus.Desktop;

using Microsoft.Win32;

/// <summary>
/// Where the WebView2 runtime is, and what to say when it is not.
///
/// The runtime can be installed **per machine** (HKLM, under Program Files) or **per user** (HKCU,
/// under %LOCALAPPDATA%). Only the first was checked, which reported "not installed" on a machine that
/// had 157.0.4341.42 sitting in the per-user location — measured. Both hives are read now, and the
/// registration's own `location` value is used instead of guessing a path.
///
/// A second wrong check is not repeated: Edge ships <c>msedgewebview2.exe</c> too, so "the executable
/// exists" says nothing. The Evergreen registration is the only reliable statement of "the runtime is
/// installed and usable by the SDK".
/// </summary>
internal static class RuntimeLocator
{
    private const string ClientKey = @"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";

    /// <summary>The parts of the registration the shell needs, or null when it is absent.</summary>
    internal sealed record Runtime(string Version, string? Location, bool PerUser);

    public static Runtime? Find()
    {
        foreach (var (hive, perUser, path) in new[]
        {
            (Registry.LocalMachine, false, @"SOFTWARE\WOW6432Node\" + ClientKey),
            (Registry.LocalMachine, false, ClientKey),
            (Registry.CurrentUser, true, ClientKey),
        })
        {
            try
            {
                using var key = hive.OpenSubKey(path, writable: false);
                if (key?.GetValue("pv") is not string version || string.IsNullOrWhiteSpace(version) || version == "0.0.0.0")
                {
                    continue;
                }

                var location = key.GetValue("location") as string;
                return new Runtime(version, string.IsNullOrWhiteSpace(location) ? null : location, perUser);
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
