namespace Argus.Agent;

using System.Text.Json;
using Argus.Monitor;

/// <summary>
/// The Windows smoke check. It starts the real ETW kernel session for a few
/// seconds rather than only inspecting configuration, because "provider enabled"
/// and "provider actually delivered or failed" are different claims.
/// </summary>
public static class AgentSelfTest
{
    public static async Task<int> RunAsync(AgentOptions options)
    {
        var warnings = new List<string>();
        var checks = new List<(string Name, bool Passed, string Detail)>();

        var elevated = AgentInfo.IsElevated;
        checks.Add(("elevation", elevated, elevated ? "administrator token" : "not elevated; live ETW will be unavailable"));

        VolumeMap volumes;
        try
        {
            volumes = VolumeMap.Build();
            checks.Add(("volume-map", volumes.Devices.Count > 0, $"{volumes.Devices.Count} device path(s) mapped"));
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
        {
            volumes = VolumeMap.Empty;
            checks.Add(("volume-map", false, exception.Message));
        }

        var metadata = WindowsProcessMetadata.TryGet(Environment.ProcessId);
        checks.Add(("process-metadata", metadata?.ImagePath is not null,
            metadata?.ImagePath ?? "image path unavailable for the agent process"));

        IReadOnlyList<TcpConnection> tcp = [];
        try
        {
            tcp = TcpTableReader.Read();
            checks.Add(("tcp-owner-table", true, $"{tcp.Count} established/connecting socket(s) attributable"));
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
        {
            checks.Add(("tcp-owner-table", false, exception.Message));
        }

        var catalog = Argus.Core.Paths.SensitivePathCatalog.Default();
        var monitor = new MonitorEventSource(new MonitorOptions
        {
            RootPid = Environment.ProcessId,
            RootImagePath = metadata?.ImagePath,
            RootStartedUtc = DateTimeOffset.UtcNow,
            Catalog = catalog,
            FileEvents = true,
            NetworkEvents = true,
            RegistryEvents = true,
            DnsEvents = true,
            ReadSampleEvery = 50,
            SessionName = "Argus-SelfTest-" + Guid.NewGuid().ToString("N"),
        });

        try
        {
            monitor.Start();
            await GenerateActivityAsync().ConfigureAwait(false);
            await Task.Delay(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        finally
        {
            await monitor.StopAsync().ConfigureAwait(false);
        }

        var stats = monitor.Stats;
        checks.Add(("etw-kernel-provider", stats.EtwStarted,
            stats.EtwStarted ? "kernel process/file/network/registry keywords enabled" : stats.EtwError ?? "not started"));

        // Delivery, not just enablement: a host can say "provider enabled" and still
        // never hand the collector a record. The probe generates its own process and
        // file activity so zero callbacks means a broken sensor, not an idle machine.
        var delivered = stats.EtwCallbacks > 0;
        checks.Add(("etw-delivery", delivered, delivered
            ? string.Create(
                System.Globalization.CultureInfo.InvariantCulture,
                $"{stats.EtwCallbacks} callback(s), {stats.EtwFiltered} filtered out, {stats.EventsSeen} mapped, {stats.Unmapped} unmapped, {stats.MappingFailures} failed")
            : "ETW started but delivered no callbacks even with generated process/file activity"));

        if (!stats.DnsProviderEnabled)
        {
            warnings.Add("DNS provider was not enabled: " + (stats.DnsError ?? "unknown reason"));
        }

        if (stats.TcpTableAvailable)
        {
            checks.Add(("tcp-polling", true, "owner table poll succeeded"));
        }
        else
        {
            checks.Add(("tcp-polling", false, "owner table poll failed"));
        }

        if (stats.EtwStarted && stats.EtwCallbacks == 0)
        {
            warnings.Add(stats.EtwError is null
                ? "ETW delivered no callbacks at all; check for another kernel session (Procmon, Sysmon, WPR) or a stale Argus session."
                : "ETW pump failed: " + stats.EtwError);
        }

        var passed = checks.All(check => check.Passed);
        var result = new
        {
            passed,
            version = AgentInfo.Version,
            timestampUtc = DateTimeOffset.UtcNow,
            elevated,
            os = Environment.OSVersion.VersionString,
            checks = checks.Select(check => new { name = check.Name, passed = check.Passed, detail = check.Detail }),
            monitor = new
            {
                stats.EtwStarted,
                stats.DnsProviderEnabled,
                stats.TcpTableAvailable,
                stats.EtwError,
                stats.DnsError,
                stats.EtwCallbacks,
                stats.EtwFiltered,
                stats.EventsSeen,
                stats.EventsForwarded,
                stats.OutsideScope,
                stats.ProcessStarts,
                stats.FileEvents,
                stats.NetworkEvents,
                stats.DnsEvents,
                stats.RegistryEvents,
                stats.MappingFailures,
                stats.Unmapped,
                stats.ChannelDropped,
                stats.EtwLostEvents,
            },
            warnings,
        };

        if (options.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(result, AgentJson.Pretty));
        }
        else
        {
            Console.WriteLine($"argus-agent self-test {AgentInfo.Version}");
            Console.WriteLine($"  platform  {Environment.OSVersion.VersionString}");
            Console.WriteLine($"  elevated  {elevated}");
            Console.WriteLine();
            foreach (var check in checks)
            {
                Console.WriteLine($"  {(check.Passed ? "pass" : "FAIL")}  {check.Name,-22} {check.Detail}");
            }

            foreach (var warning in warnings)
            {
                Console.WriteLine($"  warn  {warning}");
            }

            Console.WriteLine();
            Console.WriteLine(passed
                ? "self-test passed. Live ETW capture is available."
                : "self-test failed. Run from an elevated PowerShell; see the checks above.");
        }

        return passed ? 0 : 1;
    }

    /// <summary>
    /// Produces two seconds of attributable process and file activity inside the
    /// probe window. Everything here is benign and self-deleting; it exists so the
    /// self-test can prove delivery rather than assume it.
    /// </summary>
    private static async Task GenerateActivityAsync()
    {
        try
        {
            var file = Path.Combine(Path.GetTempPath(), $"argus-selftest-{Guid.NewGuid():N}.tmp");
            await File.WriteAllTextAsync(file, "argus self-test").ConfigureAwait(false);
            File.Delete(file);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A failed probe write is not a sensor failure; the check below decides.
        }

        try
        {
            using var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                Arguments = "/c exit 0",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });

            if (child is not null)
            {
                await child.WaitForExitAsync().ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Same reasoning as above.
        }
    }
}
