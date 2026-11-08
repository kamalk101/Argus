namespace Argus.Agent;

using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

/// <summary>
/// UAC relaunch. The parent mints the bearer token and passes it to the child in
/// its arguments (same user, same integrity), so the token never has to be
/// persisted in a file. The ready file contains only connection metadata.
/// </summary>
public static class Elevation
{
    public static async Task<int> LaunchAsync(AgentOptions options)
    {
        var token = options.Token ?? RandomNumberGenerator.GetHexString(32);
        var readyFile = options.ReadyFile
            ?? Path.Combine(Path.GetTempPath(), "argus-ready-" + Guid.NewGuid().ToString("N") + ".json");

        if (File.Exists(readyFile))
        {
            File.Delete(readyFile);
        }

        var childArguments = BuildChildArguments(options, token, readyFile);
        var (fileName, prefix) = Launcher();
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = prefix + childArguments,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Environment.CurrentDirectory,
        };

        try
        {
            using var child = Process.Start(startInfo);
            if (child is null)
            {
                Console.Error.WriteLine("argus-agent: the elevated process did not start.");
                return 3;
            }

            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
            while (DateTime.UtcNow < deadline && !File.Exists(readyFile))
            {
                await Task.Delay(250).ConfigureAwait(false);
            }

            if (!File.Exists(readyFile))
            {
                // Say what the child did, not just that nothing happened: "exited with 1"
                // and "still running" need very different fixes.
                var state = "still running";
                try
                {
                    state = child.HasExited
                        ? "exited with code " + child.ExitCode.ToString(System.Globalization.CultureInfo.InvariantCulture)
                        : "still running";
                }
                catch (InvalidOperationException)
                {
                    state = "exited";
                }

                Console.Error.WriteLine(
                    "argus-agent: the elevated process did not report readiness within 30 s (child " + state + "). "
                    + "Run from an elevated PowerShell to see its console output.");
                return 3;
            }

            var readyJson = await File.ReadAllTextAsync(readyFile).ConfigureAwait(false);
            File.Delete(readyFile);

            using var document = JsonDocument.Parse(readyJson);
            var output = new Dictionary<string, object?>
            {
                ["ready"] = document.RootElement.Clone(),
                ["token"] = token,
            };

            Console.WriteLine(JsonSerializer.Serialize(output, AgentJson.Pretty));
            return 0;
        }
        catch (System.ComponentModel.Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            Console.Error.WriteLine("argus-agent: UAC prompt was cancelled.");
            return 3;
        }
    }

    private static string BuildChildArguments(AgentOptions options, string token, string readyFile)
    {
        var original = Environment.GetCommandLineArgs().Skip(1).ToList();
        var filtered = new List<string>(original.Count);

        for (var i = 0; i < original.Count; i++)
        {
            if (original[i] is "--elevate" or "--ready-file" or "--token")
            {
                if (i + 1 < original.Count && original[i] is not "--elevate")
                {
                    i++;
                }

                continue;
            }

            filtered.Add(original[i]);
        }

        filtered.Add("--token");
        filtered.Add(token);
        filtered.Add("--ready-file");
        filtered.Add(readyFile);

        if (options.DurationSeconds is { } duration)
        {
            filtered.Add("--duration");
            filtered.Add(duration.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        return string.Join(' ', filtered.Select(Quote));
    }

    private static (string FileName, string Prefix) Launcher()
    {
        var processPath = Environment.ProcessPath
            ?? Process.GetCurrentProcess().MainModule?.FileName
            ?? throw new InvalidOperationException("Could not determine the agent executable path.");

        var entry = Assembly.GetEntryAssembly()?.Location;
        var isDotnetHost = string.Equals(
            Path.GetFileNameWithoutExtension(processPath),
            "dotnet",
            StringComparison.OrdinalIgnoreCase);

        if (isDotnetHost && !string.IsNullOrEmpty(entry))
        {
            return (processPath, Quote(entry) + " ");
        }

        return (processPath, string.Empty);
    }

    private static string Quote(string value)
    {
        if (value.Length == 0)
        {
            return "\"\"";
        }

        if (!value.Any(char.IsWhiteSpace) && !value.Contains('"'))
        {
            return value;
        }

        var builder = new StringBuilder(value.Length + 8);
        builder.Append('"');
        foreach (var character in value)
        {
            if (character == '"')
            {
                builder.Append('\\');
            }

            builder.Append(character);
        }

        builder.Append('"');
        return builder.ToString();
    }
}
