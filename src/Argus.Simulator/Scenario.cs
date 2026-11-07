namespace Argus.Simulator;

using System.Text.Json;
using Argus.Core.Events;

public sealed record ScenarioExpectation
{
    /// <summary>Rule ids that must appear in the result.</summary>
    public IReadOnlyList<string> Rules { get; init; } = [];

    /// <summary>Rule ids that must not fire (false-positive guards).</summary>
    public IReadOnlyList<string> AbsentRules { get; init; } = [];

    public string? Band { get; init; }

    public double? MinScore { get; init; }

    public double? MaxScore { get; init; }

    public int? MaxDetections { get; init; }

    public bool ExpectGaps { get; init; }
}

public sealed record ScenarioMeta
{
    public string Name { get; init; } = "unnamed";

    public string? Description { get; init; }

    /// <summary>PID of the monitored application in this scenario.</summary>
    public int RootPid { get; init; } = 1000;

    public string? RootImagePath { get; init; }

    public string? SessionId { get; init; }

    public ScenarioExpectation Expect { get; init; } = new();
}

public sealed record ScenarioFile(string Path, ScenarioMeta Meta, IReadOnlyList<RawEvent> Events);

public static class ScenarioLoader
{
    public static ScenarioFile Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        using var stream = File.OpenRead(path);
        using var reader = new StreamReader(stream);

        ScenarioMeta? meta = null;
        var events = new List<RawEvent>();

        string? line;
        var lineNumber = 0;
        while ((line = reader.ReadLine()) is not null)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            using var document = JsonDocument.Parse(line);
            if (document.RootElement.TryGetProperty("$meta", out var metaElement))
            {
                meta = metaElement.Deserialize<ScenarioMeta>(RawEventJson.Options)
                    ?? throw new InvalidDataException($"{path}:{lineNumber}: empty $meta block.");
                continue;
            }

            var rawEvent = RawEventJson.Deserialize(line)
                ?? throw new InvalidDataException($"{path}:{lineNumber}: could not read event.");
            events.Add(rawEvent);
        }

        if (meta is null)
        {
            throw new InvalidDataException($"{path}: missing $meta first line.");
        }

        if (events.Count == 0)
        {
            throw new InvalidDataException($"{path}: contains no events.");
        }

        return new ScenarioFile(path, meta, events);
    }

    public static IReadOnlyList<ScenarioFile> LoadDirectory(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException(directory);
        }

        return [.. Directory
            .EnumerateFiles(directory, "*.jsonl", SearchOption.TopDirectoryOnly)
            .OrderBy(static file => file, StringComparer.Ordinal)
            .Select(Load)];
    }

    public static string Write(ScenarioMeta meta, IEnumerable<RawEvent> events, string path)
    {
        ArgumentNullException.ThrowIfNull(meta);
        ArgumentNullException.ThrowIfNull(events);

        var directory = Directory.GetParent(path)?.FullName;
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        using var writer = new StreamWriter(path, append: false);
        writer.WriteLine(JsonSerializer.Serialize(new Dictionary<string, ScenarioMeta> { ["$meta"] = meta }, RawEventJson.Options));
        foreach (var rawEvent in events)
        {
            writer.WriteLine(RawEventJson.Serialize(rawEvent));
        }

        return path;
    }
}
