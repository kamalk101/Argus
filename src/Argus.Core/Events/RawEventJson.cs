namespace Argus.Core.Events;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// The recorded-session format: one compact JSON object per line. This is the
/// same file the Windows collector writes, which is what makes "replay the real
/// session on Linux" possible.
/// </summary>
public static class RawEventJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        WriteIndented = false,
    };

    public static string Serialize(RawEvent rawEvent) =>
        JsonSerializer.Serialize(rawEvent, Options);

    public static RawEvent? Deserialize(string line) =>
        string.IsNullOrWhiteSpace(line) ? null : JsonSerializer.Deserialize<RawEvent>(line, Options);

    public static IEnumerable<RawEvent> ReadAll(TextReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            var rawEvent = Deserialize(line);
            if (rawEvent is not null)
            {
                yield return rawEvent;
            }
        }
    }
}
