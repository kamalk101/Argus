namespace Argus.Analysis.Rules;

using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// The numbers the aggregated rules fire on, as data rather than buried constants.
///
/// Two reasons this exists. A profile is allowed to disagree with our defaults without a
/// rebuild, and — more useful day to day — the number that actually fired becomes something
/// the report can print instead of something the reader has to look up in source.
///
/// Defaults here are the shipped catalogue values. Loading rejects unknown keys rather than
/// ignoring them: a typo in a settings file must fail loudly, not quietly leave the default
/// in place while the operator believes they changed it.
/// </summary>
public sealed record RuleSettings
{
    /// <summary>Files created within the window before F-004 reports the rate.</summary>
    public int MassFileCreationCount { get; init; } = 200;

    public double MassFileCreationWindowSeconds { get; init; } = 60;

    /// <summary>Marker-appending renames before F-006 reports a burst.</summary>
    public int DestructiveRenameCount { get; init; } = 10;

    /// <summary>Directories a burst must span, so one folder renaming itself is not a wiper.</summary>
    public int DestructiveRenameDirectories { get; init; } = 5;

    public double DestructiveRenameWindowSeconds { get; init; } = 60;

    /// <summary>Callbacks needed before N-002 will talk about an interval at all.</summary>
    public int BeaconConnections { get; init; } = 6;

    public double BeaconWindowSeconds { get; init; } = 600;

    /// <summary>Below this mean interval, connections are load rather than a timer.</summary>
    public double BeaconMinMeanIntervalSeconds { get; init; } = 5;

    /// <summary>Coefficient of variation of the intervals that still counts as regular.</summary>
    public double BeaconMaxJitter { get; init; } = 0.15;

    /// <summary>Distinct switches on one image before P-006 mentions the pattern.</summary>
    public int RepeatedFlagsThreshold { get; init; } = 3;

    public double RepeatedFlagsWindowSeconds { get; init; } = 600;

    /// <summary>Bytes to one public address within the window before N-003 reports a transfer.</summary>
    public long OutboundVolumeBytes { get; init; } = 20L * 1024 * 1024;

    public double OutboundVolumeWindowSeconds { get; init; } = 60;

    public static RuleSettings Default { get; } = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static RuleSettings Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!File.Exists(path))
        {
            throw new InvalidDataException($"Rule settings file not found: {path}");
        }

        return FromJson(File.ReadAllText(path), path);
    }

    public static RuleSettings FromJson(string json, string? origin = null)
    {
        ArgumentNullException.ThrowIfNull(json);

        RuleSettings settings;
        try
        {
            settings = JsonSerializer.Deserialize<RuleSettings>(json, JsonOptions) ?? new RuleSettings();
        }
        catch (JsonException exception)
        {
            var where = origin is null ? string.Empty : $" in {origin}";
            throw new InvalidDataException($"Rule settings are not valid JSON{where}: {exception.Message}", exception);
        }

        settings.Validate(origin);
        return settings;
    }

    /// <summary>
    /// Refuses values a rule cannot act on. A threshold of zero would fire on every event and a
    /// negative window would silently match nothing, so both are errors rather than surprises.
    /// </summary>
    public void Validate(string? origin = null)
    {
        var where = origin is null ? string.Empty : $" in {origin}";

        RequirePositive(MassFileCreationCount, nameof(MassFileCreationCount));
        RequirePositive(MassFileCreationWindowSeconds, nameof(MassFileCreationWindowSeconds));
        RequirePositive(DestructiveRenameCount, nameof(DestructiveRenameCount));
        RequirePositive(DestructiveRenameDirectories, nameof(DestructiveRenameDirectories));
        RequirePositive(DestructiveRenameWindowSeconds, nameof(DestructiveRenameWindowSeconds));
        RequirePositive(BeaconConnections, nameof(BeaconConnections));
        RequirePositive(BeaconWindowSeconds, nameof(BeaconWindowSeconds));
        RequirePositive(BeaconMinMeanIntervalSeconds, nameof(BeaconMinMeanIntervalSeconds));
        RequirePositive(RepeatedFlagsThreshold, nameof(RepeatedFlagsThreshold));
        RequirePositive(RepeatedFlagsWindowSeconds, nameof(RepeatedFlagsWindowSeconds));
        RequirePositive(OutboundVolumeBytes, nameof(OutboundVolumeBytes));
        RequirePositive(OutboundVolumeWindowSeconds, nameof(OutboundVolumeWindowSeconds));

        if (BeaconMaxJitter <= 0 || BeaconMaxJitter >= 1)
        {
            throw new InvalidDataException(
                $"Rule settings{where}: BeaconMaxJitter must be between 0 and 1 (it is a coefficient of variation, not a percentage), got {BeaconMaxJitter.ToString(CultureInfo.InvariantCulture)}.");
        }

        return;

        void RequirePositive(double value, string name)
        {
            if (!(value > 0) || double.IsInfinity(value))
            {
                throw new InvalidDataException(
                    $"Rule settings{where}: {name} must be greater than zero, got {value.ToString(CultureInfo.InvariantCulture)}.");
            }
        }
    }
}
