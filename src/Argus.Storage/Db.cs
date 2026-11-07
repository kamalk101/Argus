namespace Argus.Storage;

using System.Globalization;

/// <summary>
/// Small conversion helpers. Timestamps are stored as round-trip UTC text so
/// range queries are also lexicographic comparisons, and enums as names so the
/// database stays readable during investigation.
/// </summary>
internal static class Db
{
    public static object OrNull(object? value) => value ?? DBNull.Value;

    public static string Text(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    public static string? TextOrNull(DateTimeOffset? value) =>
        value?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    public static DateTimeOffset ParseTime(object value) =>
        DateTimeOffset.Parse((string)value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    public static DateTimeOffset? ParseTimeOrNull(object value) =>
        value is DBNull ? null : ParseTime(value);

    public static TEnum ParseEnum<TEnum>(object value)
        where TEnum : struct, Enum =>
        Enum.Parse<TEnum>((string)value, ignoreCase: true);

    public static int Bool(bool value) => value ? 1 : 0;

    public static string? TextOrNull(string? value) => string.IsNullOrEmpty(value) ? null : value;
}
