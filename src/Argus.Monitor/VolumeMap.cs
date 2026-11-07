namespace Argus.Monitor;

using System.Text;
using Argus.Core.Paths;

/// <summary>
/// Maps ETW device paths (<c>\Device\HarddiskVolume3\...</c>) to drive-letter
/// paths once at startup. Unknown volumes are returned unchanged so the UI can
/// still show exactly what the sensor saw.
/// </summary>
public sealed class VolumeMap
{
    private readonly Dictionary<string, string> _devices;

    private VolumeMap(Dictionary<string, string> devices)
    {
        _devices = devices;
    }

    public IReadOnlyDictionary<string, string> Devices => _devices;

    public static VolumeMap Empty { get; } = new(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

    public static VolumeMap Build()
    {
        var devices = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var target = new StringBuilder(1024);

        for (var letter = 'A'; letter <= 'Z'; letter++)
        {
            target.Clear();
            var device = $"{letter}:";
            var length = NativeMethods.QueryDosDeviceW(device, target, target.Capacity);
            if (length == 0)
            {
                continue;
            }

            var value = target.ToString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                devices[value.TrimEnd('\0')] = device;
            }

            devices[@"\??\" + device] = device;
        }

        return new VolumeMap(devices);
    }

    public string Resolve(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        var value = path.Trim();

        if (value.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            value = value[4..];
        }

        if (value.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            value = value[4..];
        }

        if (value.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            value = windows + value[@"\SystemRoot".Length..];
        }

        return PathKey.FromDevicePath(value, _devices);
    }
}
