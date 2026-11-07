namespace Argus.Core.Tests;

using Argus.Core.Paths;
using Xunit;

public sealed class PathKeyTests
{
    [Theory]
    [InlineData(@"C:\Windows\System32\Kernel32.dll", @"c:\windows\system32\kernel32.dll")]
    [InlineData("C:/Windows/System32/", @"c:\windows\system32")]
    [InlineData(@"  ""C:\Temp\a.txt""  ", @"c:\temp\a.txt")]
    [InlineData(@"C:\Temp\\a.txt", @"c:\temp\a.txt")]
    [InlineData(@"\\Server\Share\File.txt", @"\\server\share\file.txt")]
    [InlineData("", "")]
    public void Canonicalize_normalises_windows_paths(string input, string expected) =>
        Assert.Equal(expected, PathKey.Canonicalize(input));

    [Theory]
    [InlineData(@"c:\windows\system32\a.dll", @"c:\windows\system32", true)]
    [InlineData(@"c:\windows\system32", @"c:\windows\system32", true)]
    [InlineData(@"c:\windows\system32x\a.dll", @"c:\windows\system32", false)]
    [InlineData(@"c:\windows", @"c:\windows\system32", false)]
    [InlineData(@"c:\argus-test\..\other", @"c:\argus-test", false)]
    public void IsUnder_respects_directory_boundaries(string path, string prefix, bool expected) =>
        Assert.Equal(expected, PathKey.IsUnder(PathKey.Canonicalize(path), PathKey.Canonicalize(prefix)));

    [Fact]
    public void Parts_are_extracted_from_canonical_form()
    {
        var key = PathKey.Canonicalize(@"C:\Users\Public\payload.EXE");

        Assert.Equal("payload.exe", PathKey.FileName(key));
        Assert.Equal(".exe", PathKey.Extension(key));
        Assert.Equal(@"c:\users\public", PathKey.DirectoryName(key));
    }

    [Fact]
    public void FromDevicePath_maps_known_volume()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [@"\Device\HarddiskVolume3"] = @"C:",
        };

        var mapped = PathKey.FromDevicePath(@"\Device\HarddiskVolume3\Windows\notepad.exe", map);

        Assert.Equal(@"C:\Windows\notepad.exe", mapped);
    }

    [Fact]
    public void FromDevicePath_prefers_the_longest_device_prefix()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [@"\Device\HarddiskVolume1"] = @"C:",
            [@"\Device\HarddiskVolume10"] = @"D:",
        };

        Assert.Equal(
            @"D:\Temp\x.exe",
            PathKey.FromDevicePath(@"\Device\HarddiskVolume10\Temp\x.exe", map));
        Assert.Equal(
            @"C:\Temp\x.exe",
            PathKey.FromDevicePath(@"\Device\HarddiskVolume1\Temp\x.exe", map));
    }

    [Fact]
    public void FromDevicePath_leaves_unknown_volume_visible()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        Assert.Equal(
            @"\Device\HarddiskVolume9\x.exe",
            PathKey.FromDevicePath(@"\Device\HarddiskVolume9\x.exe", map));
    }
}
