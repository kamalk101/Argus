namespace Argus.Core.Tests;

using Argus.Core.Events;
using Argus.Core.Network;
using Argus.Core.Paths;
using Xunit;

public sealed class EventAndCatalogTests
{
    [Fact]
    public void Normalizer_assigns_sequence_and_derives_category_and_path()
    {
        var normalizer = new EventNormalizer(Guid.NewGuid());
        var raw = new RawEvent
        {
            Ts = new DateTimeOffset(2026, 5, 1, 10, 0, 0, TimeSpan.Zero),
            Kind = EventKind.FileWrite,
            Pid = 4312,
            Target = @"C:\Argus-Test\Out\File.TXT",
            Source = EventSourceKind.Replay,
        };

        var first = normalizer.Normalize(raw);
        var second = normalizer.Normalize(raw);

        Assert.Equal(1, first.Seq);
        Assert.Equal(2, second.Seq);
        Assert.Equal(EventCategory.File, first.Category);
        Assert.Equal(@"c:\argus-test\out\file.txt", first.PathKey);
        Assert.Equal(Observability.Direct, first.Observability);
        Assert.Equal(0.9, first.Confidence, 3);
    }

    [Fact]
    public void Normalizer_keeps_inferred_confidence_low()
    {
        var normalizer = new EventNormalizer(Guid.NewGuid());
        var behaviorEvent = normalizer.Normalize(new RawEvent
        {
            Ts = DateTimeOffset.UnixEpoch,
            Kind = EventKind.ProcessStart,
            Pid = 1,
            Observability = Observability.Inferred,
        });

        Assert.Equal(0.5, behaviorEvent.Confidence, 3);
    }

    [Fact]
    public void Catalog_matches_persistence_and_prefers_specific_entry()
    {
        var catalog = SensitivePathCatalog.Default(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

        Assert.True(catalog.TryMatch(
            PathKey.Canonicalize(@"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk"),
            out var persistence));
        Assert.Equal("persistence", persistence.Group);

        Assert.True(catalog.TryMatch(PathKey.Canonicalize(@"C:\Windows\System32\drivers\evil.sys"), out var driver));
        Assert.Equal("Kernel drivers", driver.Label);

        Assert.True(catalog.TryMatch(PathKey.Canonicalize(@"C:\argus-test\out\file.txt"), out var fixture));
        Assert.Equal("test", fixture.Group);
    }

    [Fact]
    public void Catalog_skips_entries_with_unresolved_environment_variables()
    {
        var catalog = SensitivePathCatalog.Default(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

        Assert.DoesNotContain(catalog.Entries, entry => entry.Group == "credentials");
        Assert.All(catalog.Entries, entry => Assert.DoesNotContain("%", entry.Prefix));
    }

    [Fact]
    public void Catalog_expands_environment_templates()
    {
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["APPDATA"] = @"C:\Users\test\AppData\Roaming",
        };

        var expanded = SensitivePathCatalog.Expand(
            @"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
            environment);

        Assert.Equal(@"C:\Users\test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup", expanded);
    }

    [Theory]
    [InlineData("10.1.2.3", IpScope.Private)]
    [InlineData("172.20.0.1", IpScope.Private)]
    [InlineData("192.168.1.10", IpScope.Private)]
    [InlineData("127.0.0.1", IpScope.Loopback)]
    [InlineData("169.254.1.1", IpScope.LinkLocal)]
    [InlineData("100.64.8.8", IpScope.Cgnat)]
    [InlineData("203.0.113.7", IpScope.Public)]
    [InlineData("::1", IpScope.Loopback)]
    [InlineData("not-an-ip", IpScope.Invalid)]
    public void Addresses_are_classified_offline(string address, IpScope expected) =>
        Assert.Equal(expected, IpAddressClassifier.Classify(address));

    [Fact]
    public void Only_public_addresses_are_external()
    {
        Assert.True(IpAddressClassifier.IsExternal("8.8.8.8"));
        Assert.False(IpAddressClassifier.IsExternal("192.168.0.10"));
        Assert.False(IpAddressClassifier.IsExternal("127.0.0.1"));
    }
}
