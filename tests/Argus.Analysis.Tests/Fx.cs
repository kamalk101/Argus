namespace Argus.Analysis.Tests;

using Argus.Analysis.Pipeline;
using Argus.Core.Events;
using Argus.Core.Paths;
using Argus.Core.Risk;
using Argus.Core.Sessions;
using Argus.Simulator;

internal static class Fx
{
    public static readonly DateTimeOffset T0 = new(2026, 5, 1, 10, 0, 0, TimeSpan.Zero);

    public const int RootPid = 4312;
    public const string RootPath = @"C:\argus-test\sample.exe";
    public const string StartupDir = @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup";

    public static SensitivePathCatalog Catalog { get; } =
        SensitivePathCatalog.Default(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

    public static RawEvent ProcessStart(int pid, int? parentPid, string image, string? path = null, string? commandLine = null, double seconds = 0) => new()
    {
        Ts = T0.AddSeconds(seconds),
        Kind = EventKind.ProcessStart,
        Pid = pid,
        ParentPid = parentPid,
        ImageName = image,
        ImagePath = path,
        CommandLine = commandLine,
        Source = EventSourceKind.Replay,
    };

    public static RawEvent FileOp(EventKind kind, int pid, string target, double seconds = 1, long? bytesOut = null, FileEffect? effect = null) => new()
    {
        Ts = T0.AddSeconds(seconds),
        Kind = kind,
        Pid = pid,
        Target = target,
        BytesOut = bytesOut,
        FileEffect = effect,
        Source = EventSourceKind.Replay,
    };

    public static RawEvent NetConnect(int pid, string ip, int port, double seconds = 1, string protocol = "tcp") => new()
    {
        Ts = T0.AddSeconds(seconds),
        Kind = EventKind.NetConnect,
        Pid = pid,
        RemoteIp = ip,
        RemotePort = port,
        Protocol = protocol,
        Source = EventSourceKind.Replay,
    };

    public static RawEvent RootStart() => ProcessStart(RootPid, 9999, "sample.exe", RootPath);

    /// <summary>
    /// A process start whose image name is exactly what the sensor reported, which is
    /// sometimes extension-less (live ETW gave ImageFileName="schtasks").
    /// </summary>
    public static RawEvent ProcessStartWithImage(int pid, int? parentPid, string imageName, string? commandLine, double seconds = 0) => new()
    {
        Ts = T0.AddSeconds(seconds),
        Kind = EventKind.ProcessStart,
        Pid = pid,
        ParentPid = parentPid,
        ImageName = imageName,
        CommandLine = commandLine,
        Source = EventSourceKind.Replay,
    };

    /// <summary>A registry value write, as the kernel registry provider reports it.</summary>
    public static RawEvent RegistryOp(int pid, string key, double seconds = 1, EventKind kind = EventKind.RegistrySetValue) => new()
    {
        Ts = T0.AddSeconds(seconds),
        Kind = kind,
        Pid = pid,
        Target = key,
        Source = EventSourceKind.Replay,
    };

    /// <summary>
    /// A burst of file creates (or writes/opens, per <paramref name="kind"/> and
    /// <paramref name="effect"/>) spread evenly over <paramref name="span"/> seconds.
    /// </summary>
    public static RawEvent Rename(int pid, string previousPath, string path, double seconds = 1) => new()
    {
        Ts = T0.AddSeconds(seconds),
        Kind = EventKind.FileRename,
        Pid = pid,
        Target = path,
        PreviousPath = previousPath,
        Source = EventSourceKind.Replay,
    };

    /// <summary>
    /// Marker-appending renames spread over directories: the shape F-006 looks for.
    /// </summary>
    public static IEnumerable<RawEvent> MarkerRenames(
        int count,
        double seconds,
        double span,
        int directories = 8,
        string extension = "docx",
        string marker = "locked")
    {
        var step = count > 1 ? span / (count - 1) : 0;
        for (var i = 0; i < count; i++)
        {
            var directory = i % directories;
            var name = $"file{i:D3}.{extension}";
            var root = $@"C:\argus-test\docs\dir{directory}\";
            yield return Rename(RootPid, root + name, root + name + "." + marker, seconds + (i * step));
        }
    }

    public static IEnumerable<RawEvent> MassCreates(
        int count,
        double seconds,
        double span,
        EventKind kind = EventKind.FileCreate,
        FileEffect? effect = FileEffect.CreatedOrTruncated)
    {
        var step = count > 1 ? span / (count - 1) : 0;
        for (var i = 0; i < count; i++)
        {
            yield return FileOp(kind, RootPid, $@"C:\argus-test\bulk\f{i:D4}.dat", seconds + (i * step), effect: effect);
        }
    }

    public static (SessionSnapshot Snapshot, IReadOnlyList<BehaviorEvent> Events) Run(
        IEnumerable<RawEvent> events,
        TimeSpan? mergeWindow = null,
        RiskOptions? risk = null,
        string? rootImagePath = null)
    {
        var pipeline = new SessionPipeline(new SessionPipelineOptions
        {
            SessionId = Guid.Parse("11111111-2222-3333-4444-555555555555"),
            RootPid = RootPid,
            RootImagePath = rootImagePath ?? RootPath,
            Catalog = Catalog,
            MergeWindow = mergeWindow ?? TimeSpan.FromMinutes(5),
            Risk = risk ?? RiskOptions.Default,
        });

        var seen = new List<BehaviorEvent>();
        foreach (var rawEvent in events)
        {
            seen.Add(pipeline.Ingest(rawEvent).Event);
        }

        return (pipeline.Snapshot(), seen);
    }

    public static IReadOnlyList<string> RulesOf(SessionSnapshot snapshot) =>
        [.. snapshot.Detections.Select(d => d.RuleId).Distinct(StringComparer.Ordinal).OrderBy(id => id, StringComparer.Ordinal)];
}

internal static class RepoPaths
{
    public static string Root { get; } = FindRoot();

    public static string Scenarios => Path.Combine(Root, "tests", "fixtures", "scenarios");

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "tests", "fixtures", "scenarios")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("Repository root (tests/fixtures/scenarios) not found.");
    }
}
