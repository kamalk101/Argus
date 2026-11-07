namespace Argus.Cli;

using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Argus.Analysis.Pipeline;
using Argus.Analysis.Rules;
using Argus.Core.Events;
using Argus.Core.Paths;
using Argus.Core.Risk;
using Argus.Simulator;

public static class Program
{
    private const string Usage = """
        argus — real-time behaviour analysis harness

        Usage:
          argus replay <file-or-dir> [--assert] [--json] [--db <path>] [--verbose]
          argus rules [--json]
          argus selftest [--fixtures <dir>] [--load <count>]

        Commands:
          replay     Run recorded scenarios through the production pipeline.
                     --assert  fail with exit code 1 when expectations do not hold
                     --db      persist sessions, events, detections and scores to SQLite
          rules      Print the shipped rule catalogue
          selftest   Replay every fixture and assert the expectations, then measure
                     synthetic pipeline throughput

        Exit codes: 0 ok, 1 assertion failure, 2 usage error, 3 unexpected error.
        """;

    private static readonly HashSet<string> BooleanFlags = new(StringComparer.OrdinalIgnoreCase)
    {
        "assert", "json", "verbose", "help",
    };

    public static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0 || args.Any(static arg => arg is "--help" or "-h" or "help"))
            {
                Console.WriteLine(Usage);
                return args.Length == 0 ? 2 : 0;
            }

            var parsed = ParseArguments(args[1..]);
            return args[0].ToLowerInvariant() switch
            {
                "replay" => Replay(parsed),
                "rules" => PrintRules(parsed),
                "selftest" => SelfTest(parsed),
                _ => Fail($"Unknown command '{args[0]}'.\n\n{Usage}"),
            };
        }
        catch (UsageException exception)
        {
            return Fail(exception.Message);
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or JsonException)
        {
            Console.Error.WriteLine($"error: {exception.Message}");
            return 3;
        }
    }

    private static int Replay(ParsedArguments arguments)
    {
        var target = arguments.Positional.FirstOrDefault()
            ?? throw new UsageException("replay requires a scenario file or directory.");

        var scenarios = Directory.Exists(target)
            ? ScenarioLoader.LoadDirectory(target)
            : [ScenarioLoader.Load(target)];

        if (scenarios.Count == 0)
        {
            throw new UsageException($"No .jsonl scenarios found in {target}.");
        }

        var assertionMode = arguments.HasFlag("assert");
        var json = arguments.HasFlag("json");
        var databasePath = arguments.Value("db");
        var verbose = arguments.HasFlag("verbose");

        SessionWriter? writer = databasePath is null ? null : new SessionWriter(databasePath);
        var failures = 0;
        var results = new List<object>();

        Console.WriteLine(
            $"{"scenario",-34}{"band",-12}{"risk",6}{"peak",7}{"events",8}{"dets",6}{"gaps",6}  rules");
        Console.WriteLine(new string('-', 104));

        try
        {
            foreach (var scenario in scenarios)
            {
                var run = ScenarioRunner.Run(scenario);
                var assertion = ScenarioRunner.Verify(run);
                if (!assertion.Passed)
                {
                    failures++;
                }

                var snapshot = run.Snapshot;
                Console.WriteLine(
                    $"{Truncate(scenario.Meta.Name, 33),-34}{snapshot.Risk.Band,-12}"
                    + $"{snapshot.Risk.Score,6:0.0}{snapshot.Risk.PeakScore,7:0.0}"
                    + $"{run.Events.Count,8}{snapshot.Detections.Count,6}{snapshot.Gaps.Count,6}"
                    + $"  {string.Join(',', run.RuleIds)}");

                if (verbose)
                {
                    foreach (var detection in snapshot.Detections)
                    {
                        Console.WriteLine(
                            $"    [{detection.RuleId}] {detection.Title} — {detection.Reason}");
                    }

                    Console.WriteLine($"    score: {snapshot.Risk.Explanation}");
                }

                if (!assertion.Passed)
                {
                    Console.WriteLine("    " + assertion.Describe(scenario.Meta.Name).Replace("\n", "\n    ", StringComparison.Ordinal));
                }

                writer?.Persist(run);

                results.Add(new
                {
                    name = scenario.Meta.Name,
                    @file = Path.GetFileName(scenario.Path),
                    band = snapshot.Risk.Band.ToString(),
                    risk = snapshot.Risk.Score,
                    peak = snapshot.Risk.PeakScore,
                    events = run.Events.Count,
                    inScope = snapshot.Counters.EventsInScope,
                    outOfScope = snapshot.Counters.EventsOutsideScope,
                    detections = snapshot.Detections.Select(d => new
                    {
                        rule = d.RuleId,
                        title = d.Title,
                        severity = d.Severity,
                        confidence = Math.Round(d.Confidence, 3),
                        status = d.StatusText,
                        events = d.EventCount,
                    }),
                    gaps = snapshot.Gaps.Count,
                    passed = assertion.Passed,
                    failures = assertion.Failures,
                });
            }
        }
        finally
        {
            writer?.Dispose();
        }

        if (json)
        {
            Console.WriteLine(JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));
        }

        Console.WriteLine();
        Console.WriteLine($"{scenarios.Count - failures}/{scenarios.Count} scenarios matched their expectations.");
        if (databasePath is not null)
        {
            Console.WriteLine($"Sessions written to {databasePath}");
        }

        return assertionMode && failures > 0 ? 1 : 0;
    }

    private static int PrintRules(ParsedArguments arguments)
    {
        var catalog = RuleCatalog.CreateDefault();
        var rows = catalog.All
            .OrderBy(rule => rule.Metadata.Id, StringComparer.Ordinal)
            .Select(rule => new
            {
                id = rule.Metadata.Id,
                title = rule.Metadata.Title,
                severity = rule.Metadata.Severity,
                categories = EvidenceCategories.Describe(rule.Metadata.Categories),
                mitre = rule.Metadata.Mitre,
                kind = rule is ICorrelatedRule ? "correlated" : "per-event",
                description = rule.Metadata.Description,
            })
            .ToList();

        if (arguments.HasFlag("json"))
        {
            Console.WriteLine(JsonSerializer.Serialize(rows, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }

        Console.WriteLine($"{"id",-7}{"sev",4}  {"title",-44}{"categories",-18}mitre");
        Console.WriteLine(new string('-', 96));
        foreach (var row in rows)
        {
            Console.WriteLine(
                $"{row.id,-7}{row.severity,4}  {Truncate(row.title, 43),-44}"
                + $"{row.categories,-18}{string.Join(',', row.mitre)}");
        }

        return 0;
    }

    private static int SelfTest(ParsedArguments arguments)
    {
        var fixtures = arguments.Value("fixtures") ?? "tests/fixtures/scenarios";
        var scenarios = ScenarioLoader.LoadDirectory(fixtures);

        Console.WriteLine($"argus selftest — {scenarios.Count} fixtures from {fixtures}");
        var failures = 0;

        foreach (var scenario in scenarios)
        {
            var run = ScenarioRunner.Run(scenario);
            var assertion = ScenarioRunner.Verify(run);
            if (!assertion.Passed)
            {
                failures++;
                Console.WriteLine(assertion.Describe(scenario.Meta.Name));
            }
            else
            {
                Console.WriteLine(
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"  pass  {scenario.Meta.Name,-40} {run.Snapshot.Risk.Band,-11} {run.Snapshot.Risk.Score,6:0.0}  {string.Join(',', run.RuleIds)}"));
            }
        }

        var load = arguments.Value("load") is { } loadText && int.TryParse(loadText, CultureInfo.InvariantCulture, out var parsedLoad)
            ? parsedLoad
            : 20_000;

        if (load > 0)
        {
            MeasureThroughput(load);
        }

        Console.WriteLine();
        Console.WriteLine(failures == 0
            ? $"selftest passed ({scenarios.Count} scenarios)."
            : $"selftest FAILED ({failures}/{scenarios.Count} scenarios).");

        return failures == 0 ? 0 : 1;
    }

    private static void MeasureThroughput(int count)
    {
        var catalog = ScenarioRunner.DefaultCatalog;
        var pipeline = new SessionPipeline(new SessionPipelineOptions
        {
            SessionId = Guid.NewGuid(),
            RootPid = 4000,
            RootImagePath = @"C:\argus-test\sample.exe",
            Catalog = catalog,
        });

        var start = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

        var stopwatch = Stopwatch.StartNew();
        for (var i = 0; i < count; i++)
        {
            var isProcess = i % 50 == 0;
            var raw = new RawEvent
            {
                Ts = start.AddMilliseconds(i * 2),
                Kind = isProcess ? EventKind.ProcessStart : EventKind.FileWrite,
                Pid = isProcess ? 4000 + (i / 50 % 10) : 4000,
                ParentPid = isProcess ? 4000 : null,
                ImageName = isProcess ? "worker.exe" : null,
                Target = isProcess ? null : $@"C:\argus-test\out\file-{i % 500}.dat",
                Source = EventSourceKind.Simulated,
            };

            pipeline.Ingest(raw);
        }

        stopwatch.Stop();
        var snapshot = pipeline.Snapshot();
        var perSecond = count / Math.Max(stopwatch.Elapsed.TotalSeconds, 0.0001);
        Console.WriteLine(
            string.Create(
                CultureInfo.InvariantCulture,
                $"  load  {count} synthetic events in {stopwatch.Elapsed.TotalMilliseconds:0} ms "
                + $"({perSecond:0} events/s), risk {snapshot.Risk.Score:0.0} {snapshot.Risk.Band}"));
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 2;
    }

    private static string Truncate(string value, int width) =>
        value.Length <= width ? value : value[..Math.Max(0, width - 1)] + "…";

    private static ParsedArguments ParseArguments(string[] args)
    {
        var positional = new List<string>();
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < args.Length; i++)
        {
            var argument = args[i];
            if (!argument.StartsWith("--", StringComparison.Ordinal))
            {
                positional.Add(argument);
                continue;
            }

            var name = argument[2..];
            if (BooleanFlags.Contains(name))
            {
                flags.Add(name);
                continue;
            }

            if (i + 1 >= args.Length)
            {
                throw new UsageException($"Option --{name} requires a value.");
            }

            values[name] = args[++i];
        }

        return new ParsedArguments(positional, values, flags);
    }

    private sealed record ParsedArguments(
        IReadOnlyList<string> Positional,
        IReadOnlyDictionary<string, string?> Values,
        IReadOnlySet<string> Flags)
    {
        public bool HasFlag(string name) => Flags.Contains(name);

        public string? Value(string name) => Values.TryGetValue(name, out var value) ? value : null;
    }

    private sealed class UsageException(string message) : Exception(message);
}
