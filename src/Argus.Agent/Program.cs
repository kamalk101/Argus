namespace Argus.Agent;

using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Argus.Core.Events;
using Argus.Core.Risk;
using Argus.Monitor;
using Argus.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            var options = AgentOptions.Parse(args);

            if (options.SelfTest)
            {
                return await AgentSelfTest.RunAsync(options).ConfigureAwait(false);
            }

            if (!OperatingSystem.IsWindows())
            {
                Console.Error.WriteLine("argus-agent: this build targets Windows 10/11.");
                return 3;
            }

            if (!AgentInfo.IsElevated && !options.AllowNonElevated)
            {
                if (options.Elevate)
                {
                    return await Elevation.LaunchAsync(options).ConfigureAwait(false);
                }

                Console.Error.WriteLine(
                    "argus-agent: administrator rights are required for ETW kernel monitoring.\n"
                    + "Re-run with --elevate (UAC prompt) or from an elevated PowerShell. "
                    + "For a degraded, polling-only diagnostic run, add --allow-non-elevated.");
                return 3;
            }

            return await RunAsync(options).ConfigureAwait(false);
        }
        catch (UsageException exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 2;
        }
        catch (VersionRequestedException)
        {
            Console.WriteLine("argus-agent " + AgentInfo.Version);
            return 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Console.Error.WriteLine("argus-agent: " + exception.Message);
            return 3;
        }
    }

    private static async Task<int> RunAsync(AgentOptions options)
    {
        var token = options.Token ?? RandomNumberGenerator.GetHexString(32);
        var hub = new SseHub();
        var manager = new SessionManager(hub, options);

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = [],
            ContentRootPath = AppContext.BaseDirectory,
        });

        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, options.Port));
        builder.Services.ConfigureHttpJsonOptions(json =>
        {
            json.SerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        });
        builder.Services.AddSingleton(hub);
        builder.Services.AddSingleton(manager);

        var app = builder.Build();
        var actualPort = 0;

        app.Use(async (context, next) =>
        {
            if (!IsExpectedHost(context.Request, actualPort))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsJsonAsync(new { error = "unexpected Host header" }).ConfigureAwait(false);
                return;
            }

            var origin = context.Request.Headers.Origin.ToString();
            if (!string.IsNullOrEmpty(origin)
                && !string.Equals(origin, $"http://127.0.0.1:{actualPort}", StringComparison.Ordinal))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new { error = "unexpected Origin" }).ConfigureAwait(false);
                return;
            }

            if (context.Request.Path.StartsWithSegments("/api")
                && !context.Request.Path.StartsWithSegments("/api/health"))
            {
                var authorization = context.Request.Headers.Authorization.ToString();
                if (!TokenEquals(authorization, token))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsJsonAsync(new { error = "bearer token required" }).ConfigureAwait(false);
                    return;
                }
            }

            await next().ConfigureAwait(false);
        });

        app.MapGet("/", () => Results.Json(new
        {
            name = "Argus agent",
            version = AgentInfo.Version,
            api = "/api/health",
            note = "All /api routes except /api/health require Authorization: Bearer <token>.",
        }, AgentJson.Options));

        app.MapGet("/api/health", () =>
        {
            var active = manager.Active;
            if (active is not null)
            {
                return Results.Json(active.Health(), AgentJson.Options);
            }

            return Results.Json(new HealthDto(
                "ok",
                AgentInfo.Version,
                AgentInfo.IsElevated,
                Environment.ProcessId,
                Environment.OSVersion.VersionString,
                false,
                false,
                false,
                false,
                0,
                null,
                null,
                null,
                null,
                null), AgentJson.Options);
        });

        app.MapGet("/api/sessions", () =>
            Results.Json(manager.Sessions.Select(session => session.State()).ToArray(), AgentJson.Options));

        app.MapPost("/api/sessions", async (StartSessionRequest request) =>
        {
            try
            {
                var session = await manager.StartAsync(request.Path, request.Args, request.Mode ?? "launch").ConfigureAwait(false);
                return Results.Json(session.State(), AgentJson.Options);
            }
            catch (InvalidOperationException exception)
            {
                return Results.Conflict(new { error = exception.Message });
            }
            catch (FileNotFoundException exception)
            {
                return Results.NotFound(new { error = exception.Message, path = exception.FileName });
            }
        });

        app.MapGet("/api/sessions/{id:guid}", (Guid id) =>
        {
            var session = manager.Get(id);
            return session is null
                ? Results.NotFound(new { error = "session not found" })
                : Results.Json(new { state = session.State(), record = session.Record() }, AgentJson.Options);
        });

        app.MapPost("/api/sessions/{id:guid}/stop", async (Guid id, HttpContext context) =>
        {
            var terminate = bool.TryParse(context.Request.Query["terminate"], out var parsed) && parsed;
            var session = manager.Get(id);
            if (session is null)
            {
                return Results.NotFound(new { error = "session not found" });
            }

            await manager.StopAsync(id, terminate).ConfigureAwait(false);
            return Results.Json(session.State(), AgentJson.Options);
        });

        app.MapGet("/api/sessions/{id:guid}/events", (Guid id, HttpContext context) =>
        {
            var session = manager.Get(id);
            if (session is null)
            {
                return Results.NotFound(new { error = "session not found" });
            }

            if (context.Request.Query["q"].ToString() is { Length: > 0 } search)
            {
                return Results.Json(session.Search(search, ParseLimit(context)).Select(session.ToDto).ToArray(), AgentJson.Options);
            }

            var filter = new EventFilter
            {
                Category = ParseEnum<EventCategory>(context.Request.Query["category"]),
                Kind = ParseEnum<EventKind>(context.Request.Query["kind"]),
                Pid = int.TryParse(context.Request.Query["pid"], NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid) ? pid : null,
                AfterSeq = long.TryParse(context.Request.Query["after"], NumberStyles.Integer, CultureInfo.InvariantCulture, out var after) ? after : null,
                Text = context.Request.Query["text"].ToString() is { Length: > 0 } text ? text : null,
                Limit = ParseLimit(context),
                InScopeOnly = !string.Equals(context.Request.Query["inScope"], "false", StringComparison.OrdinalIgnoreCase),
            };

            return Results.Json(session.EventsPage(filter).Select(session.ToDto).ToArray(), AgentJson.Options);
        });

        app.MapGet("/api/sessions/{id:guid}/processes", (Guid id) =>
        {
            var session = manager.Get(id);
            return session is null
                ? Results.NotFound(new { error = "session not found" })
                : Results.Json(session.ProcessDtos(), AgentJson.Options);
        });

        app.MapGet("/api/sessions/{id:guid}/detections", (Guid id) =>
        {
            var session = manager.Get(id);
            return session is null
                ? Results.NotFound(new { error = "session not found" })
                : Results.Json(session.DetectionList(), AgentJson.Options);
        });

        app.MapGet("/api/sessions/{id:guid}/detections/{key}", (Guid id, string key) =>
        {
            var session = manager.Get(id);
            if (session is null)
            {
                return Results.NotFound(new { error = "session not found" });
            }

            var detection = session.Detection(Uri.UnescapeDataString(key));
            if (detection is null)
            {
                return Results.NotFound(new { error = "detection not found" });
            }

            var evidence = session.Evidence(detection.Id);
            return Results.Json(new
            {
                detection,
                evidenceSeq = evidence,
                events = session.ToDtoList(session.EventsByIds(evidence)),
            }, AgentJson.Options);
        });

        app.MapGet("/api/sessions/{id:guid}/timeline", (Guid id, HttpContext context) =>
        {
            var session = manager.Get(id);
            if (session is null)
            {
                return Results.NotFound(new { error = "session not found" });
            }

            var events = session.EventsPage(new EventFilter { Limit = ParseLimit(context), InScopeOnly = true })
                .Select(session.ToDto)
                .ToArray();

            var detections = session.DetectionList().Select(detection => new
            {
                detection.RuleId,
                detection.Title,
                detection.Severity,
                detection.FirstSeenUtc,
                detection.LastSeenUtc,
                detection.EventCount,
                detection.Reason,
            }).ToArray();

            return Results.Json(new { events, detections }, AgentJson.Options);
        });

        app.MapGet("/api/sessions/{id:guid}/stream", async (HttpContext context, Guid id) =>
        {
            var session = manager.Get(id);
            if (session is null)
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            context.Response.Headers.ContentType = "text/event-stream";
            context.Response.Headers.CacheControl = "no-cache";
            context.Response.Headers["X-Accel-Buffering"] = "no";

            var (subscriber, reader) = hub.Subscribe();
            try
            {
                await WriteSseAsync(context, "state", JsonSerializer.Serialize(session.State(), AgentJson.Options)).ConfigureAwait(false);
                await WriteSseAsync(context, "stats", JsonSerializer.Serialize(session.Health(), AgentJson.Options)).ConfigureAwait(false);

                await foreach (var message in reader.ReadAllAsync(context.RequestAborted).ConfigureAwait(false))
                {
                    await WriteSseAsync(context, message.Type, message.Json).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                // Client disconnected.
            }
            finally
            {
                hub.Unsubscribe(subscriber);
            }
        });

        app.MapGet("/api/sessions/{id:guid}/report.json", (Guid id) =>
        {
            var session = manager.Get(id);
            return session is null
                ? Results.NotFound(new { error = "session not found" })
                : Results.Json(BuildReport(session), AgentJson.Options);
        });

        app.MapGet("/api/sessions/{id:guid}/report.html", (Guid id) =>
        {
            var session = manager.Get(id);
            return session is null
                ? Results.NotFound(new { error = "session not found" })
                : Results.Content(BuildHtmlReport(session), "text/html; charset=utf-8");
        });

        await app.StartAsync().ConfigureAwait(false);

        var address = app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()?
            .Addresses.FirstOrDefault();

        if (!Uri.TryCreate(address, UriKind.Absolute, out var uri))
        {
            await app.StopAsync().ConfigureAwait(false);
            Console.Error.WriteLine("argus-agent: Kestrel did not report a loopback address.");
            return 3;
        }

        actualPort = uri.Port;
        var api = $"http://127.0.0.1:{actualPort}";
        LiveSession? active = null;

        try
        {
            if (options.TargetPath is { } target)
            {
                active = await manager.StartAsync(target, options.TargetArguments).ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            await manager.DisposeAsync().ConfigureAwait(false);
            await app.StopAsync().ConfigureAwait(false);
            Console.Error.WriteLine("argus-agent: could not start the session: " + exception.Message);
            return 3;
        }

        var ready = new
        {
            agent = "argus-agent",
            version = AgentInfo.Version,
            api,
            port = actualPort,
            token,
            elevated = AgentInfo.IsElevated,
            sessionId = active?.Id,
            database = active?.DatabasePath,
            record = active?.RecordPath,
            target = active?.TargetPath,
            rootPid = active?.RootPid,
        };

        if (options.ReadyFile is { } readyFile)
        {
            WriteReadyFile(readyFile, ready);
        }

        Console.WriteLine(JsonSerializer.Serialize(ready, AgentJson.Options));

        if (options.DurationSeconds is { } duration)
        {
            _ = Task.Run(async () =>
            {
                await Task.Delay(TimeSpan.FromSeconds(duration)).ConfigureAwait(false);
                await manager.StopAllAsync().ConfigureAwait(false);
                await app.StopAsync().ConfigureAwait(false);
            });
        }

        await app.WaitForShutdownAsync().ConfigureAwait(false);
        await manager.DisposeAsync().ConfigureAwait(false);
        return 0;
    }

    private static bool IsExpectedHost(HttpRequest request, int port)
    {
        if (port == 0)
        {
            return true;
        }

        return request.Host.Host == "127.0.0.1" && request.Host.Port == port;
    }

    private static bool TokenEquals(string provided, string expected)
    {
        var providedBytes = Encoding.UTF8.GetBytes(provided);
        var expectedBytes = Encoding.UTF8.GetBytes("Bearer " + expected);
        return providedBytes.Length == expectedBytes.Length
            && CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes);
    }

    private static async Task WriteSseAsync(HttpContext context, string type, string json)
    {
        await context.Response.WriteAsync($"event: {type}\ndata: {json}\n\n", context.RequestAborted).ConfigureAwait(false);
        await context.Response.Body.FlushAsync(context.RequestAborted).ConfigureAwait(false);
    }

    private static TEnum? ParseEnum<TEnum>(string? text)
        where TEnum : struct, Enum =>
        Enum.TryParse<TEnum>(text, ignoreCase: true, out var value) ? value : null;

    private static int ParseLimit(HttpContext context) =>
        int.TryParse(context.Request.Query["limit"], NumberStyles.Integer, CultureInfo.InvariantCulture, out var limit)
            ? Math.Clamp(limit, 1, 5000)
            : 200;

    private static object BuildReport(LiveSession session)
    {
        var record = session.Record();
        var detections = session.DetectionList();
        var events = session.EventsPage(new EventFilter { Limit = 5000, InScopeOnly = true })
            .Select(session.ToDto)
            .ToArray();

        return new
        {
            generatedUtc = DateTimeOffset.UtcNow,
            agent = AgentInfo.Version,
            session = record,
            state = session.State(),
            processes = session.ProcessDtos(),
            detections,
            scores = session.ScoreHistory(),
            gaps = session.Gaps().Select(gap => new
            {
                timestamp = gap.TimestampUtc,
                source = gap.Source,
                reason = gap.Reason,
                lost = gap.LostCount,
                detail = gap.Detail,
            }).ToArray(),
            events,
            limitations = new[]
            {
                "Near-real-time, not hard real-time: ETW buffering and batching add roughly 1-3 seconds.",
                "Absence of detections means no significant observed indicators, not proof of safety.",
                "Payload content, URLs and encrypted traffic are not visible; only endpoints, timing and volume are recorded.",
                "Injection indicators are inferred unless Sysmon is installed.",
                "Read events may be sampled under volume pressure; gaps are reported in this session.",
            },
        };
    }

    private static string BuildHtmlReport(LiveSession session)
    {
        var state = session.State();
        var detections = session.DetectionList();
        var processes = session.ProcessDtos();
        var score = session.ScoreHistory();
        var builder = new StringBuilder(16_384);

        builder.Append("<!doctype html><html><head><meta charset=\"utf-8\"><title>Argus report</title>");
        builder.Append("<style>body{font-family:Segoe UI,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:32px;line-height:1.45}")
            .Append("table{border-collapse:collapse;width:100%;margin:12px 0 24px}th,td{border:1px solid #30363d;padding:7px 9px;text-align:left;font-size:13px}")
            .Append("th{background:#161b22}.bad{color:#ff7b72}.warn{color:#d29922}.muted{color:#8b949e}</style></head><body>");

        builder.Append("<h1>Argus behaviour report</h1>");
        builder.Append("<p class=\"muted\">Generated ").Append(WebUtility.HtmlEncode(DateTimeOffset.UtcNow.ToString("u", CultureInfo.InvariantCulture))).Append("</p>");
        builder.Append("<p><strong>Target:</strong> ").Append(WebUtility.HtmlEncode(state.TargetPath)).Append("<br>")
            .Append("<strong>Verdict:</strong> ").Append(WebUtility.HtmlEncode(state.Verdict ?? "Benign"))
            .Append(" &nbsp; <strong>Score:</strong> ").Append(state.Score.ToString("0.0", CultureInfo.InvariantCulture))
            .Append(" &nbsp; <strong>Peak:</strong> ").Append(state.PeakScore.ToString("0.0", CultureInfo.InvariantCulture))
            .Append("<br><strong>Started:</strong> ").Append(WebUtility.HtmlEncode(state.StartedUtc.ToString("u", CultureInfo.InvariantCulture)))
            .Append(" &nbsp; <strong>Ended:</strong> ").Append(WebUtility.HtmlEncode(state.EndedUtc?.ToString("u", CultureInfo.InvariantCulture) ?? "running"))
            .Append("</p>");

        builder.Append("<h2>Detections</h2>");
        if (detections.Count == 0)
        {
            builder.Append("<p>No significant indicators were observed. That is not proof that the application is safe.</p>");
        }
        else
        {
            builder.Append("<table><tr><th>Rule</th><th>Title</th><th>Severity</th><th>Confidence</th><th>Reason</th><th>Counterfactual</th></tr>");
            foreach (var detection in detections)
            {
                builder.Append("<tr><td>").Append(WebUtility.HtmlEncode(detection.RuleId)).Append("</td><td>")
                    .Append(WebUtility.HtmlEncode(detection.Title)).Append("</td><td>")
                    .Append(detection.Severity.ToString(CultureInfo.InvariantCulture)).Append("</td><td>")
                    .Append(detection.Confidence.ToString("0.00", CultureInfo.InvariantCulture)).Append("</td><td>")
                    .Append(WebUtility.HtmlEncode(detection.Reason)).Append("</td><td>")
                    .Append(WebUtility.HtmlEncode(detection.Counterfactual)).Append("</td></tr>");
            }

            builder.Append("</table>");
        }

        builder.Append("<h2>Processes</h2><table><tr><th>PID</th><th>Parent</th><th>Image</th><th>Scope</th><th>Command line</th></tr>");
        foreach (var process in processes)
        {
            builder.Append("<tr><td>").Append(process.Pid.ToString(CultureInfo.InvariantCulture)).Append("</td><td>")
                .Append(process.ParentPid?.ToString(CultureInfo.InvariantCulture) ?? "-").Append("</td><td>")
                .Append(WebUtility.HtmlEncode(process.ImageName ?? process.ImagePath ?? "-")).Append("</td><td>")
                .Append(WebUtility.HtmlEncode(process.Scope)).Append("</td><td>")
                .Append(WebUtility.HtmlEncode(process.CommandLine ?? "-")).Append("</td></tr>");
        }

        builder.Append("</table><h2>Score history</h2><table><tr><th>Time</th><th>Score</th><th>Peak</th><th>Band</th></tr>");
        foreach (var sample in score)
        {
            builder.Append("<tr><td>").Append(WebUtility.HtmlEncode(sample.Ts.ToString("u", CultureInfo.InvariantCulture))).Append("</td><td>")
                .Append(sample.Score.ToString("0.0", CultureInfo.InvariantCulture)).Append("</td><td>")
                .Append(sample.Peak.ToString("0.0", CultureInfo.InvariantCulture)).Append("</td><td>")
                .Append(WebUtility.HtmlEncode(sample.Band)).Append("</td></tr>");
        }

        builder.Append("</table><h2>Limitations</h2><ul>")
            .Append("<li>Near-real-time, not hard real-time; ETW buffering adds roughly 1-3 seconds.</li>")
            .Append("<li>No detections means no significant observed indicators, not proof of safety.</li>")
            .Append("<li>Payload content is not visible; endpoints, timing and volume only.</li>")
            .Append("<li>Read events may be sampled under volume pressure; gaps are recorded.</li>")
            .Append("</ul></body></html>");

        return builder.ToString();
    }

    private static void WriteReadyFile(string path, object ready)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(path, JsonSerializer.Serialize(ready, AgentJson.Options));
    }
}
