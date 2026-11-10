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
        catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException or InvalidOperationException)
        {
            // Settings files are user input: a bad one is a message and exit 3, never an unhandled
            // exception with a stack trace.
            Console.Error.WriteLine("argus-agent: " + exception.Message);
            return 3;
        }
    }

    private static async Task<int> RunAsync(AgentOptions options)
    {
        var token = options.Token ?? RandomNumberGenerator.GetHexString(32);
        var hub = new SseHub();
        var tickets = new StreamTickets();
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

        // The dashboard is served by the agent itself, so the UI and the API share an origin. That is
        // what makes the bearer token and the Origin guard work without a proxy: a browser cannot
        // read another origin's responses, and the agent refuses anything but its own Host and Origin.
        var webRoot = ResolveWebRoot(options.WebRoot);
        if (webRoot is not null)
        {
            var files = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(webRoot);
            app.UseStaticFiles(new StaticFileOptions { FileProvider = files });
        }

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
                var streamTicket = context.Request.Query["ticket"].ToString();
                var isStream = context.Request.Path.Value?.EndsWith("/stream", StringComparison.Ordinal) == true;
                var sessionId = isStream ? StreamSessionId(context) : Guid.Empty;

                if (!TokenEquals(authorization, token)
                    && !(isStream && streamTicket.Length > 0 && tickets.Consume(streamTicket, sessionId)))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsJsonAsync(new { error = "bearer token required" }).ConfigureAwait(false);
                    return;
                }
            }

            await next().ConfigureAwait(false);
        });

        if (webRoot is null)
        {
            // Headless: `/` describes the API. With a dashboard the SPA fallback serves the app here.
            app.MapGet("/", () => Results.Json(new
            {
                name = "Argus agent",
                version = AgentInfo.Version,
                api = "/api/health",
                dashboard = (string?)null,
                note = "All /api routes except /api/health require Authorization: Bearer <token>.",
            }, AgentJson.Options));
        }

        // The pre-launch preview: what the operator is about to run, before anything runs. Signature is
        // three-way for the same reason it is on every event — "could not read" is not "unsigned".
        app.MapGet("/api/inspect", (HttpContext context) =>
        {
            var path = context.Request.Query["path"].ToString();
            if (string.IsNullOrWhiteSpace(path))
            {
                return Results.BadRequest(new { error = "path is required" });
            }

            var full = path.Trim().Trim('"');
            if (!Path.IsPathRooted(full))
            {
                return Results.BadRequest(new { error = "an absolute path is required" });
            }

            if (!File.Exists(full))
            {
                return Results.Json(new { exists = false, path = full }, AgentJson.Options);
            }

            var info = new FileInfo(full);
            string? hash = null;
            try
            {
                using var stream = File.OpenRead(full);
                hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                hash = null;
            }

            var signature = ImageSignature.Verify(full);
            var executable = string.Equals(info.Extension, ".exe", StringComparison.OrdinalIgnoreCase);

            return Results.Json(
                new
                {
                    exists = true,
                    path = info.FullName,
                    name = info.Name,
                    directory = info.DirectoryName,
                    size = info.Length,
                    sha256 = hash,
                    signature = signature.ToString().ToLowerInvariant(),
                    executable,
                },
                AgentJson.Options);
        });

        app.MapGet("/api/health", () =>        {
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
            catch (Exception exception)
            {
                // A launch failure has to reach the dialog as a sentence: an unhandled 500 leaves the
                // operator with a button that did nothing.
                Console.Error.WriteLine("argus-agent: launch failed: " + exception);
                return Results.Json(new { error = exception.Message }, AgentJson.Options, statusCode: StatusCodes.Status500InternalServerError);
            }
        });

        app.MapGet("/api/sessions/{id:guid}", (Guid id) =>
        {
            var session = manager.Get(id);
            return session is null
                ? Results.NotFound(new { error = "session not found" })
                : Results.Json(new { state = session.State(), record = session.Record() }, AgentJson.Options);
        });

        // The desktop shell starts the agent elevated and has to be able to end it. Stopping sessions
        // first means a shutdown never leaves a monitored target orphaned mid-session.
        app.MapPost("/api/shutdown", async () =>
        {
            await manager.StopAllAsync().ConfigureAwait(false);
            _ = Task.Run(async () =>
            {
                await Task.Delay(250).ConfigureAwait(false);
                await app.StopAsync().ConfigureAwait(false);
            });
            return Results.Json(new { stopping = true }, AgentJson.Options);
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

        app.MapGet("/api/sessions/{id:guid}/scores", (Guid id) =>
        {
            var session = manager.Get(id);
            return session is null
                ? Results.NotFound(new { error = "session not found" })
                : Results.Json(
                    session.ScoreHistory().Select(point => new
                    {
                        ts = point.Ts,
                        score = point.Score,
                        peak = point.Peak,
                        band = point.Band,
                    }).ToArray(),
                    AgentJson.Options);
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

        app.MapPost("/api/sessions/{id:guid}/stream-ticket", (Guid id) =>
        {
            if (manager.Get(id) is null)
            {
                return Results.NotFound(new { error = "session not found" });
            }

            var (ticket, expires) = tickets.Issue(id);
            return Results.Json(new { ticket, expiresUtc = expires }, AgentJson.Options);
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
                : Results.Json(
                    SessionReport.ToJson(SessionReport.Build(session, manager.RuleSettings, options.RulesPath)),
                    AgentJson.Options);
        });

        app.MapGet("/api/sessions/{id:guid}/report.html", (Guid id) =>
        {
            var session = manager.Get(id);
            return session is null
                ? Results.NotFound(new { error = "session not found" })
                : Results.Content(
                    SessionReport.ToHtml(SessionReport.Build(session, manager.RuleSettings, options.RulesPath)),
                    "text/html; charset=utf-8");
        });

        // Read-only, because the agent's options are fixed at launch: a Settings screen that offered
        // toggles it could not apply would describe a different program than the one running.
        app.MapGet("/api/settings", () =>
            Results.Json(
                EffectiveConfig.Describe(options, manager.RuleSettings, options.RulesPath, webRoot, manager.DataRoot, actualPort),
                AgentJson.Options));

        if (webRoot is not null)
        {
            var index = Path.Combine(webRoot, "index.html");
            // Client-side routes (`/threats`, `/timeline`) have no file on disk. Answer them with the
            // shell so a reload works, and keep /api honest: an unknown API path is a 404, never HTML.
            app.MapFallback(async context =>
            {
                if (context.Request.Path.StartsWithSegments("/api"))
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    await context.Response.WriteAsJsonAsync(new { error = "not found" }).ConfigureAwait(false);
                    return;
                }

                context.Response.ContentType = "text/html; charset=utf-8";
                await context.Response.SendFileAsync(index).ConfigureAwait(false);
            });
        }

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

        // A killed run leaves its kernel ETW session registered, and the session table is a machine-wide
        // limited resource (measured: six dead sessions made the next launch fail with 0x800705AA and the
        // dashboard showed only "500"). Reclaim our own before anything tries to start.
        var reclaimed = EtwCollector.ReclaimStaleSessions();
        if (reclaimed.Count > 0)
        {
            Console.Error.WriteLine(
                "argus-agent: reclaimed " + reclaimed.Count.ToString(CultureInfo.InvariantCulture)
                + " stale ETW session(s) from an earlier run that was killed rather than stopped: "
                + string.Join(", ", reclaimed));
        }

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

    /// <summary>
    /// Where the built dashboard lives. Explicit `--web-root` wins; otherwise the agent looks for
    /// `web/dist` beside its binary and in the two directories above it (which is where a `dotnet run`
    /// from the repo finds it). Null means headless: the API still works, nothing is served at `/`.
    /// </summary>
    private static string? ResolveWebRoot(string? configured)
    {
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Directory.Exists(configured) && File.Exists(Path.Combine(configured, "index.html"))
                ? configured
                : null;
        }

        var candidates = new List<string>();
        var start = new DirectoryInfo(AppContext.BaseDirectory);
        // Six levels: `src/Argus.Agent/bin/Debug/net8.0-windows` needs five to reach the repo root.
        for (var depth = 0; depth < 6 && start is not null; depth++, start = start.Parent)
        {
            candidates.Add(Path.Combine(start.FullName, "web", "dist"));
            candidates.Add(Path.Combine(start.FullName, "dist"));
        }

        return candidates.FirstOrDefault(candidate => File.Exists(Path.Combine(candidate, "index.html")));
    }

    /// <summary>
    /// The session id in `/api/sessions/{id}/stream`. Route values are populated by the time this
    /// middleware runs, but the path is parsed too so the guard never depends on that ordering.
    /// </summary>
    private static Guid StreamSessionId(HttpContext context)
    {
        if (Guid.TryParse(context.Request.RouteValues["id"]?.ToString(), out var routed))
        {
            return routed;
        }

        var segments = context.Request.Path.Value?.Split('/', StringSplitOptions.RemoveEmptyEntries) ?? [];
        return segments.Length >= 2 && Guid.TryParse(segments[1], out var parsed) ? parsed : Guid.Empty;
    }

    private static bool IsExpectedHost(HttpRequest request, int port)    {
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
