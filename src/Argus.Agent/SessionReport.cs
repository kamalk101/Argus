namespace Argus.Agent;

using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Argus.Analysis.Rules;
using Argus.Core.Events;
using Argus.Storage;

/// <summary>
/// The exported report: one object that both the JSON bundle and the HTML document are rendered from.
///
/// Building them from a single snapshot is the point. Two independent builders drift, and the drift is
/// invisible until someone compares a PDF-shaped report against the JSON from the same session and
/// finds different numbers. Everything a reader needs in order to decide what the report is worth —
/// verdict, score, coverage, gaps, configuration hash, and what the sensor cannot see — is in the
/// snapshot, so neither format can omit it by accident.
/// </summary>
internal static class SessionReport
{
    internal sealed record DetectionSection(StoredDetection Detection, IReadOnlyList<object> Evidence);

    /// <summary>A typed cell, so the HTML renderer reads fields instead of reflecting over an anonymous object.</summary>
    internal sealed record CategoryCount(string Category, long Count);

    internal sealed record Snapshot(
        DateTimeOffset GeneratedUtc,
        string Agent,
        string ConfigHash,
        string RulesPath,
        string OsBuild,
        SessionStateDto State,
        IReadOnlyList<ProcessDto> Processes,
        IReadOnlyList<DetectionSection> Detections,
        IReadOnlyList<(DateTimeOffset Ts, double Score, double Peak, string Band)> Scores,
        IReadOnlyList<object> Gaps,
        IReadOnlyList<object> Events,
        IReadOnlyList<CategoryCount> Categories,
        IReadOnlyList<ObservabilityTable.Row> Observability,
        IReadOnlyList<string> Limitations,
        MonitorCountersDto? Counters);

    public static Snapshot Build(LiveSession session, RuleSettings rules, string? rulesPath)
    {
        var state = session.State();
        var counters = session.Health().Monitor;
        var detections = session.DetectionList()
            .OrderByDescending(detection => detection.Severity)
            .ThenByDescending(detection => detection.Confidence)
            .Select(detection => new DetectionSection(
                detection,
                session.EventsByIds(session.Evidence(detection.Id))
                    .Select(eventRecord => (object)session.ToDto(eventRecord))
                    .ToArray()))
            .ToArray();

        var gaps = session.Gaps()
            .Select(gap => (object)new
            {
                timestamp = gap.TimestampUtc,
                source = gap.Source,
                reason = gap.Reason,
                lost = gap.LostCount,
                detail = gap.Detail,
            })
            .ToArray();

        var events = session.EventsPage(new EventFilter { Limit = 5000, InScopeOnly = true })
            .Select(session.ToDto)
            .Select(eventDto => (object)eventDto)
            .ToArray();

        // Sensor counters, not a count of the exported page: this section says what the session
        // collected, and the exported event list is capped at 5000 rows.
        var categories = counters is null
            ? []
            : new[]
            {
                new CategoryCount("process starts", counters.ProcessStarts),
                new CategoryCount("file events", counters.FileEvents),
                new CategoryCount("network events", counters.NetworkEvents),
                new CategoryCount("registry events", counters.RegistryEvents),
                new CategoryCount("dns events", counters.DnsEvents),
                new CategoryCount("events forwarded in scope", counters.EventsForwarded),
                new CategoryCount("events outside scope", counters.OutsideScope),
                new CategoryCount("sampled reads", counters.SampledReads),
                new CategoryCount("throttled events", counters.ThrottledEvents),
            };

        var configHash = EffectiveConfig.ConfigHash(rules, rulesPath);
        var limitations = BuildLimitations(state, gaps.Length, configHash);

        return new Snapshot(
            DateTimeOffset.UtcNow,
            AgentInfo.Version,
            configHash,
            rulesPath ?? "(defaults)",
            Environment.OSVersion.Version.ToString(),
            state,
            session.ProcessDtos(),
            detections,
            session.ScoreHistory(),
            gaps,
            events,
            categories,
            ObservabilityTable.Rows,
            limitations,
            counters);
    }

    /// <summary>
    /// Limitations are derived from this session, not from a boilerplate list: a report that always
    /// prints the same five caveats trains the reader to skip them.
    /// </summary>
    private static IReadOnlyList<string> BuildLimitations(SessionStateDto state, int gapCount, string configHash)
    {
        var limitations = new List<string>
        {
            "Near-real-time, not hard real-time: ETW buffering and batching add roughly 1-3 seconds before an event reaches this report.",
            "Absence of detections means no significant observed indicator was seen. It is not proof that the application is safe.",
            "Payload content, URLs and encrypted traffic are not visible; only endpoints, timing and volume are recorded.",
        };

        if (gapCount > 0)
        {
            limitations.Add(
                $"{gapCount} collection gap(s) were reported during this session. Anything that happened inside them may be missing from the evidence below.");
        }
        else
        {
            limitations.Add("No collection gaps were reported, so the sensor believes it delivered every event it produced.");
        }

        if (!state.Coverage.Complete)
        {
            limitations.Add("Coverage is incomplete for this session: absence of evidence is weaker than usual.");
        }

        limitations.Add(
            $"This report was produced by agent {AgentInfo.Version} with configuration digest {configHash}. "
            + "A session recorded with different rule thresholds is not directly comparable to this one.");

        return limitations;
    }

    public static object ToJson(Snapshot snapshot) => new
    {
        generatedUtc = snapshot.GeneratedUtc,
        agent = snapshot.Agent,
        configHash = snapshot.ConfigHash,
        rulesPath = snapshot.RulesPath,
        windowsBuild = snapshot.OsBuild,
        session = snapshot.State,
        categories = snapshot.Categories.Select(category => new { category = category.Category, count = category.Count }),
        detections = snapshot.Detections.Select(section => new
        {
            section.Detection,
            evidence = section.Evidence,
        }),
        processes = snapshot.Processes,
        scores = snapshot.Scores.Select(point => new { ts = point.Ts, score = point.Score, peak = point.Peak, band = point.Band }),
        gaps = snapshot.Gaps,
        events = snapshot.Events,
        counters = snapshot.Counters,
        observability = snapshot.Observability.Select(row => new { row.Observation, row.Level, row.Note }),
        limitations = snapshot.Limitations,
    };

    /// <summary>
    /// Self-contained HTML: inline CSS, no scripts, no external assets — it opens from a file share
    /// with no network and still renders. The JSON bundle is embedded too, so the document carries its
    /// own machine-readable source.
    /// </summary>
    public static string ToHtml(Snapshot snapshot)
    {
        var state = snapshot.State;
        var builder = new StringBuilder(32_768);

        builder.Append("<!doctype html><html><head><meta charset=\"utf-8\"><title>Argus report — ")
            .Append(Encode(Path.GetFileName(state.TargetPath)))
            .Append("</title><style>")
            .Append("body{font-family:Segoe UI,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:32px;line-height:1.45;max-width:1100px}")
            .Append("table{border-collapse:collapse;width:100%;margin:12px 0 24px}th,td{border:1px solid #30363d;padding:7px 9px;text-align:left;font-size:13px;vertical-align:top}")
            .Append("th{background:#161b22}code{background:#161b22;padding:1px 4px;border-radius:3px;font-size:12px}")
            .Append(".bad{color:#ff7b72}.warn{color:#d29922}.ok{color:#3fb950}.muted{color:#8b949e}")
            .Append(".pill{display:inline-block;border:1px solid currentColor;border-radius:10px;padding:0 8px;font-size:12px}")
            .Append("</style></head><body>");

        builder.Append("<h1>Argus behaviour report</h1>");
        builder.Append("<p class=\"muted\">Generated ")
            .Append(Encode(snapshot.GeneratedUtc.ToString("u", CultureInfo.InvariantCulture)))
            .Append(" · agent ").Append(Encode(snapshot.Agent))
            .Append(" · Windows build ").Append(Encode(snapshot.OsBuild))
            .Append(" · config <code>").Append(Encode(snapshot.ConfigHash)).Append("</code>")
            .Append(" · rules ").Append(Encode(snapshot.RulesPath))
            .Append("</p>");

        // Executive summary: the four facts someone reads before deciding what to do.
        var verdictClass = state.Score >= 60 ? "bad" : state.Score >= 25 ? "warn" : "ok";
        builder.Append("<h2>Summary</h2><table>")
            .Append("<tr><th style=\"width:180px\">Target</th><td><code>").Append(Encode(state.TargetPath)).Append("</code></td></tr>")
            .Append("<tr><th>Verdict</th><td class=\"").Append(verdictClass).Append("\"><strong>")
            .Append(Encode(state.Verdict ?? "Benign")).Append("</strong> — score ")
            .Append(state.Score.ToString("0.0", CultureInfo.InvariantCulture))
            .Append(", peak ").Append(state.PeakScore.ToString("0.0", CultureInfo.InvariantCulture))
            .Append("</td></tr>")
            .Append("<tr><th>Window</th><td>").Append(Encode(state.StartedUtc.ToString("u", CultureInfo.InvariantCulture)))
            .Append(" → ").Append(Encode(state.EndedUtc?.ToString("u", CultureInfo.InvariantCulture) ?? "still running"))
            .Append("</td></tr>")
            .Append("<tr><th>Coverage</th><td>")
            .Append(state.Coverage.Complete ? "<span class=\"ok\">complete</span>" : "<span class=\"warn\">incomplete</span>")
            .Append(" — ").Append(Encode(state.Coverage.Statement))
            .Append("</td></tr>")
            .Append("</table>");

        builder.Append("<h2>Activity in scope</h2><table><tr><th>Category</th><th>Count</th></tr>");
        foreach (var category in snapshot.Categories)
        {
            builder.Append("<tr><td>").Append(Encode(category.Category)).Append("</td><td>")
                .Append(category.Count.ToString(CultureInfo.InvariantCulture)).Append("</td></tr>");
        }

        builder.Append("</table>");
        if (snapshot.Counters is null)
        {
            builder.Append("<p class=\"warn\">The sensor counters were not readable when this report was generated, ")
                .Append("so the numbers above may be incomplete.</p>");
        }
        else if (snapshot.Counters.Throttled || snapshot.Counters.ThrottledEvents > 0)
        {
            builder.Append("<p class=\"warn\">The volume fuse throttled this session (")
                .Append(snapshot.Counters.ThrottledEvents.ToString(CultureInfo.InvariantCulture))
                .Append(" events held back), so the counts are a sample under pressure rather than a complete record.</p>");
        }

        builder.Append("<h2>Detections</h2>");
        if (snapshot.Detections.Count == 0)
        {
            builder.Append("<p>No significant indicators were observed in this session. ")
                .Append("<em>That is not proof that the application is safe</em> — see the limitations below.</p>");
        }
        else
        {
            foreach (var section in snapshot.Detections)
            {
                var detection = section.Detection;
                builder.Append("<h3>").Append(Encode(detection.RuleId)).Append(" — ").Append(Encode(detection.Title))
                    .Append(" <span class=\"pill\">severity ").Append(detection.Severity.ToString(CultureInfo.InvariantCulture))
                    .Append("</span> <span class=\"pill\">confidence ")
                    .Append(detection.Confidence.ToString("0.00", CultureInfo.InvariantCulture)).Append("</span></h3>")
                    .Append("<table>")
                    .Append("<tr><th style=\"width:180px\">Why this fired</th><td>").Append(Encode(detection.Reason)).Append("</td></tr>")
                    .Append("<tr><th>What would have stopped it</th><td>").Append(Encode(detection.Counterfactual)).Append("</td></tr>")
                    .Append("<tr><th>Categories</th><td>").Append(Encode(detection.Categories.ToString())).Append("</td></tr>")
                    .Append("<tr><th>Process</th><td>").Append(Encode(ScopeText(section)))
                    .Append(" · first ").Append(Encode(detection.FirstSeenUtc.ToString("u", CultureInfo.InvariantCulture)))
                    .Append(" · last ").Append(Encode(detection.LastSeenUtc.ToString("u", CultureInfo.InvariantCulture)))
                    .Append(" · ").Append(detection.EventCount.ToString(CultureInfo.InvariantCulture)).Append(" event(s)</td></tr>")
                    .Append("</table>");

                if (section.Evidence.Count > 0)
                {
                    builder.Append("<details open><summary>Evidence (").Append(section.Evidence.Count.ToString(CultureInfo.InvariantCulture))
                        .Append(" event(s))</summary><table><tr><th>Time</th><th>Kind</th><th>PID</th><th>Target</th><th>Observed</th></tr>");
                    foreach (var item in section.Evidence)
                    {
                        var json = JsonSerializer.SerializeToElement(item, AgentJson.Options);
                        builder.Append("<tr><td>").Append(Encode(TextOf(json, "timestampUtc")))
                            .Append("</td><td>").Append(Encode(TextOf(json, "kind")))
                            .Append("</td><td>").Append(Encode(TextOf(json, "pid")))
                            .Append("</td><td><code>").Append(Encode(
                                TextOf(json, "target")
                                ?? TextOf(json, "pathKey")
                                ?? TextOf(json, "remoteIp")
                                ?? TextOf(json, "imagePath")
                                ?? TextOf(json, "commandLine")
                                ?? "—"))
                            .Append("</code></td><td>").Append(Encode(TextOf(json, "observability") ?? "—")).Append("</td></tr>");
                    }

                    builder.Append("</table></details>");
                }
            }
        }

        builder.Append("<h2>Processes</h2><table><tr><th>PID</th><th>Parent</th><th>Image</th><th>Scope</th><th>Signature</th><th>Command line</th></tr>");
        foreach (var process in snapshot.Processes)
        {
            builder.Append("<tr><td>").Append(process.Pid.ToString(CultureInfo.InvariantCulture))
                .Append("</td><td>").Append(process.ParentPid?.ToString(CultureInfo.InvariantCulture) ?? "—")
                .Append("</td><td>").Append(Encode(process.ImageName ?? process.ImagePath ?? "—"))
                .Append("</td><td>").Append(Encode(process.Scope))
                .Append("</td><td>").Append(Encode(process.Signature ?? "unknown"))
                .Append("</td><td><code>").Append(Encode(process.CommandLine ?? "—")).Append("</code></td></tr>");
        }

        builder.Append("</table>");

        builder.Append("<h2>Risk over time</h2>");
        if (snapshot.Scores.Count == 0)
        {
            builder.Append("<p class=\"muted\">No score samples were recorded.</p>");
        }
        else
        {
            builder.Append("<table><tr><th>Time</th><th>Score</th><th>Peak</th><th>Band</th></tr>");
            foreach (var sample in snapshot.Scores)
            {
                builder.Append("<tr><td>").Append(Encode(sample.Ts.ToString("HH:mm:ss", CultureInfo.InvariantCulture)))
                    .Append("</td><td>").Append(sample.Score.ToString("0.0", CultureInfo.InvariantCulture))
                    .Append("</td><td>").Append(sample.Peak.ToString("0.0", CultureInfo.InvariantCulture))
                    .Append("</td><td>").Append(Encode(sample.Band)).Append("</td></tr>");
            }

            builder.Append("</table>");
        }

        builder.Append("<h2>Collection health</h2>");
        if (snapshot.Gaps.Count == 0)
        {
            builder.Append("<p class=\"ok\">No collection gaps were reported.</p>");
        }
        else
        {
            builder.Append("<table><tr><th>Time</th><th>Source</th><th>Reason</th><th>Lost</th><th>Detail</th></tr>");
            foreach (var gap in snapshot.Gaps)
            {
                var json = JsonSerializer.SerializeToElement(gap, AgentJson.Options);
                builder.Append("<tr><td>").Append(Encode(TextOf(json, "timestamp") ?? "—"))
                    .Append("</td><td>").Append(Encode(TextOf(json, "source") ?? "—"))
                    .Append("</td><td>").Append(Encode(TextOf(json, "reason") ?? "—"))
                    .Append("</td><td>").Append(Encode(TextOf(json, "lost") ?? "—"))
                    .Append("</td><td>").Append(Encode(TextOf(json, "detail") ?? "—")).Append("</td></tr>");
            }

            builder.Append("</table>");
        }

        builder.Append("<h2>What this tool can and cannot see</h2><table><tr><th>Observation</th><th>Level</th><th>Why</th></tr>");
        foreach (var row in snapshot.Observability)
        {
            var levelClass = row.Level switch
            {
                "Direct" => "ok",
                "Partial" or "Inferred" => "warn",
                _ => "bad",
            };
            builder.Append("<tr><td>").Append(Encode(row.Observation))
                .Append("</td><td class=\"").Append(levelClass).Append("\">").Append(Encode(row.Level))
                .Append("</td><td class=\"muted\">").Append(Encode(row.Note)).Append("</td></tr>");
        }

        builder.Append("</table><h2>Limitations</h2><ul>");
        foreach (var limitation in snapshot.Limitations)
        {
            builder.Append("<li>").Append(Encode(limitation)).Append("</li>");
        }

        builder.Append("</ul>");

        // The machine-readable bundle travels with the document.
        builder.Append("<h2>Raw data</h2><p class=\"muted\">The JSON bundle this report was rendered from is embedded below.</p>")
            .Append("<details><summary>report.json (")
            .Append(snapshot.Events.Count.ToString(CultureInfo.InvariantCulture))
            .Append(" events)</summary><pre><code>")
            .Append(Encode(JsonSerializer.Serialize(ToJson(snapshot), AgentJson.Options)))
            .Append("</code></pre></details>");

        builder.Append("</body></html>");
        return builder.ToString();
    }

    /// <summary>
    /// Which process a detection is about.
    ///
    /// Several rules group a finding under the process that *initiated* it (a parent that launched
    /// `reg add`), while their reason text names the child that actually ran. Printing the group pid as
    /// "the process" then contradicts the reason on the same page — measured on a live F-002 session:
    /// reason said PID 6912, the row said 792. So when the evidence comes from other processes, the
    /// row says so instead of quietly showing one number.
    /// </summary>
    private static string ScopeText(DetectionSection section)
    {
        var evidencePids = section.Evidence
            .Select(item => JsonSerializer.SerializeToElement(item, AgentJson.Options))
            .Select(json => TextOf(json, "pid"))
            .Where(pid => !string.IsNullOrEmpty(pid))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var scope = section.Detection.ScopePid.ToString(CultureInfo.InvariantCulture);
        if (evidencePids.Length == 0 || (evidencePids.Length == 1 && evidencePids[0] == scope))
        {
            return $"PID {scope}";
        }

        return $"grouped under PID {scope} · evidence from PID {string.Join(", ", evidencePids)}";
    }

    private static string? TextOf(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind is not JsonValueKind.Null and not JsonValueKind.Undefined
            ? value.ToString()
            : null;

    private static string Encode(string? text) => WebUtility.HtmlEncode(text ?? string.Empty);
}
