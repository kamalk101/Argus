namespace Argus.Agent;

/// <summary>
/// What the sensor can and cannot see, as data.
///
/// PLAN §7 requires this table in the report and in Settings, and the two must not drift: a
/// hand-maintained list in each place is a guarantee that one of them will eventually describe a
/// different product. Every row states an observability level and the reason, so "not observed" is
/// never presented as "did not happen".
/// </summary>
internal static class ObservabilityTable
{
    internal sealed record Row(string Observation, string Level, string Note);

    /// <summary>
    /// Deliberately stable text: it is quoted in exported reports, so changing a sentence changes
    /// what a reader was told about a session that already happened.
    /// </summary>
    public static IReadOnlyList<Row> Rows { get; } =
    [
        new("Process creation with parent, image path, command line and signature",
            "Direct",
            "Kernel process events; the signature is read from the file and the catalog."),
        new("File create, write, rename and directory removal",
            "Direct",
            "File create/open is distinguished by the kernel's create disposition."),
        new("File deletion",
            "Not observable",
            "Measured: 26 live deletions produced zero file events. A deletion through the API is seen as a file event with the delete disposition, one made with `del` is not."),
        new("TCP connections and per-connection byte counts",
            "Direct",
            "Kernel network events; the owning process comes from the kernel record."),
        new("UDP traffic",
            "Not observable",
            "UDP sends are not collected in this session; only TCP is attributed to a process."),
        new("DNS queries and their result status",
            "Direct",
            "DNS client provider; status distinguishes a missing name from a resolver that could not be reached."),
        new("Registry value writes",
            "Direct",
            "Manifest provider plus kernel open records joined by kernel object pointer."),
        new("File and network reads",
            "Partial",
            "Reads are sampled under volume pressure; the counter and any gaps are reported with the session."),
        new("Remote thread injection",
            "Inferred",
            "The kernel provider in this session exposes no thread-injection keyword. A process attributed by location alone is the process-table footprint of cross-process creation, not proof of injection."),
        new("Payload content, URLs and decrypted traffic",
            "Not observable",
            "Only endpoints, sizes and timing are recorded."),
        new("Elevated processes started before the session began",
            "Partial",
            "The scope tracker attributes children by kernel parent records and image path; a process whose parent chain was never observed is attributed by location."),
        new("Events produced while the agent was not running",
            "Not observable",
            "Argus is not a service: nothing is collected before the session starts or after it stops."),
    ];
}

/// <summary>
/// The configuration a session actually ran with, for Settings and for the report's provenance line.
/// Read-only on purpose: the agent's options are fixed at launch, so a UI toggle that cannot take
/// effect would be a claim about the machine that is not true.
/// </summary>
internal static class EffectiveConfig
{
    public static object Describe(
        AgentOptions options,
        Analysis.Rules.RuleSettings rules,
        string? rulesPath,
        string? webRoot,
        string dataRoot,
        int actualPort) => new
    {
        agent = AgentInfo.Version,
        agentPid = Environment.ProcessId,
        elevated = AgentInfo.IsElevated,
        os = Environment.OSVersion.VersionString,
        osBuild = Environment.OSVersion.Version.Build,
        runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
        // The bound port, not the requested one: --port 0 means "choose one", and a Settings screen
        // that printed 0 would be telling the operator to connect to nothing.
        port = actualPort,
        requestedPort = options.Port,
        dataRoot,
        rulesPath = rulesPath ?? "(defaults)",
        rules = rules,
        // Same digest the report prints, so a report can be matched to a Settings screenshot.
        configHash = ConfigHash(rules, rulesPath),
        webRoot = webRoot ?? "(headless)",
        sessionName = options.SessionName ?? "(generated per session)",
        durationSeconds = options.DurationSeconds,
        // The same rows the report prints: a Settings screen and an exported report that disagree
        // about what the sensor can see would be two different products.
        observability = ObservabilityTable.Rows.Select(row => new { row.Observation, row.Level, row.Note }),
        features = new
        {
            registryEvents = true,
            dnsEvents = true,
            tcpOwnerTable = true,
            readSampling = true,
            volumeFuse = true,
        },
    };

    /// <summary>
    /// A short digest of everything that changes what a session means. Two sessions with different
    /// thresholds are not comparable, so a report has to be able to say which rules produced it.
    /// </summary>
    public static string ConfigHash(Analysis.Rules.RuleSettings rules, string? rulesPath)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new
        {
            rules,
            source = rulesPath is null ? "defaults" : "file",
            agent = AgentInfo.Version,
        });

        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }
}
