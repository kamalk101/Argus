# Argus — Implementation Plan

**Real-Time Application Behavior Monitoring & Explainable Malware Detection for Windows 10/11**

Status: planning · Version 1.0 · Owner: you · Implementer: me (Buffy)

> Working name: **Argus** (the many-eyed watcher). Rename freely — it appears in the assembly names, pipe/HTTP routes and the UI wordmark only.

---

## 0. TL;DR of the decisions this plan makes

| Decision | Choice | Why |
|---|---|---|
| Language / runtime | C# on **.NET 8 (LTS)**, Windows 10 1903+ / 11 x64 | ETW tooling is best in .NET; single self-contained folder deploy |
| Telemetry source | **ETW real-time sessions** via `Microsoft.Diagnostics.Tracing.TraceEvent`, manifest providers first | Only supported way to get process/file/network events system-wide without a kernel driver |
| Storage | **SQLite** (WAL), per-session rows + tiered aggregation | Zero-install, queryable, FTS5 for search, easy export |
| UI | **React + TypeScript + Vite + Tailwind** dashboard, served on `127.0.0.1` by the agent, rendered in a **WebView2** window | The UI is a graded component; web tech gives the density/virtualisation a security console needs, and it is the 90% of this project I can actually build, run and verify on this Linux machine |
| Process model | **Two roles, one binary**: elevated `--agent` (ETW + HTTP + DB) and non-elevated UI shell | Keeps the browser engine and HTTP surface out of an elevated process; non-elevated UI still reaches loopback |
| Detection | Deterministic rule engine + noisy-OR risk scoring with per-detection evidence, **ML added later as an advisory, shadow-mode signal** | Requirement: explainable, multi-indicator, never single-event verdicts |
| Non-goals | Kernel driver, TLS inspection, cloud reputation lookups, automatic malware execution | Out of scope / unsafe / privacy-hostile |

---

## 1. Environment reality check (read this first)

This matters more than any diagram below, so it is not buried in an appendix.

**This dev machine is Linux** (`/home/kamal/Documents/F`), with Node 22 and Python 3.14, and the .NET 8 SDK installed user-locally in `~/.dotnet` (no system-wide change). The product targets Windows. That produces a hard split:

| Layer | Buildable & testable here (Linux) | Needs your Windows machine |
|---|---|---|
| `Argus.Core` (event model, scoring) | ✅ | — |
| `Argus.Analysis` (rules, correlator, features) | ✅ unit + replay tests | — |
| `Argus.Storage` (SQLite schema, repos) | ✅ | — |
| `Argus.Simulator` (synthetic + replay event source) | ✅ | — |
| Dashboard (`web/`) | ✅ builds, runs, verified in browser | visual check on Windows |
| `Argus.Monitor` (ETW collectors) | ✅ compiles with `EnableWindowsTargeting`; platform-neutral mapping is unit-tested | ✅ runtime required |
| `Argus.Agent` (elevation, Kestrel, live session) | ✅ compiles; live API/SSE/UAC unverifiable here | ✅ runtime required |
| `Argus.Desktop` (WebView2 shell) | ✗ not scaffolded until Phase 4 | ✅ required |
| End-to-end behaviour, event loss, perf under load | ✗ | ✅ required |

**Consequences, planned into the phases:**

1. I install the .NET 8 SDK locally via `dotnet-install.sh` into `~/.dotnet` (no sudo, no system change). This lets me compile and unit-test the entire cross-platform core and run the whole dashboard against recorded/replayed event streams.
2. The Windows-only code is **written here and compiled here** with `EnableWindowsTargeting`, then re-verified on Windows with `scripts/verify.ps1` and `scripts/smoke.ps1`. Every Windows-only file gets a thin interface boundary (`IEventSource`) so the logic behind it is still tested on Linux.
3. The first real Windows run is a **joint debugging session**, not a formality. Expect the ETW layer to need 2–3 tuning passes (provider keywords, filter scope, buffer sizing) that cannot be pre-verified.
4. I will never report ETW behaviour as "tested" when only the Linux replay path ran. Each phase's acceptance criteria state which side verified what.

**What you need on Windows:** .NET 8 SDK (or just the runtime for running my builds), WebView2 runtime (present on Win11 and patched Win10), an elevated PowerShell, and — for realistic testing — a Windows VM to use as the malware-safety boundary.

---

## 2. Scope contract

### 2.1 In scope

- User selects one `.exe`; the tool launches it (default) or attaches to a running PID (later phase) and monitors **that process tree only**.
- Continuous collection of process, file, registry (optional), network, and DNS events attributable to that tree.
- Correlated, explainable detections with severity, plain-language reasons, evidence links, and MITRE ATT&CK mapping.
- A dashboard for live observation, investigation, timeline reconstruction, search, and report export.
- Deterministic replay of recorded sessions so detections and UI can be regression-tested.
- Explicit surfacing of monitoring gaps and of "observe vs. infer" for every signal.

### 2.2 Out of scope (stated, so nobody expects it later)

- Static file scanning, AV signatures, unpacking, YARA. (A hash + signer lookup is shown for context only.)
- Kernel driver / minifilter / callbacks. No driver means some behaviours stay *inferred* (see §5.4).
- TLS decryption or packet payload capture; byte volumes and endpoints only.
- Executing or downloading real malware. Test material is the safe behaviour simulator (§11.2).
- Cloud lookups, telemetry upload, multi-machine management, service/daemon mode across reboots.

### 2.3 Grading traceability

| Requirement | Where it is delivered |
|---|---|
| §2A Process/subprocess | §5.1, Phase 2 |
| §2B File system | §5.2, Phase 2 |
| §2C Network | §5.3, Phase 2 |
| §2D Runtime correlation | §6, Phases 3–4 |
| §3 Detection engine + ML + explainability | §6, §7, Phases 3, 6 |
| §4 Advanced UI (dashboard, explorers, threat panel, timeline) | §8, Phase 4 |
| §5 Interactive investigation + export | §8.6–8.8, Phase 5 |
| §6 Technical reqs (Windows, APIs, modularity, perf, admin, storage, observe-vs-infer) | §3, §5.4, §9, §10, §13 |
| §7 Safety & limitations | §11, §12 |
| §8 Final goal / demo | §14 |

---

## 3. Architecture

```
                         ┌──────────────────────────────────────────────┐
                         │  argus.exe  (UI role, asInvoker)             │
                         │  WebView2 shell ──► http://127.0.0.1:<port>  │
                         └───────────────┬──────────────────────────────┘
                                         │ loopback HTTP + SSE, bearer token,
                                         │ Origin/Host pinned to loopback
┌────────────────────────────────────────▼─────────────────────────────────┐
│  argus.exe --agent  (elevated, no window)                                │
│                                                                          │
│  ┌──────────────┐   ┌───────────────┐   ┌──────────────┐   ┌───────────┐  │
│  │ Monitor      │──►│ Event bus     │──►│ Analysis     │──►│ Storage   │  │
│  │ (ETW+fallback│   │ bounded ring  │   │ rules+correl.│   │ SQLite    │  │
│  │  collectors) │   │ + batcher     │   │ + scorer     │   │ WAL       │  │
│  └──────────────┘   └───────┬───────┘   └──────┬───────┘   └─────┬─────┘  │
│         ▲                   │                  │                 │        │
│         │        ┌──────────▼──────────────────▼─────────────────▼─────┐  │
│         │        │ HTTP API (REST + SSE) + static dashboard files     │  │
│         │        └───────────────────────────────────────────────────┘  │
│  ┌──────┴───────────┐   ┌──────────────┐   ┌──────────────────────────┐  │
│  │ Scope tracker    │   │ Gaps recorder│   │ Score timeline / reports │  │
│  │ (process tree)   │   │ (loss, denied)│  │ (HTML + JSON export)     │  │
│  └──────────────────┘   └──────────────┘   └──────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

**Threading model (agent):** one ETW consumer thread → lock-free `Channel<BehaviorEvent>` → single normalising/scope-filtering stage → batches of ≤500 events or 250 ms → (a) SQLite transaction, (b) correlator, (c) SSE hub. Everything downstream of the filter sees ordered events, which is what makes replay deterministic.

**Failure isolation:** an exception inside a rule must not stop collection. Each stage is wrapped; the rule engine has a per-rule error counter and a circuit breaker (disable noisy rule after N exceptions, log a gap).

### 3.1 Solution layout

```
argus/
  Argus.sln
  Directory.Build.props            # LangVersion, Nullable, TreatWarningsAsErrors, analyzers
  src/
    Argus.Core/                    # net8.0   — domain model, scoring math, capability enums
    Argus.Analysis/                # net8.0   — rule catalog, correlator, feature builder
    Argus.Storage/                 # net8.0   — SQLite schema, migrations, repositories, FTS
    Argus.Monitor/                 # net8.0-windows — ETW collectors, iphlpapi, PEB, job objects
    Argus.Agent/                   # net8.0-windows — host, Kestrel, SSE hub, elevation bootstrap
    Argus.Desktop/                 # net8.0-windows — WebView2 shell, tray, runas launcher
    Argus.Simulator/               # net8.0   — synthetic behavior + JSONL replay source
    Argus.Cli/                     # net8.0   — `argus replay`, `argus export`, `argus selftest`
  web/                             # React + TS + Vite + Tailwind (built into Agent/wwwroot)
  tests/
    Argus.Core.Tests/
    Argus.Analysis.Tests/
    Argus.Storage.Tests/
    fixtures/scenarios/*.jsonl     # recorded & hand-authored behaviour scenarios
  tools/
    behavior-sim/                  # safe "suspicious behaviour" test program (C# console)
  scripts/
    verify.sh  verify.ps1  build-web.sh  run-dev.sh
  docs/
    CAPABILITY-MATRIX.md  RULES.md  THREAT-MODEL.md  DEMO.md  LIMITATIONS.md
```

`Argus.Core`, `Analysis`, `Storage`, `Simulator`, `Cli` are plain `net8.0` → compile and test on Linux. Only `Monitor`, `Agent`, `Desktop` are `net8.0-windows`.

---

## 4. Data model

### 4.1 Event contract (the spine of the whole system)

```csharp
public sealed record BehaviorEvent
{
    public long Seq { get; init; }                 // monotonic, assigned at ingest
    public required Guid SessionId { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }  // ETW event time, NOT arrival time
    public required EventKind Kind { get; init; }   // ProcessStart|FileWrite|NetConnect|DnsQuery|...
    public required EventCategory Category { get; init; }       // Process|File|Registry|Network|Dns|Meta
    public required int Pid { get; init; }
    public int? Tid { get; init; }
    public int? ParentPid { get; init; }
    public string? ImageName { get; init; }         // powershell.exe
    public int? TargetPid { get; init; }            // for injection/process-access
    public string? Target { get; init; }            // path / ip:port / domain / registry key
    public string? DetailJson { get; init; }        // kind-specific extras (bytes, status, options)
    public required Observability Observability { get; init; }  // Direct|Inferred|Aggregated
    public required double Confidence { get; init; }            // 0..1
    public required EventSourceKind Source { get; init; }       // Etw|Polling|Pe|Simulated
}
```

Rules: events are **immutable and append-only**; every detection references event `Seq` values; aggregation (§4.3) never deletes raw events inside the retention window.

### 4.2 SQLite schema (Phase 1, `schema v1`)

```sql
CREATE TABLE sessions (
  id TEXT PRIMARY KEY, target_path TEXT NOT NULL, target_sha256 TEXT, target_signer TEXT,
  mode TEXT NOT NULL,                    -- launch | attach
  started_utc TEXT NOT NULL, ended_utc TEXT, status TEXT NOT NULL,  -- running|stopped|crashed|incomplete
  os_build TEXT, agent_version TEXT, elevated INTEGER NOT NULL,
  peak_score REAL DEFAULT 0, final_score REAL, verdict TEXT,
  loss_events INTEGER DEFAULT 0, loss_bytes INTEGER DEFAULT 0
);

CREATE TABLE processes (
  session_id TEXT NOT NULL, pid INTEGER NOT NULL, parent_pid INTEGER,
  image_name TEXT, image_path TEXT, cmdline TEXT,
  start_utc TEXT NOT NULL, end_utc TEXT, exit_code INTEGER,
  signer TEXT, sha256 TEXT, integrity TEXT,
  scope_state TEXT NOT NULL,             -- root|confirmed|unconfirmed|excluded
  PRIMARY KEY (session_id, pid, start_utc)
);

CREATE TABLE events (
  seq INTEGER PRIMARY KEY, session_id TEXT NOT NULL, ts_utc TEXT NOT NULL,
  kind TEXT NOT NULL, category TEXT NOT NULL, pid INTEGER NOT NULL,
  tid INTEGER, target TEXT, detail_json TEXT,
  observability TEXT NOT NULL, confidence REAL NOT NULL, source TEXT NOT NULL
);
CREATE INDEX ix_events_session_ts ON events(session_id, ts_utc);
CREATE INDEX ix_events_session_pid_ts ON events(session_id, pid, ts_utc);
CREATE INDEX ix_events_session_kind_ts ON events(session_id, kind, ts_utc);

CREATE TABLE event_rollups (              -- cold tier (§4.3)
  session_id TEXT NOT NULL, window_start TEXT NOT NULL, window_end TEXT NOT NULL,
  category TEXT NOT NULL, kind TEXT NOT NULL, pid INTEGER,
  target_prefix TEXT, count INTEGER NOT NULL, bytes INTEGER,
  sample_seq INTEGER                      -- links back to one representative event
);

CREATE TABLE detections (
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
  rule_id TEXT NOT NULL, title TEXT NOT NULL, severity INTEGER NOT NULL,
  confidence REAL NOT NULL, categories TEXT NOT NULL,     -- csv: process,file,network
  first_ts TEXT NOT NULL, last_ts TEXT NOT NULL, event_count INTEGER NOT NULL,
  status TEXT NOT NULL,                  -- open|escalated|closed
  score_contribution REAL NOT NULL, mitre TEXT,
  reason TEXT NOT NULL,                  -- plain-language sentence
  explanation_json TEXT NOT NULL         -- factors, thresholds, values, counterfactual
);

CREATE TABLE detection_evidence (
  detection_id INTEGER NOT NULL REFERENCES detections(id),
  seq INTEGER, rollup_id INTEGER, role TEXT NOT NULL   -- trigger|corroboration|prior
);

CREATE TABLE score_history (session_id TEXT, ts_utc TEXT, score REAL, band TEXT,
  by_category_json TEXT, PRIMARY KEY (session_id, ts_utc));

CREATE TABLE gaps (session_id TEXT, ts_utc TEXT, source TEXT, reason TEXT,
  lost_count INTEGER, detail TEXT);

CREATE TABLE iocs (kind TEXT, value TEXT, label TEXT, source TEXT, PRIMARY KEY (kind, value));

CREATE VIRTUAL TABLE events_fts USING fts5(target, detail_text, content='', tokenize='unicode61');
```

Session DB lives at `%LOCALAPPDATA%\Argus\sessions\<sessionId>.db`; a small `catalog.db` lists sessions for the picker so a huge session never blocks startup.

### 4.3 Retention and tiering (how this stays lightweight)

| Age | Treatment |
|---|---|
| 0 – 24 h | Raw events, full detail |
| > 24 h (default) or > 250k events | Rolled into `event_rollups` per (10 s window, pid, kind, path prefix): counts + byte sums + one sample event retained |
| Export | Report captures a snapshot; pruning never touches an exported file |

Rollups keep evidence of volume-based rules ("12,431 files written in `C:\Windows\System32`") after raw events age out, and the UI shows an "aggregated" badge (`Observability.Aggregated`) rather than pretending the detail still exists.

---

## 5. Monitoring layer

### 5.1 Process tree

**Primary:** ETW `Microsoft-Windows-Kernel-Process` (keywords for process/thread/image-load) — event IDs 1/2 (start/stop), 5 (image unload), 3/4 (thread). The start payload carries `ProcessID`, `ParentID`, `ImageName`, `SessionID`, and TraceEvent surfaces a `CommandLine` for kernel process-start; when the payload lacks it we read the target's PEB (`NtQueryInformationProcess` + `ReadProcessMemory` of `RTL_USER_PROCESS_PARAMETERS.CommandLine`) and fall back to `Win32_Process` WMI/CIM.

**Scope resolution** (the subtle part — this decides whether an event belongs to the session at all):

```
on ProcessStart(child=pid, parent=ppid):
  if parent in scope                → child confirmed (parent_state propagated)
  elif ppid not in scope and ppid alive → child excluded
  elif ppid == 0 / dead             → look for "orphan attribution":
        start within ±1500 ms of a confirmed session process start
        AND (same parent image as a known tree member OR parent PID reused)
        → child unconfirmed  (shown with a "uncertain scope" badge, still analysed)
  else                              → excluded
```

- PID reuse is handled by keying on `(pid, start_utc)` everywhere, never PID alone.
- **Ancestry is reconstructed** from recorded `processes` rows, so a process whose parent already exited still renders correctly in the tree.
- **Job object**: optional "strict tree membership" toggle (off by default) because assigning a monitored app to a job can break installers/launchers that manage their own job; when enabled it is used only for membership queries, never limits or breakaway changes.
- **Behaviour is never modified**: no debugger attach, no DLL injection, no suspend-on-start.

### 5.2 File system

**Primary:** ETW `Microsoft-Windows-Kernel-File` (create/open/read/write/rename/delete/set-info) with keyword masks enabled per collection profile. This is a *system-wide* firehose (~10k+ events/s on a busy machine), so three filters apply, in this order:

1. **Scope filter** — keep only events from in-scope PIDs (cheap, first).
2. **Relevance filter** — keep all writes/creates/deletes/renames in scope; for *reads*, keep the first access per (pid, path) plus any path in the sensitive catalog plus 1-in-50 sampling elsewhere (documented, counted, surfaced as a collection stat).
3. **Volume fuse** — if sustained > 8k events/s for 5 s, raise the read sample rate and record a `gap` row (`reason: volume-throttle`) so the UI can say "read events sampled 1:50 during this period".

**Path normalisation:** ETW gives `\Device\HarddiskVolume3\...`; map to drive letters once at startup via `QueryDosDevice` and cache. Renames arrive as `RenamePath`/`RenameOld`/`RenameNew` on a single event — record both names in one row with `kind=FileRename`.

**Sensitive path catalog** (data file, editable in Settings; ships with defaults):

| Group | Examples |
|---|---|
| Persistence | `%APPDATA%\...\Start Menu\Programs\Startup`, `%ProgramData%\...\Startup`, `Run`/`RunOnce` keys, `Tasks\` folder |
| System integrity | `C:\Windows\System32`, `C:\Windows\SysWOW64`, `C:\Windows\System32\drivers`, `C:\Program Files*` |
| Credentials / secrets | browser `Login Data`/`Cookies`/`Local State`, `%APPDATA%\Microsoft\Credentials`, SSH keys, `.env`, wallet dirs |
| User data risk | `%USERPROFILE%\Documents`, `Desktop`, `Downloads`, `%TEMP%` (as drop location) |

The catalog is a *config*, not a constant — the safe test harness points it at a temporary directory (§11.2), which is what makes testing "startup folder write" honest without touching the real startup folder.

**Fallback when ETW file keywords are unavailable/denied:** `ReadDirectoryChangesW` on catalogued directories only, degraded mode clearly labelled (misses deletes and most temp activity).

### 5.3 Network

- **TCP** — ETW `Microsoft-Windows-Kernel-Network` (TcpIp connect/accept/send/recv/close). Connection events carry the owning process in the event header `ProcessId`; byte counters come from send/recv events aggregated per 1 s.
- **Correlation fallback / verification** — `GetExtendedTcpTable` (iphlpapi) polled at 1 s for in-scope PIDs; its `dwOwningPid` is authoritative for *established* sockets and repairs attribution when ETW's header PID is the completion thread rather than the owner. Discrepancies are recorded as `attributionConflict` detail, not silently resolved.
- **DNS** — ETW `Microsoft-Windows-DNS-Client` (3006 query, 3008 response with status/answers). Payload PID attributes the query. Response status lets us detect NXDOMAIN storms (DGA signal).
- **UDP** — recorded as flow aggregates (`ip:port → ip:port`, count/bytes); no per-datagram rows.
- **IP classification (offline only):** private / loopback / link-local / CGNAT / multicast / public, plus a curated risky-port table (21, 23, 445, 139, 3389, 4444, 5900, 25 as a *signal*, not a verdict), plus an optional local IOC list. No reputation API calls: they would leak the user's traffic and make the demo depend on the network.

### 5.4 Capability matrix — observed vs. inferred (requirement §6)

This table ships in the UI (Settings → "What this tool can and cannot see") and in every report.

| Activity | Mechanism | Class |
|---|---|---|
| Process create/exit, parent, image | Kernel-Process 1/2 | **Direct** |
| Command line | ProcessStart payload → PEB → WMI | Direct (fallback chain, may be blank for protected processes) |
| DLL/image load per process | Kernel-Process ImageLoad | Direct (only if keyword enabled; misses unloaded-early images) |
| File create/write/delete/rename | Kernel-File | **Direct** (paths normalised; some buffered writes appear late) |
| File content | — | **Not observable** (metadata only) |
| Registry set/delete | Kernel-Registry (optional) | Direct |
| TCP connect/accept + owner PID | Kernel-Network + `GetExtendedTcpTable` | Direct (attribution conflicts possible) |
| DNS query/response | DNS-Client 3006/3008 | Direct (PID attribution best-effort) |
| Bytes transferred | Kernel-Network send/recv | Direct (aggregated per second) |
| Payload / URL / TLS SNI-less content | — | **Not observable** |
| Process injection (remote thread, cross-process write) | No user-mode ETW callback for this | **Inferred** heuristics, or Direct *if* Sysmon's `Microsoft-Windows-Sysmon` provider is present (Event IDs 8/10) — optional sensor, detected at startup, degrades gracefully |
| Privilege escalation / token theft | Security-Auditing 4672/4688 (needs audit policy) | **Partial** |
| Everything, under event loss | Loss counters from the session | Reported as a gap, never hidden |

UI rule: every event and detection carries a badge (`direct` / `inferred` / `aggregated` / `partial`) rendered as text, not just colour.

---

## 6. Detection engine

### 6.1 Pipeline

```
event ─► Normaliser ─► Scope filter ─► RuleEvaluator (stateless, per event)
                                   └─► Correlator (stateful, per session+pid, time-indexed window)
                                            └─► DetectionAggregator (groups by rule+process, merges repeats)
                                                     └─► RiskScorer ─► score_history + SSE
```

- **Two rule shapes:** `IEventRule` (fires on one event, e.g. "child is `powershell.exe`") and `ICorrelatedRule` (evaluated on 1 s ticks over the window index, e.g. "startup write then external connect within 60 s").
- **Determinism:** correlated rules read only events with `TimestampUtc ≤ now` in `Seq` order; `Argus.Cli replay` feeds a JSONL fixture through the identical pipeline and diffs detections. This is how rules are regression-tested without Windows.
- **Aggregation:** a rule match opens a detection keyed `(session, ruleId, scopePid)` and increments `event_count`/`last_ts` for repeats within 5 min, so a looping malware doesn't produce 4,000 cards. Escalation (new evidence category) promotes an open detection rather than duplicating it.
- **Every detection must state three things:** what was observed (facts with `Seq` links), which rule fired (id + threshold), and what would have changed the verdict (counterfactual). "AI thinks it's bad" is never acceptable output.

### 6.2 Scoring model

Per detection `d` with severity `S ∈ [5,100]`, confidence `c ∈ (0,1]`, age `a`:

```
w_d      = (S/100) · c · decay(a),     decay(a) = max(0.60, 0.5^(a / 15 min))
risk     = 100 · (1 − Π_d (1 − w_d)) · corroboration
corroboration = min(1.25, 1 + 0.08 · (distinctEvidenceCategories − 1))
band:  Malicious   if risk ≥ 65 AND (categories ≥ 2 OR exists S ≥ 90 with c ≥ 0.8)
       Suspicious  if risk ≥ 20 OR exists S ≥ 45
       Benign      otherwise  → labelled "no significant indicators", never "safe"
```

Design points, all of which the UI exposes:

- **Noisy-OR, not sum:** ten minor signals cannot alone reach "malicious" (satisfies "should not classify on one event" and its converse).
- **Corroboration bonus** rewards *independent categories* (process + file + network), not repeated events in one category.
- **Decay floor 0.60** means evidence fades but is never forgotten mid-session; the session also keeps `peak_score` so a spike followed by quiet still reads as "had a spike at 00:03:12".
- **Confidence** starts from observability (`Direct 0.9`, `Partial 0.7`, `Inferred 0.5`) times evidence count saturation `1 − e^(−n/3)` — inferred signals must work harder.
- **Score history** is sampled at 1 s (plus on change) so the dashboard sparkline and the report show *when* risk rose, which is the actual investigative value.

### 6.3 Rule catalog v1 (shipped in `docs/RULES.md`, ~22 rules)

| ID | Title | Sev | Cat. | MITRE |
|---|---|---|---|---|
| P-001 | Shell/interpreter spawned by non-shell parent | 60 | process | T1059 |
| P-002 | Shell spawned by Office/browser/PDF reader | 85 | process | T1566, T1059 |
| P-003 | Interpreter (`wscript`, `mshta`, `rundll32`, `regsvr32`) with URL/`-enc` args | 75 | process | T1218, T1027 |
| P-004 | Executable launched from `%TEMP%`/`Downloads`/`%APPDATA%` | 45 | process | T1204 |
| P-005 | Unsigned binary (no valid Authenticode chain) launched in tree | 30 | process | T1553 |
| P-006 | Same image launched with 3+ distinct `--`/`/` flags (discovery) | 25 | process | T1082 |
| P-007 | `vssadmin`/`wbadmin`/`bcdedit` shadow-copy or recovery tampering | 80 | process | T1490 |
| P-008 | Remote-thread / cross-process access indicator (inferred or Sysmon) | 65 | process | T1055 |
| F-001 | Write into Startup folder | 80 | file | T1547.001 |
| F-002 | Write into `Run`/`RunOnce` (registry or via `reg.exe`) | 75 | file | T1547.001 |
| F-003 | Scheduled task creation (`schtasks`, `Tasks\` dir) | 70 | file | T1053.005 |
| F-004 | Mass file creation ≥ 200 in 60 s | 55 | file | T1105, T1486 |
| F-005 | Write into `System32`/`drivers`/`Program Files` | 65 | file | T1543, T1574 |
| F-006 | Delete/overwrite burst with rename churn (ransomware shape) | 85 | file | T1486 |
| F-007 | Drop an `.exe`/`.dll`/`.scr` payload into a user-writable dir | 50 | file | T1105 |
| F-008 | Access to credential stores (browser `Login Data`, SSH keys, wallet) | 70 | file | T1555 |
| N-001 | Connect to risky service port from non-service process | 45 | network | T1021 |
| N-002 | Beaconing: ≥ 6 connections to one endpoint with low jitter (<15 %) | 60 | network | T1071 |
| N-003 | Outbound volume > 20 MB to a single public IP in 60 s | 65 | network | T1041 |
| N-004 | Connection to a bare public IP with no prior DNS query | 35 | network | T1095 |
| N-005 | NXDOMAIN storm (≥ 15 distinct failed lookups/60 s) | 50 | network | T1568.002 |
| X-001 | Persistence write **then** external connection within 60 s | 90 | file+network | T1105 |
| X-002 | Startup write **then** process execution from that path | 85 | file+process | T1547.001 |

Each rule file contains: trigger, threshold, severity, confidence base, category, MITRE id, `reason` template ("`{child}` was launched by `{parent}`, which does not normally spawn command interpreters; argument matched `{pattern}`"), counterfactual text, and 2+ fixture scenarios. Thresholds live in `rules.json` (shipped + user-overridable) so tuning doesn't need a rebuild — but rule *logic* stays in C# where it is unit-tested.

---

## 7. Machine learning layer (Phase 6, advisory)

- **Features** per (session, 30 s window, pid subtree): event counts by category, unique path/domain/IP counts, subtree depth, unsigned-exec ratio, sensitive-path ratio, outbound bytes, port diversity, connection interval mean/variance (beaconing), command-line token entropy, new-extension ratio, DNS failure ratio, time-of-first-network-vs-first-write.
- **Model:** ML.NET gradient-boosted trees (FastTree), one model over windows, 3-class (benign/suspicious/malicious) + probability. Training project is separate (`tools/train/`), dataset exported from SQLite as CSV.
- **Labels, honestly:** (a) our own benign corpus (§11.1), (b) behaviour-simulator scenarios with known intent, (c) *optional* — if you supply sandbox reports or run samples in **your** VM, imported JSON labels. Public runtime-behaviour datasets are scarce; the plan does not pretend otherwise.
- **Integration:** `ml_score` is stored alongside rule risk and displayed as a separate bar labelled "model (shadow)". Blend rule: `final = max(rule_risk, 0.8 · ml_score)` **only** once calibration on our corpus shows precision ≥ 0.9 at the malicious band; until then it is display-only and never changes the verdict. A config flag (`ml.influence: off|advisory|blend`) records which mode a session ran in, and every report states it.
- **Explainability:** per-window feature contributions (masking-based delta) → "top 5 features" list. Wording is fixed: "model influence", never "the AI decided".

---

## 8. Dashboard specification

Dark-first console, 12-column grid, `ui-monospace` for data, dense by default with a comfortable toggle. Risk palette: slate base, amber `#f5a524` suspicious, red `#e5484d` malicious, teal accents. No animated gradients, no fake "scanning" theatre — the trust proposition is legibility.

### 8.1 Home / Sessions
Session cards (target, verdict pill, peak/current score, duration, counts, "incomplete monitoring" flag), "Monitor an application" primary action (file picker with signature/hash preview before launch), history table with search.

### 8.2 Live dashboard (per session)
Header: target path + hash + signer, `live`/`stopped` status, elapsed timer, `Stop monitoring` (never "kill app" without an explicit confirm).
Strip: risk gauge (current + peak marker), processes, file ops, network connections, suspicious events, monitoring gaps.
Body: risk-over-time chart (1 s samples, band shading, markers where detections fired), live signal feed (newest first, categorised, auto-pause on hover), top rules triggered, mini process tree, "collection health" (events/s, loss counter, read sampling rate).

### 8.3 Process explorer
Virtualised tree with expand/collapse, columns: name, PID, PPID, path, command line (truncated + copy), start time, still-running, risk contribution, scope state. Selecting a process opens a drawer: identity (path, hash, signer, integrity), lifetime, children, counts by category, its detections, and a filtered event list. Keyboard: arrows navigate, `Enter` opens, `/` searches.

### 8.4 File activity explorer
Table: timestamp, process, path (middle-elided with full tooltip), operation, bytes, risk classification, badges. Filters: operation, category, process, path substring, risk ≥, time range; server-side paging by `(ts, seq)` cursor. Row → detail drawer: why flagged (rule + factors), related events, "show in timeline", "filter to this path".

### 8.5 Network activity explorer
Table: process, remote IP, port, protocol, hostname (from DNS correlation, with the matched query and how it was inferred), first/last seen, connection count, bytes in/out, status, risk. Grouped-by-destination view for beaconing eyeballing. Internal-vs-external segmentation; risky-port flags are labelled as signals.

### 8.6 Threat analysis panel (the centrepiece)
Detection cards sorted by severity then recency. Each card, collapsed, shows: verdict icon, title, plain reason, severity, time, affected process, evidence count. Expanded, it shows exactly the layout the brief asks for:

```
⚠ Suspicious Process Activity — powershell.exe in tree of sample.exe
  Parent      : sample.exe (PID 4312, signed: none)
  Child       : powershell.exe (PID 5120) — cmd: -nop -w hidden -enc SQBFAF...
  Why         : sample.exe is not a shell, script host, or installer, yet it spawned
                a command interpreter with encoded arguments.
  Evidence    : 3 process events, 1 file event, 1 network event   [direct][inferred]
  Corroboration: startup-folder write 4.2 s earlier; TCP 443 → 203.0.113.7 at +11.8 s
  Risk         : 86 / Malicious — weights w = 0.61 (P-002), 0.22 (F-001), 0.14 (X-001)
                 noisy-OR = 0.74, ×1.16 corroboration (3 categories) = 0.86
  Counterfactual: would read Suspicious (34) if the child were a signed GUI app
  MITRE        : T1059, T1547.001
  [Investigate]  [Show in timeline]  [Export evidence]
```
`Investigate` opens a focused mode: the detection's evidence chain as a horizontal graph (process ▸ file ▸ connection), each node clickable, with the exact events used.

### 8.7 Timeline
Unified chronological stream (process/file/registry/network/dns/detection/gap), category filter chips, density control, jump-to-detection, brush selection on the risk chart to zoom a time range, and "explain this range" (aggregate summary + which rules were near-threshold). Groups by 1 s / 10 s / 1 min adaptive buckets with expand.

### 8.8 Search, report, settings
- **Search:** FTS5 over paths, domains, command lines, detection reasons; global shortcut `Ctrl+K`; saved filters.
- **Report export:** self-contained HTML (inline CSS, inline JSON, no external assets) + raw JSON bundle. Sections: executive summary, verdict with score, per-category counts, detections with evidence, full timeline (top N + aggregates), collection-health and **limitations** section auto-filled from actual gaps, "what was not observable" table, agent version + Windows build + config hash.
- **Settings:** collection profile (Balanced / Aggressive / Audit), read sampling, registry + DNS toggles, sensitive-path catalog editor, IOC list, retention, alert thresholds, ML mode, "what this can't see" page, diagnostics (session/loss/episode stats, open log folder).

### 8.9 UI engineering constraints
- Virtualised lists (`@tanstack/react-virtual`) — target 60 fps with 100k rows in view-model, never render more than ~40 rows.
- SSE frames coalesced at 4 Hz; payload is deltas + rolled-up counters, not every raw event.
- Front-end states mandatory everywhere: loading, empty, error, disconnecting, reconnecting, "monitoring ended".
- Accessibility: full keyboard reach, focus rings, ARIA labels on badges, `prefers-reduced-motion` respected, contrast ≥ 4.5:1 on all text.
- Persistent banner when any monitoring gap exists: "This session has collection gaps — absence of detection here is weaker evidence than usual."

---

## 9. Agent API, IPC and local security

| Route | Purpose |
|---|---|
| `POST /api/sessions` | start monitoring `{path, args, mode}` |
| `POST /api/sessions/{id}/stop` | stop (optionally with `terminate:false` default) |
| `GET /api/sessions` · `GET /api/sessions/{id}` | list / detail + counters |
| `GET /api/sessions/{id}/stream` | SSE: `event`, `detection`, `score`, `stats`, `gap`, `state` |
| `GET /api/sessions/{id}/events?category&kind&pid&q&minRisk&cursor` | paged events |
| `GET /api/sessions/{id}/processes` | tree |
| `GET /api/sessions/{id}/detections` · `/detections/{n}` | cards / full evidence |
| `GET /api/sessions/{id}/timeline?from&to` | bucketed timeline |
| `GET /api/sessions/{id}/report.html` · `/report.json` | export |
| `GET /api/health` | elevation, ETW session state, providers, version |

Security posture of an elevated local server (this project is judged on it, so it is spec'd, not assumed):

- Bind `127.0.0.1` on an ephemeral port; never `0.0.0.0`.
- 128-bit random bearer token minted per agent launch; passed to the UI shell over its stdout/CLI args (same-user, same-integrity), never in a file or URL query.
- **DNS-rebinding defense:** reject any request whose `Host` is not `127.0.0.1:<port>` and whose `Origin` (when present) is not exactly the loopback origin. No CORS headers, `SameSite`-less: no cookies at all.
- Mutating routes require the token and a loopback `Origin`; GETs are read-only.
- Static files served from an embedded manifest with strict path canonicalisation; CSP `default-src 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self'`.
- Kestrel request-body limit small (start payload is a path + args); no request logging of command lines into agent logs.
- Agent refuses to start non-elevated with a machine-readable error the UI shell turns into a "Restart as administrator" action, never a stack trace.

---

## 10. Performance and resource budget

| Metric | Target | Enforcement |
|---|---|---|
| Agent idle CPU (UI open, quiet app) | < 2 % of one core | ETW filter scope first; no polling loops faster than 1 s |
| Sustained throughput | 5k events/s, burst 20k/s for 10 s | batch insert (500 / 250 ms), bounded channel (drop-oldest + gap row) |
| Agent RAM | < 300 MB at 5k events/s | ring buffer cap 250k events; rollups; no per-event UI objects |
| UI event latency | ≤ 2 s end-to-end | SSE coalescing; ETW's own buffering is ~1–3 s (see §12) |
| DB growth | ≤ 40 MB/hour on a busy app, then flat after rollup | tiering §4.3, retention default 24 h |
| Startup to monitoring | < 1.5 s | precompiled schema, warm provider metadata |
| Query latency | p95 < 150 ms on 500k events | indexes §4.2, cursor pagination, no offset paging |

Measured with `Argus.Cli selftest --load` replaying a 200k-event fixture at speed and logging CPU/RAM/DB size. Numbers go in `docs/DEMO.md` — no speed claims without a measurement.

---

## 11. Test strategy

### 11.1 Benign corpus (false-positive baseline)
Notepad, 7-Zip (compress/extract), VLC, a small Python script, `dotnet run` of a console app, Chrome/Edge with a few tabs, VS Code open/search. Expectation: risk < 20, **zero** severity ≥ 80 detections. Any hit is either a rule bug or a genuinely suspicious benign behaviour — both get a written triage note (this log is great report material and satisfies "support safe testing with benign applications").

### 11.2 Behaviour simulator (safe, controlled, "malicious-shaped")
`tools/behavior-sim` is a console program that performs suspicious *shapes* without doing harm, each scenario a flag:

| Scenario | What it does | Expected detection |
|---|---|---|
| `startup-write` | writes a dummy `.lnk` into a **test startup root** (`--root <temp>`), never the real one | F-001 |
| `spawn-shell` | spawns `powershell -nop -enc <benign base64>` printing a string | P-002 |
| `drop-and-run` | writes `dummy.exe` (a signed-by-us hello-world) into temp and runs it | F-007, P-004 |
| `beacon` | 10 connects, 5 s apart, to a loopback listener | N-002 |
| `exfil-shape` | uploads 25 MB to loopback | N-003 (local IP → must classify as internal, assert *no* alert; then a `--public-sim` variant flips the IOC to exercise the public branch) |
| `cred-access` | opens a copy of a fake `Login Data` in a test catalog path | F-008 |
| `noise` | does 5,000 benign temp writes/reads (FP pressure) | none |

Safety rails: refuses to run without `--root`; refuses paths outside `%TEMP%`; refuses to write to any path containing `Startup` unless `--allow-system-writes` is explicitly passed (and even then only a `.txt` file it deletes); no real C2, no encryption, no privilege calls.

### 11.3 Automated levels

| Level | Tool | Runs on |
|---|---|---|
| Unit — scoring math, scope resolution, path normaliser, aggregation | xUnit + FluentAssertions | Linux |
| Rule fixtures — 30+ JSONL scenarios → expected detection set | `Argus.Cli replay --assert` | Linux |
| Storage — schema migration, WAL concurrency, rollup correctness, FTS | xUnit | Linux |
| Analysis determinism — same fixture twice ⇒ identical detection ids/scores | `replay --twice` | Linux |
| UI build + typecheck | `tsc --noEmit`, `vite build`, `eslint` | Linux |
| UI behaviour — routes render with replay data, SSE reconnect, empty/error states | Playwright (headless) | Linux |
| Windows integration — ETW providers attach, elevation, real tree, real net | `scripts/smoke.ps1` (self-test + live capture + replay), `scripts/verify.ps1 -Smoke` | Windows |
| Resilience — kill agent, kill monitored app, deny access to LSASS, ETW session conflict | scripted | Windows |
| Security — foreign `Origin`/`Host` rejected, missing token 401, path traversal 404 | xUnit + curl script | both |

Explicitly tested degradations: non-elevated start, ETW session already in use, provider not found, 0 in-scope processes, monitored app exits in <1 s, session with 0 detections (UI must say "no significant indicators" + limitations, not "safe").

---

## 12. Risks, limitations, and what the product must admit

**Known limitations (product text, not just engineering notes):**

1. **Near-real-time, not hard real-time.** ETW buffers and the pipeline add ~1–3 s. A process that lives 200 ms may be partially missed; detection is on behaviour *observed*, not behaviour *performed*.
2. **Event loss under load.** Kernel buffers can overflow. We count and display loss; a session with loss is marked *incomplete*.
3. **No payload visibility.** We see endpoints, volumes and timing, not what was sent. Exfiltration is inferred from volume/destination shape.
4. **Injection is inferred** without a driver or Sysmon; we say so on the card.
5. **Scope ambiguity.** PID reuse, fast parent exit, and services with unusual parentage produce `unconfirmed` processes; we keep them visible and labelled rather than dropping or over-claiming.
6. **Aggregated evidence.** After rollup, counts survive but individual events don't.
7. **ML is advisory and data-limited.** Public runtime-behaviour datasets are scarce; our labels are mostly self-generated. Precision is reported, not assumed.
8. **No absence-of-evidence claim.** Explicit UI copy: "No suspicious behaviour was observed in this session. This is not proof the application is safe."
9. **Legality/ethics.** Monitor only applications you are authorised to analyse; run unknown samples in a VM with host-only networking, snapshots, and no shared folders; the tool itself never executes anything except the app you chose.

**Project risks and mitigations:**

| Risk | Likelihood | Mitigation |
|---|---|---|
| ETW provider upgrade churn between Win10 builds | Medium | capability probe at startup + `docs/CAPABILITY-MATRIX.md` fallbacks; log provider metadata in report |
| File firehose swamps a laptop | High | scope-first filter, read sampling, volume fuse, visible throttle state |
| ETW/NT-Kernel-Logger exclusivity conflicts with other tools | Medium | use manifest providers in our own session (not the exclusive NT Kernel Logger) where possible; detect `ERROR_ALREADY_EXISTS` and report a clear remediation ("close Procmon/Sysmon trace") |
| UI scope creep eats the schedule | High | screen-by-screen DoD (§13), Phase 4 caps at the 8 specified screens |
| Windows-only bugs found late | High | Linux-verifiable core first, simulator + replay from Phase 1, Windows smoke test at end of Phase 2 |
| Rule false positives embarrassing in the demo | Medium | benign corpus in every phase; aggressive rules ship disabled by default |

---

## 13. Phased delivery plan

Estimates are working days of my time; you verify at the marked checkpoints. "Linux ✅" means I can prove it here; "Win ✅" means it needs your Windows machine.

**Progress (2026-11-06):** Phase 0 and Phase 1 are implemented and verified on Linux (83 tests,
14 asserted replay scenarios, SQLite round-trip). Two deliberate scoping deviations: the
Windows-only projects (`Monitor`, `Agent`, `Desktop`) are not scaffolded yet, so every project in
`Argus.sln` still builds on this machine — they land in Phase 2 with their ETW smoke test; the
web scaffold moves to Phase 4, when there is real data for it to render. See `README.md` for the
current verified/unverified split.

**Progress (2026-11-07):** Phase 2 code is implemented: `Argus.Monitor` (Kernel-Process/File/
Network/Registry/DNS ETW collection, process metadata, `GetExtendedTcpTable` owner table,
polling repair, drive-letter mapping, read sampling, volume fuse, gap accounting) and
`Argus.Agent` (elevated host, bearer token + Host/Origin guards, one active session, live
pipeline, SQLite + JSONL recording, SSE, reports, `--self-test`, UAC relaunch). Both projects
compile on Linux with `EnableWindowsTargeting`, and the pure mapping/sampling/volume logic is
covered by tests. The suite is now **96 tests** (61 core, 24 analysis, 11 storage), all green,
plus the 14 asserted replay scenarios. `scripts/smoke.ps1` (and `verify.ps1 -Smoke`) performs
the elevated Windows check: self-test JSON, a real notepad session with recording, and replay
of that recording.

The first real notepad capture from the `tiny` VM replayed on Linux (108 events, benign), which
confirms the ETW process path, JSONL format and Windows-to-Linux round trip. That replay also
exposed and fixed a scope false positive: `System32` processes with unknown parents were
attributed to a notepad target merely because they shared `System32`; the shared-directory
heuristic now excludes `Windows`, `Program Files` and `ProgramData`. **File/network/DNS volume,
event loss under load, UAC relaunch and the live API/SSE stream still need their own Windows
checks.**

### Phase 0 — Foundations (2 d)
Repo `git init`, solution + 6 projects, `Directory.Build.props`, analyzers, editorconfig, `PLAN.md`/`docs/*`, event contract + enums, capability matrix, threat model, .NET SDK bootstrap in `scripts/`, web scaffold (Vite + TS + Tailwind + shell layout), `scripts/verify.sh`.
**DoD:** `dotnet build` of cross-platform projects passes on Linux; `npm run build` passes; empty app shell renders.

### Phase 1 — Core, storage, simulator, replay harness (4 d) — Linux ✅
Schema v1 + migrations, repositories, FTS, rollups, `BehaviorEvent` normaliser, path normaliser (Windows+POSIX test doubles), scope tracker, `IEventSource` abstraction, `SimulatedEventSource`, JSONL replay, `argus replay --assert`, 12 fixture scenarios, scoring math + unit tests.
**DoD:** `replay` produces deterministic, asserted detection output for 12 scenarios; storage tests green incl. WAL concurrency; aggregator groups repeats.
**Hand-off:** you install .NET 8 SDK on Windows and run `scripts/verify.ps1` (build only) — catches Windows-target compile issues early.

### Phase 2 — Windows monitoring + agent host (6 d) — Linux ✅ · Win ✅ (process capture + replay) · file/net/UAC/API ⏳
Kernel-Process collector (cmdline chain), Kernel-File collector (scope filter, drive-letter mapping, read sampling, fuse), Kernel-Network + `GetExtendedTcpTable` attribution repair, DNS collector, registry collector (optional), gap recorder, agent host with Kestrel + SSE + token/Origin guards, elevation bootstrap (`runas` relaunch, single instance mutex), `scripts/verify.ps1` checklist, `scripts/smoke.ps1` live check, first real session recorded to JSONL.
**DoD (Windows):** monitoring `notepad.exe` and `7z.exe` yields a correct tree, real file events with resolved paths, real connections with owner PID; non-elevated start shows the elevation path, not a crash; recorded JSONL replays identically on Linux. Verified by `scripts/smoke.ps1`: self-test JSON, live notepad capture, non-empty recording, replay exit 0.

### Phase 3 — Detection engine (4 d) — Linux ✅
Correlator + window index, 22 rules with fixtures and reason templates, detection aggregation/escalation, risk scorer, score history, gap→confidence coupling, counterfactual generation, `RULES.md` generator.
**DoD:** every rule has ≥2 fixtures; benign corpus fixtures produce 0 high-severity hits; `X-001`-style correlation proven by replay; score math matches a hand-computed table.

### Phase 4 — Dashboard v1 (6 d) — Linux ✅ (browser verified)
All 8 screens against replay/SSE, virtualisation, timeline, threat panel with evidence chain, search, keyboard nav, empty/error/disconnected states, dark theme, responsive ≥ 1280 px.
**DoD:** Playwright passes on 8 routes; 100k-row fixture scrolls without jank; every event row exposes its observability badge; SSE reconnect recovers state.

### Phase 5 — Windows end-to-end + reports (4 d) — Win ✅
Full run on Windows: launch → live dashboard → explorer drill-down → report export; behaviour-sim scenarios producing the expected detections; perf measurement (§10); benign corpus triage log; `docs/LIMITATIONS.md`.
**DoD:** the §14 demo script runs start to finish on a clean Windows VM, twice, with identical verdicts; report opens self-contained and states gaps + limitations.

### Phase 6 — ML advisory layer (5 d) — Linux ✅ + Win data
Feature builder, CSV export, ML.NET training project, calibration on corpus, shadow-mode UI, contribution explanations, `ml.influence` config + report disclosure.
**DoD:** reported precision/recall per class on a held-out split; no verdict changes in `advisory` mode; blending gated on the measured precision threshold.

### Phase 7 — Hardening + packaging (3 d)
Resilience (agent crash → UI explains, session marked incomplete; app exit; ETW conflict; access denied), log/diagnostics bundle, single-folder publish (`dotnet publish -r win-x64 --self-contained`), WebView2 fallback to default browser, `DEMO.md`, `README.md`, final polish.
**DoD:** publish artifact runs on a machine without the SDK; all §11.3 predictions hold; docs complete.

**Total ≈ 34 working days.** Natural stopping points for review: end of P1 (core proven), P2 (real data flowing), P3 (detections explainable), P4 (dashboard complete), P5 (demoable product), P6 (ML story).

---

## 14. Target demo script (acceptance, in order)

1. Launch Argus → elevation prompt → dashboard opens on the Sessions screen.
2. Monitor `notepad.exe`; type text; save a file. Show tree, file writes, **0 suspicious**, and the limitations banner explaining what "no detections" means.
3. Monitor `tools/behavior-sim --scenario spawn-shell --root %TEMP%\argus-test`: watch the process tree expand, the startup-folder write appear (test catalog), the shell spawn, the loopback beacon, and **P-002 + F-001 + X-001** raise a Malicious verdict at the expected score.
4. Open the detection → read the plain-language reason, the evidence chain, the score contributions, the counterfactual, the MITRE mapping, the observability badges.
5. Jump to timeline, brush-zoom the 12 s window, show causation order (write → spawn → connect).
6. Search the session for the dropped path; filter file explorer to that process; export the HTML report and open it with the agent stopped.
7. Show Settings → "what this tool cannot see", plus a live gap counter (`beacon` scenario with collection throttled to force one).
8. Close with the ML panel in shadow mode: model score next to rule score, contributions listed, verdict unchanged.

---

## 15. Defaults I am taking unless you say otherwise

| # | Question | Default | Cost to change |
|---|---|---|---|
| 1 | Project name | **Argus** | trivial (rename pass) |
| 2 | UI technology | WebView2 + React dashboard over a .NET agent | high — pure WPF would be the alternative, and it would also make ~half this plan unverifiable on this machine |
| 3 | Attach to already-running PID | Phase 6+ stretch, launch mode only in v1 | low–medium |
| 4 | Registry monitoring | on by default (low volume, high signal for persistence) | trivial |
| 5 | Sysmon-assisted injection detection | auto-detect at startup, use if present, never require it | trivial |
| 6 | Retention | 24 h raw then rollup, manual delete | trivial |
| 7 | Windows test target | Windows 11 24H2 VM with snapshot + host-only network | — |
| 8 | UI language | English, metric-free wording | trivial |

**First concrete commits when you green-light this** (all Phase 0/1, all Linux-verifiable):
1. Solution scaffold + `Directory.Build.props` + `PLAN.md`/docs stamped into the repo.
2. `Argus.Core` event contract + scoring math + unit tests.
3. Schema v1 + repositories + `Argus.Simulator` + `argus replay` with the first 6 fixtures.
4. Dashboard shell with the Sessions + Live screens wired to replay data, shown in the browser preview.

Then we hit Phase 2, where your Windows machine becomes the critical path: you run `scripts/verify.ps1`, send back the console output and a recorded session JSONL, and I iterate on the ETW layer from that evidence.
