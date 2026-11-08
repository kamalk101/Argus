# Argus — handoff context for the Windows VM

You are picking up **Argus**, a defensive real-time application behaviour monitor for
Windows 10/11. Read `README.md` and `PLAN.md` first; this file records the exact state and
the rules that must not be broken while continuing the work.

## 1. Repository and environment

- Repo: `https://github.com/kamalk101/Argus.git`, branch `main`.
- Phase 2 handoff commit: `2a9c138` (`Drop ETW process rundown and tighten orphan scope`).
  Pull `main` before starting.
- Target environment: Windows 10/11 x64 VM, .NET 8 SDK, **elevated PowerShell** for live ETW.
- Repo root: wherever you cloned it. Do not assume the Linux path used during development.
- Cross-platform projects: `Argus.Core`, `Argus.Analysis`, `Argus.Storage`, `Argus.Simulator`,
  `Argus.Cli` (`net8.0`). Windows projects: `Argus.Monitor`, `Argus.Agent`
  (`net8.0-windows`, `EnableWindowsTargeting=true`).
- `Argus.Desktop`, `web/`, `tools/behavior-sim` and the full 22-rule catalogue **do not exist
  yet**. Do not reference or scaffold them unless the current task explicitly says so.

## 2. Product contract and non-negotiables

- Monitor **one user-selected `.exe`** and its full process tree. Do not monitor the whole
  machine as if it were the target.
- Collect process, file, network, DNS and optional registry behaviour. Correlate events into
  explainable detections with evidence, reason, counterfactual and MITRE mapping.
- Never claim an application is "safe". When nothing fires, the correct wording is
  **"no significant indicators were observed"** plus the limitations.
- Monitoring gaps, denied access and event loss must be recorded and shown, never hidden.
- No real malware, no downloading samples, no execution of anything except the selected app.
  Safe fixtures and benign applications only.
- Observed vs inferred must stay explicit (`Observability.Direct|Partial|Inferred|Aggregated`).

## 3. Current state

### Implemented and Linux-verified

- Core event contract (`RawEvent`, `BehaviorEvent`), normaliser, path canonicalisation,
  sensitive-path catalog, IP classification, risk scorer/confidence model.
- Scope tracker, process table, detection aggregation, correlation index, session pipeline.
- SQLite schema/repositories/FTS/rollups, `SessionRecorder` facade, WAL concurrency.
- JSONL replay, scenario loader/runner, `argus replay --assert`, `argus rules`,
  `argus selftest`.
- ETW record mapper, file-key cache, read sampler, volume governor (pure Core code).
- `Argus.Monitor`: Kernel-Process/File/Network/Registry ETW, DNS provider, process metadata,
  `GetExtendedTcpTable` owner table, process/TCP polling repair, drive-letter mapping,
  gap accounting, scope filtering.
- `Argus.Agent`: elevated host, loopback Kestrel API/SSE, bearer token, Host/Origin guards,
  one active session, live pipeline, SQLite + JSONL recording, JSON/HTML reports,
  `--self-test`, `--elevate`, `--allow-non-elevated`.
- `scripts/verify.sh`, `scripts/verify.ps1`, `scripts/smoke.ps1` (`verify.ps1 -Smoke`).

### Verified on the Windows `tiny` VM

- Elevated notepad capture produced a valid JSONL recording.
- That recording replayed on Linux through the same pipeline.
- The replay exposed and fixed two scope bugs (see §5). After the fixes, only the root
  process is in scope and the recording is benign.
- This confirms the ETW process path, JSONL format and Windows-to-Linux round trip.
- Kernel records now decode after registering `Source.Kernel` (before that, every record was
  `Task(<guid>)/Opcode(n)` and nothing was mapped). File capture measured: 1,235 events in one
  session, 1,098 `fileCreate`, 55 `fileRead`, 78 `fileWrite`, 2 `fileDelete`, all with
  drive-letter paths and correct owner PIDs, no `\Device\` leakage.
- File capture end-to-end through the agent: 989 events for a powershell target that wrote to
  `%TEMP%\argus-writes`, 922 `fileCreate`, 45 `fileRead`, 2 `fileWrite`, 2 `fileDelete`, all
  PID-attributed, zero gaps, zero raw device paths.
- Network + DNS end-to-end: a loopback listener plus four `.example.net` resolutions produced
  1 `netConnect` (`127.0.0.1:45999`, `direct`) and 8 `dnsQuery` + 8 `dnsResponse` with hostnames,
  `queryType 1/28` and NXDOMAIN-ish statuses, all on the target PID, `partial`
  observability. DNS needed `Source.Dynamic` registration for payload fields.
- Live API guards with a fixed token/port: `/api/health` 200 without token, `/api/sessions`
  401 without token, bad `Origin` 403, bad `Host` 400, good token 200, and SSE
  `/api/sessions/{id}/stream` delivered `state` and `stats` events.
- `--self-test` inside an elevated agent: elevation, kernel provider, DNS provider, metadata
  and TCP table all pass; the 2 s probe saw 551 callbacks and forwarded 142 in-scope events.
- Non-elevated start without `--allow-non-elevated` exits 3 with the elevation message.
- `scripts/verify.ps1 -Smoke` passes end-to-end (self-test, 15 s notepad capture, replay).

### Not yet verified

- Registry capture under real activity (writes were not exercised).
- Event loss under load and the volume fuse on a busy machine.
- `--elevate` was only verified as far as the child launch: the identical command line run
  from an already-elevated shell starts, writes its ready file with `"elevated": true` and
  records events. The UAC prompt itself cannot be approved on this unattended VM, so the
  parent-side handshake (ready file -> JSON on stdout) has not been observed succeeding there.
- `7z.exe` or any non-trivial application.
- WebView2/dashboard (Phase 4).

Current automated counts: **96 tests** (61 core, 24 analysis, 11 storage), **14/14** asserted
replay scenarios, 7 shipped rules (`F-001`, `F-005`, `F-007`, `N-001`, `P-002`, `P-003`,
`X-001`).

## 4. Architecture and data flow

```
Argus.Monitor  (ETW + polling)
      │  RawEvent channel (bounded, scope-filtered)
      ▼
Argus.Agent / LiveSession
      │
      ├─► SessionPipeline (normalise → scope → rules → correlate → score)
      ├─► SessionRecorder → SQLite (events, processes, detections, scores, gaps)
      ├─► JSONL recording (`$meta` first line, then one RawEvent per line)
      └─► SSE hub (events, detection, score, stats, gap, state)
```

Key files:

- `src/Argus.Core/Events/RawEvent.cs`, `BehaviorEvent.cs`, `RawEventJson.cs`
- `src/Argus.Core/Processes/ProcessScopeTracker.cs` — scope rules, regression-sensitive
- `src/Argus.Core/Monitoring/EtwEventMapper.cs` — pure ETW → RawEvent mapping
- `src/Argus.Monitor/MonitorEventSource.cs` — scope gate, sampling, volume fuse, gaps
- `src/Argus.Monitor/EtwCollector.cs` — TraceEvent session and provider setup
- `src/Argus.Agent/LiveSession.cs` — batching, persistence, JSONL, SSE
- `src/Argus.Agent/SessionManager.cs` — target launch and session lifecycle
- `src/Argus.Analysis/Pipeline/SessionPipeline.cs` — shared live/replay pipeline
- `src/Argus.Storage/SessionRecorder.cs` — write policy for live and replay

## 5. Bugs already fixed — do not regress

1. **ETW IPv4 byte order.** `0x0100007F` must map to `127.0.0.1`, not `1.0.0.127`.
   `EtwEventMapper.NetworkBytes` uses `BitConverter.GetBytes` without reversal.
2. **Shared system directories are not scope evidence.** A target in
   `C:\Windows\System32` does not make every System32 process a candidate child.
   `ProcessScopeTracker` skips `Windows`, `Program Files`, `Program Files (x86)`,
   `ProgramData` and drive roots for the `image-under-root-directory` heuristic.
3. **ETW process rundown is not a process start.** `DCStart`/`DCEnd` records (Event IDs 3/4)
   describe processes that already existed when the session started. `EtwCollector` drops
   them; otherwise every process on the machine floods the session.
4. **PID 0 (`Idle`) and PID 4 (`System`) are never in scope.** They are not user-mode
   descendants of the target.
5. **Timing alone is not attribution.** The old `orphan-window` rule put pathless processes
   in scope merely because they started near the root. It was removed. Scope now requires a
   known parent or app-specific structural evidence.
6. **Completion is final.** `SessionRecorder.Complete` is idempotent; a second call must not
   rewrite status, score or loss counts.
7. **Live and replay share the pipeline.** Do not fork analysis logic for live sessions.
8. **JSONL starts with `$meta`.** Keep `RawEventJson` and `ScenarioLoader` compatible; a
   recording must replay on Linux without changes.

Relevant regression tests:

- `tests/Argus.Core.Tests/MonitoringTests.cs` (IPv4, file-key cache, sampling, fuse)
- `tests/Argus.Core.Tests/ScopeTrackerTests.cs` (shared dirs, PID 0/4, no timing-only scope)
- `tests/Argus.Core.Tests/PathKeyTests.cs` (longest device prefix)
- `tests/Argus.Storage.Tests/StorageTests.cs` (`SessionRecorder`, completion idempotence)

## 6. Code rules

- `Directory.Build.props` sets nullable, implicit usings, latest LangVersion and
  **warnings as errors**. Do not add suppressions casually.
- Keep `Argus.Core` free of Windows-only types and packages. Windows P/Invoke belongs in
  `Argus.Monitor`; host/HTTP concerns belong in `Argus.Agent`.
- Put testable pure logic in Core (mapping, sampling, scope, path handling) and test it on
  Linux-compatible `net8.0`.
- New rules: implement `IEventRule`/`ICorrelatedRule`, add metadata (id, severity,
  categories, MITRE, reason, counterfactual), and add at least two JSONL fixtures with
  explicit `expect` blocks.
- Keep event timestamps as sensor time, not arrival time. Keep events append-only.
- Do not log bearer tokens, command lines or captured data to agent logs.
- Do not add a dependency without checking it works on both the Linux test host and the
  Windows VM.
- Run `dotnet test Argus.sln` and `dotnet run --project src/Argus.Cli -- replay
  tests/fixtures/scenarios --assert` after every rule or pipeline change.

## 7. Immediate tasks, in order

Status after the 2026-11 verification pass: tasks 1-6 are complete except the parts listed
under "Not yet verified" in §3. Task 7 (Phase 3) is next.

1. **Pull and verify.** — done (`git pull --ff-only` already up to date, `verify.ps1` green).
   ```powershell
   git pull --ff-only origin main
   ./scripts/verify.ps1
   ```
2. **Run the elevated smoke.** — done (passes; notepad is idle, so the live leg records only
   the root `processStart`, which is expected).
   ```powershell
   ./scripts/verify.ps1 -Smoke
   ```
   If it fails, report the exact failed self-test check; do not summarise it as a generic
   failure.
3. **Prove file capture.** — done (see §3). Original recipe, still valid:
   ```powershell
   dotnet run --project src/Argus.Agent -- `
     --target C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe `
     --args "-NoProfile -Command \"Start-Sleep 2; Set-Content -Path \$env:TEMP\argus-file-test.txt -Value hello; Start-Sleep 2\"" `
     --duration 20 `
     --record $env:TEMP\argus-file.jsonl `
     --db $env:TEMP\argus-file.db
   ```
   Confirm `FileCreate`/`FileWrite` events with resolved drive-letter paths (no
   `\Device\HarddiskVolume...`), and that only the target tree is in scope.
4. **Prove network/DNS capture.** — done (see §3). Recipe: use a target that resolves and connects after a short
   delay, or a loopback listener. Confirm `NetConnect`/`DnsQuery` events and owner PID.
5. **Prove the API guards.** — done (see §3). Recipe: start the agent with a fixed `--token` and `--port`, then check:
   - `/api/health` without token succeeds;
   - another `/api/...` route without token returns 401;
   - wrong `Origin` returns 403;
   - wrong `Host` returns 400;
   - SSE `/api/sessions/{id}/stream` delivers `state`/`stats`.
6. **Prove UAC behaviour.** — partly done: non-elevated refusal exits 3 with the elevation
   message; `--elevate` builds and launches the correct elevated child (verified by running the
   same command line in an elevated shell), but the UAC consent click cannot be automated on
   this VM. Re-verify the parent handshake interactively, then tick this task.
7. **Then start Phase 3**: the full 22-rule catalogue from `PLAN.md` §6.3, with fixtures,
   aggregation/escalation and correlated rules. Do not start the dashboard first.

## 8. Commands

```powershell
# build + tests + replay + selftest
./scripts/verify.ps1

# elevated live check (self-test, notepad capture, replay)
./scripts/verify.ps1 -Smoke

# individual checks
dotnet run --project src/Argus.Agent -- --self-test --json
dotnet run --project src/Argus.Agent -- --target C:\Windows\System32\notepad.exe `
  --duration 30 --record $env:TEMP\argus-notepad.jsonl --db $env:TEMP\argus-notepad.db
dotnet run --project src/Argus.Cli -- replay $env:TEMP\argus-notepad.jsonl --assert --verbose
dotnet run --project src/Argus.Cli -- rules
```

Live recordings are written under `%TEMP%\argus-smoke` by the smoke script. A recording can
be replayed on Linux with the same `Argus.Cli replay` command.

## 9. Pitfalls

- `--assert` on a **live** recording is weak because `$meta.expect` is empty. Inspect the
  scope breakdown, event kinds and counts; do not treat exit 0 as proof of capture quality.
- An idle notepad produces no file/network events. Make the target do something after ETW
  starts; a target that exits immediately may be missed.
- ETW is a machine-wide resource. Close Procmon, Sysmon traces, WPR or other kernel sessions
  if the agent reports a session conflict.
- A named `TraceEventSession` needs an entry on `Source.Kernel` before records decode; without
  it kernel records arrive as `Task(<guid>)/Opcode(n)` and match no mapper branch. Likewise a
  manifest provider such as DNS-Client delivers no named payload fields (`QueryName`) until
  `Source.Dynamic` has a handler. Both are one-line registrations in `EtwCollector`; removing
  either silently returns 0 events for that source rather than an error.
- `EtwStats.MappingFailures` means *payload decode failed*. Records Argus deliberately ignores
  are counted in `EtwStats.Unmapped`. Do not fold the two together: a rising failure count is a
  sensor bug, a rising unmapped count is normal.
- DNS-Client reports the **requesting** PID on the 3006/3008 record, so DNS is attributable to a
  scoped process without a payload PID. Events from the dnscache service (PID 1364 here) are
  correctly out of scope.
- ETW takes 1-3 s to become effective after `Start()`. A DNS or network probe fired in the first
  second can show 0 events while the pipeline is fine; wait before generating test activity.
- `--elevate` raises a real UAC consent prompt. On an unattended VM the prompt cannot be
  approved, `Process.Start` either throws 1223 or returns a stub that exits `0x80008083`, and
  pending `consent.exe` prompts block later elevation attempts until they time out (~2 min).
  Verify the child launch itself from an already-elevated shell instead.
- Do not reintroduce the timing-only orphan heuristic, directory-wide attribution for
  System32/Program Files, or ETW rundown as process starts.
- Do not add `Microsoft.Diagnostics.Tracing.TraceEvent` to Core or Analysis.
- Do not change the JSONL field names or `$meta` shape without updating
  `RawEventJson`/`ScenarioLoader` and re-running replay.
- Keep the agent bound to `127.0.0.1`, keep the token check and Host/Origin guards, and do
  not put the token in a URL or a world-readable file.
- If you run tests on Linux, use `~/.dotnet/dotnet` if `dotnet` is not on `PATH`.

## 10. Reporting discipline

Every handoff should state:

- the exact commit tested;
- the exact commands run;
- what was observed (counts, event kinds, scope states, gaps);
- what is **verified** vs what is **implemented but unverified**;
- any new limitation discovered.

Never report "ETW works" or "monitoring is safe" from compilation or from a replay alone.
