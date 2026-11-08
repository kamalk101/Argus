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

Current automated counts: **172 tests** (96 core, 65 analysis, 11 storage), **30/30** asserted
replay scenarios, 15 of the 23 catalogued rules shipped (`F-001` … `F-008`, `N-001` … `N-004`,
`P-002`, `P-003`, `X-001`).

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

## 7. Phase 2.5 hardening — done at `abc8960`

Phase 2 was functionally proven, but `f074b6c` landed without tests and left a few sharp edges.
All six items below are done; §7.6 is the verification report. The **contracts** they establish
are still binding for future work: a malformed payload throws (the collector is the boundary),
a known-but-uninteresting kind returns `null`, and an unresolvable file path is partial
evidence, never an ignored record.

### 7.1 Reconcile the three docs — done

`docs/HANDOFF.md` §3 said file/network/DNS/API were verified while `README.md` and `PLAN.md`
still said they were pending. Both now tell the same story:

- **verified:** ETW process capture, file capture, network + DNS capture, API guards
  (401/403/400), SSE `state`/`stats`, non-elevated refusal (exit 3), `verify.ps1 -Smoke`;
- **partial:** `--elevate` (child launch verified; the UAC consent click cannot be approved
  on the unattended VM);
- **unverified:** registry capture under real activity, event loss / volume fuse under load,
  `7z.exe`, dashboard.

Do not overclaim and do not delete limitations. Acceptance: the three files tell the same
story; grep for `pending`, `still need` and `unverifiable` and check every hit.

Done: `README.md` (status table, verified/partial/unverified sections) and `PLAN.md`
(capability matrix, Phase 2 progress note, Phase 2 heading) now match §3. `PLAN.md`'s matrix
also claimed the `web/` dashboard "builds, runs, verified in browser"; it does not exist yet
and now says so. Keep the three files in step: when a leg becomes verified, change all three
in the same commit.

### 7.2 Lock the mapper contract with tests — done

`f074b6c` removed the catch-all from `src/Argus.Core/Monitoring/EtwEventMapper.cs` but added
no tests. Add to `tests/Argus.Core.Tests/MonitoringTests.cs`:

1. A malformed/incomplete payload makes `Map` **throw** — it must not return `null`.
2. A known-but-ignored record (`FileIO/Close`, `TcpIp/Send`, thread/config event) returns
   `null`.
3. A valid kernel process start still maps correctly after the `Source.Kernel` registration
   change (image path, PID, parent PID, timestamp preserved).

The `Unmapped`/`MappingFailures` counters live in `Argus.Monitor` (`net8.0-windows`) and no
test project references it. Do **not** retarget the test projects; cover the counters through
`--self-test` on the VM (§7.4). Acceptance: `dotnet test Argus.sln` green, 96 + new tests.

Done: 9 new tests (7 here, 2 in §7.5), suite 96 -> 105. The tests are
`Malformed_payload_throws_instead_of_returning_null`,
`Malformed_process_payload_throws_instead_of_returning_null`,
`Known_but_ignored_record_returns_null` (theory: `FileIOClose`, `TcpIpSend`, `ThreadStart`,
`SystemConfigCPU`) and `Valid_kernel_process_start_maps_after_parser_registration`.

### 7.3 Make the collector's per-record boundary total — done

`src/Argus.Monitor/EtwCollector.cs` (~lines 197-200) catches only
`InvalidOperationException`, `ArgumentException`, `NotSupportedException`, `FormatException`,
`InvalidCastException`, `OverflowException`. The comment at `EtwEventMapper.cs:34-38` promises
"the collector is the boundary that keeps a bad record from stopping collection", but a
payload throwing `IndexOutOfRangeException` or `NullReferenceException` escapes the per-record
catch and is not handled by the pump catch either. One bad record can stop delivery.

Catch `Exception` around the map+emit block, increment `MappingFailures`, continue. Keep the
pure mapper free of catch-alls — the throw is the contract, the collector is the boundary.
A bounded sample of the last few exception messages in stats is fine; never log payloads.
Acceptance: a malformed record cannot terminate the pump; re-run the §7.2 tests.

Done: `OnAllEvents` catches `Exception` around map+emit. `MonitorStats.MappingFailureSamples`
keeps the last five descriptors as `"<EventName>#<id> <ExceptionType>"` — record identity and
exception type only, because format-error messages quote the offending payload value and
payload values are captured data.

### 7.4 Fix the ETW self-test race and strengthen `etw-delivery` — done

`src/Argus.Agent/AgentSelfTest.cs`:

- ~lines 64-66: `monitor.Start()` is followed immediately by `GenerateActivityAsync()`. ETW
  needs 1-3 s to be consuming (this file says so). Add a 2 s delay between `Start()` and the
  generated activity, keep the existing 2 s drain delay.
- ~line 81: `var delivered = stats.EtwCallbacks > 0;` counts callbacks **before** filtering,
  so rundown-only or all-filtered traffic still passes. Require `stats.EventsSeen > 0`
  (mapped/forwarded) and warn when `stats.MappingFailures > 0`.
- Prove the **generated** activity was seen, not just that some callback arrived: also require
  `stats.ProcessStarts > 0` (or a file event). The probe runs against the agent's own PID as
  root, so generated activity is in scope.

Acceptance: `--self-test --json` passes three runs in a row with `EventsSeen > 0`,
`ProcessStarts > 0` and a plausible `MappingFailures`.

Done: 2 s delay added before the generated activity; `etw-delivery` now requires callbacks,
`EventsSeen > 0` **and** `ProcessStarts > 0`, and its detail names which of the three is
missing. `MappingFailures > 0` adds a warning naming the records that failed to decode.

### 7.5 Stop silently dropping unresolvable file events — done

`src/Argus.Core/Monitoring/EtwEventMapper.cs` (~lines 161-165): a file event whose path cannot
be resolved returns `null`, which the collector counts as `Unmapped` (an ignored kind). That is
lost evidence, not an uninteresting kind, and §2 says loss must be recorded.

Either (a) return a `RawEvent` with `Observability.Partial` and no target, or (b) return
`null` but add a `PathUnresolved` counter surfaced in self-test/session stats as a gap.
Prefer (a) if downstream rules tolerate a null target. Acceptance: a file record with no
`FileName`, no `OpenPath` and no cached FileKey produces a partial event or a recorded gap,
not an `Unmapped` increment.

Done: option (a), which is safe because every downstream consumer already guards on an empty
path (`SensitiveWriteRule`/`DroppedExecutableRule` bail on an empty `PathKey`,
`EventNormalizer` yields an empty key, `EventRepository`/`RollupService` store `null`).
`MapFile` returns `Observability.Partial`, no `Target`, and
`Detail = {"pathUnresolved":"true","fileKey":"<key>"}`. Renames with no resolvable path are
handled the same way.

### 7.6 Verification report — `abc8960`
Commands, all from an elevated PowerShell in `C:\Users\kamal\Argus`:

```powershell
./scripts/verify.ps1           # build + tests + 14 replay scenarios + selftest
./scripts/verify.ps1 -Smoke    # + self-test, 15 s notepad capture, replay of that recording
dotnet run --project src/Argus.Agent -- --self-test --json   # x3
```

```text
verify.ps1          : pass. 105 tests (70 core, 24 analysis, 11 storage).
                      14/14 asserted replay scenarios. selftest load 20000 events in 974 ms
                      (20,529 events/s).
verify.ps1 -Smoke   : pass. self-test 2,959 events seen / 421 forwarded in the 2 s probe;
                      notepad session recorded 2 raw event lines; replay 1/1 (benign, 0 dets).
--self-test x3      : pass, pass, pass.
  callbacks          42,236 / 6,924 / 10,570
  filtered           1,391  / 1,333 / 1,335
  events seen        3,379  / 491   / 566
  process starts     4      / 2     / 2
  file events        136    / 136   / 137
  unmapped           37,466 / 5,100 / 8,669
  mapping failures   0      / 0     / 0
```

File capture re-checked after the §7.5 mapper change, with a `cmd.exe` target driven by a
batch probe (3 s delay, writes under `%TEMP%\argus-writes`, then a further 2 s):

```text
46 events: 36 fileCreate, 3 fileWrite, 2 fileRead, 3 processStart, 2 processStop
15 events under %TEMP%\argus-writes, all PID-attributed
0 raw \Device\ paths, 0 gaps, 0 pathUnresolved events (nothing regressed)
replay exit 0, verdict Suspicious (F-005, F-007)
```

The two F-005 hits are a rule-quality finding, not a regression: ETW `FileIO/Create` means
**create-or-open**, so cmd opening `C:\Windows\System32\PING.EXE` is recorded as a
`fileCreate` in System32 and `F-005` reports it as a system write. This was triaged at the
start of Phase 3 — see §12.

Still unverified after this pass: registry capture under real activity (and now known to be
limited — user-mode value writes never reached the kernel registry stream in any measurement,
see §12.7), event loss and the volume fuse under load, `7z.exe` or any non-trivial target, the
UAC consent click, and the dashboard. Do not claim ETW works from compilation or replay alone.

## 8. Immediate tasks, in order

Status after the Phase 2.5 pass at `abc8960`: Phase 2 tasks 1-6 are complete except the parts
listed under "Not yet verified" in §3, and **§7 is done**. Phase 3 is unblocked.

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
   **Unblocked — §7 (Phase 2.5) is done at `abc8960`.** Triage the `FileIO/Create`
   create-or-open false positive on `F-005` (§7.6) as part of that rule work.

## 9. Commands

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

## 10. Pitfalls

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
- `dotnet run --project src/Argus.Agent -- --args "-NoProfile -Command \"...\""` does **not**
  preserve embedded quotes: `dotnet run` re-splits the child argument list and the agent exits 2
  with `Unexpected argument '2;'`. Invoke the built assembly directly
  (`& $dotnet src/Argus.Agent/bin/Debug/net8.0-windows/argus-agent.dll @cliArgs` with a
  PowerShell argument array), or use a target whose arguments need no nesting —
  `cmd.exe --args "/c <batch file>"` is the reliable shape.
- `timeout /t N` inside a batch probe exits immediately when the parent redirects stdin, so a
  "delayed" probe runs before ETW is consuming and captures nothing. Use
  `ping -n <N+1> 127.0.0.1 > nul` for the delay instead.
- ETW `FileIO/Create` means create-**or-open**, and the two live cases look identical apart from
  one field. TraceEvent already decodes `CreateDisposition` (`OPEN_EXISTING` for the loader
  opening `PING.EXE`, `CREATE_ALWAYS`/`CREATE_NEW` for a real write), and the mapper turns it
  into `RawEvent.FileEffect`. **Do not** read a `fileCreate` with `FileEffect.Opened` as a
  write, and do not add a rule that does.
- A directory create arrives as a Create record too, with `FileAttributes=Normal`: the marker
  is `FILE_DIRECTORY_FILE` (0x1) in `CreateOptions` (live value 2113569 = 0x204021), or a
  trailing separator in the name. Windows recreates `System32\CatRoot2` this way during
  signature checks; treating it as a file write is a false positive.
- A same-volume `copy` produces **no** `FileWrite` events at all (extent duplication): measured
  one `CREATE_ALWAYS` create and zero writes for a 53 KB `copy /y`. Any rule that waits for a
  write to confirm a drop will miss the most common drop method — use the create disposition.
- A child `powershell.exe` writes its own `__psscriptpolicytest_*.ps1` into `%TEMP%` on every
  invocation, which `F-007` correctly but noisily reports. Expect it in interpreter-heavy
  trees and do not "fix" it by suppressing script drops.
- **Process image names are not always `x.exe`.** Live ETW reported `ImageFileName="schtasks"`
  and `"PING.EXE"` in the same session, and one `schtasks /create` arrived with **no command
  line at all**. Match image names through `ProcessNames.IsOneOf` (accepts both spellings), and
  do not assume `CommandLine` is populated for command-line rules; a missing argument means no
  detection, not a negative result.
- **`Registry/SetValue` has an empty `KeyName`.** Like `FileIO` writes, the write events carry
  only a handle; the key name comes from the earlier `Registry/Open`/`Registry/Create`. The mapper
  keeps a `(pid, KeyHandle) → KeyName` cache. A write whose open happened before the session
  started cannot be attributed and is dropped — do not "fix" that by guessing a key.
- **A monitored app's registry write may be attributed to a service.** `schtasks /create` was
  observed as registry writes on pid 4 (System) and the Task Scheduler service, both out of
  scope. Only the tool launch (`schtasks.exe` + arguments) is in-scope evidence for those; that
  is why `F-003` is a process-channel rule.
- **Capture runs before the target, and the root pid arrives late.** `MonitorEventSource` starts
  with `RootPid = 0`; the agent enables ETW, waits until it is actually delivering
  (`WaitForDelivery`), launches the target, then calls `AttachRoot`. Before this the target was
  launched first and the first ~150 ms of every session was unobserved. `MonitorOptions.RootPid`
  = 0 is the documented "not attached yet" value, `ProcessScopeTracker.HasRoot` is false until
  then, and **nothing is in scope while there is no root** — including the
  "image under the root directory" fallback, which must stay behind `HasRoot`. The old ordering
  still works for direct callers, and `capture-start-latency` still fires if a caller launches
  first.
- **A target that exits fast used to lose its last events.** ETW delivers asynchronously and the
  session stopped the moment the root exited, cancelling the pump before it drained. The same
  80 ms probe recorded **1 event** (only the synthetic root) and the same tree living 2 s recorded
  37. Records for an instantly-dying tree can arrive later than 2 s of quiet, so `LiveSession`
  now drains with a floor (`DrainAsync`, 600 ms floor / 2 s ceiling), and the pump is awaited
  (channel completed by the monitor) before its token is cancelled. Same probe now records
  11–228 events. If a session still sees nothing beyond the root, it stops with a
  `target-exited-immediately` gap instead of looking like a quiet clean run.
- **The volume fuse counts in-scope events only.** It used to observe every ETW record before the
  scope check, so unrelated system file activity pushed it to 10 675 events/s and reported a
  `volume-throttle` gap in a session whose own target was doing very little (which also marked a
  clean run `incomplete`). Machine-wide volume is not the session's volume.
- **Deletions are invisible to this sensor.** `del`/`DeleteFile` produces no file event at all:
  a live probe deleted 26 files and recorded **zero** `fileDelete` events, while the same probe's
  renames and writes were all present. The kernel `FileIO` subscription reports create, write, read
  and rename, not delete. `F-006` is built on the rewrite-then-rename shape for exactly this
  reason, and a delete-only wiper is undetected. Closing this needs another sensor (minifilter, or
  `FileIO/SetInfo` with `FileDispositionInformation`) — do not paper over it with a rule.
- **`HasRoot` decides whether events are forwarded at all.** Events are buffered while it is
  false, so every path that names a root must flip it — `SeedRoot` does, for both orderings.
  Leaving it to `AttachRoot` alone made the legacy path (root supplied up front) buffer forever;
  `--self-test` caught it with "mapped but none of the generated process activity was seen". If a
  session records only its root event, check this first.
- **Registry writes are attributed through a kernel object, not a handle.** The manifest provider
  (`Microsoft-Windows-Kernel-Registry`) names a key when it is opened or created and reports the
  value write separately; only the object pointer links them. Do not try to join on `KeyHandle`:
  measured live, an Open reports either `0` or an unrelated handle. Cached names must be dropped
  when the kernel retires the object (id 13) because the pointers are reused.
- **Registry event names must match exactly.** `Registry/KCBCreate` / `Registry/KCBDelete` are the
  kernel's key-cache traffic; their header pid is whichever process triggered a cache operation, so
  substring matching turned them into writes "by the target" (104 bogus `registryDeleteValue` events
  for a session that ran `echo hello`). Only `Registry/Open|Create|Close|SetValue|DeleteValue` are
  mapped. Related: real user-mode value writes (`reg add`, `Set-ItemProperty`) do not appear in the
  kernel registry stream on this VM, so do not assert that the registry write path is proven.
- **A rename is two records, not one.** `FileIO/Rename` carries the source path and
  `FileIo/RenamePath` the destination, both with the same `FileKey`. The old mapper treated each as
  a whole rename and filled the missing side with the present one, so `ren a.docx b.locked` became
  `a.docx → a.docx` plus `b.locked → b.locked`. They are now paired by `(pid, FileKey)` and one
  event is emitted with `PreviousPath` + `Target`; an unpaired destination is `Partial`.
- **A ~20 ms target can still lose everything, just later.** ETW delivered the records of a tree
  that lived ~20 ms after more than 600 ms of quiet, so an early drain floor lost them. The
  post-exit floor is now 1.5 s (ceiling 3 s). Measured before/after on the same probe: 1 event
  before, 19 after.
- **The scope tracker is shared.** `Observe`/`ClassifyPid` are called from the ETW pump and both
  repair pollers, and the root can now be attached from the launch thread while those run, so the
  pid table is behind a lock. Do not add unlocked state to it.
- If you run tests on Linux, use `~/.dotnet/dotnet` if `dotnet` is not on `PATH`.

## 11. Reporting discipline

Every handoff should state:

- the exact commit tested;
- the exact commands run;
- what was observed (counts, event kinds, scope states, gaps);
- what is **verified** vs what is **implemented but unverified**;
- any new limitation discovered.

Never report "ETW works" or "monitoring is safe" from compilation or from a replay alone.

## 12. Phase 3 work log

### 12.1 File write evidence: create vs open — done

The first Phase 3 item was the `F-005` false positive found during the Phase 2.5 pass: ETW's
kernel `FileIO/Create` covers create **and** open, so opening `System32\PING.EXE` to run it was
reported as a system write. Fixing it at the rule level alone is wrong, because the
discriminator lives in the sensor:

- **`RawEvent.FileEffect`** (`Argus.Core.Events.FileEffect`: `Unknown` / `Opened` /
  `CreatedOrTruncated`) carries what the operation did. The mapper decodes TraceEvent's
  `CreateDisposition` (`OPEN_EXISTING` → `Opened`; `CREATE_ALWAYS`/`CREATE_NEW`/`SUPERSEDE`/
  `TRUNCATE_EXISTING` → `CreatedOrTruncated`; `OPEN_ALWAYS` → `Unknown`). Directory creates are
  `Unknown` (see the pitfall in §10). Sensors without a disposition leave it null.
- **`Argus.Analysis.Rules.FileChangeEvidence`** is the single shared decision used by `F-001`,
  `F-005`, `F-007` and `X-001`: writes, deletes and renames are content changes; a create is one
  only with `CreatedOrTruncated`, or with bytes attributed when the effect is unknown. An
  ambiguous create is never treated as a write.
- **Byte counts moved into the contract**: the mapper now sets `BytesOut`/`BytesIn` (and keeps
  `offset`/`disposition` in `Detail`) instead of burying bytes in `Detail` only. Recordings made
  before this commit carry `Detail.bytes` and no `BytesOut`, so their creates replay as
  ambiguous — replayable, deliberately more conservative.

Measured live on the VM (elevated, `cmd.exe` root, batch probe: `ping`, `copy /y
System32\PING.EXE %TEMP%\argus-writes\stage3.exe`, a PowerShell write):

```text
855 events: 677 fileCreate (570 opened, 12 createdOrTruncated, 95 unknown), 118 fileRead,
57 fileWrite, 2 fileDelete, 4 processStart, 4 processStop, 0 gaps
replay: Suspicious 35.1, 2 detections, both F-007
  F-007  stage3.exe dropped in %TEMP%\argus-writes   (copy: CREATE_ALWAYS, zero writes)
  F-007  __psscriptpolicytest_*.ps1 in %TEMP%        (the child powershell's own probe)
no F-005 at all: the PING.EXE open and the CatRoot2 directory create are correctly ignored
```

Before the fix the same probe produced `F-005 "write to System32"` for `PING.EXE`. After it,
precision was kept in the other direction too: gating on `FileWrite` alone would have missed
`stage3.exe`, because a same-volume copy emits no writes (see §10).

Defence against the drop case is proven twice: the unit test `Create_always_in_system32_is_a_system_write`
and fixture `16-dropped-then-written`.

### 12.2 Persistence rules: F-002, F-003, F-004 — done

Three catalogue rules, each with a firing fixture, a quiet fixture and unit tests:

| Rule | Trigger | Quiet case proven |
|---|---|---|
| `F-002` Run/RunOnce write (75, registry) | a `RegistrySetValue`/`DeleteValue` under a `CurrentVersion\{Run,RunOnce,RunServices,RunOnceEx}` segment, **or** a `reg.exe add|import` naming one | `Explorer\RunMRU` (starts with "Run", never executed), unrelated Explorer values, `reg query` |
| `F-003` Scheduled task created (70, process) | `schtasks.exe` with a create verb, or `at.exe` (legacy scheduler) | `schtasks /query`, `/end`, `/delete` |
| `F-004` Mass file creation (55, file) | ≥ 200 content-changing creates per 60 s, counted from the correlation index, reported once per threshold crossing (200, 400, …) | 150 creates in 30 s, and bursts of writes or opens |

Thresholds are constants in the rule classes; `rules.json` binding promised by `PLAN.md` §6.3 is
still open.

Measured live on the VM with a benign probe (a batch file under a monitored `cmd.exe`: wait, `reg
add` + `reg delete` of `HKCU\…\Run\ArgusProbeF002`, `schtasks /create` then `/delete` of
`ArgusProbeF003`, 250 files into `%TEMP%`):

```text
695 events: 9 processStart, 395 fileCreate, 250 fileWrite, 29 fileRead, 3 registrySetValue,
1 monitorGap
replay: Suspicious 48.5 (3 channels, corroboration 1.16)
  F-002  reg.exe started with arguments writing CurrentVersion\Run
  F-003  schtasks /create registered "ArgusProbeF003"
  F-004  200 files created in 60 s (640/s)
```

The probe creates and deletes its own artefacts; nothing was left behind.

### 12.3 Two sensor bugs the live probe exposed

Neither was visible from unit tests or replay, which is the whole reason the rule says to run
it on Windows.

1. **Image names arrive without the extension.** Live ETW reported `ImageFileName="schtasks"`
   for one launch and `"PING.EXE"` for another. Every rule compared the literal name against a
   set of `x.exe` names, so an extension-less child silently matched nothing — including
   `P-002`/`P-003` on a real shell. `ProcessNames.IsOneOf` now accepts both spellings and
   `ProcessNames.Display` renders the extension for reason text. Tests:
   `Task_registration_is_recognised_without_the_exe_extension`,
   `Unexpected_shell_is_recognised_without_the_exe_extension`.
2. **Registry writes were mapped to nothing.** All registry writes in every live capture so far
   produced zero events (`registryEvents: 0`). The records do arrive, but `Registry/SetValue`
   carries an **empty `KeyName`** — only a `KeyHandle`. The old mapper required `KeyName` and
   dropped the write. The mapper now caches `(pid, KeyHandle) → KeyName` from
   `Registry/Open`/`Registry/Create` (and forgets it on `Registry/Close`), so a write is
   attributed to the key that handle was opened on, marked `Observability.Inferred`. Live
   result: `registrySetValue` went from 0 to 3, and `--self-test` now reports
   `registryEvents: 2`. A write whose handle was opened before capture began is still
   unattributable and stays out of the stream (§10).

### 12.4 Capture starts before the target launches (infrastructure item)

The previous pass found that the target was launched **before** the ETW session was enabled, so
the first ~150 ms of every session was unobserved (measured 142–156 ms, and a probe's first
`reg add`/`schtasks /create` were lost). That is now fixed, and the fix exposed two more losses
that were worse than the original one.

1. **Ordering.** The agent now enables ETW with `RootPid = 0`, waits for delivery
   (`WaitForDelivery`, bounded at 2 s, reports `capture-not-delivering` on timeout), launches the
   target, and attaches the root pid (`MonitorEventSource.AttachRoot`). `ProcessScopeTracker`
   gained `AttachRoot`/`HasRoot`; nothing is in scope before the root exists, and the
   "image under the root directory" fallback is now behind `HasRoot` — without that guard a
   pre-launch probe was still attributed by directory. `Start()` is idempotent because
   `LiveSession.Start` starts the monitor again. `MonitorOptions.RootPid` documents 0 as
   "not attached yet", so the old launch-first ordering keeps working.
2. **Short-lived targets lost everything.** With the ordering fixed, an 80 ms target recorded
   **1** event: `LiveSession.WatchAsync` stopped the session on root exit, and `StopAsync`
   cancelled the pump before it drained the channel. ETW records for such a tree can arrive
   hundreds of milliseconds late (measured: event timestamp +637 ms), well after one quiet
   window. `MonitorEventSource.DrainAsync` (200 ms quiet, 600 ms floor, 2 s ceiling) now runs
   before the stop, the pump is awaited to completion (the monitor completes the channel), and
   cancel is only the fallback. Same probe: 11 events. Longer tree: 37 → 228 events.
   A session that still sees nothing beyond the root ends with a `target-exited-immediately`
   gap, decided after the pump has persisted everything (judging it earlier produced the gap even
   though the child's records landed afterwards).
3. **The volume fuse was counting the whole machine.** It observed every ETW record *before* the
   scope check, so an unrelated system burst hit 10 675 events/s, throttled reads and emitted a
   `volume-throttle` gap for a session whose target was idle — and a gap marks the session
   `incomplete`. It now observes in-scope events only (process starts included, via
   `ObserveVolume`).

Verified live: the 30 s two-channel probe records 228 events with **0 gaps** and still detects
`F-002` + `F-003`; the 80 ms probe records 11 events with 0 gaps; `--self-test --json` is green
with 0 mapping failures; `verify.ps1` passes (tests + 22 fixtures + smoke). Tests: 143 (85 core,
47 analysis, 11 storage), with three new scope tests covering the no-root window, late attach and
double attach.

### 12.5 F-006: ransomware-shaped rename burst — done

Three things had to be true before this rule could exist, and only the first was.

1. **Renames had to be one event, not two.** Live, `ren a.docx a.docx.locked` arrived as
   `FileIO/Rename` (source) and `FileIo/RenamePath` (destination). The mapper treated each as a
   complete rename and filled the missing side with the present one, producing `a.docx → a.docx`
   and `b.locked → b.locked` — 24 events for 12 renames, none of them usable. The two records are
   now paired by `(pid, FileKey)`, and the source path is a contract field (`PreviousPath` on
   `RawEvent`/`BehaviorEvent`) instead of a JSON blob, because a rule has to compare the old and
   the new name. Unpaired destinations stay as `Partial` evidence.
2. **Deletions are not observable.** The plan's F-006 says "delete/overwrite burst". Measured: 26
   `del`s produced **zero** file events — the kernel `FileIO` subscription has no delete. So the
   rule is built on what the sensor actually reports: rewrites plus marker-appending renames.
   This is recorded as a sensor gap in §10 and in `docs/RULES.md`, not smoothed over.
3. **Short-lived targets still lost their events.** A ~20 ms `cmd` tree delivered its records
   later than 600 ms of quiet, so the drain floor added in `560b64a` was not enough; the post-exit
   floor is 1.5 s now (1 event before, 19 after on the same probe).

The rule itself: marker-appending renames (new name starts with the old one, at least 10 in 60 s)
spread over 5+ directories, firing per 10-rename crossing. Download completion (`.part` →
final) is excluded because it is the commonest extension change on a desktop. Verified live:
a probe renaming 12 files across 8 directories produced `F-006` at 20.5 Suspicious with 0 gaps,
and replay of the same recording reproduces it. New fixtures 23 (`rename-burst-ransomware`,
fires) and 24 (`bulk-rename-benign`: 60 in-folder renames with the extension kept plus 12 finished
downloads, quiet). Tests: 172 (96 core, 65 analysis, 11 storage); 30/30 fixtures.

### 12.6 F-008: credential store access — done

`F-008` (70, file, T1555) fires when a process reads a store that belongs to another program:
browser login databases (Chrome, Edge, Brave, Opera, Firefox `logins.json`/`key4.db`), SSH private
keys, Windows credential files, DPAPI master keys and wallet files. The owning program is excluded
(`chrome.exe` reading its own `Login Data`, `ssh.exe`/`git.exe` reading their own key), because
flagging the normal case would make the rule useless on any machine with a browser.

Two design points worth keeping:

- **Recognition is by path shape, not only by the configured catalog.** The real locations are
  user-profile paths, and replay deliberately drops environment-dependent catalog entries, so a
  rule that could only match a live profile could never be replayed. The catalog is still consulted
  first, so a user-configured entry can supply the label.
- **Access means read or open-existing, never write.** A `FileCreate` with
  `CreatedOrTruncated` belongs to the write rules; `FileChangeEvidence.Evidence` is carried in the
  factors so the distinction is visible in the finding.

Verified live: `cmd /c type "<Chrome Login Data>"` plus a decoy `~/.ssh/id_rsa` read by the same
`cmd` produced `F-008` at 63.0 Suspicious with 0 gaps, and replay of the recording reproduces it.
Fixtures 25 (fires: login database, SSH key, wallet) and 26 (`browser-reads-own-credentials`, quiet:
Chrome and the SSH client reading their own stores through the same paths).

### 12.7 Two sensor corrections found while verifying F-008

Both were found by watching the *volume* of a session, not by a failing test, and both change what
the catalogue may claim:

1. **Kernel registry cache traffic was being reported as value writes.** `Registry/KCBCreate` and
   `Registry/KCBDelete` are the kernel's own key-control-block traffic, whose header process id is
   whichever process happened to trigger a cache operation. Matching event names by substring
   ("Delete", "Set") mapped them to `RegistryDeleteValue`/`RegistrySetValue`. A session that only ran
   `echo hello` recorded **104** `registryDeleteValue` events against
   `HKLM\SYSTEM\ControlSet001\Control\SafeBoot` — a third of its event stream, attributed to the
   target. Registry mapping now matches exact names (`Registry/Open|Create|Close|SetValue|
   DeleteValue`) and ignores everything else.
2. **The classic registry keyword cannot attribute a write, and that looked like blindness.** With
   the noise gone it became apparent that `reg add …\CurrentVersion\Run` produced no
   *attributable* `RegistrySetValue`: the write carries a handle that no earlier open had reported
   (opens report either `0` or an unrelated value). It is not done yet — §12.8 shows the write was
   in the stream all along, keyed by kernel object. The earlier "live 0 → 3 registry events"
   measurement was the cache noise, so `F-002` was a process-channel rule until §12.8 landed.
3. **Directory removal occasionally surfaces, file removal never has.** Five `del`s one second apart,
   and 26 `del`s in an earlier probe, produced zero file events; `rd /s /q` produced a `fileDelete`
   for the *directory* path in two runs out of three. Whatever the delete half of `F-006` becomes, it
   cannot be built on `del`.

Tests: 163 (96 core, 56 analysis, 11 storage); 26/26 fixtures; `verify.ps1` and `verify.sh` green.

### 12.8 Registry writes, attributed through the kernel object

The gap at §12.7 item 2 is closed. Two things were measured, in this order:

1. The write **was** arriving. A `logman` capture of `Microsoft-Windows-Kernel-Registry` around a
   `reg add` showed event 1 (CreateKey) carrying `RelativeName` = `Software\Microsoft\Windows\CurrentVersion\Run`
   plus `KeyObject`, and event 5 (SetValue) carrying the same `KeyObject` and the value name. The
   name and the write are in different records joined by a kernel pointer, which is why the classic
   handle-based join never worked: the handle in a SetValue record is not the handle an Open
   reported.
2. The provider can be enabled from an ordinary elevated session next to the kernel keywords
   (`EnableProvider("Microsoft-Windows-Kernel-Registry", Verbose, ulong.MaxValue)`), so no new
   capture architecture was needed.

The sensor now enables it when registry capture is on and maps ids 1/2 (open/create: object → key
name), 5 (value write: object + value name → event) and 13 (object retired: forget it). Two details
are load-bearing:

- **Objects are reused.** The same pointer was measured belonging to `system\Setup` and later to
  an unrelated NLS key, so a cached name is dropped when the kernel retires the object, and a write
  whose object is unknown is dropped rather than guessed — the rule that already governs
  unresolvable file paths.
- **A relative name is composed with its named parent** and only when the parent name is absolute;
  composing with a bare `S-1-5-21-…` produced paths that look absolute and are not. Anything joined
  through the object table is emitted as `Observability.Inferred`.

Verified live with two probes, both replayed afterwards: `reg add …Run /v ArgusSpike` produced
`\REGISTRY\USER\<sid>\Software\Microsoft\Windows\CurrentVersion\Run\ArgusSpike` (Inferred) and `F-002`
at 34.5 Suspicious with **two** detections (registry + command line), 0 gaps; and a write to
`HKCU\Software\ArgusSpike` was recorded but stayed **Benign, 0 detections**, so the new
channel does not put an autostart finding on ordinary application settings. `--self-test` now reports
`registryProviderEnabled: true` and 4 registry events from its own probe, and warns if the provider
cannot be enabled. Nine new mapper tests cover the join, the unknown object, the retired object, the
relative-name composition, and MuiCache value names (which are themselves device paths — joining them
with a separator produced a path that does not exist).

### 12.9 Network cluster: N-002, N-003, N-004

Three rules, one sensor addition. `TcpIp/Send` and `TcpIp/Recv` were being dropped by the
network mapper: a connect record says where data is going, never how much went, so a volume rule
had nothing to sum. Both now map to `NetFlow` with `BytesOut`/`BytesIn`.

- **`N-002` regular callbacks (60, T1071).** Reads connection times for one (pid, endpoint) out of
  the correlation index, requires 6+ within 10 minutes, a mean interval of at least 5 s, and a
  coefficient of variation of the intervals below 15 %. Fires once per six callbacks. Intervals are
  recomputed from the index every time, so there is no rule-side accumulator to drift and replay
  reproduces the verdict.
- **`N-003` outbound concentration (65, T1041).** Sums `BytesOut` to one public address over 60 s and
  fires per 20 MB crossing. Private addresses are excluded, and 22 MB spread over eleven addresses
  stays quiet — the rule is about one destination, not about being large.
- **`N-004` bare public address (35, T1095).** Connects to a public address with no DNS query by that
  process in the previous two minutes. Deliberately weak: the sensor records queries, not answers,
  so it cannot tell whether that address was resolved. It is documented as an ingredient, never as
  a lone finding.

`N-005` (NXDOMAIN storm) was **not** shipped: the DNS status field sits only in the event's `Detail`
JSON, and rules are not allowed to read facts from a blob. It needs a contract field first.

Verified live on the VM, each probe replayed afterwards:

```text
beacon   6 TCP connects to 1.1.1.1:53, 10 s apart   -> N-002 + N-004, 1506 events, 0 gaps
upload   24.1 MB to 172.66.0.218 in 387 sends       -> N-003 at 49.8 Suspicious, 0 gaps
```

New fixtures 27 (`beacon-callback`, fires; also trips N-004 and the suite says so), 28
(`beacon-jittery-benign`: same endpoint, same count, irregular spacing and a lookup each time), 29
(`outbound-volume`, fires at the 20 MB crossing) and 30 (`volume-spread-benign`: 22 MB over eleven
addresses plus 6 MB to a LAN server). Fixture 08 (`risky-port`) gained a DNS query, because the
bare-address connection it models would otherwise trip N-004 — which it did, in the suite, before
the fixture was made to match what the description claimed.

### 12.10 Next in Phase 3

The rest of `PLAN.md` §6.3: the full 22-rule catalogue with at least two fixtures per rule,
aggregation/escalation, correlated rules, and `docs/RULES.md` kept in step. Use
`FileChangeEvidence` for every file rule — do not reintroduce "create means wrote". Known noise
to tune with fixtures rather than suppression: the interpreter scratch `.ps1` in `%TEMP%`
(§10), and utility `cmd.exe`/`powershell.exe` children under `P-002` when the parent is an
installer or IDE.
