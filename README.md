# Argus

**Real-time application behaviour monitoring and explainable malware detection for Windows 10/11.**

Argus watches one application you choose, builds its process tree, records what it does to
files, the registry and the network, and explains — with evidence — why any of it looks
malicious. It does not scan a file and print a verdict.

> Defensive tooling. Monitor only applications you are authorised to analyse, and run
> unknown samples in an isolated VM. See "Safety" below.

## Status

| Phase | Scope | State |
|---|---|---|
| 0 | Solution, event contract, docs, scripts | **done** (Linux-verified) |
| 1 | Core model, scope tracking, scoring, SQLite, replay harness, fixtures | **done** (Linux-verified) |
| 2 | ETW collectors + elevated agent host | **done on Windows** for process, file, network+DNS capture and the API guards; `--elevate` UAC consent click unverified (unattended VM), registry volume and loss under load unverified |
| 3 | Full catalogue + correlation | **complete**; all 23 catalogued rules shipped, with tunable thresholds and the catalogue table gated by a test (persistence incl. registry writes, system write, payload drop, mass file creation, ransomware-shaped rename burst, credential-store access, unexpected shell, unattributed interpreter, encoded interpreter, user-writable launch, unsigned image, switch cycling, recovery tampering, cross-process launch, risky port, beacon-shaped callbacks, large outbound transfers, bare-address connections, lookup storms, persistence-then-network, startup-write-then-execution) |
| 4 | Dashboard (8 screens) | not started |
| 5 | Windows end-to-end, reports, tuning | not started |
| 6 | ML advisory layer | not started |
| 7 | Hardening, packaging | not started |

Full plan and phase acceptance criteria: [`PLAN.md`](PLAN.md).

**What is verified today:** the full Phase 3 rule catalogue — **23 of 23 rules** — with **248 unit
tests** (96 core, 141 analysis, 11 storage) and **54 recorded scenarios** replaying through the real
pipeline with asserted verdicts, each rule carrying at least one firing and one quiet twin. A measured
benign corpus of six applications ([`docs/BENIGN-CORPUS.md`](docs/BENIGN-CORPUS.md)) sits at
**Benign 0.0 with zero detections and zero gaps**. SQLite persistence and FTS search round-trip.

**Dashboard (Phase 4, in progress):** `web/` renders the agent's own JSON in eight screens — Sessions,
Live, Processes, Files, Network, Detections, Timeline, Search — with a virtualised event list (100k
rows asserted), a risk chart with detection markers, an evidence chain per detection, an
observability badge on every row and a persistent coverage banner. **16 Playwright tests** run
against payloads captured from real sessions by `scripts/dashboard-fixtures.ps1`, so the tests cannot
pass while a DTO breaks the UI. Live checks: `scripts/check-stream-ticket.sh` (single-use SSE tickets,
8/8) and `scripts/check-sse-reconnect.sh` (reconnect recovers the snapshot, 4/4). Live ETW sessions on Windows that produced real `F-001`,
`F-002`, `F-003`, `F-004`, `F-007`, `F-008`, `N-005`, `P-005` and `X-002` detections from benign and
self-cleaning probes, with the replayed verdict matching the live one. The Windows projects
(`Argus.Monitor`, `Argus.Agent`) compile on Linux with `EnableWindowsTargeting`, and their
platform-neutral mapping, sampling and volume logic is covered by the core tests.

A real elevated notepad capture from the Windows `tiny` VM has also been recorded and replayed
on Linux through the same pipeline. That confirms the ETW process path, JSONL recording format
and the Windows-to-Linux replay round trip. The first replay exposed two scope bugs: unrelated
`System32` processes were attributed to notepad because they shared its directory, and ETW
process rundown records put Idle/System in scope, which then confirmed their children. Shared
directories are now excluded, ETW `DCStart`/`DCEnd` rundown records are dropped, PIDs 0/4 are
never in scope, and timing alone is no longer evidence. The same recording now replays with 83
of 84 events correctly out of scope, only the root process in scope, and 0 detections.

Live Windows legs verified on the `tiny` VM since then (see `docs/HANDOFF.md` §3 for counts):

- **File capture** — 989 events for a powershell target that wrote to `%TEMP%\argus-writes`,
  PID-attributed, drive-letter paths, zero gaps, zero raw `\Device\` paths.
- **Network + DNS capture** — a loopback listener plus four `.example.net` resolutions produced
  `netConnect` and `dnsQuery`/`dnsResponse` with hostnames on the target PID, `partial`
  observability for DNS.
- **API guards** — `/api/health` 200 without a token, `/api/sessions` 401 without a token, bad
  `Origin` 403, bad `Host` 400, good token 200, and SSE
  `/api/sessions/{id}/stream` delivering `state` and `stats`.
- **Non-elevated refusal** — exits 3 with the elevation message unless `--allow-non-elevated`.
- **`scripts/verify.ps1 -Smoke`** — passes end-to-end (self-test, 15 s notepad capture, replay).
- **`--self-test`** inside an elevated agent — elevation, kernel provider, DNS provider,
  metadata and TCP table all pass.

**Partially verified:** `--elevate` builds and launches the correct elevated child (checked by
running the identical command line from an already-elevated shell), but the UAC consent click
cannot be approved on the unattended VM, so the parent-side ready-file handshake has not been
observed succeeding there.

**What is not verified:** registry capture under real activity (writes were not exercised),
event loss and the volume fuse under load on a busy machine, any non-trivial target such as
`7z.exe`, and the dashboard. Treat those as unverified until they have run on the target VM.

## Layout

```
src/Argus.Core        event contract, scope attribution, path/IP classification, risk scoring,
                      ETW record mapping, read sampling, volume fuse
src/Argus.Analysis    rule contracts, correlator, detection aggregation, session pipeline
src/Argus.Storage     SQLite schema, repositories, FTS5 search, tiered rollups, session recorder
src/Argus.Monitor     Windows ETW collectors, process metadata, TCP owner table, polling repair
src/Argus.Agent       elevated host: Kestrel API/SSE, live session, JSONL recording, reports
src/Argus.Simulator   scenario files, replay driver, expectation assertions
src/Argus.Cli         `argus` — replay, rules, selftest
web/                  dashboard: React 19 + Vite + TS shell, eight routes, Playwright suite
tests/                unit tests + tests/fixtures/scenarios/*.jsonl
docs/RULES.md         rule catalogue, scoring model, how to add a rule
docs/BENIGN-CORPUS.md measured false-positive baseline: six benign apps, every detection triaged
docs/HANDOFF.md       Windows VM handoff: state, invariants, pitfalls, next tasks
```

## Quick start

Requires the .NET 8 SDK. A user-local install works and needs no administrator rights:

```bash
curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
bash /tmp/dotnet-install.sh --channel 8.0 --install-dir "$HOME/.dotnet" --no-path
export PATH="$HOME/.dotnet:$PATH"
```

Then:

```bash
./scripts/verify.sh                 # build + tests + replay assertions + selftest

dotnet run --project src/Argus.Cli -- replay tests/fixtures/scenarios --assert
dotnet run --project src/Argus.Cli -- replay tests/fixtures/scenarios --db /tmp/argus.db
dotnet run --project src/Argus.Cli -- rules              # catalogue
dotnet run --project src/Argus.Cli -- rules --markdown   # the table docs/RULES.md carries
```

Rule thresholds are data, so a profile can be tightened or relaxed without a rebuild — see
"Thresholds are data" in `docs/RULES.md`. Unknown keys and impossible values are rejected:

```bash
dotnet run --project src/Argus.Cli -- replay recording.jsonl --rules profile.json
```

On Windows (including the `tiny` VM):

```powershell
./scripts/verify.ps1                 # build + tests + replay + selftest
./scripts/verify.ps1 -InstallSdk     # if the SDK is missing
./scripts/smoke.ps1                  # elevated: self-test + live notepad capture + replay
./scripts/verify.ps1 -Smoke          # both, in one command (elevated)
```

`smoke.ps1` writes a real session database and `live-session.jsonl` under
`%TEMP%\argus-smoke`. Copy the JSONL to any machine and replay it through the same pipeline:

```bash
dotnet run --project src/Argus.Cli -- replay /path/to/live-session.jsonl --assert
```

## Live agent (Phase 2)

The agent launches one `.exe`, records its process tree and scope-filtered file, network,
DNS and registry activity, runs the same analysis pipeline as replay, and exposes a loopback
API. It requires administrator rights for ETW; without them it refuses to start rather than
pretending to monitor.

```powershell
# elevated
dotnet run --project src/Argus.Agent -- --target C:\Windows\System32\notepad.exe `
    --duration 30 --record $env:TEMP\argus-notepad.jsonl --db $env:TEMP\argus-notepad.db

dotnet run --project src/Argus.Agent -- --self-test --json
```

Startup prints one JSON line with the ephemeral port, bearer token, session id, database and
recording paths. Every `/api` route except `/api/health` requires
`Authorization: Bearer <token>`; `Host` and `Origin` are pinned to `127.0.0.1:<port>`. If the
agent is not elevated, `--elevate` relaunches through UAC and `--allow-non-elevated` gives a
deliberately degraded polling-only diagnostic run.

A recording starts with a `$meta` line and is directly replayable on Linux. Live sessions
mark themselves `incomplete` when ETW loss or channel drops occurred, and the report JSON/HTML
always states the observation limits.

## What a detection looks like

```
persistence-then-c2               Malicious     75.1   75.4       6     5     0  F-001,F-007,P-002,P-003,X-001
```

Each stored detection carries the plain-language reason, the factors that produced it, a
counterfactual ("would not fire if…"), MITRE mapping, evidence sequence numbers and its
weight in the risk calculation. A verdict without those is a bug.

## Safety

- The tool never executes anything except the application you select.
- Test material is recorded JSONL fixtures and the benign notepad baseline; the safe
  behaviour simulator lands with the Phase 3/5 test harness. No real malware is included,
  downloaded or executed.
- Absence of detections is reported as *no significant indicators*, never as proof of safety.
- Monitoring gaps (lost events, denied access) are recorded and shown, not hidden.

## Design constraints worth knowing

- **Near-real-time.** ETW buffers and batching mean ~1–3 s between an action and the
  dashboard; timestamps are the sensor's event time, never arrival time.
- **Observed vs inferred.** Every event and detection carries an observability badge; process
  injection is inferred without a kernel driver (or an optional Sysmon provider).
- **Scope ambiguity is surfaced.** Child processes whose parent exited before the event was
  captured are attributed by image path or explicit orphan window, and marked *unconfirmed*.
