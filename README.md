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
| 3 | Full 22-rule catalogue + correlation | **in progress**; 10 of the 23 catalogued rules shipped and verified live (persistence, system write, payload drop, mass file creation, unexpected shell, encoded interpreter, risky port, persistence-then-network) |
| 4 | Dashboard (8 screens) | not started |
| 5 | Windows end-to-end, reports, tuning | not started |
| 6 | ML advisory layer | not started |
| 7 | Hardening, packaging | not started |

Full plan and phase acceptance criteria: [`PLAN.md`](PLAN.md).

**What is verified today:** 140 unit tests (82 core, 47 analysis, 11 storage), 22 recorded
scenarios replaying through the real pipeline with asserted verdicts, SQLite persistence and
FTS search round-trip, and live ETW sessions on Windows that produced real `F-002`, `F-003`,
`F-004` and `F-007` detections from a benign probe. The Windows projects (`Argus.Monitor`, `Argus.Agent`)
compile on Linux with `EnableWindowsTargeting`, and their platform-neutral mapping, sampling
and volume logic is covered by the core tests.

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
tests/                unit tests + tests/fixtures/scenarios/*.jsonl
docs/RULES.md         rule catalogue, scoring model, how to add a rule
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
dotnet run --project src/Argus.Cli -- rules
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
