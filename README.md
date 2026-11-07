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
| 2 | ETW collectors + elevated agent host | **implemented**; live process capture + JSONL replay confirmed on Windows; file/network/DNS volume, UAC and API/SSE checks pending |
| 3 | Full 22-rule catalogue + correlation | not started |
| 4 | Dashboard (8 screens) | not started |
| 5 | Windows end-to-end, reports, tuning | not started |
| 6 | ML advisory layer | not started |
| 7 | Hardening, packaging | not started |

Full plan and phase acceptance criteria: [`PLAN.md`](PLAN.md).

**What is verified today:** 96 unit tests (61 core, 24 analysis, 11 storage), 14 recorded
scenarios replaying through the real pipeline with asserted verdicts, SQLite persistence and
FTS search round-trip, and a throughput measurement of the analysis stage (~67k events/s on
synthetic input in the latest run). The Windows projects (`Argus.Monitor`, `Argus.Agent`)
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

**What is not verified:** the rest of live Windows behaviour. File/network/DNS/registry volume,
event loss under load, UAC relaunch and the loopback API/SSE stream are implemented but still
need their own checks. Use `scripts/smoke.ps1` (elevated) for the live path; until each leg has
run on the target VM, treat it as unverified.

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
