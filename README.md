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
| 2 | ETW collectors + elevated agent host | not started — needs Windows |
| 3 | Full 22-rule catalogue + correlation | not started |
| 4 | Dashboard (8 screens) | not started |
| 5 | Windows end-to-end, reports, tuning | not started |
| 6 | ML advisory layer | not started |
| 7 | Hardening, packaging | not started |

Full plan and phase acceptance criteria: [`PLAN.md`](PLAN.md).

**What is verified today:** 83 unit tests, 14 recorded scenarios replaying through the real
pipeline with asserted verdicts, SQLite persistence and FTS search round-trip, and a
throughput measurement of the analysis stage (~47k events/s on synthetic input).

**What is not verified:** anything Windows-specific. There is no ETW collector yet, so no
claim is made about live capture, event loss under load, elevation or WebView2.

## Layout

```
src/Argus.Core        event contract, scope attribution, path/IP classification, risk scoring
src/Argus.Analysis    rule contracts, correlator, detection aggregation, session pipeline
src/Argus.Storage     SQLite schema, repositories, FTS5 search, tiered rollups
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

On Windows (including the `tiny` VM): `./scripts/verify.ps1`, or
`./scripts/verify.ps1 -InstallSdk` if the SDK is missing.

## What a detection looks like

```
persistence-then-c2               Malicious     75.1   75.4       6     5     0  F-001,F-007,P-002,P-003,X-001
```

Each stored detection carries the plain-language reason, the factors that produced it, a
counterfactual ("would not fire if…"), MITRE mapping, evidence sequence numbers and its
weight in the risk calculation. A verdict without those is a bug.

## Safety

- The tool never executes anything except the application you select.
- Test material is a safe behaviour simulator (Phase 2) and recorded JSONL fixtures — no real
  malware is included, downloaded or executed.
- Absence of detections is reported as *no significant indicators*, never as proof of safety.
- Monitoring gaps (lost events, denied access) are recorded and shown, not hidden.

## Design constraints worth knowing

- **Near-real-time.** ETW buffers and batching mean ~1–3 s between an action and the
  dashboard; timestamps are the sensor's event time, never arrival time.
- **Observed vs inferred.** Every event and detection carries an observability badge; process
  injection is inferred without a kernel driver (or an optional Sysmon provider).
- **Scope ambiguity is surfaced.** Child processes whose parent exited before the event was
  captured are attributed by image path or explicit orphan window, and marked *unconfirmed*.
