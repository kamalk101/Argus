# Rule catalogue and scoring model

Generated view: `dotnet run --project src/Argus.Cli -- rules` (add `--json` for machine output).

This is the **Phase 1 starter set** — the rules needed to prove the pipeline end to end.
Phase 3 extends it to the ~22-rule catalogue in `PLAN.md` §6.3 using the same contract.

## Shipped rules

| ID | Title | Severity | Channel | MITRE | Kind |
|---|---|---|---|---|---|
| P-002 | Unexpected command interpreter | 85 | process | T1059 | per-event |
| P-003 | Interpreter with encoded or remote payload | 75 | process | T1218, T1027 | per-event |
| F-001 | Write to an autostart location | 80 | file | T1547.001 | per-event |
| F-005 | Write to a system location | 65 | file | T1543, T1574 | per-event |
| F-007 | Executable payload dropped in a writable location | 50 | file | T1105 | per-event |
| N-001 | Connection to a risky service port | 45 | network | T1021 | per-event |
| X-001 | Persistence write followed by external connection | 90 | file + network | T1105, T1547 | correlated (60 s) |

### Why these severities

- **85 / 90** — a single observation is already hard to explain innocently
  (an application with no shell role starting PowerShell; autostart write then external
  connection). They still need corroboration to reach the *malicious* band unless a
  critical rule fires.
- **65 / 75** — strong but commonly dual-use (installers, updaters, admins).
- **45 / 50** — signals worth surfacing, insufficient alone.

## Scoring

Per detection `d` with severity `S`, confidence `c` and age `a`:

```
c    = baseConfidence × (1 − e^(−n / 3))        n = observed occurrences
decay = max(0.60, 0.5^(a / 15 min))
w_d  = (S / 100) × c × decay
risk = 100 × (1 − Π(1 − w_d)) × min(1.25, 1 + 0.08 × (channels − 1))
```

Band selection:

| Condition | Band |
|---|---|
| `risk ≥ 65` **and** (`channels ≥ 2` **or** a rule with `S ≥ 90 && c ≥ 0.80` fired) | Malicious |
| `risk ≥ 65` with one channel and no critical rule | Suspicious (explained as gated) |
| `risk ≥ 20` **or** any rule with `S ≥ 45` | Suspicious |
| otherwise | Benign — reported as *no significant indicators*, never "safe" |

Properties this buys:

- **No single-event verdicts.** Repeats raise confidence along a saturation curve, but a
  single channel cannot reach the malicious band without a critical rule.
- **Independent corroboration is what escalates.** Two detections in the *same* channel get
  no bonus; file + network gets up to 1.25×.
- **Evidence decays but is never forgotten** while the session is open; the peak score is
  retained so a spike followed by quiet still reads as a spike.
- **Every number is explainable.** Each detection stores its reason, factors, counterfactual
  and evidence sequence numbers; the assessment stores the arithmetic in prose.

## Adding a rule

1. Implement `IEventRule` or `ICorrelatedRule` in `src/Argus.Analysis/Rules/`.
2. Set `RuleMetadata` (id, title, severity, evidence channels, MITRE, description).
3. Emit `RuleFinding` with a **reason** naming the observed facts and a **counterfactual**
   stating what would have prevented it. `GroupPid` groups repeats under the acting process
   (e.g. the parent that spawned a shell).
4. Register it in `RuleCatalog.CreateDefault()`.
5. Add at least two fixtures in `tests/fixtures/scenarios/` — one that fires, one that must
   stay quiet — and a unit test in `tests/Argus.Analysis.Tests/`.
6. `./scripts/verify.sh` must stay green.

## Fixture format

One JSON object per line; the first line is metadata, the rest are raw sensor events.

```json
{"$meta":{"name":"unexpected-shell","rootPid":4312,"rootImagePath":"C:\\argus-test\\sample.exe",
  "expect":{"rules":["P-002"],"absentRules":["P-003"],"band":"Suspicious","minScore":20,"maxDetections":1}}}
{"ts":"2026-05-01T10:00:00.000Z","kind":"processStart","pid":4312,"parentPid":9999,
  "imageName":"sample.exe","imagePath":"C:\\argus-test\\sample.exe","source":"replay"}
{"ts":"2026-05-01T10:00:02.500Z","kind":"processStart","pid":5120,"parentPid":4312,
  "imageName":"powershell.exe","commandLine":"powershell.exe -nop -w hidden","source":"replay"}
```

Replay is deterministic: the same file always produces the same detections, counts and
scores, so a rule change that alters a verdict fails `--assert`.

## Test catalog note

Replay uses a fixed catalog containing only environment-independent paths
(`C:\Windows\System32`, `C:\Program Files\…`, `%ProgramData%…\Startup`, and the fixture root
`C:\argus-test`). Entries that require `%APPDATA%`/`%USERPROFILE%` are skipped during replay
so results never depend on the machine running the tests. Live monitoring uses the full
catalog with the real environment.
