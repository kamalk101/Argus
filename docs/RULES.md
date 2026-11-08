# Rule catalogue and scoring model

Generated view: `dotnet run --project src/Argus.Cli -- rules` (add `--json` for machine output).

This is **23 of the 23 rules** in `PLAN.md` §6.3 — the catalogue is complete. Each lands in the same contract: one rule,
reason, counterfactual and at least two fixtures.

## Shipped rules

| ID | Title | Severity | Channel | MITRE | Kind |
|---|---|---|---|---|---|
| F-001 | Write to an autostart location | 80 | file | T1547.001 | per-event |
| F-002 | Write to a Run/RunOnce autostart key | 75 | registry | T1547.001 | per-event |
| F-003 | Scheduled task created | 70 | process | T1053.005 | per-event |
| F-004 | Mass file creation | 55 | file | T1105, T1486 | aggregated (60 s) |
| F-005 | Write to a system location | 65 | file | T1543, T1574 | per-event |
| F-006 | Destructive rename burst (ransomware shape) | 85 | file | T1486 | aggregated (60 s) |
| F-007 | Executable payload dropped in a writable location | 50 | file | T1105 | per-event |
| F-008 | Credential store accessed | 70 | file | T1555 | per-event |
| N-001 | Connection to a risky service port | 45 | network | T1021 | per-event |
| N-002 | Periodic callbacks to one endpoint | 60 | network | T1071 | aggregated (600 s) |
| N-003 | Large outbound transfer to one address | 65 | network | T1041 | aggregated (60 s) |
| N-004 | Connection to a bare public address | 35 | network | T1095 | per-event |
| N-005 | Storm of lookups for names that do not exist | 50 | network | T1568.002 | aggregated (60 s) |
| P-001 | Shell or interpreter spawned by a non-shell parent | 60 | process | T1059 | per-event |
| P-002 | Unexpected command interpreter | 85 | process | T1059 | per-event |
| P-003 | Interpreter with encoded or remote payload | 75 | process | T1218, T1027 | per-event |
| P-004 | Executable launched from a user-writable directory | 45 | process | T1204 | per-event |
| P-005 | Unsigned image launched in the monitored tree | 30 | process | T1553 | per-event |
| P-006 | Repeated launches of one program with different switches | 25 | process | T1082 | aggregated (600 s) |
| P-007 | Shadow copy or recovery tampering | 80 | process | T1490 | per-event |
| P-008 | Process in the application's directory with no observed creator | 65 | process | T1055 | per-event |
| X-001 | Persistence write followed by external connection | 90 | file + network | T1105, T1547 | correlated |
| X-002 | Startup write followed by execution of that file | 85 | process + file | T1547.001 | correlated |

**How registry writes are attributed (measured).** The classic registry keyword names a key
when it is opened and reports the value write separately, but the handle in the write never
matched a handle an open had reported — opens report either `0` or an unrelated value — so that
path can never attribute a write. The kernel's manifest provider
(`Microsoft-Windows-Kernel-Registry`) does it by object: an open or create event carries the key
name and the kernel object it produced, and the value write carries that object. The sensor
enables it alongside the classic keyword and joins the two, which is how
`reg add …\CurrentVersion\Run` is reported as
`\REGISTRY\USER\<sid>\Software\Microsoft\Windows\CurrentVersion\Run\<value>`. Because the join is through an
object pointer the event is marked `Inferred`, not `Direct`, and an entry is dropped as soon as
the kernel retires the object — those pointers are reused, and the same value was measured
belonging to two unrelated keys.

**How P-005 knows a binary is unsigned (measured, and three-way on purpose).**
`RawEvent.Signature` carries a `SignatureStatus` of `Valid`, `Invalid` or nothing, and no value at all
is never read as "unsigned". Two wrong ways to establish it were measured on this machine before the
current one was kept, and both are worth recording because they look correct:

- `X509Certificate.CreateFromSignedFile` reads only an *embedded* certificate. Most of `System32`
  carries none — Windows verifies those by hashing the file and looking the hash up in a signed
  catalog. A rule built on that API reported that a copy of `whoami.exe` had "no trusted publisher
  signature" while `Get-AuthenticodeSignature` called it `Valid, type=Catalog, signer=Microsoft
  Windows`, before and after the copy. That is a false fact about provenance, not a threshold to tune.
- `WinVerifyTrust` resolves embedded signatures only. Against a catalog-signed file it returns
  `TRUST_E_NOSIGNATURE` (`0x800B0100`) — byte for byte the same code as a file with no signature at
  all — so its "no signature" answer cannot be trusted either. Measured directly.

The monitor therefore tries embedded Authenticode, and on `TRUST_E_NOSIGNATURE` looks the file's
SHA-256 up with `CryptCATAdminEnumCatalogFromHash` and verifies the catalog file it finds. A file with
no embedded signature and no catalog entry is `Invalid`; a failed lookup for any other reason is
`Unknown`, so an unreadable file or an unavailable trust provider never becomes an accusation.
Revocation is not checked and chain retrieval is cache-only, so the result means "the chain is
trusted", never "the publisher is not revoked". Measured end to end: `whoami.exe` and `notepad.exe`
→ `Valid`, a freshly built unsigned .NET apphost → `Invalid`, a missing path → `Unknown`.

One live limitation, stated rather than papered over: the signature is only known if the process is
still alive when the sensor opens it. A payload that exits in milliseconds often yields no value at
all — observed repeatedly — so P-005 misses those rather than guessing. Most unsigned utilities on a
workstation are harmless, which is why P-005 is the quietest process signal at severity 30 and adds
provenance, not intent.

**How P-008 infers cross-process creation (it is an inference, and the report says so).**
Nothing in the enabled kernel keywords reports `CreateRemoteThread` or an APC injection, so there is
no injection event to read; the agent's own limitations already state that injection indicators are
inferred. P-008 therefore reads the scope tracker: a process whose image sits under the root
application's own directory but for which no parent link was ever observed is marked
`Unconfirmed` (`image-under-root-directory`), and for a single-tenant application directory that is
a contradiction — it is the application's own code, yet the application was never seen starting it.
A shared directory (`System32`, `Program Files`) proves nothing by location and is excluded, and
the finding carries `basis=inferred-from-process-table` so the evidence panel cannot present it as
an observation.

**P-001 and P-002 are disjoint by construction.** Both concern an interpreter with no human typing
its arguments. Where a creator was observed, P-002 names it and reports at severity 85; P-001 fires
only when no parent record exists at all and the interpreter is in the tree by location alone,
reporting at 60. The first draft of P-001 used the same predicate as P-002 and every shell fixture
produced two findings for one launch — the disjointness is the rule, not a filter applied afterwards.

Two things the stream still contains and the rules do not use: the kernel's own key-cache
traffic (`Registry/KCBCreate`, `Registry/KCBDelete`), whose header pid is whichever process
triggered a cache operation and which used to be mapped as writes by substring matching — a
session that only ran `echo hello` collected 104 `registryDeleteValue` events against
`HKLM\SYSTEM\…\SafeBoot`, a third of its stream, before that was fixed;
and the shell's MuiCache entries, whose *value names* are device paths, so their targets are
hive-relative and visibly partial.

A rule's channel names what the finding is **about**, not which sensor produced it. `F-002` is a
registry autostart write whether it was seen as a `RegistrySetValue` or as
`reg.exe add …\CurrentVersion\Run`: the second form says so in its factors
(`evidence=command-line`) and never claims the value was observed being written. `F-003` is a
scheduled-task registration, and it is a process-channel rule because the task file itself is
written by the Task Scheduler service, which is out of scope — only the tool launch is in-scope
evidence.

### F-008: whose credentials, and which ones

`F-008` fires when a process reads a credential store that belongs to a different program: browser
login databases, SSH private keys, Windows credential files, DPAPI master keys, wallet files. The
owning program is excluded — Chrome reading its own `Login Data` and `ssh.exe` reading its own key
are the normal case, and flagging them would make the rule useless on any machine with a browser.

Stores are recognised by **path shape**, not only by the configured catalog, because the real
locations are user-profile paths and replay deliberately drops environment-dependent catalog
entries. A rule that could only match a live profile could not be replayed, and a rule that cannot
be replayed cannot be shown to work twice.

Two limits are worth stating plainly. It only sees reads and opens, so a credential store reached
over the network, or through a service that is out of scope, is invisible. And an un-attributable
read — a path that could not be resolved — produces nothing rather than a guess.

### The network cluster: three signals, none of them a verdict

`N-002`, `N-003` and `N-004` describe different shapes of the same problem — traffic that leaves for
somewhere the user never chose — and each is deliberately narrow:

- **`N-002` measures regularity, not count.** For each process and endpoint it reads the connection
  times out of the correlation index and computes the coefficient of variation of the intervals
  (standard deviation over mean). Six callbacks at 30 s with a 2 s spread is 6.7 % and fires; a user
  clicking around is far above 15 % and does not. Connections faster than one per five seconds are
  not counted at all: a burst is load, not a timer.
- **`N-003` measures concentration, not volume.** Twenty megabytes to *one* public address inside a
  minute, summed from the send records; the same 22 MB spread over eleven addresses stays quiet, as
  does any transfer to a private address. Uploads, backups and video calls move this much routinely,
  which is why it is severity 65 and meant to sit next to what was written and where.
- **`N-004` is the weakest and says so.** The sensor records DNS queries, not answers, so the rule
  cannot check whether *that* address was resolved — only whether the process asked for any name in
  the previous two minutes. Anything using its own resolver, a cached address or DNS-over-HTTPS looks
  like a hardcoded callback. Severity 35, and it should never appear as the only finding in a report.

`N-005` (NXDOMAIN storm) needed one contract change to ship honestly. The DNS-Client record carries
the resolver's status, but it was parked in the event's `Detail` JSON, and a rule is not allowed to
dig a fact out of a blob. `BehaviorEvent.DnsStatus` is now a first-class field with three values:
`Success`, `NameDoesNotExist` and `NoAnswer`. That third value is the point — a timeout or a refused
query says something about the path to the resolver, not about the name, so lumping the failures
together would let a flaky network look exactly like a domain-generation algorithm. The rule counts
**distinct** names per process, so one dead host retried forty times is quiet; fifteen candidates that
were never registered is not.

**What a live capture taught us about that status (measured).** Verifying N-005 on a real machine with
18 unregistered names showed the first parser was wrong. The DNS-Client provider reports
`QueryStatus=87` on **every** `A` (QueryType 1) response, including for names that resolve: in the same
capture, `example.com` answered with its addresses through the AAAA record while its A record carried
`87` and an empty `QueryResults`. The first version treated any unrecognised non-zero code as "the
lookup did not complete", so 18 successful-or-failed A records were recorded as `NoAnswer` — a false
fact in the contract, and exactly the kind of thing a later rule would reason from. Unrecognised codes
are now `Unknown`, and only codes whose meaning is known are mapped: `0` is success, `9003` (and
textual `NXDOMAIN`) is the one negative answer that counts, and `1460`/`9005`/`9501` are the
incomplete-answer cases. The AAAA record carries the real outcome, which is why the rule still sees
all 18 names.

`X-002` pairs a persistence write with execution of **that same canonical path**. Matching on the file
name instead would correlate every install where a helper shares a name with something in Startup, so
the rule compares `PathKey`s. It reads only a write that changed content — a bare create is
create-or-open and proves nothing was written.

**A path-only match turned out to miss the real thing, so there is a narrow fallback.** Measured live:
a payload launched out of the real Startup folder arrived as `observability=partial` with
`imagePath=null`, because the kernel process-start record names only the image and the metadata lookup
lost the race against a process that exits in milliseconds. Payloads are short-lived by nature, so that
is the common case rather than the edge — the rule would have been unable to fire for the very scenario
it was written for. When no path was resolved, X-002 accepts a launch only if **both** the launched
image name equals the written file's name **and** the launching process is the process that performed
the write, and it records `match_basis=path` or `match_basis=name-and-parent` so the evidence panel
cannot present the weaker match as a path equality. Name alone is not enough: a same-named process with
any other parent stays quiet, which is fixture 47. Both bases were then exercised against real ETW —
the resolved-path run and the unresolved-path run each produced X-002 at severity 85, giving
`Malicious 65.7` alongside F-001, F-007 and P-005.

Volume rules needed one sensor addition: `TcpIp/Send` and `TcpIp/Recv` were being dropped, because a
connection record says where data is going, not how much went. Both now map to `NetFlow` with
`BytesOut`/`BytesIn`.

### Thresholds are data

The numbers a windowed rule fires on live in `RuleSettings` (`src/Argus.Analysis/Rules/RuleSettings.cs`)
and can be overridden without a rebuild:

```json
{
  "massFileCreationCount": 200,
  "massFileCreationWindowSeconds": 60,
  "destructiveRenameCount": 10,
  "destructiveRenameDirectories": 5,
  "destructiveRenameWindowSeconds": 60,
  "beaconConnections": 6,
  "beaconWindowSeconds": 600,
  "beaconMinMeanIntervalSeconds": 5,
  "beaconMaxJitter": 0.15,
  "outboundVolumeBytes": 20971520,
  "outboundVolumeWindowSeconds": 60
}
```

```text
argus replay recording.jsonl --rules profile.json
argus-agent --target app.exe --rules profile.json --duration 120
```

Three properties keep this from becoming a way to lie about the product:

- **Unknown keys are errors.** A typo (`beaconThreshold`) fails with the offending name instead of
  silently leaving the default in place while the operator believes otherwise.
- **Impossible values are errors.** A count of zero would fire on every event; a negative window
  would match nothing. Both are rejected with the field named.
- **The finding quotes the threshold that fired.** Factors carry `threshold=…` and the
  counterfactual says "would not fire below N creates per W s", so a lowered profile cannot
  produce a detection that describes a different rule than the one that ran.

Code built the wrong way round here is a real risk: the threshold must be read from settings at
construction, never duplicated in the reason text.

### F-006: what it counts, and what it cannot see

`F-006` counts a *pattern*, not an intensity: renames where the new name starts with the old one
and adds something (`report.docx` → `report.docx.locked`), spread over at least 5 directories, at
least 10 of them in 60 s, firing once per 10-rename crossing. A build, an unzip or a batch renamer
either keeps the extension or works inside one folder, so breadth plus an appended marker is the
signal. Renames that merely drop an intermediate extension (`.part`, `.crdownload`, `.tmp`) are
never counted: finishing a download looks identical otherwise.

**The delete half of this rule does not exist, because the sensor cannot see file deletions.**
Measured live: 26 files deleted by `del` produced **zero** file events, and a second probe with five
deletes, one second apart, also produced zero — the kernel `FileIO` subscription used here reports
creates, writes, reads and renames, but not `del`/`DeleteFile`. Removing a *directory* (`rd /s /q`)
did surface a `fileDelete` for the directory path in two runs out of three, which is a narrower
signal than it looks: it names a folder, not the files inside it. So a wiper that only deletes is
invisible to `F-006` and to the whole pipeline; `F-006` keys on the rewrite-then-rename shape
encryptors leave behind. Never present a quiet `F-006` as evidence that nothing was destroyed, and
do not "fix" this by treating a create as a delete. Closing the gap needs a different sensor (a
minifilter or `FileIO/SetInfo` with `FileDispositionInformation`), and it is recorded as an open item
in `docs/HANDOFF.md` §10.

### Thresholds and volume

`F-004` and `F-006` count events in a 60 s window from the correlation index and fire once per
threshold crossing (200, 400, 600 … creates; 10, 20, 30 … renames), so one detection represents one
escalation step instead of hundreds of duplicate findings. Bursts of writes to existing files and bursts of opens do not count —
a compiler or a scanner must stay quiet. Thresholds are constants in the rule class today;
`rules.json` binding is still open.

### Not a write

`F-002` excludes `Explorer\RunMRU`, which begins with "Run" but is the Run-dialog history Windows
never executes; the match is on whole key segments. `F-004` excludes opens for the same reason it
excludes writes: nothing appeared.

### Why these severities

- **85 / 90** — a single observation is already hard to explain innocently
  (an application with no shell role starting PowerShell; autostart write then external
  connection). They still need corroboration to reach the *malicious* band unless a
  critical rule fires.
- **65 / 75** — strong but commonly dual-use (installers, updaters, admins).
- **45 / 50 / 55** — signals worth surfacing, insufficient alone.

## What counts as a file write

ETW's kernel `FileIO/Create` covers **both** creating a file and opening an existing one:
loading `System32\PING.EXE` arrives as a `fileCreate` in System32. Before this was handled,
`F-005` fired on every system binary a process opened, which made the benign corpus useless.

The sensor's create disposition settles it, and every file rule uses one shared decision
(`Argus.Analysis.Rules.FileChangeEvidence`):

| Event | Content changed? |
|---|---|
| `FileWrite`, `FileDelete`, `FileRename` | yes |
| `FileCreate` with `FileEffect.CreatedOrTruncated` (`CREATE_ALWAYS`, `CREATE_NEW`, `TRUNCATE_EXISTING`) | yes |
| `FileCreate` with `FileEffect.Opened` (`OPEN_EXISTING`) | **no** — the file already existed |
| `FileCreate` with `FileEffect.Unknown` (`OPEN_ALWAYS`, old recordings, no disposition) | only if bytes were attributed to the event |
| Directory create (`FILE_DIRECTORY_FILE` in the create options, or a trailing separator) | no |

Two consequences worth knowing before writing a rule:

- **Do not wait for a `FileWrite` to confirm a drop.** A same-volume `copy` duplicates file
extents and emits *no* write events at all — measured: one `CREATE_ALWAYS` create and zero
writes for a 53 KB `copy /y`. Gating on writes hides the most common drop method.
- **Fixtures may set `bytesOut` or `fileEffect`** to model a create that carried content. A
fixture `fileCreate` with neither is an open, and a rule must stay quiet on it.

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

### A worked table, computed by hand

Three cases, worked from the formula above rather than from a run, so the model stays checkable
without the code. A test (`The_documented_score_table_matches_the_scorer`) asserts these numbers.

| Case | Inputs | Arithmetic | Risk | Band |
|---|---|---|---|---|
| One file detection, fresh | `S = 80`, `c = 0.90`, `a = 0`, 1 channel | `w = 0.80 × 0.90 × 1 = 0.72`; `1 − 0.28 = 0.72`; `× 1.00` | **72.0** | Suspicious — one channel, nothing critical fired, so the gate holds it below malicious |
| File and network detections, fresh | `S = 80, c = 0.90` (file) and `S = 50, c = 0.75` (network), 2 channels | `w₁ = 0.72`, `w₂ = 0.50 × 0.75 = 0.375`; `1 − (0.28 × 0.625) = 0.825`; `× 1.08` | **89.1** | Malicious — two independent channels |
| The first case, 15 minutes later | `S = 80`, `c = 0.90`, `a = 15 min` | `0.5^(15/15) = 0.50`, but the decay floor is `0.60`, so `decay = 0.60`; `w = 0.80 × 0.90 × 0.60 = 0.432`; `× 1.00` | **43.2** | Suspicious — still above threshold, and the peak score of 72.0 is retained separately. The floor is why old evidence cannot fade below 60 % while the session is open |

### Coverage travels with the verdict

Collection gaps (a throttled volume fuse, a target that exited before anything was captured, a lost
ETW buffer, a provider that would not start) do **not** subtract from the score. A dropped event is
not evidence of anything, and inventing a penalty would make the number mean less rather than more.

What gaps do is forbid one reading: **"no detections" may never be rendered as "nothing happened."**
`SessionSnapshot.Coverage` states whether the session was complete, how many gaps there were, the
distinct reasons in first-seen order, and one sentence the report can print verbatim. The scorer's
explanation is extended in the same direction — either "the score may understate what the
application did" or "this is not an all-clear" — and the agent publishes the same object beside every
verdict in `/state` and the final state event, so a consumer would have to go out of its way to
present an incomplete session as a clean one.

The gap log also names gaps by their machine reason (`volume-throttle`,
`target-exited-immediately`), not by their prose: the sensor sends the reason in `Target` and the
explanation in `Detail`, and the pipeline used to read the two fields the wrong way round.

## Adding a rule

1. Implement `IEventRule` or `ICorrelatedRule` in `src/Argus.Analysis/Rules/`; add
   `IWindowedRule` if it decides from a window of earlier events.
2. Set `RuleMetadata` (id, title, severity, evidence channels, MITRE, description).
3. Emit `RuleFinding` with a **reason** naming the observed facts and a **counterfactual**
   stating what would have prevented it. `GroupPid` groups repeats under the acting process
   (e.g. the parent that spawned a shell).
4. Add any threshold to `RuleSettings` and read it from there — never a constant and never a second
   copy in the reason text.
5. Register it in `RuleCatalog.CreateDefault(settings)`.
5. Add at least two fixtures in `tests/fixtures/scenarios/` — one that fires, one that must
   stay quiet — and a unit test in `tests/Argus.Analysis.Tests/`. For a file rule, the quiet
   fixture is usually the `FileEffect.Opened` case.
7. Re-run `argus rules --markdown` and paste the table above; a test compares it against the
   catalogue, so a forgotten row fails the build rather than shipping a stale table.
8. `./scripts/verify.sh` must stay green.

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
