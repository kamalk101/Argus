# Benign corpus — measured false-positive baseline

This is the triage log PLAN.md §11.1 asks for: benign applications run under the elevated monitor,
their recorded sessions replayed through the production pipeline, and every detection either fixed
or written up with a reason.

Measured on 2026-11-09 on the Windows test machine (Windows Server 2019 build, elevated session),
with `scripts/corpus.ps1`, which is checked in so any number here can be reproduced:

```powershell
./scripts/corpus.ps1 -Target all      # or one of: notepad 7zip python dotnet chrome vscode
```

Every case builds its own workspace under `%TEMP%\argus-corpus\<target>`, records the session there
and leaves it behind for inspection. Nothing outside `%TEMP%` is written, and the two GUI cases
(notepad, browser, IDE) close themselves.

**The §11.1 expectation is: risk < 20 and zero detections at severity ≥ 80.**

## Result

| Target | What it did | Events | Risk | Detections | Gaps |
|---|---|---|---|---|---|
| `notepad.exe` | typed text, saved a file | 1903 | 0.0 Benign | none | 0 |
| `7z.exe` (via `cmd /c`) | compressed 40 files, extracted the archive | 441 | 0.0 Benign | none | 0 |
| `python.exe` 3.12 | 2000 sha256 values, wrote and re-read a 145 KB JSON file | 473 | 0.0 Benign | none | 0 |
| `dotnet run` | created, built and ran a console project | 4752 | 0.0 Benign | none | 0 |
| `chrome.exe` | new window on a local page, own profile | 930 | 0.0 Benign | none | 0 |
| `Qoder.exe` (VS Code/Electron) | opened a 30-folder workspace, indexed it | 1020 | 0.0 Benign | none | 0 |

All six are below the threshold with no detection at any severity, and every session had complete
coverage: zero gaps, so nothing here is a quiet run caused by lost events.

Not measured: **VLC** (not installed on the machine) and **VS Code** proper — the Electron IDE
present was `Qoder.exe`, a VS Code fork with the same multi-process architecture. The numbers above
are the applications that were actually on disk; no claim is made about the two that were not.

## The four findings, and what happened to each

The first run of the same six cases, before any of this was fixed:

| Target | Then | Detection | Cause |
|---|---|---|---|
| `python.exe` | Suspicious 9.6 | `P-004` | the application under test is installed in `%LOCALAPPDATA%\Programs` |
| `dotnet run` | Suspicious 37.1 | `F-007` | Roslyn unpacks its analyzers as DLLs into `%TEMP%\VBCSCompiler` |
| `chrome.exe` | Benign 15.9 | `P-006` ×4 | renderer, GPU, utility and crashpad processes are `chrome.exe --type=…` |
| `Qoder.exe` | Suspicious 46.2 | `P-004`, `P-006` ×2, `N-004` | per-user install, Electron self-relaunch, telemetry connection |

### 1. P-004 reported the application under test (fixed)

`P-004` flags an executable started from a directory the user can write to. A per-user installation
lives in exactly such a directory — `%LOCALAPPDATA%\Programs\Python\Python312\python.exe`,
`%LOCALAPPDATA%\Programs\Qoder\Qoder.exe` — so the rule reported the one process the operator chose
and Argus launched. That is not behaviour of the session.

The rule now skips two things and nothing else:

- the monitored root itself (`current.Pid == context.RootPid`);
- a launch whose image directory is the root's own image directory — the Electron IDE relaunching
  `Qoder.exe` out of its install folder, which is what it does on every window.

A helper staged in `%TEMP%` by the same application still reports (fixture
`52-per-user-install-launch-benign`), a payload dropped next to the application is still covered by
`F-007` (the drop) and `P-008` (an app-directory process with no observed creator), and a payload in
`Downloads` or `%TEMP%` is unaffected.

### 2. F-007 reported the C# compiler's analyzer cache (fixed)

`dotnet run` of a 6-line console project produced eight `createdOrTruncated` DLLs under
`%TEMP%\VBCSCompiler\AnalyzerAssemblyLoader\<hash>\<guid>\` — the compiler server unpacking the
analyzers it loads. `F-007` is about a *payload* appearing in a writable location; a loader cache is
not that, and it made an ordinary build Suspicious 37.1.

Only `.dll` files under `\vbcscompiler\` are excluded. An `.exe` dropped in that same directory still
fires, which is asserted by `An_executable_in_the_compiler_cache_still_fires`.

### 3. P-006 reported a browser's own child processes (fixed)

Chrome builds its renderer, GPU, utility and crashpad processes by starting copies of its own
executable with a different `--type` switch. `P-006` counts exactly that shape — one image, several
launches, different switches — so a browser scored four findings in 25 seconds and the Electron IDE
two more.

The rule now ignores a launch whose image equals its **parent's** image. Discovery enumeration (the
shape the rule exists for: one tool driven repeatedly by a script) has a different parent for each
invocation and still counts, which is what `One_tool_driven_with_different_switches_is_flagged` keeps
honest.

### 4. N-004 in the Electron IDE (kept, no change)

`N-004` (a public address with no name looked up in the window, severity 35) fired once during the
IDE session. That is the rule doing what it says: a telemetry or marketplace connection whose name
resolution happened before the window. It is deliberately a weak ingredient with its severity set to
15 in the catalogue and is never a verdict on its own; the session scored 46.2 with it, and 9.6
without the two fixed rule bugs. After the fixes it does not appear in the final run at all, because
the IDE's connections in that shorter session were preceded by their lookups.

## What this does not prove

- One machine, one user profile, six applications. A corpus of six is a floor, not a baseline: the
  useful part is the triage, and every case is reproducible with the checked-in script.
- `7-Zip` was installed for this measurement (7-Zip 25.01, x64 MSI from 7-zip.org); it was not
  present on the machine before. Its installer is unsigned, which would itself be reported by `P-005`
  if the installer were run under the monitor — it was not.
- The GUI cases are driven by `SendKeys` and window activation, so the *interaction* varies slightly
  between runs even when the verdicts do not.
- Nothing here exercises the corpus at the volume of real user activity (a browser with twenty tabs,
  an IDE with a full build). `argus selftest --load` covers pipeline throughput separately.
