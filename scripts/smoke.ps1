<#
    Argus Windows smoke test (Phase 2).

    Run this from an ELEVATED PowerShell in the repository root:
        ./scripts/smoke.ps1

    It proves the live path, not just compilation:
      1. argus-agent --self-test --json (elevation, ETW kernel provider, DNS,
         process metadata, TCP owner table)
      2. a real notepad.exe session with ETW capture, SQLite persistence and a
         raw JSONL recording
      3. replay of that recording through the production pipeline

    The script leaves the recording and database in -OutputDir so they can be
    copied to a Linux machine and replayed again there with:
        dotnet run --project src/Argus.Cli -- replay <file>.jsonl --assert

    Notes:
      - It launches a fresh notepad.exe and closes only the PID it started.
      - It never downloads or executes test malware. notepad is the benign
        baseline; suspicious scenarios belong to the behaviour simulator.
      - A self-test failure is reported with the exact failed check, never
        hidden behind a generic "smoke failed" message.
#>
[CmdletBinding()]
param(
    [string]$Target = (Join-Path $env:WINDIR 'System32\notepad.exe'),
    [int]$Seconds = 15,
    [string]$OutputDir = (Join-Path $env:TEMP 'argus-smoke'),
    [switch]$SkipBuild,
    [switch]$KeepTarget
)

$ErrorActionPreference = 'Stop'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

Set-Location (Split-Path -Parent $PSScriptRoot)

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'smoke.ps1 exercises live ETW capture and must run on Windows 10/11.'
}

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Elevated)) {
    throw @'
smoke.ps1 needs an elevated PowerShell: ETW kernel monitoring requires administrator rights.
Open PowerShell with "Run as administrator", then rerun:
    ./scripts/smoke.ps1
'@
}

function Resolve-Dotnet {
    $local = Join-Path $env:USERPROFILE '.dotnet\dotnet.exe'
    if (Test-Path $local) { return $local }
    $onPath = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    throw '.NET 8 SDK not found. Run ./scripts/verify.ps1 -InstallSdk first.'
}

$dotnet = Resolve-Dotnet
if (-not (Test-Path $Target)) {
    throw "Target executable not found: $Target"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$record = Join-Path $OutputDir 'live-session.jsonl'
$database = Join-Path $OutputDir 'live-session.db'
$readyFile = Join-Path $OutputDir 'ready.json'
foreach ($file in @($record, $database, $database + '-wal', $database + '-shm', $readyFile)) {
    if (Test-Path $file) { Remove-Item -Force $file }
}

Write-Host "== dotnet $(& $dotnet --version) =="
if (-not $SkipBuild) {
    & $dotnet build Argus.sln -v q --nologo
    if ($LASTEXITCODE -ne 0) { throw 'build failed' }
}

Write-Host ''
Write-Host '== 1/3 agent self-test ==' -ForegroundColor Cyan
$selfTestOutput = & $dotnet run --project src/Argus.Agent -v q --no-build -- --self-test --json
$selfTestExit = $LASTEXITCODE
$selfTestText = ($selfTestOutput | Out-String).Trim()
if ([string]::IsNullOrWhiteSpace($selfTestText)) {
    throw "agent self-test produced no output (exit $selfTestExit)."
}

if ($selfTestExit -ne 0) {
    Write-Host $selfTestText
    throw "agent self-test failed (exit $selfTestExit). The failed check is listed above."
}

$selfTest = $selfTestText | ConvertFrom-Json
if (-not $selfTest.passed) {
    Write-Host $selfTestText
    throw 'agent self-test reported passed=false.'
}

Write-Host ("   pass  elevation, ETW kernel provider, DNS, metadata, TCP table")
Write-Host ("   events seen in the 2 s probe: {0}; forwarded: {1}" -f $selfTest.monitor.eventsSeen, $selfTest.monitor.eventsForwarded)
foreach ($warning in @($selfTest.warnings)) {
    if ($warning) { Write-Host "   warn  $warning" -ForegroundColor Yellow }
}

Write-Host ''
Write-Host "== 2/3 live capture: $Target for ${Seconds}s ==" -ForegroundColor Cyan
$agentArgs = @(
    'run', '--project', 'src/Argus.Agent', '-v', 'q', '--no-build', '--',
    '--target', $Target,
    '--duration', "$Seconds",
    '--db', $database,
    '--record', $record,
    '--ready-file', $readyFile,
    '--port', '0'
)
& $dotnet @agentArgs
$agentExit = $LASTEXITCODE
if ($agentExit -ne 0) {
    throw "live agent exited with $agentExit; see the message above."
}

if (-not (Test-Path $readyFile)) { throw "agent did not write the ready file: $readyFile" }
$ready = Get-Content -Raw $readyFile | ConvertFrom-Json
Write-Host ("   session {0}, root PID {1}, api {2}" -f $ready.sessionId, $ready.rootPid, $ready.api)
Write-Host ("   database {0}" -f $database)
Write-Host ("   recording {0}" -f $record)

if (-not (Test-Path $record)) { throw "recording was not written: $record" }
$recordLines = @(Get-Content $record | Where-Object { $_.Trim().Length -gt 0 })
if ($recordLines.Count -lt 2) {
    throw "recording contains only $($recordLines.Count) line(s); expected a meta line and at least one event."
}
if ($recordLines[0] -notmatch '"\$meta"') { throw 'recording does not start with a $meta line.' }
if (-not (Test-Path $database)) { throw "session database was not written: $database" }

if (-not $KeepTarget -and $ready.rootPid) {
    Stop-Process -Id ([int]$ready.rootPid) -ErrorAction SilentlyContinue
}

Write-Host ("   captured {0} raw event line(s)" -f ($recordLines.Count - 1))

Write-Host ''
Write-Host '== 3/3 replay the recording through the production pipeline ==' -ForegroundColor Cyan
& $dotnet run --project src/Argus.Cli -v q --no-build -- replay $record --assert
if ($LASTEXITCODE -ne 0) {
    throw 'replay of the live recording failed.'
}

Write-Host ''
Write-Host 'smoke.ps1: all checks passed' -ForegroundColor Green
Write-Host "Live evidence kept in $OutputDir"
Write-Host 'Copy live-session.jsonl to a Linux checkout and run:'
Write-Host "  dotnet run --project src/Argus.Cli -- replay <path>/live-session.jsonl --assert"
