# Capture the agent's real API payloads as fixtures for the dashboard's Playwright tests.
#
# The dashboard is tested against the same JSON the agent serves, not against hand-written mocks:
# a fixture that drifts from the real payload is a test that passes while the screen is broken.
# Re-run this after any change to a DTO and the web build will fail loudly if a field disappears.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/dashboard-fixtures.ps1
#
# Requires an elevated shell (the agent refuses to start otherwise). Writes into
# web/src/api/fixtures/ and leaves the recording under %TEMP%\argus-fixtures.

[CmdletBinding()]
param(
    [int]$Duration = 15,
    [string]$Target = "$env:WINDIR\System32\notepad.exe",
    [string]$TargetArgs = '',
    [string]$FixtureName = 'benign'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$OutDir = Join-Path $repo "web\public\fixtures\$FixtureName"
$agentDll = Join-Path $repo 'src\Argus.Agent\bin\Debug\net8.0-windows\argus-agent.dll'
$work = Join-Path $env:TEMP ("argus-fixtures-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))

if (-not (Test-Path $agentDll)) { throw "agent not built: $agentDll (run: dotnet build Argus.sln)" }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
New-Item -ItemType Directory -Force -Path $work | Out-Null

$ready = Join-Path $work 'ready.txt'
$log = Join-Path $work 'agent.log'

Write-Host "== recording a $Duration s session ($FixtureName) to capture API payloads"
$arguments = @(
    $agentDll,
    '--port', '0',
    '--target', $Target,
    '--duration', "$Duration",
    '--record', (Join-Path $work 'session.jsonl'),
    '--db', (Join-Path $work 'session.db'),
    '--ready-file', $ready
)
if ($TargetArgs) { $arguments += @('--args', $TargetArgs) }

# Start-Process splits an argument array on spaces inside values, so build one command line and
# quote only the values that need it: quoting a path unconditionally leaves the agent parsing the
# quotes as part of the file name ("Target executable was not found").
$commandLine = ($arguments | ForEach-Object {
    if ($_ -match '\s') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
}) -join ' '

$agent = Start-Process -FilePath (Join-Path $HOME '.dotnet\dotnet.exe') -ArgumentList $commandLine `
    -NoNewWindow -PassThru -RedirectStandardOutput $log -RedirectStandardError "$log.err"

# The ready file carries the port and token the agent actually bound.
$deadline = (Get-Date).AddSeconds(40)
while (-not (Test-Path $ready)) {
    if ((Get-Date) -gt $deadline) { throw "agent never wrote $ready; see $log" }
    if ($agent.HasExited) { throw "agent exited $($agent.ExitCode); see $log.err" }
    Start-Sleep -Milliseconds 200
}

$info = Get-Content $ready -Raw | ConvertFrom-Json
$base = "http://127.0.0.1:$($info.port)"
$headers = @{ Authorization = "Bearer $($info.token)" }
Write-Host "== agent on $base"

function Save([string]$Path, [string]$Name) {
    $response = Invoke-WebRequest -Uri ($base + $Path) -Headers $headers -UseBasicParsing
    $text = $response.Content
    # Pretty-print so a fixture diff is readable in review. Windows PowerShell's ConvertTo-Json
    # collapses a one-element array into a bare object, which would make the dashboard's array
    # contract look optional; restore the brackets when the agent sent an array.
    $value = $text | ConvertFrom-Json
    $pretty = if ($null -eq $value) { '[]' } else { $value | ConvertTo-Json -Depth 40 }
    if (-not $pretty) { $pretty = '[]' }
    if ($text.TrimStart().StartsWith('[') -and -not $pretty.TrimStart().StartsWith('[')) {
        $pretty = "[$pretty]"
    }
    Set-Content -Path (Join-Path $OutDir $Name) -Value $pretty -Encoding utf8
    Write-Host ("   {0,-40} {1,8} bytes" -f $Name, $pretty.Length)
}

# Wait for the session to exist, then for it to carry real activity.
$sessions = $null
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 500
    try { $sessions = (Invoke-WebRequest -Uri "$base/api/sessions" -Headers $headers -UseBasicParsing).Content | ConvertFrom-Json } catch { continue }
    if ($sessions.Count -gt 0) { break }
}
if (-not $sessions -or $sessions.Count -eq 0) { throw "agent never reported a session" }

$id = $sessions[0].id
Write-Host "== session $id"

# Let the session accumulate before snapshotting: capturing the instant it exists yields a handful
# of events and a single score sample, which makes the dashboard's charts and filters look empty
# even though the code is fine.
$settle = if ($Duration -gt 20) { 10 } else { 7 }
Write-Host "== settling for $settle s"
Start-Sleep -Seconds $settle

Save '/api/health'                    'health.json'
Save '/api/sessions'                  'sessions.json'
Save "/api/sessions/$id"              'session.json'
Save "/api/sessions/$id/processes"    'processes.json'
Save "/api/sessions/$id/detections"   'detections.json'
Save "/api/sessions/$id/events?limit=500" 'events.json'
Save "/api/sessions/$id/timeline?limit=500" 'timeline.json'
Save "/api/sessions/$id/scores"        'scores.json'

# The evidence chain for the most severe detection: the Threats screen expands a card into exactly
# the events the agent says the detection rests on, and that is a different payload from the list.
$detections = Get-Content (Join-Path $OutDir 'detections.json') -Raw | ConvertFrom-Json
$worst = $detections | Sort-Object -Property severity -Descending | Select-Object -First 1
if ($worst) {
    $key = [uri]::EscapeDataString($worst.detectionKey)
    Save "/api/sessions/$id/detections/$key" 'evidence.json'
}

$open = $sessions | Where-Object { $_.status -ne 'stopped' }
if ($open) {
    Invoke-WebRequest -Uri "$base/api/sessions/$id/stop" -Method Post -Headers $headers -UseBasicParsing | Out-Null
    Write-Host "== stopped session"
}

$deadline = (Get-Date).AddSeconds(30)
while (-not $agent.HasExited -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }

Write-Host "== fixtures in $OutDir"
Get-ChildItem $OutDir | Format-Table Name, Length -AutoSize
