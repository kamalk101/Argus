<#
    Benign-corpus measurement (PLAN.md §11.1).

    Runs one benign application under the elevated agent, records the session, replays the
    recording through the production pipeline and prints one factual row: band, risk, event
    count, detections, gaps. Nothing is asserted here — the numbers are what the docs quote,
    and a triage note is written by hand for anything the table shows above the expected
    thresholds (risk < 20, no detection at severity >= 80).

        ./scripts/corpus.ps1 -Target notepad
        ./scripts/corpus.ps1 -Target all

    Each case builds its own workspace under %TEMP%\argus-corpus\<target> and leaves the
    recording there for inspection. Nothing outside %TEMP% is written, except the notepad case,
    which saves to its own workspace folder.
#>
[CmdletBinding()]
param(
    [ValidateSet('notepad', '7zip', 'python', 'dotnet', 'chrome', 'vscode', 'all')]
    [string]$Target = 'all',

    [int]$Duration = 25
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

function Resolve-Dotnet {
    $local = Join-Path $env:USERPROFILE '.dotnet\dotnet.exe'
    if (Test-Path $local) { return $local }
    $onPath = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    throw '.NET SDK not found.'
}

$dotnet = Resolve-Dotnet
$agent = 'src/Argus.Agent/bin/Debug/net8.0-windows/argus-agent.dll'
$cli = 'src/Argus.Cli/bin/Debug/net8.0/argus.dll'

if (-not (Test-Path $agent) -or -not (Test-Path $cli)) {
    & $dotnet build Argus.sln -v q --nologo | Out-Host
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw 'This script needs an elevated PowerShell: live ETW capture requires administrator rights.'
}

$root = Join-Path $env:TEMP 'argus-corpus'

function New-Workspace([string]$name) {
    $dir = Join-Path $root $name
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return $dir
}

# Runs the agent with a target and replays the recording. Returns the replay row as text.
function Invoke-Case {
    param([string]$Name, [string]$Exe, [string]$Arguments, [int]$Seconds = $Duration, [scriptblock]$During)

    # Not New-Workspace: the cases below prepare their own payload in this folder, and wiping it
    # here deleted the batch file or script they had just written (7zip/python/dotnet captured
    # nothing but cmd.exe starting and stopping).
    $dir = Join-Path $root $Name
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $record = Join-Path $dir 'session.jsonl'
    $db = Join-Path $dir 'session.db'

    # One argument string with every value quoted: Start-Process joins -ArgumentList with spaces
    # and does not quote items itself, so a value containing a space (an --args string, a Program
    # Files path) would otherwise arrive as several arguments and the agent would exit 2 having
    # written no recording.
    $agentArgs = @(
        "`"$agent`"", '--target', "`"$Exe`"",
        '--record', "`"$record`"", '--db', "`"$db`"", '--duration', $Seconds
    )
    if ($Arguments) { $agentArgs += @('--args', "`"$Arguments`"") }

    Write-Host "== $Name : $([IO.Path]::GetFileName($Exe)) $Arguments" -ForegroundColor Cyan
    $proc = Start-Process -FilePath $dotnet -ArgumentList ($agentArgs -join ' ') -PassThru -WindowStyle Hidden

    if ($During) {
        Start-Sleep -Seconds 7
        & $During
    }

    $proc.WaitForExit()
    if (-not (Test-Path $record)) { throw "$Name produced no recording" }

    $lines = & $dotnet $cli replay $record --json 2>&1 | ForEach-Object { "$_" }
    $start = -1
    $end = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($start -lt 0 -and $lines[$i].TrimStart().StartsWith('[')) { $start = $i }
        if ($start -ge 0 -and $lines[$i].Trim() -eq ']') { $end = $i }
    }
    if ($start -lt 0 -or $end -lt $start) { throw "$Name : replay produced no JSON`n$($lines -join "`n")" }
    $result = ($lines[$start..$end] -join "`n") | ConvertFrom-Json
    $scenario = $result[0]

    $rules = if ($scenario.detections.Count -gt 0) { ($scenario.detections | ForEach-Object { $_.rule }) -join ',' } else { '-' }
    $row = '{0,-10} {1,-12} {2,6} {3,7} {4,5} {5,5}  {6}' -f `
        $Name, $scenario.band, $scenario.risk, $scenario.events, $scenario.detections.Count, $scenario.gaps, $rules
    Write-Host $row -ForegroundColor Green
    Write-Host "   recording: $record" -ForegroundColor DarkGray
    return $row
}

$rows = @()

if ($Target -in @('notepad', 'all')) {
    # The plan's row: type text, save a file. SendKeys drives a real notepad window.
    $dir = New-Workspace 'notepad'
    $save = Join-Path $dir 'note.txt'
    $rows += Invoke-Case -Name 'notepad' -Exe 'C:\Windows\System32\notepad.exe' -Arguments '' -During {
        $shell = New-Object -ComObject WScript.Shell
        for ($i = 0; $i -lt 20; $i++) {
            if ($shell.AppActivate('Notepad')) { break }
            Start-Sleep -Milliseconds 400
        }
        $shell.SendKeys('benign corpus text')
        Start-Sleep -Milliseconds 500
        $shell.SendKeys('^s')
        Start-Sleep -Milliseconds 1500
        $shell.SendKeys($save)
        Start-Sleep -Milliseconds 500
        $shell.SendKeys('{ENTER}')
        Start-Sleep -Milliseconds 800
        $shell.SendKeys('%{F4}')
    }
}

if ($Target -in @('7zip', 'all')) {
    # Compress then extract: the shapes a real archiver produces.
    $dir = New-Workspace '7zip'
    $payload = Join-Path $dir 'payload'
    New-Item -ItemType Directory -Path $payload -Force | Out-Null
    for ($i = 0; $i -lt 40; $i++) {
        Set-Content -Path (Join-Path $payload ('doc{0:D2}.txt' -f $i)) -Value ("argus benign corpus {0}" -f $i)
    }
    $script = Join-Path $dir 'run.bat'
    @(
        '@echo off',
        "`"C:\Program Files\7-Zip\7z.exe`" a `"$dir\bundle.7z`" `"$payload\*`" > nul",
        "`"C:\Program Files\7-Zip\7z.exe`" x `"$dir\bundle.7z`" -o`"$dir\extracted`" -y > nul",
        'echo done'
    ) | Set-Content -Path $script -Encoding ASCII
    $rows += Invoke-Case -Name '7zip' -Exe 'C:\Windows\System32\cmd.exe' -Arguments "/c $script"
}

if ($Target -in @('python', 'all')) {
    $dir = New-Workspace 'python'
    $script = Join-Path $dir 'work.py'
    @(
        'import hashlib, json, os, pathlib, time',
        'here = pathlib.Path(__file__).parent',
        'rows = [{"i": i, "h": hashlib.sha256(str(i).encode()).hexdigest()} for i in range(2000)]',
        '(here / "out.json").write_text(json.dumps(rows))',
        'data = (here / "out.json").read_text()',
        'print(len(data))',
        'time.sleep(1)'
    ) | Set-Content -Path $script -Encoding ASCII
    $rows += Invoke-Case -Name 'python' -Exe 'C:\Users\kamal\AppData\Local\Programs\Python\Python312\python.exe' -Arguments "`"$script`""
}

if ($Target -in @('dotnet', 'all')) {
    # A console project built and run: msbuild, Roslyn, the apphost — heavy, ordinary file churn.
    $dir = New-Workspace 'dotnet'
    $proj = Join-Path $dir 'hello'
    New-Item -ItemType Directory -Path $proj -Force | Out-Null
    @(
        '<Project Sdk="Microsoft.NET.Sdk">',
        '  <PropertyGroup>',
        '    <OutputType>Exe</OutputType>',
        '    <TargetFramework>net8.0</TargetFramework>',
        '    <Nullable>enable</Nullable>',
        '  </PropertyGroup>',
        '</Project>'
    ) | Set-Content -Path (Join-Path $proj 'hello.csproj') -Encoding ASCII
    @(
        'var path = Path.Combine(AppContext.BaseDirectory, "out.txt");',
        'File.WriteAllText(path, "argus benign corpus");',
        'Console.WriteLine(File.ReadAllText(path).Length);'
    ) | Set-Content -Path (Join-Path $proj 'Program.cs') -Encoding ASCII
    $script = Join-Path $dir 'run.bat'
    @(
        '@echo off',
        "`"$dotnet`" run --project `"$proj`" -v q --nologo > nul",
        'echo done'
    ) | Set-Content -Path $script -Encoding ASCII
    $rows += Invoke-Case -Name 'dotnet' -Exe 'C:\Windows\System32\cmd.exe' -Arguments "/c $script" -Seconds 40
}

if ($Target -in @('chrome', 'all')) {
    $dir = New-Workspace 'chrome'
    $page = Join-Path $dir 'page.html'
    Set-Content -Path $page -Value '<html><body><h1>argus corpus</h1></body></html>' -Encoding ASCII
    $profileDir = Join-Path $dir 'profile'
    $arguments = "--user-data-dir=$profileDir --no-first-run --new-window file:///$($page -replace '\\','/')"
    $rows += Invoke-Case -Name 'chrome' -Exe 'C:\Program Files\Google\Chrome\Application\chrome.exe' -Arguments $arguments -During {
        Start-Sleep -Seconds 5
        Get-Process chrome -ErrorAction SilentlyContinue | Where-Object { $_.Path } | Select-Object -First 1 | Out-Null
    }
    Get-Process chrome -ErrorAction SilentlyContinue | ForEach-Object { $_.CloseMainWindow() | Out-Null }
}

if ($Target -in @('vscode', 'all')) {
    $qoder = Join-Path $env:LOCALAPPDATA 'Programs\Qoder\Qoder.exe'
    if (-not (Test-Path $qoder)) {
        Write-Host 'vscode: no VS Code or Qoder installation found — skipped' -ForegroundColor Yellow
    }
    else {
        $dir = New-Workspace 'vscode'
        for ($i = 0; $i -lt 30; $i++) {
            New-Item -ItemType Directory -Path (Join-Path $dir ('src{0:D2}' -f $i)) -Force | Out-Null
            Set-Content -Path (Join-Path $dir ('src{0:D2}\file.cs' -f $i)) -Value "class C$i { }" -Encoding ASCII
        }
        $rows += Invoke-Case -Name 'vscode' -Exe $qoder -Arguments "--new-window $dir" -During { Start-Sleep -Seconds 6 }
        Get-Process Qoder -ErrorAction SilentlyContinue | ForEach-Object { $_.CloseMainWindow() | Out-Null }
    }
}

Write-Host ''
Write-Host 'target       band           risk  events dets  gaps  rules'
Write-Host '----------------------------------------------------------------'
$rows | ForEach-Object { Write-Host $_ }
Write-Host ''
Write-Host "recordings under $root"
