<#
    Verify Argus on Windows (or any host with the .NET 8 SDK).

    Run from an ordinary PowerShell in the repository root:
        ./scripts/verify.ps1

    Add -InstallSdk to install the .NET 8 SDK into %USERPROFILE%\.dotnet first
    (no administrator rights required, no system-wide change).

    Add -Smoke to also run the elevated live-capture check (scripts/smoke.ps1).
    That switch requires an elevated PowerShell; the default checks do not.
#>
[CmdletBinding()]
param(
    [switch]$InstallSdk,
    [switch]$SkipTests,
    [switch]$Smoke
)

$ErrorActionPreference = 'Stop'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

Set-Location (Split-Path -Parent $PSScriptRoot)

function Resolve-Dotnet {
    $local = Join-Path $env:USERPROFILE '.dotnet\dotnet.exe'
    if (Test-Path $local) { return $local }
    $onPath = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    return $null
}

$dotnet = Resolve-Dotnet

if (-not $dotnet -and $InstallSdk) {
    Write-Host 'Installing .NET 8 SDK into %USERPROFILE%\.dotnet ...'
    $installer = Join-Path $env:TEMP 'dotnet-install.ps1'
    Invoke-WebRequest -UseBasicParsing 'https://dot.net/v1/dotnet-install.ps1' -OutFile $installer
    & $installer -Channel 8.0 -InstallDir (Join-Path $env:USERPROFILE '.dotnet') -NoPath
    $dotnet = Resolve-Dotnet
}

if (-not $dotnet) {
    Write-Error @'
.NET SDK not found. Either install it with:
    winget install Microsoft.DotNet.SDK.8
or rerun this script with -InstallSdk (user-local, no admin required).
'@
}

Write-Host "== dotnet $(& $dotnet --version) =="

& $dotnet build Argus.sln -v q --nologo
if ($LASTEXITCODE -ne 0) { throw 'build failed' }

if (-not $SkipTests) {
    & $dotnet test Argus.sln --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw 'tests failed' }

    & $dotnet run --project src/Argus.Cli -v q --no-build -- replay tests/fixtures/scenarios --assert
    if ($LASTEXITCODE -ne 0) { throw 'replay assertions failed' }

    & $dotnet run --project src/Argus.Cli -v q --no-build -- selftest
    if ($LASTEXITCODE -ne 0) { throw 'selftest failed' }
}

if ($Smoke) {
    Write-Host ''
    Write-Host '== live smoke (elevated) ==' -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'smoke.ps1') -SkipBuild
    if ($LASTEXITCODE -ne 0) { throw 'smoke test failed' }
}

Write-Host ''
Write-Host 'verify.ps1: all checks passed' -ForegroundColor Green
