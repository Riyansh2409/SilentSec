param([string]$Backend = "", [string]$Python = "")
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not $Backend) {
    if (Test-Path -LiteralPath '.data/config.json') { $Backend = (Get-Content '.data/config.json' -Raw | ConvertFrom-Json).backend_path }
    else { $Backend = Split-Path -Parent $PSScriptRoot }
}
$Backend = (Resolve-Path -LiteralPath $Backend).Path
if (-not (Test-Path -LiteralPath (Join-Path $Backend 'src/silentsec'))) { throw 'Choose a SilentSec repository with -Backend.' }
if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) {
    if ($Python) { $candidate = $Python }
    elseif (Get-Command python -ErrorAction SilentlyContinue) { $candidate = (Get-Command python).Source }
    else { throw 'Install Python 3.11 or newer, then run setup.ps1 -Python <path-to-python.exe>.' }
    & $candidate -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)'
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 or newer is required. Pass its path using -Python.' }
    & $candidate -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the local environment.' }
}
$localPython = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
& $localPython -m ensurepip --upgrade
if ($LASTEXITCODE -ne 0) { throw 'Could not prepare pip.' }
& $localPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw 'Could not update pip.' }
$package = "${Backend}[api,scanners]"
& $localPython -m pip install -e $package
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. Review the error above.' }
New-Item -ItemType Directory -Path '.data' -Force | Out-Null
@{backend_path=$Backend} | ConvertTo-Json | Set-Content -LiteralPath '.data/config.json' -Encoding utf8
Write-Host 'Python dependencies installed. Gitleaks is a separate executable; see README.md.'
Write-Host 'Start with .\Start-SilentSec.cmd, then open http://127.0.0.1:8767'
