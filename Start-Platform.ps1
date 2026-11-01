param([int]$Port = 8780)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$platformPython = Join-Path $PSScriptRoot 'frontend/.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $platformPython)) { throw 'Install the platform extras into frontend/.venv first; see docs/platform.md.' }
& $platformPython -m silentsec.platform local-config
$localSettings = Get-Content -LiteralPath '.platform/dev-settings.json' -Raw | ConvertFrom-Json
$env:SILENTSEC_PLATFORM_ENVIRONMENT = 'development'
$env:SILENTSEC_PLATFORM_AUTH_MODE = 'development'
$env:SILENTSEC_PLATFORM_SESSION_SECRET = $localSettings.session_secret
$env:SILENTSEC_PLATFORM_DEV_LOGIN_CODE = $localSettings.dev_login_code
if ($localSettings.database_url) { $env:SILENTSEC_PLATFORM_DATABASE_URL = $localSettings.database_url }
else { $env:SILENTSEC_PLATFORM_DATABASE_URL = 'sqlite:///./.platform/platform.db' }
if ($localSettings.redis_url) { $env:SILENTSEC_PLATFORM_REDIS_URL = $localSettings.redis_url }
else { $env:SILENTSEC_PLATFORM_REDIS_URL = '' }
$env:SILENTSEC_PLATFORM_ALLOWED_ORIGINS = '[]'
$env:SILENTSEC_PLATFORM_PUBLIC_URL = "http://127.0.0.1:$Port"
$env:SILENTSEC_PLATFORM_AUTO_WORKER = 'true'
$env:SILENTSEC_PLATFORM_WORKSTATION_ENABLED = 'true'
& $platformPython -m silentsec.platform init-db
if ($LASTEXITCODE -ne 0) { throw 'Migration failed.' }
& $platformPython -m silentsec.platform seed-dev --email developer@silentsec.local --name Developer
& $platformPython -m silentsec.platform seed-dev --email admin@silentsec.local --name Administrator --admin
Write-Host "Local development access code: $($localSettings.dev_login_code)"
Write-Host "Customer: http://127.0.0.1:$Port/login (developer@silentsec.local)"
Write-Host "Administrator: http://127.0.0.1:$Port/admin/login (admin@silentsec.local)"
& $platformPython -m silentsec.platform serve --port $Port
