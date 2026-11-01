# Connected original workspace

The original frontend is now served by the same login, organization and billing
backend. Its existing scanner adapter is reused; scanner-core and CLI files have
not been changed by this integration.

## Open locally

Open the `SilentSec-integrated` repository root in VS Code. In PowerShell:

```powershell
# On a fresh checkout only:
.\frontend\setup.ps1 -Platform

# Start the connected app and local worker:
.\Start-Platform.ps1
```

Open http://127.0.0.1:8780/app. Sign in with the locally provisioned developer
identity and the development access code displayed by the launcher. The admin
login is http://127.0.0.1:8780/admin/login. Development login is a simulator;
production must use the configured OIDC provider and verified MFA for admins.
PostgreSQL/Redis are selected when configured in ignored local settings; otherwise
development uses SQLite. Payment checkout and private-repository providers are
not configured.

For local-folder workflows, register each checkout as an operator, in a terminal
with the same platform environment/database configuration as the running server:

```powershell
$localSettings = Get-Content .platform/dev-settings.json -Raw | ConvertFrom-Json
foreach ($item in $localSettings.PSObject.Properties) {
  [Environment]::SetEnvironmentVariable('SILENTSEC_PLATFORM_' + $item.Name.ToUpper(), [string]$item.Value, 'Process')
}
$env:SILENTSEC_PLATFORM_WORKSTATION_ENABLED = 'true'
.\frontend\.venv\Scripts\python.exe -m silentsec.platform register-local `
  --email developer@silentsec.local --path C:\demo\your-repository
```

The demo checkout was registered for this computer's developer workspace. Other
folders need their own explicit registration. There is no browser endpoint that
accepts arbitrary server roots. Local-folder mode cannot start in production.

## Original feature coverage

| Original feature | Connected behavior | Verification |
|---|---|---|
| Particle landing page | Original page and scroll scene at `/` | Served original HTML; nonce applied to its inline script |
| Local scan and score | Exact registered checkout; original score, components, coverage and findings | Real browser scan and real worker test |
| GitHub / ZIP / source file | Native safe ingestion through durable jobs | Upload validation and real source upload; live GitHub download not exercised |
| Findings, filters, exposure and deduplication | Original views and backend model retained; source excerpts withheld | Browser result and original frontend tests |
| AI triage and fix proposal | Existing provider chain, explicit opt-in, paid entitlement and named AI budget | Configuration/error paths; no live inference tested |
| Local / GitHub / upload patch verification | Original verification model; isolated copies; no web repository tests | Real local and upload patches; GitHub shares the native adapter, not live-tested |
| PR check | Original base/head, policy, verdict, findings and SARIF | Real Git fixture worker |
| Time Machine | Original timeline, cache, recurrence and commit details | Real two-commit Git history; paid history entitlement |
| Reports | Original offline HTML template; optional history and owned fix reports | Real report/history generation and export tests |
| JSON and SARIF | Original export controls; organization-authorized retained artifacts | Original frontend tests and real scan exports |
| Saved operations | Persistent organization job picker and reconnect/cancellation | API ownership/idempotency/cancellation tests; browser reopen |
| Original CLI/local mode | Existing entry points remain available independently | Existing suite and 30 original frontend tests |

Billing and account/team screens appear in the original sidebar. Architecture and
pattern exploration share the same organization and saved scan database at
`/account`. The admin portal uses the same identity backend with its stronger
server-side authorization; it does not receive private scan artifacts by default.

## Usage rules

- Free receives 30 standard scan credits per calendar month in the workspace billing timezone.
- A local, GitHub or upload scan, or a fresh report, reserves one standard unit.
- Validation/preparation failures and queued cancellations release the reservation.
- History commits, verification, PR checks and AI findings have separately named allowances.
- History and AI require the relevant plan entitlement and configuration. UI errors explain blocked actions.
- All debits, reservations, authorization and concurrency checks happen on the server.

The existing `frontend/Start-SilentSec.cmd` is the independent standalone mode.
The running 8769 address on this computer is an optional redirect gateway to the
connected app. To recreate that gateway in a second terminal:

```powershell
cd frontend
.\.venv\Scripts\python.exe -m local_api.server --port 8769 --platform-url http://127.0.0.1:8780
```

No remote push, production deployment or payment purchase was performed.
