# SilentSec platform: local setup and implementation boundaries

The platform is a separate application in `src/silentsec/platform`. The original
scanner, CLI, `silentsec serve`, and `frontend/local_api` are preserved. The local
API can accept trusted local paths and optional tests; it is never mounted by the
SaaS server. SaaS inputs accept only validated public GitHub links and uploads,
and never execute repository code, tests, hooks, plugins or user commands.

## Open this checkout

Open `C:\Users\harsh\Documents\Codex\2026-10-31\w\outputs\SilentSec-integrated`
in VS Code. Work is on `codex/saas-platform`. There is no remote push or deployment.

From the repository root in PowerShell:

```powershell
# This computer is already installed:
.\Start-Platform.ps1

# On a fresh clone, first use Python 3.11 or newer:
python -m venv frontend/.venv
.\frontend\.venv\Scripts\python.exe -m pip install -e '.[platform,scanners,dev]'
# Install Gitleaks on PATH or in frontend/.tools before scanning.
.\Start-Platform.ps1
```

The launcher creates/reuses local credentials, runs Alembic migrations, provisions
explicit development identities, and starts the server on loopback:

- Customer login: http://127.0.0.1:8780/login — `developer@silentsec.local`
- Internal login: http://127.0.0.1:8780/admin/login — `admin@silentsec.local`
- Customer dashboard: http://127.0.0.1:8780/workspace
- Internal portal: http://127.0.0.1:8780/admin

To read only the local sign-in code without restarting the running app:

```powershell
(Get-Content .platform/dev-settings.json -Raw | ConvertFrom-Json).dev_login_code
```

The shared **development access code** is printed by the launcher and saved in
ignored `.platform/dev-settings.json`. No account passwords are stored. Admin MFA
is explicitly simulated by the development identity adapter, not proof of real
MFA. Development authentication cannot start in production mode. The first signup
never becomes a platform administrator automatically.

Keep the terminal open. Do not start a second server on the same port. The previous
local frontend is a different service on 8769; it is not the SaaS platform.

## PostgreSQL and Redis on this computer

The dedicated `silentsec-platform` Compose project uses loopback ports **55432**
and **56379**. It does not modify the existing CTI container. Official images are
pinned by digest. Persistent Docker volumes hold database/queue data.

```powershell
# .platform/docker.env was generated locally; it contains the development DB password.
docker compose --env-file .platform/docker.env -p silentsec-platform -f compose.platform.yml up -d
```

The current ignored `dev-settings.json` points the launcher at these services.
On another computer, omit its `database_url`/`redis_url` fields to use local SQLite
and DB polling, or configure new local services. Never share the credentials file.
For a new Compose installation, set `SILENTSEC_POSTGRES_PASSWORD` yourself and pass
it through your environment or an ignored env file. Redis here is loopback-only
development infrastructure; production needs private networking and authentication.

## Credit rules

- A personal organization receives exactly **30 standard scan credits per calendar
  month**, in its billing timezone (UTC by default).
- A verified OIDC identity gets one personal organization. Users cannot create
  unlimited workspaces to mint new free grants. Joining teams does not mint grants.
- Timezone is chosen at creation and database-locked after the first grant. A future
  timezone change requires a separately designed next-period migration.
- A valid submission reserves one credit atomically. Queue capacity is checked
  before reservation. Repeating the same idempotency key returns the same job;
  changing its input gives 409.
- Source validation, pre-execution internal/preparation failures, queued cancellation
  and expired queued reservations do not spend credits. Once valid scanning starts,
  usage is committed even if later cancelled or incomplete.
- Pro and Enterprise record standard scans without normal-credit debits. Their
  running/queued limits, rate, timeout, retention and optional Enterprise pool still
  apply. “Unlimited” never means unbounded resources.
- AI findings, deep-history commits and verification are separately named units.
  They are **not enabled operations in this SaaS release** and never silently debit
  standard scan credits. They remain available through existing local/CLI workflows
  where supported and explicitly configured.
- Monthly grants, reservations, commits, releases and manual adjustments are an
  append-only ledger, not a mutable balance. PostgreSQL/SQLite triggers protect audit,
  grants, ledger and entitlement snapshots; approved pattern packs are append-only.

The worker runs retry-safe maintenance at least between jobs and on idle minute
intervals. Billing reads/submissions also ensure the current month's grant. Operators
can independently schedule `python -m silentsec.platform maintain` every minute so
grant/retention scheduling is not delayed by a busy worker. Expired results cannot
be read even before deletion runs.

## Plans and fair use

Initial limits are in `platform/billing.py`; they are policy defaults, not benchmark
claims. Every job stores an immutable entitlement snapshot. Current plan downgrades
can tighten organization concurrency. Old snapshots never authorize cross-tenant
access or bypass current graph entitlements.

| Plan | Standard credits | Concurrent / queued | Rate / min | Scan timeout | Maximum result retention |
|---|---|---|---|---|---|
| Free | 30 / month | 1 / 10 | 3 | 180s | 7 days |
| Pro | Metered fair use | 2 / 20 | 10 | 300s | 30 days |
| Enterprise | Optional contract pool | 4 / 40 default | 20 | 600s | 90 days default |

Existing hard ingestion limits still apply: 20 MB uploads, 100 MB expanded ZIPs,
5,000 archive entries, and public GitHub repositories up to 200 MB/20,000 files.

## Authentication and organization access

Production uses a configurable OIDC confidential client (Authlib code flow with
PKCE/state/nonce) and strict JWT verification (allowlisted asymmetric algorithms,
configured issuer/audience/JWKS, required subject/expiry/issued-at). JWT roles never
grant platform administration. Existing users are matched by issuer and subject;
matching email alone never automatically links an identity.

Browser sessions use opaque random cookies, hashed session identifiers in the DB,
HttpOnly, SameSite, CSRF tokens, rotation on login and explicit logout/revocation.
Production cookies use Secure and `__Host-`. Admin sessions additionally require a
database platform-admin role, verified MFA claims and recent authentication for
mutations; lifetime is 15 minutes with a 5-minute reauthentication window by default.
The identity provider must enforce its own MFA/login policy and be configured with
the appropriate `amr` or approved `acr` claims. No live identity provider is connected
or verified by the local test setup.

Org roles are owner/admin/member/viewer. Viewing another organization's object ID
returns 404. Platform admins get explicit safe metadata routes, not implicit access
to tenant reports/findings/source. Support access is default-deny; the schema is
reserved for future explicit, temporary tenant-approved support workflows.

API keys are generated on the caller's device; only a salted scrypt hash, prefix,
scopes and expiry are saved. The API never returns the full key. Keys cannot access
admin routes. Keep them in a credential manager and transmit them only over TLS.

## Jobs and private results

PostgreSQL is the durable queue and state authority. Redis is a bounded wake-up
adapter: losing a notification cannot lose the DB job. Workers poll for queued work,
claim it under organization row locks, enforce concurrency, and use fencing tokens
and expiring leases. A late worker cannot overwrite a recovered job. Interrupted
jobs are not automatically rerun and charged again; retries require an explicit
admin action/new submission. Upload retries require reattaching the source.

Scanning runs in bounded subprocess trees in short OS temporary directories.
Worker environments remove control-plane configuration and AI credentials.
Prepared source and scratch data are cleaned after normal completion/failure;
expired leases are recovered. Raw upload inbox files are private and ignored.
Reports and versioned JSON results are stored in PostgreSQL and authorized per org.
SaaS reports deliberately withhold source snippets and all secret values. Findings
retain safe titles, file/line references, scores, scanner states and static paths.

Local subprocess isolation is **not** a production security sandbox. A production
operator must deploy separately isolated, non-root, least-privilege workers with
CPU/memory/PID/disk limits, restricted network egress and private shared inbox storage.
The production configuration refuses SQLite, development auth, in-process workers,
wildcard origins and missing Redis/OIDC/isolation settings. These guards do not
replace infrastructure review or verify that an operator's isolation flag is true.

## Graphs and code patterns

Versioned graph output reuses existing Python import and route-reachability analysis,
adds bounded static call links, cycle highlights and fan-in/out/isolated metrics.
Free gets module summaries; Pro gets detail and an authorized comparison endpoint.
The canvas supports pan/zoom/search/type filters and an accessible node table.
This first graph schema groups files under module nodes; complete package/class and
external-dependency expansion, portfolio views and a comparison picker are future UI
extensions. Static paths over-approximate and never prove exploitability.

The advisory token analyzer normalizes identifiers/literals/comments, keeps selected
security API names and compares hashed five-token shingles at Jaccard >=0.8. It has
file/block/pair/time/output caps, excludes `.env` and hidden/excluded paths, stores no
raw shingles, and never changes core security scores. Five explainable pattern
classes are supported. Enterprise packs select only bounded built-in rule IDs;
arbitrary regex and executable rule packs are rejected. Packs are versioned, approved
and audited. These heuristics need false-positive calibration before scoring use.

## Payments and unavailable integrations

No checkout, charge, paid subscription purchase or external provider account is
created. Admin plan changes are local operational actions with reasons/idempotency.
The signed billing-event adapter is disabled without its secret. Its versioned
contract verifies timestamp/HMAC, rejects replay/input mismatches and applies only
increasing subscription sequences transactionally. A real payment adapter must first
verify its provider's own signatures and translate authoritative state. This endpoint
is **not a Stripe webhook endpoint**. No Stripe integration is claimed.

Private GitHub/GitLab credentials, production cloud-AI orchestration,
contract editing UI, custom SSO-provider setup, support access, portfolio reporting,
and SLA workflows remain separate follow-on work. Capability responses explicitly
mark unavailable integrations false even on paid plans. Do not sell them as enabled.

## Checks

```powershell
.\frontend\.venv\Scripts\python.exe -m pytest -q
.\frontend\.venv\Scripts\python.exe -m ruff check .
.\frontend\.venv\Scripts\python.exe -m ruff format --check src/silentsec/platform tests/platform
# Same platform tests against an isolated PostgreSQL test schema per test:
$env:SILENTSEC_TEST_POSTGRES_URL = 'postgresql+psycopg://USER:PASSWORD@127.0.0.1:55432/silentsec'
.\frontend\.venv\Scripts\python.exe -m pytest tests/platform -q
```

The test account needs permission to create/drop its own `ssec_test_<random>` schemas;
never point this test setting at a production database. CI uses disposable services.
Pinned, hash-verified platform dependency input is `requirements/platform.lock`.
Existing scanner installation/tests remain separate and unchanged.

Before real deployment, verify OIDC/MFA and callback behavior with the chosen provider,
use separate restricted database roles (including a migration role), deploy proper
worker isolation/egress, configure backups and retention, and validate rate limits
behind the trusted reverse proxy. No internet-facing deployment has been performed.

## Original frontend integration

`/app` and `/workspace` now serve the original frontend with the same authenticated
organization/session and server-enforced billing. `/` preserves the original particle
landing page. `/account` adds graph/pattern exploration and saved scan details;
its navigation returns to the full workspace. `/admin` remains separately protected.
See [frontend-integration.md](frontend-integration.md) for workflow coverage and setup.

Development workstation mode preserves local scans, history, PR gates, patches, AI
fixes and combined reports using the existing `frontend/local_api/adapter.py`. It is
explicitly forbidden in production. Only operator-registered exact repository roots
are accepted for that organization; no HTTP endpoint registers local paths. GitHub
and upload jobs reuse the existing safe native API and do not require local roots.
All workflows use durable database jobs, organization concurrency, leases, retention
and immutable audit/usage events. Raw uploads and patches stay in the private inbox
until execution/cancellation cleanup, never inside the job database.

A scan or fresh report reserves one standard scan unit. Verification, PR checks,
history commits and AI findings use distinct reservations and never silently debit
Free scan credits. Initial monthly verification/PR limits are Free 20/30 and paid
200/300; plan entitlement JSON can override `monthly_verifications`,
`monthly_pr_checks`, `monthly_history_commits`. Pro/Enterprise history defaults to
20 commits per operation and 400 commits per month; AI budgets reuse plan limits.
Named reservations release before execution failure/cancellation and expire before
execution at the month boundary or after 24 hours. AI operations require explicit
opt-in and operator-configured providers; no live AI provider was tested. AI quota
is a conservative finding budget reserved at submission, not a token-cost estimate.

Account results withhold source excerpts and secret values. The original offline
report template, score components, JSON/SARIF exports and remediation review remain.
Repository test execution is rejected by the web interface; the original trusted
CLI retains its existing test-verification behavior.
