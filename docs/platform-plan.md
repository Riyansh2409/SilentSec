# SaaS implementation plan

The scanner and existing local API remain separate. New entry point: `python -m silentsec.platform` (loopback by default). Existing `silentsec serve` and CLI behavior are unchanged.

## Files and boundaries
- `platform/config.py`: validated settings; production requires PostgreSQL, Redis, OIDC, explicit origins, secure cookies and isolated workers.
- `platform/models.py`, `db.py`, `migrations/`: users, orgs/RBAC, accounts, sessions, repositories, hashed keys, usage ledger/reservations, snapshots, jobs/results, audit and webhook records.
- `platform/auth/`: configurable OIDC code+PKCE and JWT verification. Browser sessions are opaque, server-side, revocable and CSRF-protected. Dev authentication only on loopback development instances with a configured access code and provisioned identities. No passwords stored or separate admin password.
- `platform/access.py`: organization ownership and platform role checks; no claims-based self-promotion.
- `platform/billing.py`: month/timezone grants, append-only usage and atomic reservations. Standard scans are a separate unit from AI/history/verification. Org-row transaction locks serialize spending and worker claims. SQLite is local-test only.
- `platform/jobs.py`, `worker.py`: DB queue is durable source of truth. Redis is a wake-up adapter (loss of a hint cannot lose a job); polling recovers. DB concurrency and leases survive restarts. Isolated subprocess execution; no repository tests or code execution; sanitized environments; bounded uploads/results and source lifetime.
- `platform/analysis.py`: bounded versioned graph using existing imports/reachability, advisory hashed Python token shingles, no raw source n-grams persisted.
- `platform/app.py`, `routes.py`: customer/admin endpoints with scopes, rate limits, idempotency and audit.
- `frontend/platform/`: buildless HTML/CSS/JS extending established brand, distinct login/admin screens and accessible graph fallback. No new frontend framework.
- `tests/platform/`, CI: auth/tenant attacks, credit concurrency/rollover, jobs, redaction, graph/pattern and migration checks; PostgreSQL integration checks when configured.

## Dependencies and minimum configuration
Optional `[platform]` extras keep CLI installs unchanged. SQLAlchemy 2.0 + Alembic + Psycopg behind a persistence service. PostgreSQL URL required in production; SQLite allowed for dev/tests. Authlib handles code+PKCE; PyJWT verifies allowlisted algorithms/issuer/audience/expiry and keys from configured trusted issuer. Production OIDC requires issuer, client ID/secret, callback URL, API audience and configured MFA claims. No identity provider account is created.
Redis is transport only, configured by server URL; users never supply queue names or worker paths. Payment boundary accepts verified, idempotent provider events. Payments remain disabled without server configuration; plan changes can be exercised with audited local administration. Stripe, private repo providers and external credentials must never be represented as configured or working when absent.

## Initial configurable fair-use defaults
Free: 30 standard scans/month, 1 running/10 queued, 3 submissions/minute, public GitHub/ZIP, 180s scans, no AI/history, module graph, 7-day retention. Pro: no normal credit debit, 2 running/20 queued, 10 submissions/minute, 300s scans, 30-day retention, detailed graph; separate AI/history units. Enterprise: contract-configurable limits, 4 running/40 queued default, 20 submissions/minute, 600s scans, 90-day retention. Never exceed existing ingestion hard limits. Limits are server-enforced snapshots, not promises of unlimited resource use.

Production deployment requires real identity configuration, PostgreSQL/Redis validation, isolated least-privilege worker containers and restrictive network egress. A Windows subprocess is not a production sandbox. Paid integrations remain unavailable until configured. No remote push or deployment is part of this task.

## Original workspace bridge (no new dependencies)
- `platform/workstation.py`: authenticated original API contract, exact per-organization registered local roots, named quotas and private input references.
- `platform/workstation_runner.py`: existing adapter in the bounded worker, original JSON/HTML/SARIF formats, redacted persistence and no repository-code execution.
- Migration `0003`: registered roots, operation requests/results and named quota reservations. Scanner-core models remain untouched.
- `frontend/web/api.js`, `app.js`, `account.js`, `account.css`: original views retained; transport selects standalone or authenticated mode, billing and account views reuse platform components.
- `platform/app.py`: authenticated original workspace and nonce-protected original landing page; distinct admin access retained.
- `frontend/local_api/adapter.py`: optional execution/scan capture hooks; default standalone behavior preserved.
- `Start-Platform.ps1`, setup `-Platform`, `register-local`: explicit development startup/provisioning. `local_api.server --platform-url` is an optional UI redirect gateway.
- `tests/platform/test_workstation.py`: tenant/root protection, usage concurrency/expiry/cancellation, original route parity and real workflow integration.
