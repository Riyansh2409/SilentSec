# Local verification — 1 November 2026

Base: GitHub main `7bcff94`, still current when checked. Branch: `codex/saas-platform`.
No scanner-core source or existing local frontend source was changed.

## Automated evidence
- Full repository regression run: **638 passed, 18 skipped**.
- Real PostgreSQL platform run: **51 passed** (each test used its own temporary schema).
- After the last repository-name redaction, local worker-health-path and production-cookie fixes: **30 focused auth/admin/analysis/worker checks passed**. These include the new checks added after the full run; the final snapshot has not had another complete suite run.
- Existing local frontend/adapter suite: **30 passed**.
- Ruff checks, platform Python formatting checks, browser JavaScript syntax checks and Git whitespace checks passed.
- Two upstream deprecation warnings remain (Authlib/Starlette HTTPX compatibility); no test failures remained.

## Live local evidence
- PostgreSQL and Redis run in the dedicated loopback-only Compose project.
- Customer sign-in and explicit internal administrator sign-in verified with the development provider. Real MFA is not claimed for this simulator.
- Real demonstration ZIP completed: 6 grouped findings, 66.287 backend debt score; required scanners completed, optional OSV skipped.
- The scan reserved and committed exactly one credit: 30 -> 29. A real UTC calendar-month rollover later renewed the account to 30 while preserving previous scan history.
- Administrator grant and revocation were applied with reasons and appeared in audit records.
- Server restart preserved scan results, credit records and sessions subject to expiry.
- Report download, customer denial from admin endpoints, local worker readiness, Redis ping and worker-PATH scanner discovery verified against the running HTTP service.
- Static graph and advisory patterns are returned for the saved scan. Graph search and zoom/reset controls were exercised in the browser. No source snippets or secret values are included in SaaS evidence/report output.
- Desktop and actual 390-CSS-pixel Chrome mobile layouts reviewed; sign-out remained available and no page-wide horizontal overflow was observed on the mobile dashboard.
- A real worker integration test proved uploaded repository code did not execute and its raw inbox file was removed. Queued cancellation, orphan-cleanup races and pre-scan missing-tool behavior have regression checks.

## Limits of this review
- No remote push, PR, production deployment or payment transaction was performed.
- Real OIDC identity-provider/MFA login and public GitHub scanning in this new platform were not exercised end to end; public URL validation and the existing ingestion adapter are reused.
- Private repository providers, actual payment checkout/provider webhooks, live AI provider inference, portfolio reporting, contract UI, complete package/class graph expansion and custom SSO/support workflows are not enabled. See platform.md for the current boundary.
- Linux CI has been configured but has not run on this local branch. Production isolation, egress, backups and restricted database roles require deployment work.

## Connected original frontend verification

- Original frontend is now at `/app` and `/workspace`, with original landing page at `/`.
- A real browser local-folder scan completed with the original 66.29 score and six grouped findings. The same account changed from 30 to 29 credits; the billing ledger links back to the saved original result without another scan.
- Full suite at the integration checkpoint: **647 passed, 18 skipped**. Original frontend: **30 unittest cases passed**, plus the existing Node view-data checks.
- Expanded real-workflow checks: **7 passed**, including real local scans, two-commit history, PR gate, local verification, report with history, native source upload and uploaded verification; original files stayed unchanged and private inbox files were removed. This checkpoint preceded three added focused tests.
- Latest focused SQLite integration checks: **8 passed**, excluding two expensive real-worker tests already exercised. Named-unit expiry/concurrency and API-key scope checks passed.
- Latest PostgreSQL integration/migration checks: **11 passed**, excluding those two real-worker tests, using isolated disposable test schemas.
- Ruff and formatting checks pass. JS module syntax checks pass. Scanner-core, native ingestion, remediation engine and CLI files have no integration diff.
- Original fix-review, PR-check, Time Machine and report screens were opened in Chrome; billing and account screens render in the original navigation. Account layout was checked at an actual 390 CSS pixels with no page-wide horizontal overflow.
- Chrome reported no page errors. Automated browser ZIP selection was blocked by the extension's file-URL permission; no extension permission was changed. API-level native upload/verification tests passed; a successful browser ZIP submission is not claimed.
- AI provider inference and live GitHub download/verification remain untested end to end. Source excerpts and secret values are withheld from account persistence, and web requests cannot execute repository tests; trusted CLI behavior remains available.
