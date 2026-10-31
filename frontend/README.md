# SilentSec frontend

This folder contains the local browser interface and its connection layer. The backend is the parent SilentSec checkout (`../src/silentsec`), installed in editable mode. This integration was reviewed against main commit **3bf1a65** on 1 November 2026 and is on the local branch `codex/frontend-integration`.

## Open and run on this computer

Open this repository in VS Code:

```text
C:\Users\harsh\Documents\Codex\2026-10-31\w\outputs\SilentSec-integrated
```

In its PowerShell terminal:

```powershell
cd frontend
.\Start-SilentSec.cmd --port 8769
```

Open **http://127.0.0.1:8769/app** for the workspace, or **http://127.0.0.1:8769/** for the landing page. Keep the terminal open. Port 8769 allows this checkout to run alongside the older app on 8767; do not start two services on the same port. The launcher defaults to 8767 if no port is specified.

Dependencies are already installed in this checkout. On a fresh clone, run setup first:

```powershell
cd frontend
.\setup.ps1
.\Start-SilentSec.cmd
```

Python 3.11+ and Git are required. Setup creates `frontend/.venv`, installs the parent checkout with `[api,scanners]`, and remembers the backend path in the ignored `.data/config.json`. Gitleaks is a separate binary: place it on PATH or in `frontend/.tools`. OSV is optional; missing OSV is displayed as skipped, not complete dependency coverage. Setup needs internet to install packages.

An explicit backend override remains available:

```powershell
.\setup.ps1 -Backend 'C:\path\to\SilentSec'
.\.venv\Scripts\python.exe -m local_api.server --backend 'C:\path\to\SilentSec' --port 8769
```

The older backend at `C:\Projects\SilentSec` and frontend at `outputs\SilentSec-local` were preserved. This new checkout uses its own backend, environment and data folder.

## What the interface connects

- Local folder scans, normalized findings, correlation, backend score components and bounded redacted source context.
- Native public GitHub and ZIP/source upload scans through the backend's ASGI API. GitHub downloads require internet; uploaded source is sent to this local server.
- Patch verification, optional AI fix proposals, PR security checks, commit history, backend HTML reports, JSON and SARIF exports.
- Current exposure fields: reachable, no detected entry-point path, or unknown; detected call paths, returned scoring multiplier, and analysis limitations. A path is not proof of exploitability. An absent path is not proof of safety. The browser never recalculates scores.
- Current AI configuration: ordered providers/models and whether each uses a local or external host. Finding details show provider, model, local/external status and fresh/cached attribution from PR #44. Older cache entries explicitly show unknown provider/model; legacy text attribution remains supported.

The native API does not return an exposure multiplier per issue; the frontend shows the supplied state/path without inventing one. Native scan AI remains off as defined by that API. Local scans can opt into configured AI triage.

## Optional Ollama and cloud AI

AI is off by default. No model is pulled or started by this frontend. To select an already installed local Ollama service/model, set the server environment before starting it:

```powershell
$env:SILENTSEC_AI_PROVIDERS = 'ollama'
$env:SILENTSEC_OLLAMA_MODEL = 'qwen2.5-coder:7b'
.\Start-SilentSec.cmd --port 8769
```

The backend defaults to loopback Ollama. Configured does not mean reachable: service/model availability is checked when used. Mixed chains, such as `ollama,groq`, can send sanitized context to an external fallback, and the interface says so. Explicitly enabled remote Ollama is also labeled external. Credentials stay in the server environment; `.env` is not automatically loaded by this launcher. Restart after changing provider configuration.

## Local runtime

The service binds to `127.0.0.1`. Same-origin Host/Origin checks and a per-process request token protect the local API. One long operation runs at a time in a separate worker process. Results, reports, configuration and caches live in ignored `frontend/.data`; the session list resets on restart. Worker scratch files use a short, operation-scoped OS temporary folder and are cleaned on normal completion, avoiding Semgrep's failure with deeply nested Windows temporary paths.

Ordinary scanning reads files without running the repository. Optional local verification tests execute repository code as your user; they remain off by default. Native verification does not execute repository tests. A scanner-only verified-fix verdict is distinct from tested correctness. No changes are automatically applied to the scanned repository.

## Code to share or review

```text
frontend/web/                 HTML, CSS, JavaScript and result mapping
frontend/local_api/adapter.py Backend imports and native API operations
frontend/local_api/server.py  Local API, jobs and artifacts
frontend/local_api/worker.py  Isolated operation runtime
frontend/local_api/config.py  Backend discovery and saved path
frontend/tests/               API/adapter and view-data checks
frontend/setup.ps1            Editable installation
frontend/Start-SilentSec.cmd  Local launcher
```

Share these source folders, scripts and this README. Exclude `.data`, `.env`, `.venv`, `.tools`, caches and Git metadata.

## Checks

```powershell
# From frontend/:
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
node --check web/app.js
node --check web/api.js
.\.venv\Scripts\python.exe -m ruff check local_api tests
# Optional backend development tools:
.\.venv\Scripts\python.exe -m pip install -e '..[api,scanners,dev]'
.\.venv\Scripts\python.exe -m pytest ..\tests -q
```

Validated in this checkout: 30 frontend/adapter checks and JavaScript syntax checks; backend suite 585 passed, 17 skipped. Provider configuration tests make no inference requests. Real Ollama/cloud generation and live public GitHub verification were not exercised. The backend source was not modified for this integration. Nothing was pushed or merged into remote main.


Live checks against this checkout also passed: complete local demo scan (66.287 debt, six grouped issues), bad/good PR checks (fail/pass), good/bad local patches (verified_fix/regression), four-commit history, ZIP upload scan, uploaded good-patch verification, source context, HTML report download and SARIF 2.1.0 downloads. Semgrep, Bandit, Gitleaks and architecture analysis succeeded; optional OSV was skipped. Desktop and 390px mobile layouts were reviewed; no page overflow or browser warning/error logs were observed. Real AI generation, public GitHub verification and POSIX worker termination remain unverified here.

PR #44 compatibility was rechecked after updating to 3bf1a65: structured provider/model/local/cache attribution and older text/unknown-cache attribution pass the view-data checks. The 30 frontend checks and 585 backend tests pass against that revision.
