# SilentSec

Explainable security and architectural debt intelligence for AI-assisted code.
**Python-first:** the full pipeline is built and tested on Python repositories.

## Vision

SilentSec detects security weaknesses and architectural patterns
that accumulate hidden debt in AI-assisted codebases.

## Current Capabilities

- Security scanning with Semgrep, Bandit, and Gitleaks, normalized into one finding format.
- Security finding correlation and deterministic security-debt scoring.
- Safe source-context extraction.
- AI-assisted triage and finding verification.
- Architectural debt analysis using Python AST parsing.
- Fix + Verify: check a proposed patch in an isolated copy and report what it fixed and broke.
- AI fix proposals: an AI provider suggests a fix, which is then verified the same way.
- Time Machine: how security debt changed across recent commits, and which commit introduced or fixed each finding.
- HTML report: one offline page with the score, issues and their evidence, history, and checked fixes.

## Installation

Requires Python 3.11+.

```powershell
git clone https://github.com/Riyansh2409/SilentSec.git
cd SilentSec
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev,scanners]"
```

`[scanners]` installs Semgrep and Bandit. Gitleaks is a separate binary: install
it from the [Gitleaks releases](https://github.com/gitleaks/gitleaks/releases)
(tested with 8.21.2) and make sure `gitleaks version` works in your terminal.

AI triage is optional. To enable it, copy `.env.example` to `.env` (or set the
variables in your shell) and fill in your own keys. Never commit real keys.

How AI triage spends API quota:

- Each finding goes to one provider at a time (Gemini primary, Gemini
  fallback, then Groq). A timeout, connection error, or HTTP 408/429/5xx is
  retried once on the same provider with backoff; authentication and request
  errors move straight to the next provider.
- A scan makes at most `3 × --max-ai-findings` provider calls in total.
- Results are cached in `~/.cache/silentsec/triage` (override with
  `SILENTSEC_TRIAGE_CACHE_DIR`, disable with `SILENTSEC_TRIAGE_CACHE=off` or
  `--no-triage-cache`). The cache key is the finding fingerprint, a hash of the
  redacted message and source context, the prompt version, and the provider
  models, so changed code or a different model is triaged again. The cache
  holds triage text derived from your code; delete the folder to clear it.
- If triage fails, findings and the score are unaffected; the report marks
  triage incomplete.

## Usage

```powershell
silentsec scan path\to\repository
silentsec scan path\to\repository --json report.json
silentsec scan path\to\repository --ai-triage --max-ai-findings 10
```

The command prints scanner statuses, the score with both risk levels, top
findings, and recurring patterns. `--json` writes the full report.

The score is capped at 100. When the uncapped total is higher, the output also
shows it (for example `Score: 100.0 / 100  (uncapped 111.3 ...)`), and
`silentsec verify` and `silentsec fix` show the uncapped before/after change,
so an improvement is not hidden by the cap. The scoring formula is unchanged.

Exit codes: `0` when every scanner succeeded, `2` when the scan is incomplete
(for example, a scanner is not installed), `64` for usage errors. An incomplete
scan still returns findings and a score, but verification will not confirm any
finding as resolved.

## Scanners

| Scanner | Finds | Notes |
|---|---|---|
| Semgrep | Code-level vulnerabilities | Uses SilentSec's bundled offline rules in `src/silentsec/rules/semgrep/`; no internet needed. Set `SILENTSEC_SEMGREP_CONFIG` to use another ruleset (registry rulesets such as `p/security-audit` need network access). |
| Bandit | Python security issues | Runs only when the repository has Python files. |
| Gitleaks | Hard-coded secrets | Secret values are redacted and never sent to AI providers. |
| Architecture analyzer | Structural debt | See below. |

Scanners never execute repository code and never write into the scanned
repository. The bundled Semgrep rules are a focused starter set of 13 Python
rules, not a replacement for the full Semgrep registry. They include command
execution hidden behind `__import__`, `importlib.import_module` or `getattr`
(for example `__import__("os").system(cmd)`), which Bandit does not flag; this
matters when verifying AI-proposed fixes.

A folder without its own `.git` (history snapshots, verify/fix copies, or a
subfolder such as `silentsec scan src`) is scanned by Semgrep as a standalone
project: a parent repository's `.gitignore` is not applied, while the built-in
excludes (`.venv`, `node_modules`, ...) and `.semgrepignore` still are.

When different tools report the same issue, SilentSec merges them:

- matching CWE on overlapping lines across tools
- equivalent exception-handler rules (Bandit B110/B112, SSEC-ARCH-001/002) on
  the same handler
- rule pairs that describe the same issue under different CWEs, on the same
  line: eval (B307), exec (B102), `subprocess.getoutput` (B605), `os.exec*`/
  `os.spawn*` (B606), unsafe YAML (B506), `mktemp` (B306) and Flask debug
  (B201), each with its Semgrep counterpart
- one secret matched by several rules on the same line (for example Gitleaks
  `generic-api-key` and `github-pat`, or Bandit B105)

The gate counts issues the same way, so "1 issue (2 scanner findings)" means
two tools reported one problem.

## Architectural Debt Analyzer

Architecture debt is capped at 25 points and reported as a separate risk level; it never raises the security risk level.

The architecture analyzer detects the following patterns in Python code:

- **SSEC-ARCH-001:** Broad exception handlers, such as bare `except` and handlers catching `Exception` or `BaseException`.
- **SSEC-ARCH-002:** Potentially swallowed exceptions. This is a heuristic, not proof that an exception is unintentionally ignored.
- **SSEC-ARCH-003:** High cyclomatic complexity in functions and methods. Low severity is reported above 10; medium severity above 20.
- **SSEC-ARCH-004:** Circular imports, including supported relative imports.
- **SSEC-ARCH-005:** Duplicated functions. Two functions match when their syntax trees are identical after ignoring local names, argument names, literal values, docstrings, type hints and decorators; attribute and keyword names still count. Functions under 5 statements or 6 lines are ignored. This finds copy-paste-and-rename clones, not near-duplicates whose structure differs.

Analysis uses Python AST parsing and does not execute repository code. Oversized files and excluded directories are skipped. Syntax errors in individual files are reported without preventing analysis of other files.

Coupling-hotspot analysis and near-duplicate (similar but not identical) detection are planned capabilities, not implemented features.

## Explainable Score

SilentSec reports a deterministic security-debt score alongside a breakdown of its contributing components. Existing score, raw score, per-finding scores, and security risk calculations remain unchanged.

### Score Components

- **`security_severity`**: Points from security and secret findings using the existing severity and confidence formula.
- **`architectural_fragility`**: Architecture and maintainability debt points, capped at 25. Architecture risk is reported separately and does not raise the security risk level.
- **`other_findings`**: Points from findings outside the security, secret, architecture, and maintainability categories.
- **`score_cap_adjustment`**: An adjustment, when needed, that reconciles the component total with the existing repository score cap.
- **`recurrence`**: Informational points based on recurring patterns spanning multiple files. Each additional file contributes 2 points, capped at 15. This component is informational and is not added to the repository score.

The sum of non-informational score components equals the reported repository score. Informational recurrence points do not change the score or risk level.

### Repository Size Awareness

When a repository root is provided, the report includes:

- **`analyzed_lines`**: Number of nonblank lines in eligible source files, using the analyzer's directory exclusions and file-size limit. Files are inspected as text and repository code is never executed for line counting.
- **`debt_density_per_kloc`**: Number of unique open correlation groups per 1,000 analyzed nonblank source lines, rounded to two decimal places. Density is `None` for repositories with fewer than 500 analyzed lines, where a handful of findings would look like an alarming rate. If no repository root is provided, both fields are `None`.

### Remediation Effort

Each scored finding has a separate remediation-effort estimate: **`low`**, **`medium`**, or **`high`**. Estimates use a documented static rule table for secrets, selected architecture rules, and selected injection CWEs; other findings default to `low`.

Remediation effort is informational. It does not affect per-finding scores, the repository score, or either risk level. The report also includes counts grouped by remediation effort.

## Fix + Verify

`silentsec verify` checks whether a proposed patch actually fixes findings,
without changing your repository:

```powershell
# Make the fix in a working tree, then export it as a patch.
git diff --output=fix.diff

# Verify it against the repository.
silentsec verify path\to\repository --patch fix.diff
silentsec verify path\to\repository --patch fix.diff --run-tests --json verify.json
```

Use `git diff --output=fix.diff` rather than `git diff > fix.diff`: in Windows
PowerShell the redirect re-encodes the file. SilentSec accepts UTF-16 and CRLF
patches anyway and says so in the report.

What happens:

1. The patch is validated. Absolute paths, `..`, `.git/`, binary patches, file
   mode changes, symlinks, renames, and patches over 20 files or 200 KB are
   rejected.
2. The repository is copied to a temporary folder, without `.git`, virtual
   environments, build and cache folders, local `.env` files, or symlinks.
3. The copy is scanned (baseline), the patch is applied to the copy with
   `git apply`, and the copy is scanned again. Both scans see the same files.
4. With `--run-tests` (or `--test-command "..."`), the repository's tests run in
   the copy, with a timeout and with credential-like environment variables
   removed. **This executes repository code**, so it is off by default.
5. The temporary copy is deleted.

**Targets** are the findings the patch is meant to fix: by default, findings on
the lines the patch changes. Pass `--target FINGERPRINT` (from a
`silentsec scan --json` report) to choose them explicitly.

| Verdict | Meaning | Exit code |
|---|---|---|
| `VERIFIED_FIX` | Every target resolved; no new finding at medium severity or above; tests passed or were not run | 0 |
| `PARTIAL` | Some targets resolved, some remain | 1 |
| `UNRESOLVED` | No target resolved | 1 |
| `REGRESSION` | A new finding at medium severity or above appeared, or the tests failed | 1 |
| `NOT_VERIFIED` | The result could not be established: invalid patch, patch did not apply, a scanner did not complete, tests timed out, or no targets | 2 |

New findings below medium severity are still listed under "New" and in the
reasons; `--strict` makes any new finding a regression.

Limitations, also printed with every report:

- Passing scans and tests do not prove the absence of vulnerabilities.
- Isolation is file-level, not a security sandbox: commands in the copy run as
  the current user with network access (credential-like variables removed).
- Files that are not copied (local `.env` files, virtual environments, build
  and cache folders) are not verified.
- Git must be installed and on `PATH`.

## AI Fix Proposals

`silentsec fix` asks the configured AI provider for a fix to one finding and
verifies it before showing it to you:

```powershell
silentsec fix path\to\repository                         # top security finding
silentsec fix path\to\repository --finding FINGERPRINT --out fix.diff
```

- The model sees only the finding and a numbered, redacted window of the code
  (the enclosing Python function, or about 25 lines around the finding). It
  never sees secret values, and secret findings are refused: they need the
  credential rotated, not a code edit.
- The model returns line edits, not a diff. SilentSec rejects edits outside
  the shown lines, overlapping edits, edits to redacted lines, and edits that
  change nothing, then builds the patch itself.
- The patch then goes through `silentsec verify` in an isolated copy, using the
  finding and any findings merged with it (for example the same SQL injection
  from Semgrep and Bandit) as targets.
- Nothing is applied to your repository. `--out` saves the patch so you can
  review it and apply it yourself with `git apply`.
- Providers are tried in order (Gemini primary, Gemini fallback, Groq); an
  invalid answer moves to the next provider.

A verified AI fix is evidence, not proof, and always needs human review.

## Time Machine

`silentsec history` scans the last commits on the current branch and shows how
debt changed, commit by commit:

```powershell
silentsec history path\to\repository                  # last 10 commits
silentsec history path\to\repository --commits 25 --json timeline.json
```

```text
Commit    Date         Score  Change Issues   New Fixed  Subject
d7dbd03e  2026-10-30     0.0              0     -     -  Add user lookup
13713b02  2026-10-30    14.2   +14.2      1     2     0  AI refactor: simplify query
d17bcc4e  2026-10-30    20.6    +6.4      2     3     0  Add config loader
5e6e502b  2026-10-30     6.4   -14.2      1     0     2  Fix SQL injection
df4edacf  2026-10-30    21.9   +15.5      3     2     0  Add settings

Biggest increase: df4edacf "Add settings" (+15.5)
  + [HIGH    ] settings.py:1  gitleaks github-pat
```

- Each commit's files are exported with `git archive` into a temporary folder
  and scanned. Your working tree and `.git` folder are never modified, and
  uncommitted changes are not part of the history.
- Consecutive scans are compared, so "New" and "Fixed" are attributed to the
  commit that changed them. The oldest commit in the window is the baseline.
  When a scan is incomplete (a scanner failed), changes next to it show `?`.
- Scores here are uncapped, so changes stay visible above 100.
- An issue that was fixed by one commit and brought back by a later one is
  listed under "Came back after a fix", with both commits. The HTML report
  rings that commit in the chart, and the API marks it with
  `"reintroduced": true` and `"previously_fixed_in"`. Only fixes inside the
  scanned window are known, so `--commits` decides how far back this looks.
- Results are stored in SQLite under `~/.cache/silentsec/history/` (or
  `--db`), keyed by commit and by the SilentSec version and rules used, so a
  second run only scans new commits. `--no-cache` rescans everything.
  Incomplete scans are not stored.
- Commits are followed along the first parent, so a merged branch counts as
  one step. In a shallow clone, older commits are missing; the output says so.

## HTML Report

`silentsec report` writes one self-contained HTML file you can open in any
browser, share, or present:

```powershell
silentsec report path\to\repository --out report.html
silentsec verify path\to\repository --patch fix.diff --json verify.json
silentsec fix path\to\repository --json ai-fix.json
silentsec report path\to\repository --out report.html --fix-report verify.json --fix-report ai-fix.json
```

The report shows:

- a plain-language verdict and how the score is made up (security,
  architecture, and the 100-point cap);
- every issue, most serious first, with merged scanner reports, the redacted
  code around it, how many points it adds, and AI triage when `--ai-triage`
  is used;
- recurring patterns;
- the Time Machine chart and table for the last `--commits` commits (skip
  with `--no-history`);
- the result of each patch or AI fix passed with `--fix-report`.

The file works offline and loads nothing from the internet. Everything taken
from the repository (paths, messages, code, commit subjects) is HTML-escaped,
and a Content-Security-Policy allows only the report's own small script, so a
malicious repository cannot run code in the viewer's browser. Secret values and
the code around secret findings are never included. It follows the system
light or dark theme and prints cleanly.

## Pull-Request Security Gate

`silentsec gate` decides whether a change adds security debt. It scans the
base and the head version, then sorts every finding:

- **NEW**: in head but not in base, so the change introduced it
- **EXISTING**: already in base; old debt never blocks the change
- **RESOLVED**: in base but gone in head

```bash
silentsec gate . --base main --head HEAD
silentsec gate . --base main --head feature/login --fail-on medium --json gate.json
```

| Result | Exit code | When |
|---|---|---|
| PASS | 0 | no new security or secret finding at or above `--fail-on` (default `high`) |
| FAIL | 1 | at least one such new finding |
| INCOMPLETE | 2 | a scanner failed on either version, so "nothing new" cannot be confirmed |

New architecture/maintainability findings are warnings; add
`--fail-on-architecture` to make them fail the gate. Base is compared at the
merge base of `--base` and `--head`, so commits that landed on the base
branch after the head branch was created are not blamed on it. Both versions
are exported with `git archive` into temporary folders; the repository and
its working tree are not modified, and uncommitted changes are ignored. The
exit codes make it usable as a CI step.

## HTTP API (for a web frontend)

`silentsec serve` starts an HTTP API so a web page can scan a public GitHub
repository or an uploaded file. Install the extra packages first:

```bash
pip install -e ".[api]"
silentsec serve                      # http://127.0.0.1:8000, docs at /docs
silentsec serve --cors-origin http://localhost:5173
```

| Method | Path | Input | Returns |
|---|---|---|---|
| GET | `/api/health` | - | version, and which of git/semgrep/bandit/gitleaks are installed |
| POST | `/api/scan/github` | JSON `{"url": "https://github.com/owner/repo", "history_commits": 10}` | scan result |
| POST | `/api/scan/upload` | multipart form, field `file` (a `.zip` or one source file, max 20 MB) | scan result |
| POST | `/api/verify/github` | JSON `{"url": "...", "patch": "<unified diff>", "targets": null}` | Fix + Verify result |
| POST | `/api/verify/upload` | multipart form, fields `file` (.zip or source file) and `patch` (diff file) | Fix + Verify result |
| GET | `/api/scans` | - | recent scans, newest first |
| GET | `/api/scans/{id}` | - | the full scan result again |
| GET | `/api/scans/{id}/report` | - | the self-contained HTML report (can be shown in an iframe) |

A scan result has `summary` (score, risk levels, issue counts), `scanners`,
`issues` (severity, title, file and line, merged sources, points, fix effort
and the surrounding code; code is withheld for possible secrets), `timeline`
(Time Machine points for GitHub scans) and `report_url`. Errors return
`{"detail": "..."}` with status 400 (bad input), 404, 413 (too large), 422
(invalid request) or 429 (two scans already running). Full schemas are at
`/docs`.

A Fix + Verify result has `verdict` (`verified_fix`, `partial`, `unresolved`,
`regression` or `not_verified`), `reasons`, the `targets`, `resolved`,
`remaining` and `new` findings, and the score before and after. The patch is
applied to a temporary copy only, and repository tests are never run through
the API, because that would execute uploaded code.

```js
const response = await fetch("http://127.0.0.1:8000/api/scan/github", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ url: "https://github.com/owner/repo", history_commits: 10 }),
});
const scan = await response.json(); // scan.summary.score, scan.issues, scan.report_url

const form = new FormData();
form.append("file", fileInput.files[0]);
const uploaded = await (await fetch("http://127.0.0.1:8000/api/scan/upload", {
  method: "POST",
  body: form,
})).json();
```

Safety:

- Only public `https://github.com/owner/repo` links are accepted. Clones use no
  stored credentials, prompts, submodules or LFS downloads, and symlinks are
  checked out as plain files.
- Zip uploads refuse absolute paths, `..` and symlinks, stop at 100 MB
  extracted, and drop any `.git` folder.
- Uploaded or cloned code is only read by the scanners, never run. AI triage
  is off for API scans.
- Temporary copies are deleted after each scan. Results are kept in memory for
  the last 20 scans only.
- The server listens on this computer only by default. `--host 0.0.0.0` lets
  other devices on the network start scans; use it only on a network you trust.

## Planned Capabilities

- Broader multi-language architectural analysis.
- MCP tools for controlled analysis operations.
- LangSmith tracing and evaluation.
- Docker packaging.

## Continuous Integration

GitHub Actions runs Ruff and the test suite on every push and pull request,
plus a smoke job that installs the real scanners (Gitleaks pinned and
checksum-verified), runs the real-scanner tests, and checks that a full scan
completes without modifying the repository, including on a non-git copy nested
inside the checkout (the layout history snapshots and verify copies use).

## Status

Development in progress.
