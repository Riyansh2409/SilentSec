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

## Usage

```powershell
silentsec scan path\to\repository
silentsec scan path\to\repository --json report.json
silentsec scan path\to\repository --ai-triage --max-ai-findings 10
```

The command prints scanner statuses, the score with both risk levels, top
findings, and recurring patterns. `--json` writes the full report.

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
repository. The bundled Semgrep rules are a focused starter set for Python, not
a replacement for the full Semgrep registry.

When different tools report the same issue, SilentSec merges them: matching CWE
on overlapping lines across tools, and equivalent exception-handler rules
(Bandit B110/B112, SSEC-ARCH-001/002) on the same handler.

## Architectural Debt Analyzer

Architecture debt is capped at 25 points and reported as a separate risk level; it never raises the security risk level.

The architecture analyzer detects the following patterns in Python code:

- **SSEC-ARCH-001:** Broad exception handlers, such as bare `except` and handlers catching `Exception` or `BaseException`.
- **SSEC-ARCH-002:** Potentially swallowed exceptions. This is a heuristic, not proof that an exception is unintentionally ignored.
- **SSEC-ARCH-003:** High cyclomatic complexity in functions and methods. Low severity is reported above 10; medium severity above 20.
- **SSEC-ARCH-004:** Circular imports, including supported relative imports.

Analysis uses Python AST parsing and does not execute repository code. Oversized files and excluded directories are skipped. Syntax errors in individual files are reported without preventing analysis of other files.

Duplicate-logic detection and coupling-hotspot analysis are planned capabilities, not implemented features.

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

## Planned Capabilities

- Broader multi-language architectural analysis.
- MCP tools for controlled analysis operations.
- LangSmith tracing and evaluation.
- Security-debt history across Git commits.
- Docker packaging.

## Continuous Integration

GitHub Actions runs Ruff and the test suite on every push and pull request,
plus a smoke job that installs the real scanners (Gitleaks pinned and
checksum-verified), runs the real-scanner tests, and checks that a full scan
completes without modifying the repository.

## Status

Development in progress.
