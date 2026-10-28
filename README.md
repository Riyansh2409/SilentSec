# SilentSec

AI-powered Multi-language Security Debt Intelligence Platform.

## Vision

SilentSec detects security weaknesses and architectural patterns
that accumulate hidden debt in AI-assisted codebases.

## Current Capabilities

- Multi-language security scanning using Semgrep, Bandit, and Gitleaks.
- Security finding correlation and deterministic security-debt scoring.
- Safe source-context extraction.
- AI-assisted triage and finding verification.
- Architectural debt analysis using Python AST parsing.

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
- **`debt_density_per_kloc`**: Number of unique open correlation groups per 1,000 analyzed nonblank source lines, rounded to two decimal places. A repository with zero analyzed lines reports `0.0`. If no repository root is provided, both fields are `None`.

### Remediation Effort

Each scored finding has a separate remediation-effort estimate: **`low`**, **`medium`**, or **`high`**. Estimates use a documented static rule table for secrets, selected architecture rules, and selected injection CWEs; other findings default to `low`.

Remediation effort is informational. It does not affect per-finding scores, the repository score, or either risk level. The report also includes counts grouped by remediation effort.

## Planned Capabilities

- Broader multi-language architectural analysis.
- MCP tools for controlled analysis operations.
- LangSmith tracing and evaluation.
- Security-debt history across Git commits.
- AI-assisted fix proposals.
- Docker and GitHub Actions CI/CD.

## Status

Development in progress.
