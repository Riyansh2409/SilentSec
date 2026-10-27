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

The architecture analyzer detects the following patterns in Python code:

- **SSEC-ARCH-001:** Broad exception handlers, such as bare `except` and handlers catching `Exception` or `BaseException`.
- **SSEC-ARCH-002:** Potentially swallowed exceptions. This is a heuristic, not proof that an exception is unintentionally ignored.
- **SSEC-ARCH-003:** High cyclomatic complexity in functions and methods. Low severity is reported above 10; medium severity above 20.
- **SSEC-ARCH-004:** Circular imports, including supported relative imports.

Analysis uses Python AST parsing and does not execute repository code. Oversized files and excluded directories are skipped. Syntax errors in individual files are reported without preventing analysis of other files.

Duplicate-logic detection and coupling-hotspot analysis are planned capabilities, not implemented features.

## Planned Capabilities

- Broader multi-language architectural analysis.
- MCP tools for controlled analysis operations.
- LangSmith tracing and evaluation.
- Security-debt history across Git commits.
- AI-assisted fix proposals.
- Docker and GitHub Actions CI/CD.

## Status

Development in progress.
