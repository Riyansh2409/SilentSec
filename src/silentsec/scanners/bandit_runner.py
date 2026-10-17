
from pathlib import Path
from typing import Any

from silentsec.languages import detect_languages
from silentsec.schemas import Finding, FindingCategory

from .common import (
    create_fingerprint,
    extract_cwe,
    normalize_confidence,
    normalize_file_path,
    normalize_severity,
)
from .results import ScannerRunResult, ScannerStatus
from .runner_utils import run_json_command

EXCLUDED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "tests",
    "test",
    "sample_repositories",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "site-packages",
}


def parse_bandit_payload(
    payload: dict[str, Any],
    root: Path,
) -> tuple[list[Finding], list[str]]:
    """Convert Bandit's JSON output to normalized SilentSec findings."""

    raw_results = payload.get("results")

    if not isinstance(raw_results, list):
        raise TypeError("Bandit JSON must contain a results list.")

    findings: list[Finding] = []
    errors: list[str] = []

    for index, item in enumerate(raw_results):
        if not isinstance(item, dict):
            errors.append(f"Bandit result {index} is not an object.")
            continue

        raw_path = item.get("filename")
        rule_id = item.get("test_id")
        line = item.get("line_number")

        if not isinstance(raw_path, str) or not raw_path:
            errors.append(
                f"Bandit result {index} is missing its file path."
            )
            continue

        if not isinstance(rule_id, str) or not rule_id:
            errors.append(
                f"Bandit result {index} is missing its rule ID."
            )
            continue

        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            errors.append(
                f"Bandit result {index} has an invalid line number."
            )
            continue

        file_path = normalize_file_path(root, raw_path)
        line_range = item.get("line_range") or []

        last_line = line
        if isinstance(line_range, list) and line_range:
            candidate_line = line_range[-1]
            if (
                isinstance(candidate_line, int)
                and not isinstance(candidate_line, bool)
                and candidate_line >= line
            ):
                last_line = candidate_line

        findings.append(
            Finding(
                fingerprint=create_fingerprint(
                    "bandit",
                    rule_id,
                    file_path,
                    line,
                ),
                tool="bandit",
                rule_id=rule_id,
                file_path=file_path,
                start_line=line,
                end_line=last_line,
                category=FindingCategory.SECURITY,
                severity=normalize_severity(
                    item.get("issue_severity")
                ),
                message=str(item.get("issue_text") or rule_id),
                cwe_id=extract_cwe(item.get("issue_cwe")),
                confidence=normalize_confidence(
                    item.get("issue_confidence")
                ),
            )
        )

    return findings, errors


def _is_eligible_python_file(file_path: str) -> bool:
    """Exclude dependencies, generated files, tests, and demo code."""

    normalized = file_path.replace("\\", "/")
    parts = normalized.split("/")
    filename = parts[-1].casefold()

    for part in parts:
        directory = part.casefold()

        if directory in EXCLUDED_DIRECTORIES:
            return False

        if directory.endswith(".egg-info"):
            return False

    if filename.startswith("test_") or filename.endswith("_test.py"):
        return False

    return filename.endswith((".py", ".pyi"))


def run_bandit(
    repo_path: str | Path,
    timeout_seconds: int = 120,
) -> ScannerRunResult:
    """Scan eligible Python source files using Bandit."""

    root = Path(repo_path).expanduser().resolve()

    if not root.is_dir():
        return ScannerRunResult(
            scanner="bandit",
            status=ScannerStatus.FAILED,
            duration_seconds=0,
            errors=[
                f"Repository directory does not exist: {root}"
            ],
        )

    language_report = detect_languages(root)

    if "Python" not in language_report.languages:
        return ScannerRunResult(
            scanner="bandit",
            status=ScannerStatus.SKIPPED,
            duration_seconds=0,
            errors=[
                "Bandit skipped: no Python source files were detected."
            ],
        )

    python_files = [
        file_path
        for file_path in language_report.files_by_language.get(
            "Python", []
        )
        if _is_eligible_python_file(file_path)
    ]

    if not python_files:
        return ScannerRunResult(
            scanner="bandit",
            status=ScannerStatus.SKIPPED,
            duration_seconds=0,
            errors=[
                "Bandit skipped: no eligible Python source files found."
            ],
        )

    command = [
        "bandit",
        "-f",
        "json",
        "-q",
        *python_files,
    ]

    return run_json_command(
        scanner="bandit",
        command=command,
        repo_path=root,
        parser=parse_bandit_payload,
        timeout_seconds=timeout_seconds,
    )
