
from pathlib import Path
from typing import Any

from silentsec.schemas import Finding, FindingCategory

from .common import (
    create_fingerprint,
    extract_cwe,
    normalize_confidence,
    normalize_file_path,
    normalize_severity,
)
from .results import ScannerRunResult
from .runner_utils import run_json_command


def parse_semgrep_payload(
    payload: dict[str, Any],
    root: Path,
) -> tuple[list[Finding], list[str]]:
    raw_results = payload.get("results")

    if not isinstance(raw_results, list):
        raise TypeError("Semgrep JSON must contain a results list.")

    findings: list[Finding] = []
    errors: list[str] = []

    for index, item in enumerate(raw_results):
        if not isinstance(item, dict):
            errors.append(f"Semgrep result {index} is not an object.")
            continue

        extra = item.get("extra") or {}
        start = item.get("start") or {}
        end = item.get("end") or {}
        metadata = extra.get("metadata") or {}

        raw_path = item.get("path")
        rule_id = item.get("check_id")
        line = start.get("line")

        if not isinstance(raw_path, str) or not raw_path:
            errors.append(f"Semgrep result {index} is missing its file path.")
            continue

        if not isinstance(rule_id, str) or not rule_id:
            errors.append(f"Semgrep result {index} is missing its rule ID.")
            continue

        if not isinstance(line, int) or line < 1:
            errors.append(f"Semgrep result {index} has an invalid start line.")
            continue

        file_path = normalize_file_path(root, raw_path)
        raw_end = end.get("line")
        end_line = raw_end if isinstance(raw_end, int) and raw_end >= line else line

        category_raw = str(metadata.get("category", "security")).lower()

        if "maintainability" in category_raw:
            category = FindingCategory.MAINTAINABILITY
        elif "architecture" in category_raw:
            category = FindingCategory.ARCHITECTURE
        elif "secret" in category_raw:
            category = FindingCategory.SECRET
        else:
            category = FindingCategory.SECURITY

        findings.append(
            Finding(
                fingerprint=create_fingerprint(
                    "semgrep", rule_id, file_path, line
                ),
                tool="semgrep",
                rule_id=rule_id,
                file_path=file_path,
                start_line=line,
                end_line=end_line,
                category=category,
                severity=normalize_severity(extra.get("severity")),
                message=str(extra.get("message") or rule_id),
                cwe_id=extract_cwe(metadata.get("cwe")),
                confidence=normalize_confidence(metadata.get("confidence")),
            )
        )

    return findings, errors


def run_semgrep(
    repo_path: str | Path,
    timeout_seconds: int = 180,
    config: str = "p/security-audit",
) -> ScannerRunResult:
    root = Path(repo_path).expanduser().resolve()

    command = [
      "semgrep",
        "scan",
        "--config",
        config,
        "--json",
        "--metrics=off",
        "--quiet",
        "--exclude",
        "sample_repositories",
        "--exclude",
        ".venv",
        "--exclude",
        "node_modules",
        "--exclude",
        "dist",
        "--exclude",
        "build",
        str(root),
    ]

    return run_json_command(
        scanner="semgrep",
        command=command,
        repo_path=root,
        parser=parse_semgrep_payload,
        timeout_seconds=timeout_seconds,
    )
