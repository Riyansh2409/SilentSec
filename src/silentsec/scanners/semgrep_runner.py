import os
import re
from functools import lru_cache
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

# Offline ruleset shipped inside the package (see rules/semgrep/).
BUNDLED_SEMGREP_RULES = Path(__file__).resolve().parent.parent / "rules" / "semgrep"
SEMGREP_CONFIG_ENV = "SILENTSEC_SEMGREP_CONFIG"
SEMGREP_PER_FILE_TIMEOUT_SECONDS = 30
SEMGREP_EXCLUDED_DIRECTORIES = (".venv", "venv", "node_modules", "dist", "build", ".git")

_RULE_ID_LINE = re.compile(r"^\s*-\s*id:\s*([A-Za-z0-9_.\-]+)\s*$", re.MULTILINE)


@lru_cache(maxsize=1)
def bundled_rule_ids() -> frozenset[str]:
    """Read rule IDs from the bundled YAML files without a YAML dependency."""
    ids: set[str] = set()
    for rule_file in sorted(BUNDLED_SEMGREP_RULES.glob("*.yml")):
        ids.update(_RULE_ID_LINE.findall(rule_file.read_text(encoding="utf-8")))
    return frozenset(ids)


def normalize_rule_id(check_id: str) -> str:
    """Strip the path prefix Semgrep adds to rules loaded from a local file.

    Semgrep reports local rules as "<dotted config path>.<rule id>", which
    differs between machines and would change finding fingerprints.
    """
    for rule_id in bundled_rule_ids():
        if check_id == rule_id or check_id.endswith(f".{rule_id}"):
            return rule_id
    return check_id


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

        rule_id = normalize_rule_id(rule_id)

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


def resolve_semgrep_config(config: str | None = None) -> str:
    """Choose the Semgrep ruleset: explicit argument, env override, or bundled rules.

    The bundled rules work offline. Registry configs such as "p/security-audit"
    still work when passed explicitly, but they require network access.
    """
    if config:
        return config

    override = os.getenv(SEMGREP_CONFIG_ENV, "").strip()
    if override:
        return override

    return str(BUNDLED_SEMGREP_RULES)


def run_semgrep(
    repo_path: str | Path,
    timeout_seconds: int = 180,
    config: str | None = None,
) -> ScannerRunResult:
    root = Path(repo_path).expanduser().resolve()

    command = [
        "semgrep",
        "scan",
        "--config",
        resolve_semgrep_config(config),
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--timeout",
        str(SEMGREP_PER_FILE_TIMEOUT_SECONDS),
        "--quiet",
        *(
            argument
            for directory in SEMGREP_EXCLUDED_DIRECTORIES
            for argument in ("--exclude", directory)
        ),
        # A folder without its own .git (history snapshots, verify/fix copies)
        # would otherwise use the nearest parent Git repository as the project
        # root. If that is e.g. a home folder, file discovery walks all of it
        # and can take minutes. ".git" may be a file in worktrees and
        # submodules, so exists() keeps Semgrep's normal Git handling there.
        *(() if (root / ".git").exists() else ("--project-root", ".")),
        # Scan "." from inside the repository (run_json_command uses cwd=root).
        # With an absolute target, --exclude patterns also match parent
        # folders, so a repository stored under e.g. ".../build/app" would be
        # silently skipped.
        ".",
    ]

    return run_json_command(
        scanner="semgrep",
        command=command,
        repo_path=root,
        parser=parse_semgrep_payload,
        timeout_seconds=timeout_seconds,
    )
