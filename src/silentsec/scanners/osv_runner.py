"""Dependency vulnerabilities with OSV-Scanner (https://google.github.io/osv-scanner/).

The other scanners look at the project's own code. OSV-Scanner reads its
dependency files (requirements.txt, poetry.lock, package-lock.json, ...) and
checks each pinned package version against the OSV vulnerability database.

* Optional: when ``osv-scanner`` is not installed, or the repository has no
  dependency files, the scanner is SKIPPED with an informational note, so a
  scan without it still counts as complete.
* It needs network access to api.osv.dev. When the database cannot be
  reached the scanner FAILS, so a scan never claims "no vulnerable
  dependencies" without having checked.
* One finding per vulnerability group (OSV groups aliases such as a GHSA and
  a PYSEC id for the same issue), placed on the line that declares the
  package when that line can be found.
"""

import re
import shutil
from pathlib import Path
from typing import Any

from silentsec.schemas import Finding, FindingCategory, Severity

from .common import create_fingerprint, normalize_file_path
from .results import ScannerRunResult, ScannerStatus
from .runner_utils import run_json_command

TOOL_NAME = "osv-scanner"
EXECUTABLE = "osv-scanner"

# File names OSV-Scanner reads as dependency lists or lockfiles.
DEPENDENCY_FILES = frozenset(
    {
        "requirements.txt",
        "poetry.lock",
        "pipfile.lock",
        "pdm.lock",
        "uv.lock",
        "pylock.toml",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "go.mod",
        "cargo.lock",
        "gemfile.lock",
        "composer.lock",
        "pom.xml",
        "gradle.lockfile",
        "packages.lock.json",
        "pubspec.lock",
        "mix.lock",
    }
)
REQUIREMENTS_RE = re.compile(r"^requirements[\w.-]*\.txt$", re.IGNORECASE)
SKIPPED_DIRECTORIES = frozenset(
    {".git", ".venv", "venv", "env", "node_modules", "__pycache__", "dist", "build", ".tox"}
)
MAX_FILES_TO_INSPECT = 50_000


def _is_dependency_file(name: str) -> bool:
    lowered = name.casefold()
    return lowered in DEPENDENCY_FILES or bool(REQUIREMENTS_RE.match(name))


def find_dependency_files(root: Path) -> list[Path]:
    """Dependency files in the repository, skipping virtualenvs and vendored folders."""
    found: list[Path] = []
    inspected = 0
    stack = [root]
    while stack:
        folder = stack.pop()
        try:
            entries = list(folder.iterdir())
        except OSError:
            continue
        for entry in entries:
            inspected += 1
            if inspected > MAX_FILES_TO_INSPECT:
                return sorted(found)
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in SKIPPED_DIRECTORIES:
                    stack.append(entry)
            elif _is_dependency_file(entry.name):
                found.append(entry)
    return sorted(found)


def _severity_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


LABEL_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _severity(group: dict[str, Any], vulnerabilities: list[dict[str, Any]]) -> Severity:
    """CVSS score of the group, else the advisory's label, else medium."""
    try:
        score = float(group.get("max_severity") or "")
    except ValueError:
        score = None
    if score is not None:
        return _severity_from_cvss(score)
    for vulnerability in vulnerabilities:
        label = str((vulnerability.get("database_specific") or {}).get("severity", "")).upper()
        if label in LABEL_SEVERITY:
            return LABEL_SEVERITY[label]
    return Severity.MEDIUM


def _fixed_versions(vulnerabilities: list[dict[str, Any]], package: str) -> list[str]:
    versions: set[str] = set()
    for vulnerability in vulnerabilities:
        for affected in vulnerability.get("affected") or []:
            affected_name = str((affected.get("package") or {}).get("name", ""))
            if affected_name and _canonical(affected_name) != _canonical(package):
                continue
            for version_range in affected.get("ranges") or []:
                for event in version_range.get("events") or []:
                    if isinstance(event, dict) and event.get("fixed"):
                        versions.add(str(event["fixed"]))
    return sorted(versions, key=_version_key)


def _version_key(version: str) -> tuple:
    return tuple(int(part) if part.isdigit() else 0 for part in re.split(r"[.\-+]", version))


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _declaration_line(path: Path, package: str) -> int:
    """The line that names the package in the dependency file, else 1."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 1
    wanted = _canonical(package)
    pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
    for number, line in enumerate(lines, start=1):
        for match in pattern.finditer(line):
            if _canonical(match.group(0)) == wanted:
                return number
    return 1


def _preferred_id(ids: list[str]) -> str:
    """GHSA ids are the most widely linked; then CVE-style ids; else the first."""
    for prefix in ("GHSA-", "PYSEC-", "CVE-"):
        for item in ids:
            if item.startswith(prefix):
                return item
    return ids[0]


def _cwe(vulnerabilities: list[dict[str, Any]]) -> str | None:
    for vulnerability in vulnerabilities:
        for cwe in (vulnerability.get("database_specific") or {}).get("cwe_ids") or []:
            if isinstance(cwe, str) and cwe.upper().startswith("CWE-"):
                return cwe.upper()
    return None


def parse_osv_report(payload: dict[str, Any], root: Path) -> tuple[list[Finding], list[str]]:
    """Normalize OSV-Scanner JSON into findings, one per vulnerability group."""
    findings: list[Finding] = []
    errors: list[str] = []
    results = payload.get("results")
    if results is None:
        return findings, errors
    if not isinstance(results, list):
        raise TypeError("'results' must be a list")

    for result in results:
        source_path = str((result.get("source") or {}).get("path", ""))
        file_path = normalize_file_path(root, source_path) if source_path else "dependencies"
        for entry in result.get("packages") or []:
            package = entry.get("package") or {}
            name = str(package.get("name", "")).strip()
            version = str(package.get("version", "")).strip()
            ecosystem = str(package.get("ecosystem", "")).strip()
            if not name:
                errors.append("OSV-Scanner reported a package without a name; skipped.")
                continue
            vulnerabilities = [v for v in entry.get("vulnerabilities") or [] if isinstance(v, dict)]
            by_id = {str(v.get("id")): v for v in vulnerabilities if v.get("id")}
            groups = entry.get("groups") or [
                {"ids": [vulnerability_id]} for vulnerability_id in by_id
            ]
            line = _declaration_line(root / file_path, name)

            for group in groups:
                ids = [str(item) for item in group.get("ids") or [] if item]
                if not ids:
                    continue
                members = [by_id[item] for item in ids if item in by_id]
                if members and all(member.get("withdrawn") for member in members):
                    continue
                rule_id = _preferred_id(ids)
                aliases = sorted(
                    (
                        {str(alias) for alias in group.get("aliases") or [] if alias}
                        | {str(a) for member in members for a in member.get("aliases") or []}
                        | set(ids)
                    )
                    - {rule_id}
                )
                summary = next(
                    (str(member["summary"]) for member in members if member.get("summary")),
                    "Known vulnerability",
                )
                fixed = _fixed_versions(members, name)
                fix_text = (
                    f" Upgrade to {fixed[0]} or later."
                    if fixed
                    else " No fixed version is listed yet."
                )
                also = f" Also known as {', '.join(aliases[:4])}." if aliases else ""
                findings.append(
                    Finding(
                        fingerprint=create_fingerprint(
                            TOOL_NAME, rule_id, f"{file_path}#{_canonical(name)}", line
                        ),
                        tool=TOOL_NAME,
                        rule_id=rule_id,
                        file_path=file_path,
                        start_line=line,
                        category=FindingCategory.SECURITY,
                        severity=_severity(group, members),
                        message=(
                            f"Dependency {name} {version} ({ecosystem}) has a known "
                            f"vulnerability {rule_id}: {summary.rstrip('.')}.{fix_text}{also}"
                        ),
                        cwe_id=_cwe(members),
                        confidence=0.9,
                    )
                )
    return findings, errors


def run_osv_scanner(repo_path: str | Path, timeout_seconds: int = 180) -> ScannerRunResult:
    """Check dependency files for known vulnerable package versions."""
    root = Path(repo_path).expanduser().resolve()
    if shutil.which(EXECUTABLE) is None:
        return ScannerRunResult(
            scanner="osv",
            status=ScannerStatus.SKIPPED,
            duration_seconds=0,
            errors=[
                (
                    "Informational: osv-scanner is not installed, so dependencies were not "
                    "checked for known vulnerabilities."
                )
            ],
        )
    if root.is_dir() and not find_dependency_files(root):
        return ScannerRunResult(
            scanner="osv",
            status=ScannerStatus.SKIPPED,
            duration_seconds=0,
            errors=["Informational: no dependency files were found."],
        )

    command = [
        EXECUTABLE,
        "scan",
        "source",
        "--format=json",
        "--recursive",
        "--allow-no-lockfiles",
        "--verbosity=error",
        # Scan "." from inside the repository (run_json_command uses cwd=root).
        ".",
    ]
    result = run_json_command("osv", command, root, parse_osv_report, timeout_seconds)
    if result.status == ScannerStatus.FAILED and any(
        "osv.dev" in error or "request failed" in error for error in result.errors
    ):
        result = result.model_copy(
            update={
                "errors": [
                    (
                        "OSV-Scanner could not reach the OSV vulnerability database "
                        "(api.osv.dev); dependency checks need network access."
                    )
                ]
            }
        )
    return result
