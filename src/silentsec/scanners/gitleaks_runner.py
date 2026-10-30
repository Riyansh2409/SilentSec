import json
import os
import subprocess  # nosec B404
import tempfile
from collections.abc import Callable
from pathlib import Path
from time import perf_counter
from typing import Any

from silentsec.schemas import Finding, FindingCategory, Severity

from .common import create_fingerprint, normalize_file_path
from .results import ScannerRunResult, ScannerStatus

# Shipped inside the package so it is available for editable and regular installs.
GITLEAKS_CONFIG_PATH = Path(__file__).resolve().parent.parent / "rules" / "gitleaks.toml"


def parse_gitleaks_payload(
    payload: Any,
    root: Path,
) -> tuple[list[Finding], list[str]]:
    """Convert Gitleaks JSON into normalized findings without exposing secrets."""

    if not isinstance(payload, list):
        raise TypeError("Gitleaks JSON must contain a list of findings.")

    findings: list[Finding] = []
    errors: list[str] = []

    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            errors.append(f"Gitleaks result {index} is not an object.")
            continue

        raw_path = item.get("File")
        rule_id = item.get("RuleID")
        start_line = item.get("StartLine")

        if not isinstance(raw_path, str) or not raw_path:
            errors.append(f"Gitleaks result {index} is missing its file path.")
            continue

        if not isinstance(rule_id, str) or not rule_id:
            errors.append(f"Gitleaks result {index} is missing its rule ID.")
            continue

        if (
            not isinstance(start_line, int)
            or isinstance(start_line, bool)
            or start_line < 1
        ):
            errors.append(f"Gitleaks result {index} has an invalid start line.")
            continue

        raw_end_line = item.get("EndLine")
        end_line = (
            raw_end_line
            if isinstance(raw_end_line, int)
            and not isinstance(raw_end_line, bool)
            and raw_end_line >= start_line
            else start_line
        )

        file_path = normalize_file_path(root, raw_path)

        findings.append(
            Finding(
                fingerprint=create_fingerprint(
                    "gitleaks",
                    rule_id,
                    file_path,
                    start_line,
                ),
                tool="gitleaks",
                rule_id=rule_id,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                category=FindingCategory.SECRET,
                severity=Severity.HIGH,
                message=(
                    f"Potential secret detected by Gitleaks rule "
                    f"'{rule_id}'. Review the source locally."
                ),
                cwe_id=None,
                confidence=None,
            )
        )

    return findings, errors


def run_gitleaks(
    repo_path: str | Path,
    timeout_seconds: int = 180,
) -> ScannerRunResult:
    """Scan current repository files for potential exposed secrets."""

    root = Path(repo_path).expanduser().resolve()
    started = perf_counter()

    def elapsed() -> float:
        return round(perf_counter() - started, 3)

    if not root.is_dir():
        return ScannerRunResult(
            scanner="gitleaks",
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            errors=["Repository directory does not exist."],
        )

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    config_path = GITLEAKS_CONFIG_PATH

    if not config_path.is_file():
        return ScannerRunResult(
            scanner="gitleaks",
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            errors=["SilentSec Gitleaks configuration file is missing."],
        )

    # Write the report to a private temporary file outside the scanned
    # repository. Some Gitleaks versions treat "--report-path=-" as a literal
    # file name, which would create a file inside the repository and leave
    # stdout empty.
    report_fd, report_name = tempfile.mkstemp(
        prefix="silentsec-gitleaks-",
        suffix=".json",
    )
    os.close(report_fd)
    report_path = Path(report_name)

    try:
        return _run_gitleaks_command(
            root=root,
            config_path=config_path,
            report_path=report_path,
            timeout_seconds=timeout_seconds,
            elapsed=elapsed,
        )
    finally:
        report_path.unlink(missing_ok=True)


def _run_gitleaks_command(
    *,
    root: Path,
    config_path: Path,
    report_path: Path,
    timeout_seconds: int,
    elapsed: Callable[[], float],
) -> ScannerRunResult:
    """Execute Gitleaks and parse the report it wrote to report_path."""

    command = [
        "gitleaks",
        "dir",
        "--config",
        str(config_path),
        "--report-format=json",
        f"--report-path={report_path}",
        "--exit-code=0",
        "--redact=100",
        "--no-banner",
        "--no-color",
        "--log-level=fatal",
        # Scan "." with cwd=root so allowlist path patterns only match inside
        # the repository. With an absolute target, a repository stored under
        # a folder named e.g. "build" would have every file allowlisted.
        ".",
    ]

    try:
        # Gitleaks receives a fixed argument list; shell execution is disabled.
        completed = subprocess.run(  # nosec B603
            command,
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return ScannerRunResult(
            scanner="gitleaks",
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            errors=[
                "Gitleaks executable was not found. Verify installation and PATH."
            ],
        )
    except subprocess.TimeoutExpired:
        return ScannerRunResult(
            scanner="gitleaks",
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            errors=[
                f"Gitleaks timed out after {timeout_seconds} seconds."
            ],
        )
    except OSError:
        return ScannerRunResult(
            scanner="gitleaks",
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            errors=[
                "Gitleaks could not be executed; diagnostic output suppressed."
            ],
        )

    if completed.returncode != 0:
        return ScannerRunResult(
            scanner="gitleaks",
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            exit_code=completed.returncode,
            errors=[
                "Gitleaks exited with a non-zero status; diagnostic output suppressed."
            ],
        )

    try:
        report_text = report_path.read_text(encoding="utf-8")
    except OSError:
        report_text = ""

    try:
        # An empty report file means Gitleaks found nothing to report.
        payload = json.loads(report_text) if report_text.strip() else []
    except (json.JSONDecodeError, TypeError):
        return ScannerRunResult(
            scanner="gitleaks",
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            exit_code=completed.returncode,
            errors=["Gitleaks did not produce valid JSON; output suppressed."],
        )

    try:
        findings, parse_errors = parse_gitleaks_payload(payload, root)
    except (TypeError, ValueError):
        return ScannerRunResult(
            scanner="gitleaks",
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            exit_code=completed.returncode,
            errors=["Gitleaks report could not be parsed."],
        )

    status = ScannerStatus.PARTIAL if parse_errors else ScannerStatus.SUCCESS

    return ScannerRunResult(
        scanner="gitleaks",
        status=status,
        findings=findings,
        duration_seconds=elapsed(),
        exit_code=completed.returncode,
        errors=parse_errors,
    )