import json
import subprocess  # nosec B404
from collections.abc import Callable
from pathlib import Path
from time import perf_counter
from typing import Any

from silentsec.process import run_bounded
from silentsec.schemas import Finding

from .results import ScannerRunResult, ScannerStatus

FindingParser = Callable[
    [dict[str, Any], Path],
    tuple[list[Finding], list[str]],
]


def _payload_errors(payload: dict[str, Any]) -> list[str]:
    raw_errors = payload.get("errors", [])

    if not isinstance(raw_errors, list):
        return ["Scanner returned an invalid errors field."]

    errors: list[str] = []

    for item in raw_errors:
        if isinstance(item, dict):
            message = item.get("message") or item.get("error")
            errors.append(str(message or item))
        else:
            errors.append(str(item))

    return errors


def run_json_command(
    scanner: str,
    command: list[str],
    repo_path: str | Path,
    parser: FindingParser,
    timeout_seconds: int = 180,
) -> ScannerRunResult:
    """Execute a scanner safely and parse its JSON report."""

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    root = Path(repo_path).expanduser().resolve()
    started = perf_counter()

    if not root.is_dir():
        return ScannerRunResult(
            scanner=scanner,
            status=ScannerStatus.FAILED,
            duration_seconds=0,
            errors=[f"Repository directory does not exist: {root}"],
        )

    def elapsed() -> float:
        return round(perf_counter() - started, 3)

    try:
        # Scanner command arguments are passed as a list; shell execution is disabled.
        # On timeout run_bounded kills the scanner's whole process tree.
        completed = run_bounded(command, cwd=root, timeout=timeout_seconds)
    except FileNotFoundError:
        return ScannerRunResult(
            scanner=scanner,
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            errors=[
                f"Executable '{command[0]}' was not found. Install the scanner and verify PATH."
            ],
        )
    except subprocess.TimeoutExpired:
        return ScannerRunResult(
            scanner=scanner,
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            errors=[f"Scanner timed out after {timeout_seconds} seconds."],
        )
    except OSError as exc:
        return ScannerRunResult(
            scanner=scanner,
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            errors=[f"Could not execute scanner: {exc}"],
        )

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        diagnostic = (completed.stderr or completed.stdout or "").strip()
        diagnostic = diagnostic[-500:]

        return ScannerRunResult(
            scanner=scanner,
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            exit_code=completed.returncode,
            errors=[
                "Scanner did not produce valid JSON.",
                diagnostic or "No diagnostic output was provided.",
            ],
        )

    if not isinstance(payload, dict):
        return ScannerRunResult(
            scanner=scanner,
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            exit_code=completed.returncode,
            errors=["Scanner JSON root must be an object."],
        )

    try:
        findings, parse_errors = parser(payload, root)
    except (ValueError, TypeError, KeyError) as exc:
        return ScannerRunResult(
            scanner=scanner,
            status=ScannerStatus.FAILED,
            duration_seconds=elapsed(),
            exit_code=completed.returncode,
            errors=[f"Could not parse scanner report: {exc}"],
        )

    errors = _payload_errors(payload) + parse_errors

    # Exit code 1 is allowed because scanners can use it when findings exist.
    if completed.returncode not in (0, 1):
        errors.append(f"Scanner exited with code {completed.returncode}.")

        return ScannerRunResult(
            scanner=scanner,
            status=ScannerStatus.FAILED,
            findings=findings,
            duration_seconds=elapsed(),
            exit_code=completed.returncode,
            errors=errors,
        )

    status = ScannerStatus.PARTIAL if errors else ScannerStatus.SUCCESS

    return ScannerRunResult(
        scanner=scanner,
        status=status,
        findings=findings,
        duration_seconds=elapsed(),
        exit_code=completed.returncode,
        errors=errors,
    )
