from collections.abc import Callable
from pathlib import Path
from time import perf_counter

from pydantic import BaseModel, Field

from silentsec.languages import detect_languages
from silentsec.schemas import Finding
from silentsec.scoring import SecurityDebtReport, score_findings

from .bandit_runner import run_bandit
from .gitleaks_runner import run_gitleaks
from .results import ScannerRunResult, ScannerStatus
from .semgrep_runner import run_semgrep


class RepositoryScanResult(BaseModel):
    """Combined result of all scanner runs for one repository."""

    repo_path: str
    languages: list[str] = Field(default_factory=list)
    status: ScannerStatus
    scanners: list[ScannerRunResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    duration_seconds: float = Field(ge=0)
    errors: list[str] = Field(default_factory=list)
    security_debt: SecurityDebtReport | None = None
    security_debt_complete: bool = False


ScannerRunner = Callable[..., ScannerRunResult]


def _run_safely(
    scanner_name: str,
    runner: ScannerRunner,
    root: Path,
    timeout_seconds: int,
) -> ScannerRunResult:
    """Run one scanner without allowing its exception to abort others."""

    started = perf_counter()

    try:
        return runner(
            root,
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:  # noqa: BLE001
        # Do not expose raw exception text, which might contain sensitive data.
        return ScannerRunResult(
            scanner=scanner_name,
            status=ScannerStatus.FAILED,
            duration_seconds=round(perf_counter() - started, 3),
            errors=[
                f"{scanner_name} runner raised {type(exc).__name__}."
            ],
        )


def _overall_status(
    results: list[ScannerRunResult],
) -> ScannerStatus:
    """Calculate overall status without treating skipped tools as failures."""

    if not results:
        return ScannerStatus.SKIPPED

    successful = [
        result
        for result in results
        if result.status
        in {
            ScannerStatus.SUCCESS,
            ScannerStatus.PARTIAL,
        }
    ]

    failed = [
        result
        for result in results
        if result.status == ScannerStatus.FAILED
    ]

    partial = [
        result
        for result in results
        if result.status == ScannerStatus.PARTIAL
    ]

    if not successful:
        if failed:
            return ScannerStatus.FAILED
        return ScannerStatus.SKIPPED

    if failed or partial:
        return ScannerStatus.PARTIAL

    return ScannerStatus.SUCCESS


def scan_repository(
    repo_path: str | Path,
    timeout_seconds: int = 180,
) -> RepositoryScanResult:
    """Run scanners and calculate an explainable security-debt report."""

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    root = Path(repo_path).expanduser().resolve()
    started = perf_counter()

    if not root.is_dir():
        return RepositoryScanResult(
            repo_path=str(root),
            status=ScannerStatus.FAILED,
            duration_seconds=0,
            errors=["Repository directory does not exist."],
        )

    try:
        language_report = detect_languages(root)
    except (OSError, ValueError):
        return RepositoryScanResult(
            repo_path=str(root),
            status=ScannerStatus.FAILED,
            duration_seconds=round(perf_counter() - started, 3),
            errors=["Could not inspect repository languages."],
        )

    scanner_specs: list[tuple[str, ScannerRunner]] = [
        ("semgrep", run_semgrep),
        ("bandit", run_bandit),
        ("gitleaks", run_gitleaks),
    ]

    results = [
        _run_safely(
            scanner_name=name,
            runner=runner,
            root=root,
            timeout_seconds=timeout_seconds,
        )
        for name, runner in scanner_specs
    ]

    # Preserve raw findings from all scanners. The scoring engine independently
    # deduplicates matching fingerprints for its repository-level report.
    findings = [
        finding
        for result in results
        for finding in result.findings
    ]

    errors = [
        f"{result.scanner}: {error}"
        for result in results
        for error in result.errors
    ]

    overall_status = _overall_status(results)
    debt_report = score_findings(findings)

    return RepositoryScanResult(
        repo_path=str(root),
        languages=language_report.languages,
        status=overall_status,
        scanners=results,
        findings=findings,
        duration_seconds=round(perf_counter() - started, 3),
        errors=errors,
        security_debt=debt_report,
        security_debt_complete=all(
             result.status == ScannerStatus.SUCCESS
             for result in results
                      ),
    )