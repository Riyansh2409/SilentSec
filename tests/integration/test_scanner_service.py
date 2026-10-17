from pathlib import Path
from unittest.mock import patch

from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import scan_repository
from silentsec.schemas.finding import (
    Finding,
    FindingCategory,
    FindingStatus,
    Severity,
)
from silentsec.scoring import RiskLevel


def make_finding(
    *,
    fingerprint: str = "fingerprint-1",
    severity: Severity = Severity.MEDIUM,
    confidence: float | None = 0.8,
    status: FindingStatus = FindingStatus.OPEN,
) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        tool="test-scanner",
        rule_id="TEST001",
        file_path="src/app.py",
        start_line=10,
        end_line=12,
        category=FindingCategory.SECURITY,
        severity=severity,
        message="Test security finding",
        confidence=confidence,
        status=status,
    )


def make_result(
    scanner: str,
    status: ScannerStatus = ScannerStatus.SUCCESS,
    errors: list[str] | None = None,
    findings: list[Finding] | None = None,
) -> ScannerRunResult:
    return ScannerRunResult(
        scanner=scanner,
        status=status,
        findings=findings or [],
        duration_seconds=0.01,
        exit_code=0 if status == ScannerStatus.SUCCESS else None,
        errors=errors or [],
    )


def test_runs_all_three_scanners(tmp_path: Path):
    with (
        patch(
            "silentsec.scanners.scanner_service.run_semgrep",
            return_value=make_result("semgrep"),
        ) as semgrep,
        patch(
            "silentsec.scanners.scanner_service.run_bandit",
            return_value=make_result("bandit"),
        ) as bandit,
        patch(
            "silentsec.scanners.scanner_service.run_gitleaks",
            return_value=make_result("gitleaks"),
        ) as gitleaks,
    ):
        report = scan_repository(tmp_path)

    assert report.status == ScannerStatus.SUCCESS
    assert len(report.scanners) == 3
    assert [item.scanner for item in report.scanners] == [
        "semgrep",
        "bandit",
        "gitleaks",
    ]
    assert report.security_debt is not None
    assert report.security_debt.score == 0
    assert report.security_debt.risk_level == RiskLevel.NONE
    assert report.security_debt_complete is True

    semgrep.assert_called_once()
    bandit.assert_called_once()
    gitleaks.assert_called_once()


def test_one_failed_scanner_does_not_abort_others(tmp_path: Path):
    with (
        patch(
            "silentsec.scanners.scanner_service.run_semgrep",
            return_value=make_result("semgrep"),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_bandit",
            return_value=make_result(
                "bandit",
                ScannerStatus.FAILED,
                ["simulated failure"],
            ),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_gitleaks",
            return_value=make_result("gitleaks"),
        ),
    ):
        report = scan_repository(tmp_path)

    assert report.status == ScannerStatus.PARTIAL
    assert len(report.scanners) == 3
    assert any("simulated failure" in error for error in report.errors)
    assert report.security_debt is not None
    assert report.security_debt_complete is False


def test_scanner_exception_does_not_abort_others(tmp_path: Path):
    with (
        patch(
            "silentsec.scanners.scanner_service.run_semgrep",
            side_effect=RuntimeError("simulated exception"),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_bandit",
            return_value=make_result("bandit"),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_gitleaks",
            return_value=make_result("gitleaks"),
        ),
    ):
        report = scan_repository(tmp_path)

    assert report.status == ScannerStatus.PARTIAL
    assert len(report.scanners) == 3
    assert report.scanners[0].status == ScannerStatus.FAILED
    assert "simulated exception" not in str(report.errors)
    assert report.security_debt_complete is False


def test_skipped_bandit_is_not_a_failure(tmp_path: Path):
    with (
        patch(
            "silentsec.scanners.scanner_service.run_semgrep",
            return_value=make_result("semgrep"),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_bandit",
            return_value=make_result("bandit", ScannerStatus.SKIPPED),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_gitleaks",
            return_value=make_result("gitleaks"),
        ),
    ):
        report = scan_repository(tmp_path)

    assert report.status == ScannerStatus.SUCCESS


def test_scoring_report_contains_finding_score(tmp_path: Path):
    finding = make_finding(
        severity=Severity.MEDIUM,
        confidence=0.8,
    )

    with (
        patch(
            "silentsec.scanners.scanner_service.run_semgrep",
            return_value=make_result("semgrep", findings=[finding]),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_bandit",
            return_value=make_result("bandit"),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_gitleaks",
            return_value=make_result("gitleaks"),
        ),
    ):
        report = scan_repository(tmp_path)

    assert report.status == ScannerStatus.SUCCESS
    assert len(report.findings) == 1
    assert report.security_debt is not None
    assert report.security_debt.score == 7.2
    assert report.security_debt.raw_score == 7.2
    assert report.security_debt.risk_level == RiskLevel.LOW
    assert report.security_debt.unique_open_findings_count == 1
    assert report.security_debt_complete is True


def test_duplicate_fingerprints_are_not_double_counted(
    tmp_path: Path,
):
    low_finding = make_finding(
        fingerprint="same-issue",
        severity=Severity.LOW,
        confidence=1.0,
    )
    high_finding = make_finding(
        fingerprint="same-issue",
        severity=Severity.HIGH,
        confidence=1.0,
    )

    with (
        patch(
            "silentsec.scanners.scanner_service.run_semgrep",
            return_value=make_result(
                "semgrep",
                findings=[low_finding],
            ),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_bandit",
            return_value=make_result(
                "bandit",
                findings=[high_finding],
            ),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_gitleaks",
            return_value=make_result("gitleaks"),
        ),
    ):
        report = scan_repository(tmp_path)

    assert len(report.findings) == 2
    assert report.security_debt is not None
    assert report.security_debt.input_findings_count == 2
    assert report.security_debt.unique_open_findings_count == 1
    assert report.security_debt.duplicate_findings_removed == 1
    assert report.security_debt.score == 15.0
    assert report.security_debt.scored_findings[0].finding.severity == Severity.HIGH


def test_partial_scan_still_returns_available_debt_report(
    tmp_path: Path,
):
    finding = make_finding(
        fingerprint="partial-scan-finding",
        severity=Severity.MEDIUM,
        confidence=0.8,
    )

    with (
        patch(
            "silentsec.scanners.scanner_service.run_semgrep",
            return_value=make_result("semgrep", findings=[finding]),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_bandit",
            return_value=make_result(
                "bandit",
                ScannerStatus.FAILED,
                ["simulated failure"],
            ),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_gitleaks",
            return_value=make_result("gitleaks"),
        ),
    ):
        report = scan_repository(tmp_path)

    assert report.status == ScannerStatus.PARTIAL
    assert report.security_debt is not None
    assert report.security_debt.score == 7.2
    assert report.security_debt_complete is False
    assert any("simulated failure" in error for error in report.errors)