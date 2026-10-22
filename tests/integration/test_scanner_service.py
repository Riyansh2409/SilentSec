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
from silentsec.triage import TriagePriority, TriageResult
from silentsec.verification import VerificationHistory, VerificationStatus


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
    assert report.status == ScannerStatus.SUCCESS
    assert report.security_debt_complete is False


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


def make_triage_result(finding: Finding) -> TriageResult:
    return TriageResult(
        finding_id=finding.finding_id,
        fingerprint=finding.fingerprint,
        priority=TriagePriority.HIGH,
        summary="Potential security issue requiring review.",
        rationale="The scanner reported a potentially unsafe operation.",
        remediation_steps=["Review the operation and validate its inputs."],
        evidence=["A scanner finding identifies the affected source location."],
        limitations=["Exploitability has not been independently verified."],
        requires_human_review=True,
    )


def mock_scanners(findings: list[Finding]):
    """Patch all scanners to return controlled findings."""
    return (
        patch(
            "silentsec.scanners.scanner_service.run_semgrep",
            return_value=make_result("semgrep", findings=findings),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_bandit",
            return_value=make_result("bandit"),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_gitleaks",
            return_value=make_result("gitleaks"),
        ),
    )


def test_ai_triage_receives_source_context(tmp_path: Path):
    source_file = tmp_path / "src" / "app.py"
    source_file.parent.mkdir()
    source_file.write_text(
        "\n".join(f"# line {number}" for number in range(1, 16)),
        encoding="utf-8",
    )
    finding = make_finding()
    received_contexts: list[str] = []

    class FakeRouter:
        def triage(self, *, finding: Finding, context: str = "") -> TriageResult:
            received_contexts.append(context)
            return make_triage_result(finding)

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
        patch(
            "silentsec.scanners.scanner_service.build_default_router",
            return_value=FakeRouter(),
        ),
    ):
        report = scan_repository(tmp_path, enable_ai_triage=True)

    assert report.triage_attempted is True
    assert report.triage_complete is True
    assert len(report.triage_results) == 1
    assert len(received_contexts) == 1
    assert "line 10" in received_contexts[0]


def test_ai_triage_failure_does_not_stop_remaining_findings(
    tmp_path: Path,
):
    first = make_finding(fingerprint="first-finding")
    second = make_finding(fingerprint="second-finding")
    calls: list[str] = []

    class FlakyRouter:
        def triage(self, *, finding: Finding, context: str = "") -> TriageResult:
            calls.append(finding.fingerprint)
            if finding.fingerprint == "first-finding":
                raise RuntimeError("simulated provider failure")
            return make_triage_result(finding)

    with (
        patch(
            "silentsec.scanners.scanner_service.run_semgrep",
            return_value=make_result("semgrep", findings=[first, second]),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_bandit",
            return_value=make_result("bandit"),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_gitleaks",
            return_value=make_result("gitleaks"),
        ),
        patch(
            "silentsec.scanners.scanner_service.build_default_router",
            return_value=FlakyRouter(),
        ),
    ):
        report = scan_repository(tmp_path, enable_ai_triage=True)

    assert len(calls) == 2
    assert len(report.triage_results) == 1
    assert report.triage_results[0].fingerprint == "second-finding"
    assert report.triage_complete is False
    assert report.triage_errors


def test_ai_triage_limit_is_reported(tmp_path: Path):
    findings = [
        make_finding(fingerprint="low-finding", severity=Severity.LOW),
        make_finding(fingerprint="high-finding", severity=Severity.HIGH),
    ]

    class FakeRouter:
        def triage(self, *, finding: Finding, context: str = "") -> TriageResult:
            return make_triage_result(finding)

    with (
        patch(
            "silentsec.scanners.scanner_service.run_semgrep",
            return_value=make_result("semgrep", findings=findings),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_bandit",
            return_value=make_result("bandit"),
        ),
        patch(
            "silentsec.scanners.scanner_service.run_gitleaks",
            return_value=make_result("gitleaks"),
        ),
        patch(
            "silentsec.scanners.scanner_service.build_default_router",
            return_value=FakeRouter(),
        ),
    ):
        report = scan_repository(
            tmp_path,
            enable_ai_triage=True,
            max_ai_triage_findings=1,
        )

    assert len(report.triage_results) == 1
    assert report.triage_results[0].fingerprint == "high-finding"
    assert report.triage_complete is False
    assert any("1 findings were skipped" in error for error in report.triage_errors)


def test_ai_provider_failure_preserves_security_debt_score(
    tmp_path: Path,
):
    finding = make_finding(
        fingerprint="score-preservation",
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
        patch(
            "silentsec.scanners.scanner_service.build_default_router",
            side_effect=RuntimeError("simulated provider failure"),
        ),
    ):
        report = scan_repository(tmp_path, enable_ai_triage=True)

    assert report.security_debt is not None
    assert report.security_debt.score == 7.2
    assert report.security_debt_complete is True
    assert report.triage_attempted is True
    assert report.triage_complete is False
    assert report.triage_errors


def test_verification_integrates_with_complete_repository_scan(
    tmp_path: Path,
):
    baseline = make_finding(fingerprint="baseline")
    current = make_finding(fingerprint="current")

    with (
        patch(
            "silentsec.scanners.scanner_service.run_semgrep",
            return_value=make_result("semgrep", findings=[current]),
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
        report = scan_repository(
            tmp_path,
            verification_baseline=[baseline],
        )

    assert report.verification_attempted is True
    assert report.verification_report is not None
    assert report.verification_report.scan_complete is True
    assert report.verification_report.still_open_count == 1
    assert report.verification_report.results[0].current_finding == current


def test_incomplete_repository_scan_cannot_confirm_resolution(
    tmp_path: Path,
):
    baseline = make_finding(fingerprint="baseline")

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
        report = scan_repository(
            tmp_path,
            verification_baseline=[baseline],
        )

    assert report.security_debt_complete is False
    assert report.verification_report is not None
    assert report.verification_report.scan_complete is False
    assert report.verification_report.incomplete_count == 1
    assert report.verification_report.resolved_count == 0


def test_verification_is_not_attempted_without_baseline(
    tmp_path: Path,
):
    with (
        patch(
            "silentsec.scanners.scanner_service.run_semgrep",
            return_value=make_result("semgrep"),
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

    assert report.verification_attempted is False
    assert report.verification_report is None


def test_missing_repository_marks_verification_incomplete(tmp_path: Path):
    baseline = make_finding(fingerprint="baseline")
    missing_repo = tmp_path / "missing-repository"
    history = VerificationHistory()

    report = scan_repository(
        missing_repo,
        verification_baseline=[baseline],
        verification_history=history,
    )

    assert report.status == ScannerStatus.FAILED
    assert report.verification_attempted is True
    assert report.verification_report is not None
    assert report.verification_report.scan_complete is False
    assert report.verification_report.incomplete_count == 1
    assert report.verification_report.resolved_count == 0
    assert report.verification_report.results[0].status == (VerificationStatus.INCOMPLETE)
    assert not history.resolved_identities


def test_language_detection_failure_marks_verification_incomplete(
    tmp_path: Path,
):
    baseline = make_finding(fingerprint="baseline")
    history = VerificationHistory()

    with patch(
        "silentsec.scanners.scanner_service.detect_languages",
        side_effect=OSError("simulated filesystem failure"),
    ):
        report = scan_repository(
            tmp_path,
            verification_baseline=[baseline],
            verification_history=history,
        )

    assert report.status == ScannerStatus.FAILED
    assert report.verification_attempted is True
    assert report.verification_report is not None
    assert report.verification_report.scan_complete is False
    assert report.verification_report.incomplete_count == 1
    assert report.verification_report.resolved_count == 0
    assert report.verification_report.results[0].status == (VerificationStatus.INCOMPLETE)
    assert not history.resolved_identities
