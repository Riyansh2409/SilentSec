
from pathlib import Path
from unittest.mock import patch

from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import scan_repository


def make_result(
    scanner: str,
    status: ScannerStatus = ScannerStatus.SUCCESS,
    errors: list[str] | None = None,
) -> ScannerRunResult:
    return ScannerRunResult(
        scanner=scanner,
        status=status,
        findings=[],
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
