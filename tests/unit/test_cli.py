import json
from pathlib import Path
from unittest.mock import patch

import pytest

from silentsec import cli
from silentsec.remediation import FindingSummary, FixVerdict, FixVerificationReport
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult
from silentsec.schemas import Severity
from silentsec.scoring import score_findings


def make_result(tmp_path: Path, *, complete: bool) -> RepositoryScanResult:
    status = ScannerStatus.SUCCESS if complete else ScannerStatus.PARTIAL
    return RepositoryScanResult(
        repo_path=str(tmp_path),
        status=status,
        scanners=[
            ScannerRunResult(scanner="bandit", status=status, duration_seconds=0.1)
        ],
        duration_seconds=0.1,
        security_debt=score_findings([]),
        security_debt_complete=complete,
    )


def test_complete_scan_exits_zero_and_prints_summary(tmp_path: Path, capsys):
    with patch.object(cli, "scan_repository", return_value=make_result(tmp_path, complete=True)):
        code = cli.main(["scan", str(tmp_path)])

    output = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "Score: 0.0 / 100" in output
    assert "Security risk: NONE" in output


def test_incomplete_scan_exits_two_and_warns(tmp_path: Path, capsys):
    with patch.object(cli, "scan_repository", return_value=make_result(tmp_path, complete=False)):
        code = cli.main(["scan", str(tmp_path)])

    assert code == cli.EXIT_SCAN_INCOMPLETE
    assert "score is incomplete" in capsys.readouterr().out


def test_json_report_is_written(tmp_path: Path):
    report_path = tmp_path / "report.json"

    with patch.object(cli, "scan_repository", return_value=make_result(tmp_path, complete=True)):
        cli.main(["scan", str(tmp_path), "--json", str(report_path)])

    assert json.loads(report_path.read_text(encoding="utf-8"))["repo_path"] == str(tmp_path)


def test_missing_directory_is_a_usage_error(tmp_path: Path):
    with patch.object(cli, "scan_repository") as scan:
        code = cli.main(["scan", str(tmp_path / "missing")])

    assert code == cli.EXIT_USAGE_ERROR
    scan.assert_not_called()


def test_ai_triage_is_off_unless_requested(tmp_path: Path):
    with patch.object(
        cli, "scan_repository", return_value=make_result(tmp_path, complete=True)
    ) as scan:
        cli.main(["scan", str(tmp_path)])

    assert scan.call_args.kwargs["enable_ai_triage"] is False


# --- silentsec verify -------------------------------------------------------

PATCH = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a\n+b\n"


def make_report(verdict: FixVerdict) -> FixVerificationReport:
    resolved = FindingSummary(
        fingerprint="fp",
        tool="semgrep",
        rule_id="sql",
        file_path="app.py",
        start_line=3,
        severity=Severity.HIGH,
    )
    return FixVerificationReport(
        verdict=verdict,
        reasons=["because"],
        resolved=[resolved],
        score_before=14.2,
        score_after=0.0,
        checks_run=["semgrep (success)"],
        limitations=["Passing scans and tests do not prove the absence of vulnerabilities."],
    )


def write_patch(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "fix.diff"
    path.write_bytes(data)
    return path


@pytest.mark.parametrize(
    ("verdict", "code"),
    [
        (FixVerdict.VERIFIED_FIX, cli.EXIT_OK),
        (FixVerdict.PARTIAL, cli.EXIT_FIX_NOT_CONFIRMED),
        (FixVerdict.UNRESOLVED, cli.EXIT_FIX_NOT_CONFIRMED),
        (FixVerdict.REGRESSION, cli.EXIT_FIX_NOT_CONFIRMED),
        (FixVerdict.NOT_VERIFIED, cli.EXIT_NOT_VERIFIED),
    ],
)
def test_verify_exit_codes(tmp_path: Path, verdict: FixVerdict, code: int):
    patch_file = write_patch(tmp_path, PATCH.encode())

    with patch.object(cli, "verify_fix", return_value=make_report(verdict)):
        assert cli.main(["verify", str(tmp_path), "--patch", str(patch_file)]) == code


def test_verify_prints_verdict_score_and_limitations(tmp_path: Path, capsys):
    patch_file = write_patch(tmp_path, PATCH.encode())

    with patch.object(cli, "verify_fix", return_value=make_report(FixVerdict.VERIFIED_FIX)):
        cli.main(["verify", str(tmp_path), "--patch", str(patch_file)])

    output = capsys.readouterr().out
    assert "Verdict: VERIFIED FIX" in output
    assert "Score: 14.2 -> 0.0" in output
    assert "Resolved (1):" in output
    assert "do not prove the absence" in output


@pytest.mark.parametrize(
    "data",
    [
        PATCH.encode("utf-8"),
        b"\xef\xbb\xbf" + PATCH.encode("utf-8"),
        PATCH.encode("utf-16"),  # Windows PowerShell 5 redirect
    ],
)
def test_patch_file_encodings_are_accepted(tmp_path: Path, data: bytes):
    patch_file = write_patch(tmp_path, data)

    assert cli.read_patch_file(patch_file) == PATCH


def test_verify_passes_targets_and_keeps_tests_off_by_default(tmp_path: Path):
    patch_file = write_patch(tmp_path, PATCH.encode())

    with patch.object(
        cli, "verify_fix", return_value=make_report(FixVerdict.VERIFIED_FIX)
    ) as verify:
        cli.main(
            ["verify", str(tmp_path), "--patch", str(patch_file), "--target", "a", "--target", "b"]
        )

    kwargs = verify.call_args.kwargs
    assert kwargs["target_fingerprints"] == ["a", "b"]
    assert kwargs["run_tests"] is False


def test_test_command_implies_running_tests(tmp_path: Path):
    patch_file = write_patch(tmp_path, PATCH.encode())

    with patch.object(
        cli, "verify_fix", return_value=make_report(FixVerdict.VERIFIED_FIX)
    ) as verify:
        cli.main(
            ["verify", str(tmp_path), "--patch", str(patch_file), "--test-command", "pytest -q tests"]
        )

    assert verify.call_args.kwargs["run_tests"] is True
    assert verify.call_args.kwargs["test_command"] == ["pytest", "-q", "tests"]


def test_verify_missing_patch_is_usage_error(tmp_path: Path):
    with patch.object(cli, "verify_fix") as verify:
        code = cli.main(["verify", str(tmp_path), "--patch", str(tmp_path / "missing.diff")])

    assert code == cli.EXIT_USAGE_ERROR
    verify.assert_not_called()


def test_verify_writes_json_report(tmp_path: Path):
    patch_file = write_patch(tmp_path, PATCH.encode())
    out = tmp_path / "verify.json"

    with patch.object(cli, "verify_fix", return_value=make_report(FixVerdict.PARTIAL)):
        cli.main(["verify", str(tmp_path), "--patch", str(patch_file), "--json", str(out)])

    assert json.loads(out.read_text(encoding="utf-8"))["verdict"] == "partial"


def test_strict_flag_sets_lowest_regression_threshold(tmp_path: Path):
    patch_file = write_patch(tmp_path, PATCH.encode())

    with patch.object(
        cli, "verify_fix", return_value=make_report(FixVerdict.VERIFIED_FIX)
    ) as verify:
        cli.main(["verify", str(tmp_path), "--patch", str(patch_file)])
        assert verify.call_args.kwargs["regression_severity"] == Severity.MEDIUM

        cli.main(["verify", str(tmp_path), "--patch", str(patch_file), "--strict"])
        assert verify.call_args.kwargs["regression_severity"] == Severity.INFO


def test_scan_triage_cache_flag(tmp_path: Path):
    with patch.object(
        cli, "scan_repository", return_value=make_result(tmp_path, complete=True)
    ) as scan:
        cli.main(["scan", str(tmp_path)])
        assert scan.call_args.kwargs["use_triage_cache"] is True

        cli.main(["scan", str(tmp_path), "--no-triage-cache"])
        assert scan.call_args.kwargs["use_triage_cache"] is False
