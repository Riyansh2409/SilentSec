import json
from pathlib import Path
from unittest.mock import patch

from silentsec import cli
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult
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
