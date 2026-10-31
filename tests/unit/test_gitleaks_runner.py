import json
import shutil
import subprocess
from pathlib import Path

import pytest

from silentsec.scanners import gitleaks_runner
from silentsec.scanners.gitleaks_runner import parse_gitleaks_payload, run_gitleaks
from silentsec.scanners.results import ScannerStatus
from silentsec.schemas import FindingCategory, Severity


def test_parses_gitleaks_finding_without_exposing_secret(tmp_path: Path):
    secret_value = "example-sensitive-token-123456"

    payload = [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API key detected",
            "File": "app/config.py",
            "StartLine": 12,
            "EndLine": 12,
            "Secret": secret_value,
            "Match": f"API_KEY={secret_value}",
            "Fingerprint": "example-fingerprint",
        }
    ]

    findings, errors = parse_gitleaks_payload(payload, tmp_path)

    assert errors == []
    assert len(findings) == 1

    finding = findings[0]

    assert finding.tool == "gitleaks"
    assert finding.rule_id == "generic-api-key"
    assert finding.file_path == "app/config.py"
    assert finding.start_line == 12
    assert finding.category == FindingCategory.SECRET
    assert finding.severity == Severity.HIGH
    assert secret_value not in finding.message
    assert secret_value not in finding.model_dump_json()


def test_skips_invalid_gitleaks_records(tmp_path: Path):
    payload = [
        {
            "RuleID": "missing-path",
            "StartLine": 5,
        }
    ]

    findings, errors = parse_gitleaks_payload(payload, tmp_path)

    assert findings == []
    assert errors


def test_rejects_invalid_report_structure(tmp_path: Path):
    with pytest.raises(TypeError):
        parse_gitleaks_payload({"results": []}, tmp_path)


def _fake_gitleaks(report_payload, seen_paths):
    """Return a subprocess.run replacement that writes a Gitleaks report."""

    def fake_run(command, **kwargs):
        report_arg = next(arg for arg in command if arg.startswith("--report-path="))
        report_path = Path(report_arg.split("=", 1)[1])
        seen_paths.append(report_path)
        report_path.write_text(report_payload, encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    return fake_run


def _tree(root: Path) -> list[str]:
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))


def test_report_is_written_outside_repository_and_removed(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
    before = _tree(repo)

    payload = json.dumps(
        [
            {
                "RuleID": "github-pat",
                "File": str(repo / "app.py"),
                "StartLine": 1,
                "EndLine": 1,
                "Secret": "REDACTED",
            }
        ]
    )
    seen_paths: list[Path] = []
    monkeypatch.setattr(
        gitleaks_runner, "run_bounded", _fake_gitleaks(payload, seen_paths)
    )

    result = run_gitleaks(repo)

    assert result.status == ScannerStatus.SUCCESS
    assert [finding.rule_id for finding in result.findings] == ["github-pat"]
    assert result.findings[0].file_path == "app.py"
    assert seen_paths and not seen_paths[0].is_relative_to(repo)
    assert not seen_paths[0].exists()
    assert _tree(repo) == before


def test_empty_report_means_no_findings(tmp_path: Path, monkeypatch):
    seen_paths: list[Path] = []
    monkeypatch.setattr(gitleaks_runner, "run_bounded", _fake_gitleaks("", seen_paths))

    result = run_gitleaks(tmp_path)

    assert result.status == ScannerStatus.SUCCESS
    assert result.findings == []
    assert not seen_paths[0].exists()


def test_report_is_removed_when_gitleaks_times_out(tmp_path: Path, monkeypatch):
    seen_paths: list[Path] = []

    def fake_run(command, **kwargs):
        report_arg = next(arg for arg in command if arg.startswith("--report-path="))
        seen_paths.append(Path(report_arg.split("=", 1)[1]))
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(gitleaks_runner, "run_bounded", fake_run)

    result = run_gitleaks(tmp_path, timeout_seconds=1)

    assert result.status == ScannerStatus.FAILED
    assert not seen_paths[0].exists()


def test_config_ships_inside_package():
    assert gitleaks_runner.GITLEAKS_CONFIG_PATH.is_file()
    assert "silentsec" in gitleaks_runner.GITLEAKS_CONFIG_PATH.parts


FAKE_TOKEN = "ghp_" + "1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4rS5tU"


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_real_gitleaks_scans_repository_stored_under_excluded_name(tmp_path: Path):
    repo = tmp_path / "build" / "project"
    (repo / "__pycache__").mkdir(parents=True)
    (repo / "settings.py").write_text(f'TOKEN = "{FAKE_TOKEN}"\n', encoding="utf-8")
    (repo / "__pycache__" / "settings.cpython-313.pyc").write_text(
        f"{FAKE_TOKEN}\n", encoding="utf-8"
    )

    result = run_gitleaks(repo)

    assert result.status == ScannerStatus.SUCCESS
    # Found despite the parent folder being named "build"; caches are skipped.
    assert [finding.file_path for finding in result.findings] == ["settings.py"]


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_real_gitleaks_finds_token_without_touching_repository(tmp_path: Path):
    token = "ghp_" + "1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4rS5tU"
    (tmp_path / "settings.py").write_text(f'GITHUB_TOKEN = "{token}"\n', encoding="utf-8")
    before = _tree(tmp_path)

    result = run_gitleaks(tmp_path)

    assert result.status == ScannerStatus.SUCCESS
    assert any(finding.file_path == "settings.py" for finding in result.findings)
    assert token not in result.model_dump_json()
    assert _tree(tmp_path) == before
