import shutil
import subprocess
from pathlib import Path

import pytest

from silentsec.scanners import semgrep_runner
from silentsec.scanners.results import ScannerStatus
from silentsec.scanners.semgrep_runner import (
    BUNDLED_SEMGREP_RULES,
    SEMGREP_CONFIG_ENV,
    resolve_semgrep_config,
    run_semgrep,
)


def test_bundled_rules_ship_inside_package():
    assert BUNDLED_SEMGREP_RULES.is_dir()
    assert list(BUNDLED_SEMGREP_RULES.glob("*.yml"))
    assert "silentsec" in BUNDLED_SEMGREP_RULES.parts


def test_default_config_is_offline_bundled_rules(monkeypatch):
    monkeypatch.delenv(SEMGREP_CONFIG_ENV, raising=False)

    assert resolve_semgrep_config() == str(BUNDLED_SEMGREP_RULES)


def test_environment_override_is_used(monkeypatch):
    monkeypatch.setenv(SEMGREP_CONFIG_ENV, "p/security-audit")

    assert resolve_semgrep_config() == "p/security-audit"


def test_explicit_config_wins_over_environment(monkeypatch):
    monkeypatch.setenv(SEMGREP_CONFIG_ENV, "p/security-audit")

    assert resolve_semgrep_config("custom.yml") == "custom.yml"


def test_command_is_offline_and_bounded(tmp_path: Path, monkeypatch):
    monkeypatch.delenv(SEMGREP_CONFIG_ENV, raising=False)
    captured: dict = {}

    def fake_run_json_command(**kwargs):
        captured.update(kwargs)
        return semgrep_runner.ScannerRunResult(
            scanner="semgrep",
            status=ScannerStatus.SUCCESS,
            duration_seconds=0,
        )

    monkeypatch.setattr(semgrep_runner, "run_json_command", fake_run_json_command)

    run_semgrep(tmp_path)
    command = captured["command"]

    assert command[command.index("--config") + 1] == str(BUNDLED_SEMGREP_RULES)
    assert "--metrics=off" in command
    assert "--disable-version-check" in command
    assert command[command.index("--timeout") + 1] == "30"


VULNERABLE_SOURCE = '''
import subprocess


def lookup(conn, name):
    return conn.execute("SELECT * FROM users WHERE name = '%s'" % name)


def run(cmd):
    return subprocess.call(cmd, shell=True)


def safe(conn, name):
    return conn.execute("SELECT * FROM users WHERE name = ?", (name,))


def not_sql(lines, name):
    lines.append(f"hello {name}")
    lines.append("total: %s" % name)
    return "-".join(lines)
'''


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_real_semgrep_bundled_rules_detect_known_issues(tmp_path: Path, monkeypatch):
    monkeypatch.delenv(SEMGREP_CONFIG_ENV, raising=False)
    (tmp_path / "app.py").write_text(VULNERABLE_SOURCE, encoding="utf-8")

    result = run_semgrep(tmp_path, timeout_seconds=120)

    assert result.status == ScannerStatus.SUCCESS, result.errors
    found = {(finding.rule_id, finding.start_line) for finding in result.findings}
    assert ("silentsec.python.sql-injection.formatted-query", 6) in found
    assert ("silentsec.python.command-injection.subprocess-shell-true", 10) in found
    assert all(finding.start_line != 14 for finding in result.findings)
    # String formatting outside execute() is not SQL injection.
    assert all(finding.start_line < 17 for finding in result.findings)
    assert {finding.cwe_id for finding in result.findings} == {"CWE-89", "CWE-78"}


def test_bundled_rule_ids_are_read_from_yaml():
    ids = semgrep_runner.bundled_rule_ids()

    assert "silentsec.python.sql-injection.formatted-query" in ids
    assert len(ids) >= 10


def test_local_path_prefix_is_stripped_from_rule_id():
    rule = "silentsec.python.sql-injection.formatted-query"

    assert semgrep_runner.normalize_rule_id(f"home.user.repo.rules.semgrep.{rule}") == rule
    assert semgrep_runner.normalize_rule_id(rule) == rule
    assert semgrep_runner.normalize_rule_id("python.lang.security.audit.eval") == (
        "python.lang.security.audit.eval"
    )


def test_parser_reports_machine_independent_rule_ids(tmp_path: Path):
    payload = {
        "results": [
            {
                "check_id": (
                    "C.Users.dev.SilentSec.src.silentsec.rules.semgrep."
                    "silentsec.python.tempfile.mktemp"
                ),
                "path": "app.py",
                "start": {"line": 3},
                "end": {"line": 3},
                "extra": {"severity": "WARNING", "message": "m", "metadata": {}},
            }
        ]
    }

    findings, errors = semgrep_runner.parse_semgrep_payload(payload, tmp_path)

    assert errors == []
    assert findings[0].rule_id == "silentsec.python.tempfile.mktemp"


def test_command_targets_repository_relative_path(tmp_path: Path, monkeypatch):
    captured: dict = {}

    def fake_run_json_command(**kwargs):
        captured.update(kwargs)
        return semgrep_runner.ScannerRunResult(
            scanner="semgrep",
            status=ScannerStatus.SUCCESS,
            duration_seconds=0,
        )

    monkeypatch.setattr(semgrep_runner, "run_json_command", fake_run_json_command)

    run_semgrep(tmp_path)

    # Excludes only apply inside the repository when the target is relative.
    assert captured["command"][-1] == "."
    assert captured["repo_path"] == tmp_path.resolve()
    assert "sample_repositories" not in captured["command"]


def _captured_command(repo: Path, monkeypatch) -> list[str]:
    captured: dict = {}

    def fake_run_json_command(**kwargs):
        captured.update(kwargs)
        return semgrep_runner.ScannerRunResult(
            scanner="semgrep",
            status=ScannerStatus.SUCCESS,
            duration_seconds=0,
        )

    monkeypatch.setattr(semgrep_runner, "run_json_command", fake_run_json_command)
    run_semgrep(repo)
    return captured["command"]


def test_folder_without_git_is_its_own_project_root(tmp_path: Path, monkeypatch):
    command = _captured_command(tmp_path, monkeypatch)

    # Otherwise Semgrep uses a parent Git repository (e.g. a home folder) as
    # the project root and walks all of it.
    assert command[command.index("--project-root") + 1] == "."
    assert command[-1] == "."


def test_git_repository_keeps_default_project_root(tmp_path: Path, monkeypatch):
    (tmp_path / ".git").mkdir()

    assert "--project-root" not in _captured_command(tmp_path, monkeypatch)


def test_git_worktree_or_submodule_keeps_default_project_root(tmp_path: Path, monkeypatch):
    # In worktrees and submodules .git is a file pointing at the real git dir.
    (tmp_path / ".git").write_text("gitdir: ../.git/worktrees/x\n", encoding="utf-8")

    assert "--project-root" not in _captured_command(tmp_path, monkeypatch)


@pytest.mark.skipif(
    shutil.which("semgrep") is None or shutil.which("git") is None,
    reason="semgrep or git not installed",
)
def test_real_semgrep_scans_folder_nested_in_git_repository(tmp_path: Path, monkeypatch):
    monkeypatch.delenv(SEMGREP_CONFIG_ENV, raising=False)
    # Same layout as a history snapshot under a home folder that is a Git repo.
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    snapshot = tmp_path / "work" / "repo"
    snapshot.mkdir(parents=True)
    (snapshot / "app.py").write_text("eval(input())\n", encoding="utf-8")

    result = run_semgrep(snapshot, timeout_seconds=120)

    assert result.status == ScannerStatus.SUCCESS, result.errors
    assert [finding.file_path for finding in result.findings] == ["app.py"]


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_real_semgrep_scans_repository_stored_under_excluded_name(
    tmp_path: Path, monkeypatch
):
    monkeypatch.delenv(SEMGREP_CONFIG_ENV, raising=False)
    repo = tmp_path / "build" / "project"
    (repo / "build").mkdir(parents=True)
    (repo / "app.py").write_text("eval(input())\n", encoding="utf-8")
    (repo / "build" / "generated.py").write_text("eval(input())\n", encoding="utf-8")

    result = run_semgrep(repo, timeout_seconds=120)

    assert result.status == ScannerStatus.SUCCESS, result.errors
    # The repository is scanned even though a parent folder is named "build",
    # while its own build/ folder is still excluded.
    assert [finding.file_path for finding in result.findings] == ["app.py"]


OBFUSCATED_SOURCE = '''
import importlib
import os
import subprocess


def run(cmd):
    __import__("os").system(cmd)
    importlib.import_module("os").system(cmd)
    getattr(os, "system")(cmd)
    os.execvp(cmd, [cmd])
    subprocess.getoutput(cmd)


def safe():
    __import__("json").dumps({})
    getattr(os, "getcwd")()
    os.execvp("ls", ["ls"])
    subprocess.getoutput("date")
'''


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_real_semgrep_catches_obfuscated_command_execution(tmp_path: Path, monkeypatch):
    monkeypatch.delenv(SEMGREP_CONFIG_ENV, raising=False)
    (tmp_path / "app.py").write_text(OBFUSCATED_SOURCE, encoding="utf-8")

    result = run_semgrep(tmp_path, timeout_seconds=120)

    assert result.status == ScannerStatus.SUCCESS, result.errors
    lines = sorted({finding.start_line for finding in result.findings})
    assert lines == [8, 9, 10, 11, 12]
    assert {finding.cwe_id for finding in result.findings} == {"CWE-78"}
