"""Security Debt Time Machine."""

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from silentsec import cli
from silentsec.history import HistoryError, HistoryStore, build_timeline
from silentsec.history import store as store_module
from silentsec.history.store import analysis_version, default_database_path
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import scan_repository

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

CLEAN = "def load(path):\n    with open(path) as handle:\n        return handle.read()\n"
SWALLOWED = "def load(path):\n    try:\n        return open(path).read()\n    except Exception:\n        pass\n"


def git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_DATE": "2026-10-01T10:00:00",
        "GIT_COMMITTER_DATE": "2026-10-01T10:00:00",
    }
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=dev", "-c", "user.email=dev@example.com", *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout


def commit(repo: Path, files: dict[str, str], message: str) -> None:
    for name, text in files.items():
        (repo / name).write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    commit(root, {"app.py": CLEAN}, "Add loader")
    commit(root, {"app.py": SWALLOWED}, "Refactor loader")
    commit(root, {"app.py": CLEAN}, "Handle errors properly")
    return root


def skipped(name: str):
    return lambda *args, **kwargs: ScannerRunResult(
        scanner=name, status=ScannerStatus.SKIPPED, duration_seconds=0
    )


@pytest.fixture
def architecture_only():
    """Use the real architecture analyzer; skip external scanners."""
    with (
        patch("silentsec.scanners.scanner_service.run_semgrep", skipped("semgrep")),
        patch("silentsec.scanners.scanner_service.run_bandit", skipped("bandit")),
        patch("silentsec.scanners.scanner_service.run_gitleaks", skipped("gitleaks")),
    ):
        yield


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        digest.update(path.relative_to(root).as_posix().encode())
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def test_attributes_introduced_and_fixed_findings(repo: Path, tmp_path: Path, architecture_only):
    report = build_timeline(repo, database=tmp_path / "h.db")

    assert [point.subject for point in report.points] == [
        "Add loader",
        "Refactor loader",
        "Handle errors properly",
    ]
    first, second, third = report.points
    assert first.attribution == "baseline"
    assert {change.rule_id for change in second.introduced} == {"SSEC-ARCH-001", "SSEC-ARCH-002"}
    assert second.fixed == []
    assert {change.rule_id for change in third.fixed} == {"SSEC-ARCH-001", "SSEC-ARCH-002"}
    assert third.introduced == []
    assert second.raw_score > first.raw_score == third.raw_score == 0
    assert report.biggest_increase.subject == "Refactor loader"
    assert report.branch == "main"


def test_repository_and_git_directory_are_untouched(repo: Path, tmp_path: Path, architecture_only):
    (repo / "uncommitted.py").write_text("x = 1\n", encoding="utf-8")
    before = tree_digest(repo)

    report = build_timeline(repo, database=tmp_path / "h.db")

    assert tree_digest(repo) == before
    # Uncommitted files are never part of the history.
    assert all(
        point.unique_issues == 0 or point.subject == "Refactor loader" for point in report.points
    )


def test_second_run_reuses_stored_scans(repo: Path, tmp_path: Path):
    calls: list[Path] = []

    def counting_scan(root, **kwargs):
        calls.append(Path(root))
        return scan_repository(root, **kwargs)

    with (
        patch("silentsec.scanners.scanner_service.run_semgrep", skipped("semgrep")),
        patch("silentsec.scanners.scanner_service.run_bandit", skipped("bandit")),
        patch("silentsec.scanners.scanner_service.run_gitleaks", skipped("gitleaks")),
    ):
        first = build_timeline(repo, database=tmp_path / "h.db", scan=counting_scan)
        second = build_timeline(repo, database=tmp_path / "h.db", scan=counting_scan)
        third = build_timeline(
            repo, database=tmp_path / "h.db", scan=counting_scan, use_cache=False
        )

    assert len(calls) == 6  # 3 for the first run, 0 for the second, 3 for --no-cache
    assert not any(point.from_cache for point in first.points)
    assert all(point.from_cache for point in second.points)
    assert [p.raw_score for p in first.points] == [p.raw_score for p in second.points]
    assert not any(point.from_cache for point in third.points)
    # Every scan ran on a temporary export, never on the repository itself.
    assert all(not root.is_relative_to(repo) for root in calls)


def test_incomplete_scans_are_marked_unknown_and_not_stored(repo: Path, tmp_path: Path):
    def failing_bandit(*args, **kwargs):
        return ScannerRunResult(scanner="bandit", status=ScannerStatus.FAILED, duration_seconds=0)

    with (
        patch("silentsec.scanners.scanner_service.run_semgrep", skipped("semgrep")),
        patch("silentsec.scanners.scanner_service.run_bandit", failing_bandit),
        patch("silentsec.scanners.scanner_service.run_gitleaks", skipped("gitleaks")),
    ):
        report = build_timeline(repo, database=tmp_path / "h.db")

    assert all(not point.complete for point in report.points)
    assert [point.attribution for point in report.points] == ["baseline", "unknown", "unknown"]
    assert all(point.introduced == [] for point in report.points)
    assert (
        HistoryStore(tmp_path / "h.db").get(report.points[0].commit_sha, analysis_version()) is None
    )
    assert any("incomplete" in item for item in report.limitations)


def test_commit_window_is_limited(repo: Path, tmp_path: Path, architecture_only):
    report = build_timeline(repo, commits=2, database=tmp_path / "h.db")

    assert [point.subject for point in report.points] == [
        "Refactor loader",
        "Handle errors properly",
    ]
    assert report.points[0].attribution == "baseline"

    with pytest.raises(ValueError):
        build_timeline(repo, commits=0, database=tmp_path / "h.db")
    with pytest.raises(ValueError):
        build_timeline(repo, commits=51, database=tmp_path / "h.db")


def test_short_history_is_reported(repo: Path, tmp_path: Path, architecture_only):
    report = build_timeline(repo, commits=10, database=tmp_path / "h.db")

    assert any("Only 3 commit(s)" in item for item in report.limitations)


def test_shallow_clone_is_reported(repo: Path, tmp_path: Path, architecture_only):
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", repo.as_uri(), str(shallow)],
        check=True,
        capture_output=True,
    )

    report = build_timeline(shallow, database=tmp_path / "s.db")

    assert report.shallow_clone
    assert any("shallow clone" in item for item in report.limitations)


def test_not_a_git_repository(tmp_path: Path, monkeypatch):
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))

    with pytest.raises(HistoryError, match="Not a Git repository"):
        build_timeline(plain, database=tmp_path / "h.db")


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_symlink_leaving_repository_is_skipped(repo: Path, tmp_path: Path, architecture_only):
    (repo / "escape").symlink_to("../../../../etc")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "Add link")

    report = build_timeline(repo, commits=1, database=tmp_path / "h.db")

    assert report.points[0].complete
    assert any("unsafe archive" in item for item in report.limitations)


def test_default_database_is_outside_repository(repo: Path):
    path = default_database_path(repo)

    assert not path.is_relative_to(repo)
    assert path.suffix == ".db"


def test_analysis_version_changes_with_rules(tmp_path: Path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yml").write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr(store_module, "_RULES_DIR", rules)
    before = analysis_version()

    (rules / "r.yml").write_text("rules: [changed]\n", encoding="utf-8")

    assert analysis_version() != before


# --- CLI --------------------------------------------------------------------


def test_cli_prints_timeline_table(repo: Path, tmp_path: Path, architecture_only, capsys):
    code = cli.main(["history", str(repo), "--db", str(tmp_path / "h.db")])

    output = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "SilentSec Time Machine" in output
    assert "Refactor loader" in output
    assert "Biggest increase:" in output
    assert "SSEC-ARCH-002" in output


def test_progress_reports_cached_commits_separately(repo: Path, tmp_path: Path, architecture_only):
    first: list[tuple] = []
    second: list[tuple] = []

    build_timeline(repo, database=tmp_path / "h.db", progress=lambda *a: first.append(a))
    build_timeline(repo, database=tmp_path / "h.db", progress=lambda *a: second.append(a))

    assert [(index, total, cached) for index, total, _, cached in first] == [
        (1, 3, False),
        (2, 3, False),
        (3, 3, False),
    ]
    assert [(index, cached) for index, _, _, cached in second] == [(1, True), (2, True), (3, True)]
    assert all(len(sha) == 12 for _, _, sha, _ in second)


def test_cli_progress_says_stored_scan_for_cached_commits(
    repo: Path, tmp_path: Path, architecture_only, capsys
):
    cli.main(["history", str(repo), "--db", str(tmp_path / "h.db")])
    first = capsys.readouterr().err
    cli.main(["history", str(repo), "--db", str(tmp_path / "h.db")])
    second = capsys.readouterr().err

    assert first.count("Scanning commit") == 3 and "Using stored scan" not in first
    assert second.count("Using stored scan") == 3 and "Scanning commit" not in second
    assert "Using stored scan 1/3 (" in second


def test_cli_history_suggests_longer_timeout_after_scanner_timeout(
    repo: Path, tmp_path: Path, capsys
):
    def timed_out(*args, **kwargs):
        return ScannerRunResult(
            scanner="semgrep",
            status=ScannerStatus.FAILED,
            duration_seconds=180,
            errors=["Scanner timed out after 180 seconds."],
        )

    with (
        patch("silentsec.scanners.scanner_service.run_semgrep", timed_out),
        patch("silentsec.scanners.scanner_service.run_bandit", skipped("bandit")),
        patch("silentsec.scanners.scanner_service.run_gitleaks", skipped("gitleaks")),
    ):
        code = cli.main(["history", str(repo), "--db", str(tmp_path / "h.db")])

    output = capsys.readouterr().out
    assert code == cli.EXIT_SCAN_INCOMPLETE
    # One hint for the whole table, not one per failed commit.
    assert output.count("Try --timeout 600 for large repositories.") == 1


def test_cli_rejects_bad_options_and_non_repositories(tmp_path: Path, monkeypatch, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))

    assert cli.main(["history", str(plain), "--commits", "0"]) == cli.EXIT_USAGE_ERROR
    assert cli.main(["history", str(plain), "--db", str(tmp_path / "h.db")]) == cli.EXIT_USAGE_ERROR
    assert "Not a Git repository" in capsys.readouterr().err


def test_incomplete_commit_explains_which_scanner_failed_and_hides_fake_change(
    repo: Path, tmp_path: Path, capsys
):
    """Reproduces the Windows case: one commit's Semgrep run times out."""
    calls = {"count": 0}

    def flaky_semgrep(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 3:  # the newest commit
            return ScannerRunResult(
                scanner="semgrep",
                status=ScannerStatus.PARTIAL,
                duration_seconds=0,
                errors=["Timeout when running rules on app.py"],
            )
        return ScannerRunResult(scanner="semgrep", status=ScannerStatus.SUCCESS, duration_seconds=0)

    with (
        patch("silentsec.scanners.scanner_service.run_semgrep", flaky_semgrep),
        patch("silentsec.scanners.scanner_service.run_bandit", skipped("bandit")),
        patch("silentsec.scanners.scanner_service.run_gitleaks", skipped("gitleaks")),
    ):
        report = build_timeline(repo, database=tmp_path / "h.db")
        # Fresh counter and database so the CLI run hits the same failure.
        calls["count"] = 0
        cli.main(["history", str(repo), "--db", str(tmp_path / "cli.db")])

    last = report.points[-1]
    assert not last.complete
    assert last.scanner_problems == ["semgrep (partial): Timeout when running rules on app.py"]
    # The drop to the last commit is not counted as a real change.
    assert report.biggest_increase.subject == "Refactor loader"

    output = capsys.readouterr().out
    last_row = next(line for line in output.splitlines() if line.startswith(last.short_sha))
    assert " ? " in last_row and "[incomplete scan]" in last_row
    assert "! semgrep (partial): Timeout when running rules on app.py" in output
    # A per-file rule timeout is not a whole-scanner timeout.
    assert "Try --timeout" not in output


def test_biggest_increase_ignores_steps_next_to_incomplete_scans():
    from silentsec.history.timeline import TimelinePoint, TimelineReport

    def point(sha: str, raw: float, complete: bool = True) -> TimelinePoint:
        return TimelinePoint(
            commit_sha=sha * 40,
            short_sha=sha * 8,
            committed_at="2026-10-01T00:00:00+00:00",
            subject=sha,
            score=raw,
            raw_score=raw,
            security_points=raw,
            architecture_points=0,
            unique_issues=1,
            complete=complete,
        )

    report = TimelineReport(
        repo_path="r",
        branch="main",
        analysis_version="v",
        database="d",
        points=[point("a", 10), point("b", 0, complete=False), point("c", 40), point("d", 45)],
    )

    # 0 -> 40 crosses an incomplete scan and is ignored; 40 -> 45 is the real rise.
    assert report.biggest_increase.subject == "d"


def test_analysis_version_changes_with_analysis_code(tmp_path: Path, monkeypatch):
    package = tmp_path / "silentsec"
    (package / "scoring").mkdir(parents=True)
    engine = package / "scoring" / "engine.py"
    engine.write_text("POINTS = 1\n", encoding="utf-8")
    monkeypatch.setattr(store_module, "_PACKAGE_DIR", package)
    before = analysis_version()

    engine.write_text("POINTS = 2\n", encoding="utf-8")
    changed = analysis_version()
    engine.write_bytes(b"POINTS = 2\r\n")  # a Windows checkout of the same code

    assert changed != before
    assert analysis_version() == changed
