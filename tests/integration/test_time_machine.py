"""Time Machine with the real scanners on a small commit history."""

import shutil
import subprocess
from pathlib import Path

import pytest

from silentsec.history import build_timeline

pytestmark = pytest.mark.skipif(
    any(shutil.which(tool) is None for tool in ("git", "semgrep", "bandit", "gitleaks")),
    reason="git, semgrep, bandit and gitleaks are required",
)

SAFE = (
    "import sqlite3\n\n\ndef find_user(conn, name):\n"
    '    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()\n'
)
UNSAFE = SAFE.replace('name = ?", (name,))', "name = '%s'\" % name)")
TOKEN = "ghp_" + "1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4rS5tU"


def commit(repo: Path, files: dict[str, str], message: str) -> None:
    for name, text in files.items():
        (repo / name).write_text(text, encoding="utf-8")
    for args in (["add", "-A"], ["commit", "-q", "-m", message]):
        subprocess.run(
            ["git", "-C", str(repo), "-c", "user.name=dev", "-c", "user.email=dev@example.com", *args],
            check=True,
            capture_output=True,
        )


def test_real_scanners_attribute_each_change_to_its_commit(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    commit(repo, {"db.py": SAFE}, "Add user lookup")
    commit(repo, {"db.py": UNSAFE}, "AI refactor: simplify query")
    commit(repo, {"db.py": SAFE}, "Fix SQL injection")
    commit(repo, {"settings.py": f'TOKEN = "{TOKEN}"\n'}, "Add settings")

    report = build_timeline(repo, database=tmp_path / "h.db", timeout_seconds=240)
    points = {point.subject: point for point in report.points}

    assert all(point.complete for point in report.points)
    introduced = {(c.tool, c.rule_id) for c in points["AI refactor: simplify query"].introduced}
    assert ("bandit", "B608") in introduced
    assert ("semgrep", "silentsec.python.sql-injection.formatted-query") in introduced
    assert {c.tool for c in points["Fix SQL injection"].fixed} >= {"bandit", "semgrep"}
    assert ("gitleaks", "github-pat") in {(c.tool, c.rule_id) for c in points["Add settings"].introduced}
    assert TOKEN not in report.model_dump_json()
    # Bandit's hardcoded-password message used to carry the value into storage.
    assert TOKEN.encode() not in (tmp_path / "h.db").read_bytes()
