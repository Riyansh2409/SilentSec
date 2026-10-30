"""AI fix proposals verified by the real scanners (the model itself is scripted)."""

import json
import shutil
from pathlib import Path

import pytest

from silentsec.remediation.ai_fix import AIFixStatus, ai_fix_and_verify
from silentsec.remediation.verify import FixVerdict

pytestmark = pytest.mark.skipif(
    any(shutil.which(tool) is None for tool in ("git", "semgrep", "bandit", "gitleaks")),
    reason="git, semgrep, bandit and gitleaks are required",
)

SOURCE = """\
import sqlite3


def find_user(conn, name):
    return conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()
"""


class ScriptedModel:
    """Stands in for an LLM: answers with fixed edits for whatever finding it gets."""

    name = "scripted:model"
    model = "model"

    def __init__(self, replacement: str):
        self.replacement = replacement

    def complete(self, *, system: str, user: str) -> str:
        finding = json.loads(user.split("\n", 1)[1])["finding"]
        return json.dumps(
            {
                "fingerprint": finding["fingerprint"],
                "explanation": "Scripted edit.",
                "edits": [{"start_line": 5, "end_line": 5, "replacement": self.replacement}],
            }
        )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "db.py").write_text(SOURCE, encoding="utf-8")
    return tmp_path


def test_correct_ai_fix_is_verified(repo: Path):
    model = ScriptedModel(
        '    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()'
    )

    report = ai_fix_and_verify(repo, providers=[model], timeout_seconds=240)

    assert report.status == AIFixStatus.PROPOSED, report.errors
    assert report.verification.verdict == FixVerdict.VERIFIED_FIX, report.verification.reasons
    assert (repo / "db.py").read_text(encoding="utf-8") == SOURCE


def test_ai_fix_that_adds_command_injection_is_a_regression(repo: Path):
    model = ScriptedModel(
        "    import subprocess\n"
        '    subprocess.call("echo " + name, shell=True)\n'
        '    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()'
    )

    report = ai_fix_and_verify(repo, providers=[model], timeout_seconds=240)

    assert report.status == AIFixStatus.PROPOSED
    assert report.verification.verdict == FixVerdict.REGRESSION, report.verification.reasons
    assert report.verification.new
