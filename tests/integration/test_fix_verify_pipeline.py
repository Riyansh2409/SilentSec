"""End-to-end Fix + Verify with the real scan pipeline."""

import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from silentsec.remediation import FixVerdict, verify_fix
from silentsec.scanners.results import ScannerRunResult, ScannerStatus

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

HANDLER_SOURCE = """\
def load(path):
    try:
        return open(path).read()
    except Exception:
        pass
"""

HANDLER_FIX = """\
--- a/app.py
+++ b/app.py
@@ -1,5 +1,5 @@
 def load(path):
     try:
         return open(path).read()
-    except Exception:
-        pass
+    except FileNotFoundError:
+        raise
"""

SQL_SOURCE = """\
import sqlite3


def find_user(conn, name):
    return conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()
"""

SQL_FIX = """\
--- a/db.py
+++ b/db.py
@@ -2,4 +2,4 @@ import sqlite3


 def find_user(conn, name):
-    return conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()
+    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
"""

# Fixes the SQL injection but adds a command injection.
SQL_FIX_WITH_REGRESSION = """\
--- a/db.py
+++ b/db.py
@@ -1,5 +1,7 @@
 import sqlite3
+import subprocess


 def find_user(conn, name):
-    return conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()
+    subprocess.call("echo " + name, shell=True)
+    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
"""


def skipped(name: str):
    return lambda *args, **kwargs: ScannerRunResult(
        scanner=name, status=ScannerStatus.SKIPPED, duration_seconds=0
    )


def test_real_architecture_analyzer_verifies_exception_handler_fix(tmp_path: Path):
    (tmp_path / "app.py").write_text(HANDLER_SOURCE, encoding="utf-8")

    # External scanners are skipped so this runs without them installed; the
    # real architecture analyzer and scoring pipeline still run.
    with (
        patch("silentsec.scanners.scanner_service.run_semgrep", skipped("semgrep")),
        patch("silentsec.scanners.scanner_service.run_bandit", skipped("bandit")),
        patch("silentsec.scanners.scanner_service.run_gitleaks", skipped("gitleaks")),
    ):
        report = verify_fix(tmp_path, HANDLER_FIX)

    assert report.verdict == FixVerdict.VERIFIED_FIX, report.reasons
    assert {item.rule_id for item in report.resolved} == {"SSEC-ARCH-001", "SSEC-ARCH-002"}
    assert report.score_after < report.score_before
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == HANDLER_SOURCE


requires_scanners = pytest.mark.skipif(
    any(shutil.which(tool) is None for tool in ("semgrep", "bandit", "gitleaks")),
    reason="semgrep, bandit and gitleaks are required",
)


@requires_scanners
def test_real_scanners_verify_sql_injection_fix(tmp_path: Path):
    (tmp_path / "db.py").write_text(SQL_SOURCE, encoding="utf-8")

    report = verify_fix(tmp_path, SQL_FIX, timeout_seconds=240)

    assert report.verdict == FixVerdict.VERIFIED_FIX, report.reasons
    resolved_tools = {item.tool for item in report.resolved}
    assert {"semgrep", "bandit"} <= resolved_tools
    assert set(report.scanners_after.values()) <= {"success", "skipped"}
    assert (tmp_path / "db.py").read_text(encoding="utf-8") == SQL_SOURCE


@requires_scanners
def test_real_scanners_catch_fix_that_introduces_command_injection(tmp_path: Path):
    (tmp_path / "db.py").write_text(SQL_SOURCE, encoding="utf-8")

    report = verify_fix(tmp_path, SQL_FIX_WITH_REGRESSION, timeout_seconds=240)

    assert report.verdict == FixVerdict.REGRESSION, report.reasons
    assert any("shell" in item.rule_id or item.rule_id == "B602" for item in report.new)
    assert report.resolved
