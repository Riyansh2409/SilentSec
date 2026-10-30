"""Verdict tests for verify_fix with an injected scan function."""

import hashlib
import shutil
import sys
from pathlib import Path

import pytest

from silentsec.remediation import FixVerdict, verify_fix
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult
from silentsec.schemas import Finding, FindingCategory, Severity
from silentsec.scoring import score_findings

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

SOURCE = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
FIX = """\
--- a/app.py
+++ b/app.py
@@ -1,5 +1,6 @@
 import os
+import subprocess


 def run(cmd):
-    os.system(cmd)
+    subprocess.run(["echo", cmd], check=True)
"""


def finding(rule_id: str, *, file_path: str = "app.py", line: int = 5) -> Finding:
    return Finding(
        fingerprint=f"{rule_id}-{file_path}-{line}",
        tool="semgrep",
        rule_id=rule_id,
        file_path=file_path,
        start_line=line,
        end_line=line,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message="m",
    )


def scan_result(findings: list[Finding], status: ScannerStatus = ScannerStatus.SUCCESS):
    return RepositoryScanResult(
        repo_path="copy",
        status=status,
        scanners=[ScannerRunResult(scanner="semgrep", status=status, duration_seconds=0)],
        findings=findings,
        duration_seconds=0,
        security_debt=score_findings(findings),
        security_debt_complete=status == ScannerStatus.SUCCESS,
    )


class FakeScanner:
    """Return the baseline result on the first call and the after-patch result next."""

    def __init__(self, *results: RepositoryScanResult) -> None:
        self.results = list(results)
        self.roots: list[Path] = []

    def __call__(self, root, **kwargs):
        assert kwargs["enable_ai_triage"] is False
        self.roots.append(Path(root))
        return self.results.pop(0)


def digest(root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        h.update(path.relative_to(root).as_posix().encode())
        if path.is_file():
            h.update(path.read_bytes())
    return h.hexdigest()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(SOURCE, encoding="utf-8")
    return root


def test_verified_fix(repo: Path):
    target = finding("os-system")
    scanner = FakeScanner(scan_result([target]), scan_result([]))
    before = digest(repo)

    report = verify_fix(repo, FIX, scan=scanner)

    assert report.verdict == FixVerdict.VERIFIED_FIX, report.reasons
    assert [item.rule_id for item in report.resolved] == ["os-system"]
    assert report.remaining == [] and report.new == []
    assert report.score_before > report.score_after == 0
    assert report.patch_files == ["app.py"]
    assert digest(repo) == before
    # Both scans ran on the isolated copy, never on the original.
    assert all(not root.is_relative_to(repo) for root in scanner.roots)
    assert scanner.roots[0] == scanner.roots[1]


def test_partial_fix(repo: Path):
    # Both findings are on line 5, which the patch changes.
    fixed, still = finding("os-system"), finding("other-rule")
    scanner = FakeScanner(scan_result([fixed, still]), scan_result([still]))

    report = verify_fix(repo, FIX, scan=scanner)

    assert report.verdict == FixVerdict.PARTIAL
    assert [item.rule_id for item in report.remaining] == ["other-rule"]


def test_default_targets_are_findings_on_changed_lines_only(repo: Path):
    target = finding("os-system", line=5)
    unrelated = finding("hardcoded-token", line=4)
    scanner = FakeScanner(scan_result([target, unrelated]), scan_result([unrelated]))

    report = verify_fix(repo, FIX, scan=scanner)

    assert report.verdict == FixVerdict.VERIFIED_FIX
    assert [item.rule_id for item in report.targets] == ["os-system"]


def low_finding(rule_id: str, line: int) -> Finding:
    return finding(rule_id, line=line).model_copy(update={"severity": Severity.LOW})


def test_new_low_severity_finding_is_reported_but_not_a_regression(repo: Path):
    scanner = FakeScanner(
        scan_result([finding("os-system")]),
        scan_result([low_finding("subprocess-without-shell", 7)]),
    )

    report = verify_fix(repo, FIX, scan=scanner)

    assert report.verdict == FixVerdict.VERIFIED_FIX
    assert [item.rule_id for item in report.new] == ["subprocess-without-shell"]
    assert any("lower-severity" in reason for reason in report.reasons)


def test_strict_threshold_treats_any_new_finding_as_regression(repo: Path):
    scanner = FakeScanner(
        scan_result([finding("os-system")]),
        scan_result([low_finding("subprocess-without-shell", 7)]),
    )

    report = verify_fix(repo, FIX, scan=scanner, regression_severity=Severity.INFO)

    assert report.verdict == FixVerdict.REGRESSION


def test_unresolved_fix(repo: Path):
    target = finding("os-system")
    scanner = FakeScanner(scan_result([target]), scan_result([target]))

    assert verify_fix(repo, FIX, scan=scanner).verdict == FixVerdict.UNRESOLVED


def test_new_finding_is_a_regression(repo: Path):
    target, introduced = finding("os-system"), finding("subprocess-shell", line=6)
    scanner = FakeScanner(scan_result([target]), scan_result([introduced]))

    report = verify_fix(repo, FIX, scan=scanner)

    assert report.verdict == FixVerdict.REGRESSION
    assert [item.rule_id for item in report.new] == ["subprocess-shell"]
    assert [item.rule_id for item in report.resolved] == ["os-system"]


def test_new_finding_in_untouched_file_is_still_a_regression(repo: Path):
    target = finding("os-system")
    elsewhere = finding("os-system", file_path="other.py")
    scanner = FakeScanner(scan_result([target]), scan_result([elsewhere]))

    assert verify_fix(repo, FIX, scan=scanner).verdict == FixVerdict.REGRESSION


def test_failing_tests_are_a_regression(repo: Path):
    scanner = FakeScanner(scan_result([finding("os-system")]), scan_result([]))

    report = verify_fix(
        repo,
        FIX,
        scan=scanner,
        run_tests=True,
        test_command=[sys.executable, "-c", "raise SystemExit(3)"],
    )

    assert report.verdict == FixVerdict.REGRESSION
    assert report.tests.exit_code == 3
    assert any(check.startswith("tests:") for check in report.checks_run)


def test_passing_tests_keep_a_verified_fix(repo: Path):
    scanner = FakeScanner(scan_result([finding("os-system")]), scan_result([]))

    report = verify_fix(
        repo,
        FIX,
        scan=scanner,
        run_tests=True,
        test_command=[sys.executable, "-c", "import app"],
    )

    assert report.verdict == FixVerdict.VERIFIED_FIX, report.reasons
    assert report.tests.passed
    assert not any("tests were not run" in item for item in report.limitations)


def test_test_timeout_is_not_verified(repo: Path):
    scanner = FakeScanner(scan_result([finding("os-system")]), scan_result([]))

    report = verify_fix(
        repo,
        FIX,
        scan=scanner,
        run_tests=True,
        test_command=[sys.executable, "-c", "import time; time.sleep(30)"],
        test_timeout_seconds=1,
    )

    assert report.verdict == FixVerdict.NOT_VERIFIED
    assert report.tests.timed_out


def test_tests_run_without_credentials(repo: Path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "real-key")
    monkeypatch.setenv("GITHUB_TOKEN", "real-token")
    scanner = FakeScanner(scan_result([finding("os-system")]), scan_result([]))
    probe = "import os, sys; sys.exit(int('GEMINI_API_KEY' in os.environ or 'GITHUB_TOKEN' in os.environ))"

    report = verify_fix(
        repo,
        FIX,
        scan=scanner,
        run_tests=True,
        test_command=[sys.executable, "-c", probe],
    )

    assert report.tests.passed, report.tests.output_tail


def test_incomplete_scan_is_not_verified(repo: Path):
    target = finding("os-system")
    scanner = FakeScanner(scan_result([target]), scan_result([], ScannerStatus.FAILED))

    report = verify_fix(repo, FIX, scan=scanner)

    assert report.verdict == FixVerdict.NOT_VERIFIED
    assert "semgrep (failed)" in report.reasons[0]
    assert report.resolved == []


def test_invalid_patch_is_not_verified_and_nothing_is_scanned(repo: Path):
    scanner = FakeScanner()

    report = verify_fix(repo, "--- a/../x.py\n+++ b/../x.py\n@@ -1 +1 @@\n-a\n+b\n", scan=scanner)

    assert report.verdict == FixVerdict.NOT_VERIFIED
    assert scanner.roots == []


def test_patch_that_does_not_apply_is_not_verified(repo: Path):
    scanner = FakeScanner(scan_result([finding("os-system")]))

    report = verify_fix(repo, FIX.replace("os.system(cmd)", "os.system(x)"), scan=scanner)

    assert report.verdict == FixVerdict.NOT_VERIFIED
    assert "could not be applied" in report.reasons[0]
    assert len(scanner.roots) == 1


def test_patch_touching_no_finding_is_not_verified(repo: Path):
    scanner = FakeScanner(scan_result([finding("x", file_path="other.py")]), scan_result([]))

    report = verify_fix(repo, FIX, scan=scanner)

    assert report.verdict == FixVerdict.NOT_VERIFIED
    assert "No targeted findings" in report.reasons[0]


def test_explicit_target_fingerprints(repo: Path):
    first, second = finding("os-system"), finding("other-rule", line=4)
    scanner = FakeScanner(scan_result([first, second]), scan_result([second]))

    report = verify_fix(repo, FIX, scan=scanner, target_fingerprints=[first.fingerprint])

    assert report.verdict == FixVerdict.VERIFIED_FIX
    assert [item.fingerprint for item in report.targets] == [first.fingerprint]


def test_unknown_target_fingerprint_is_not_verified(repo: Path):
    scanner = FakeScanner(scan_result([finding("os-system")]))

    report = verify_fix(repo, FIX, scan=scanner, target_fingerprints=["missing"])

    assert report.verdict == FixVerdict.NOT_VERIFIED
    assert "missing" in report.reasons[0]


def test_report_states_limitations(repo: Path):
    scanner = FakeScanner(scan_result([finding("os-system")]), scan_result([]))

    report = verify_fix(repo, FIX, scan=scanner)

    assert any("do not prove the absence" in item for item in report.limitations)
    assert any("tests were not run" in item for item in report.limitations)
    assert report.diff_text == FIX
