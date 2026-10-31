from pathlib import Path

import pytest
from test_gate import commit, fake_scan, git

from silentsec.gate import GatePolicy, GateVerdict, run_gate
from silentsec.report.html import render_report
from silentsec.scope import IgnoreRules, is_test_path, split_findings
from silentsec.scoring import score_findings


@pytest.mark.parametrize(
    "path",
    [
        "tests/unit/test_ai_fix.py",
        "pkg/tests/helpers.py",
        "test/app.py",
        "sample_repositories/semgrep_validation/app.py",
        "fixtures/secret.txt",
        "docs/examples/demo.py",
        "src/test_utils.py",
        "src/app_test.py",
        "conftest.py",
        "web\\__tests__\\app.js",
    ],
)
def test_test_and_sample_paths(path):
    assert is_test_path(path)


@pytest.mark.parametrize(
    "path",
    ["src/app.py", "src/latest.py", "contest.py", "testing_tools/run.py", "src/attest.py"],
)
def test_production_paths(path):
    assert not is_test_path(path)


def test_ignore_rules_follow_gitignore_style():
    rules = IgnoreRules.parse(
        "# vendored code\n"
        "vendor/\n"
        "*.min.js\n"
        "/build\n"
        "docs/**/generated_*.py\n"
        "scripts/*\n"
        "!scripts/keep.py\n"
    )
    ignored = [
        "vendor/lib.py",
        "src/vendor/lib.py",
        "static/app.min.js",
        "build/out.py",
        "docs/api/v1/generated_client.py",
        "scripts/smoke.py",
    ]
    kept = ["src/build/out.py", "src/vendor.py", "app.js", "scripts/keep.py", "src/app.py"]
    for path in ignored:
        assert rules.match(path) is not None, path
    for path in kept:
        assert rules.match(path) is None, path
    assert rules.match("vendor/lib.py").pattern == "vendor/"


def test_missing_ignore_file_ignores_nothing(tmp_path: Path):
    assert IgnoreRules.load(tmp_path).rules == []


def finding(path: str, rule: str = "B605"):
    from silentsec.schemas import Finding, FindingCategory, Severity

    return Finding(
        fingerprint=f"{rule}|{path}",
        tool="fake",
        rule_id=rule,
        file_path=path,
        start_line=1,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message=f"{rule} found",
        confidence=1.0,
    )


def test_split_reports_what_was_excluded(tmp_path: Path):
    (tmp_path / ".silentsecignore").write_text("vendor/\n", encoding="utf-8")
    items = [finding("src/app.py"), finding("tests/test_app.py"), finding("vendor/x.py")]

    main, test_code, ignored, scope = split_findings(items, tmp_path)

    assert [f.file_path for f in main] == ["src/app.py"]
    assert [f.file_path for f in test_code] == ["tests/test_app.py"]
    assert [f.file_path for f in ignored] == ["vendor/x.py"]
    assert scope.ignore_patterns == ["vendor/"]
    assert scope.ignored_files == ["vendor/x.py"]
    lines = scope.lines()
    assert "1 finding(s) in 1 test or sample file(s)" in lines[0]
    assert "excluded by .silentsecignore (patterns: vendor/)" in lines[1]


def test_scan_keeps_test_code_out_of_the_main_score(tmp_path: Path):
    from silentsec.scanners.scanner_service import scan_repository

    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_eval.py").write_text(
        "def test_it(x):\n    return eval(x)\n", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    result = scan_repository(tmp_path, timeout_seconds=60)

    assert all(not is_test_path(f.file_path) for f in result.findings)
    assert all(is_test_path(f.file_path) for f in result.test_findings)
    assert result.scope.test_code_findings == len(result.test_findings)


def test_html_report_lists_test_code_separately(tmp_path: Path):
    from silentsec.scanners.results import ScannerStatus
    from silentsec.scanners.scanner_service import RepositoryScanResult
    from silentsec.scope import ScopeSummary

    test_items = [finding("tests/test_app.py")]
    scan = RepositoryScanResult(
        repo_path=str(tmp_path),
        status=ScannerStatus.SUCCESS,
        duration_seconds=0,
        security_debt=score_findings([]),
        test_findings=test_items,
        test_code_debt=score_findings(test_items),
        scope=ScopeSummary(
            test_code_findings=1, test_code_file_count=1, test_code_files=["tests/test_app.py"]
        ),
    )
    from datetime import datetime

    html = render_report(scan, repo_name="r", generated_at=datetime(2026, 1, 1))
    assert "Not in the score" in html
    assert "Test and sample code: 1 issue" in html
    assert "tests/test_app.py:1" in html


def scoped_fake_scan(root: Path, **kwargs):
    """The gate test scanner, plus the real test-code / ignore split."""
    result = fake_scan(root, **kwargs)
    main, test_code, _ignored, scope = split_findings(result.findings, root)
    return result.model_copy(
        update={
            "findings": main,
            "test_findings": test_code,
            "security_debt": score_findings(main),
            "scope": scope,
        }
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "tests").mkdir()
    git(repo, "init", "-q", "-b", "main")
    commit(repo, {"app.py": "x = 1\n", "tests/test_app.py": "x = 1\n"}, "base")
    git(repo, "switch", "-q", "-c", "feature")
    return repo


def gate(repo: Path, **kwargs):
    return run_gate(repo, base="main", head="feature", scan=scoped_fake_scan, **kwargs)


def test_new_finding_in_test_code_does_not_block(repo: Path):
    commit(repo, {"tests/test_app.py": "import os\nos.system(cmd)\n"}, "test helper")

    report = gate(repo)

    assert report.verdict == GateVerdict.PASS
    assert any("test or sample code were not counted" in item for item in report.limitations)


def test_include_tests_gates_test_code(repo: Path):
    commit(repo, {"tests/test_app.py": "import os\nos.system(cmd)\n"}, "test helper")

    report = gate(repo, policy=GatePolicy(include_tests=True))

    assert report.verdict == GateVerdict.FAIL
    assert [item.file_path for item in report.blocking] == ["tests/test_app.py"]


def test_head_cannot_hide_findings_with_its_own_ignore_file(repo: Path):
    commit(
        repo,
        {"app.py": "import os\nos.system(cmd)\n", ".silentsecignore": "app.py\n"},
        "sneaky",
    )

    report = gate(repo)

    assert report.verdict == GateVerdict.FAIL
    assert any(".silentsecignore" in item for item in report.limitations)


def test_base_ignore_file_applies_to_head(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    commit(repo, {"app.py": "x = 1\n", ".silentsecignore": "vendor/\n"}, "base")
    git(repo, "switch", "-q", "-c", "feature")
    (repo / "vendor").mkdir()
    commit(repo, {"vendor/lib.py": "import os\nos.system(cmd)\n"}, "vendor code")

    report = gate(repo)

    assert report.verdict == GateVerdict.PASS
