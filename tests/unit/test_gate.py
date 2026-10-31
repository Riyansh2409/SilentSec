import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from silentsec import cli
from silentsec.gate import GatePolicy, GateReport, GateVerdict, run_gate
from silentsec.history import HistoryError
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult
from silentsec.schemas import Finding, FindingCategory, Severity
from silentsec.scoring import score_findings

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

# Markers in file content -> the finding the fake scanner reports for them.
RULES = {
    "os.system": ("B605", FindingCategory.SECURITY, Severity.HIGH),
    "md5(": ("B324", FindingCategory.SECURITY, Severity.MEDIUM),
    "API_KEY": ("generic-api-key", FindingCategory.SECRET, Severity.HIGH),
    "except: pass": ("SSEC-ARCH-002", FindingCategory.ARCHITECTURE, Severity.MEDIUM),
}


def fake_scan(root: Path, *, fail: bool = False, **kwargs) -> RepositoryScanResult:
    findings = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for marker, (rule, category, severity) in RULES.items():
                if marker in line:
                    findings.append(
                        Finding(
                            fingerprint=f"{rule}|{relative}|{number}",
                            tool="fake",
                            rule_id=rule,
                            file_path=relative,
                            start_line=number,
                            category=category,
                            severity=severity,
                            message=f"{rule} found",
                            confidence=1.0,
                        )
                    )
    status = ScannerStatus.FAILED if fail else ScannerStatus.SUCCESS
    return RepositoryScanResult(
        repo_path=str(root),
        status=status,
        scanners=[
            ScannerRunResult(
                scanner="fake",
                status=status,
                findings=findings,
                duration_seconds=0.1,
                errors=["Scanner timed out after 180 seconds."] if fail else [],
            )
        ],
        findings=findings,
        duration_seconds=0.1,
        security_debt=score_findings(findings),
        security_debt_complete=not fail,
    )


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@e", "-c", "core.autocrlf=false", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def commit(repo: Path, files: dict[str, str], message: str) -> str:
    for name, text in files.items():
        (repo / name).write_bytes(text.encode("utf-8"))
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    commit(repo, {"app.py": "import os\nos.system(cmd)\n", "util.py": "x = 1\n"}, "base")
    git(repo, "switch", "-q", "-c", "feature")
    return repo


def gate(repo: Path, **kwargs) -> GateReport:
    kwargs.setdefault("scan", fake_scan)
    return run_gate(repo, base="main", head="feature", **kwargs)


def test_change_without_new_findings_passes(repo: Path):
    commit(repo, {"util.py": "x = 2\n"}, "harmless")

    report = gate(repo)

    assert report.verdict == GateVerdict.PASS
    assert report.new_count == 0
    assert report.existing_count == 1  # the old os.system does not block


def test_new_high_security_finding_fails(repo: Path):
    commit(repo, {"util.py": "import os\nos.system(user)\n"}, "add command")

    report = gate(repo)

    assert report.verdict == GateVerdict.FAIL
    assert [(item.rule_id, item.file_path) for item in report.blocking] == [("B605", "util.py")]
    assert report.existing_count == 1


def test_new_secret_fails(repo: Path):
    commit(repo, {"config.py": 'API_KEY = "x"\n'}, "add key")

    report = gate(repo)

    assert report.verdict == GateVerdict.FAIL
    assert report.blocking[0].category == FindingCategory.SECRET


def test_severity_threshold(repo: Path):
    commit(repo, {"util.py": "import hashlib\nhashlib.md5(data)\n"}, "weak hash")

    default = gate(repo)
    strict = gate(repo, policy=GatePolicy(fail_on=Severity.MEDIUM))

    assert default.verdict == GateVerdict.PASS
    assert [item.rule_id for item in default.other_new] == ["B324"]
    assert strict.verdict == GateVerdict.FAIL


def test_architecture_debt_warns_unless_policy_says_fail(repo: Path):
    commit(repo, {"util.py": "try:\n    x()\nexcept: pass\n"}, "swallow errors")

    default = gate(repo)
    strict = gate(repo, policy=GatePolicy(fail_on_architecture=True))

    assert default.verdict == GateVerdict.PASS
    assert [item.rule_id for item in default.warnings] == ["SSEC-ARCH-002"]
    assert any("Warning" in reason for reason in default.reasons)
    assert strict.verdict == GateVerdict.FAIL


def test_resolved_findings_are_reported(repo: Path):
    commit(repo, {"app.py": "import subprocess\nsubprocess.run([cmd])\n"}, "fix")

    report = gate(repo)

    assert report.verdict == GateVerdict.PASS
    assert [item.rule_id for item in report.resolved] == ["B605"]
    assert report.score_after < report.score_before


def test_incomplete_scan_cannot_pass(repo: Path):
    commit(repo, {"util.py": "x = 3\n"}, "change")

    report = gate(repo, scan=lambda root, **kw: fake_scan(root, fail=True, **kw))

    assert report.verdict == GateVerdict.INCOMPLETE
    assert report.scanner_problems and report.scanner_problems[0].startswith("base:")


def test_changes_on_base_after_branching_are_not_blamed(repo: Path):
    commit(repo, {"util.py": "x = 2\n"}, "feature work")
    git(repo, "switch", "-q", "main")
    main_tip = commit(repo, {"main_only.py": "import os\nos.system(a)\n"}, "main adds debt")

    report = gate(repo)

    assert report.verdict == GateVerdict.PASS
    assert report.base_sha != main_tip
    assert any("merge base" in item for item in report.limitations)


def test_same_commit_passes_without_scanning(repo: Path):
    def no_scan(*args, **kwargs):
        raise AssertionError("should not scan")

    report = gate(repo, scan=no_scan)

    assert report.verdict == GateVerdict.PASS
    assert "no changes" in report.reasons[0]


def test_repository_is_not_modified(repo: Path):
    commit(repo, {"util.py": "import os\nos.system(user)\n"}, "add command")
    before = git(repo, "status", "--porcelain", "--ignored")

    gate(repo)

    assert git(repo, "status", "--porcelain", "--ignored") == before
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "feature"


@pytest.mark.parametrize("bad_ref", ["does-not-exist", "--output=x"])
def test_unknown_or_option_like_refs_are_rejected(repo: Path, bad_ref: str):
    with pytest.raises(HistoryError):
        run_gate(repo, base=bad_ref, head="feature", scan=fake_scan)


def test_not_a_git_repository(tmp_path: Path, monkeypatch):
    # The temp folder may sit inside another repository (e.g. a home folder).
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    with pytest.raises(HistoryError, match="Not a Git repository"):
        run_gate(tmp_path, scan=fake_scan)


# --- CLI ------------------------------------------------------------------------


def make_report(verdict: GateVerdict) -> GateReport:
    return GateReport(
        verdict=verdict,
        reasons=["because"],
        policy=GatePolicy(),
        base_ref="main",
        head_ref="HEAD",
        base_sha="a" * 40,
        head_sha="b" * 40,
        limitations=["only committed files"],
    )


@pytest.mark.parametrize(
    ("verdict", "code", "text"),
    [
        (GateVerdict.PASS, cli.EXIT_OK, "Gate: PASS"),
        (GateVerdict.FAIL, cli.EXIT_GATE_FAILED, "Gate: FAIL"),
        (GateVerdict.INCOMPLETE, cli.EXIT_GATE_INCOMPLETE, "Gate: INCOMPLETE"),
    ],
)
def test_cli_exit_codes(tmp_path: Path, capsys, verdict, code, text):
    with patch.object(cli, "run_gate", return_value=make_report(verdict)):
        assert cli.main(["gate", str(tmp_path)]) == code
    assert text in capsys.readouterr().out


def test_cli_passes_policy_and_writes_json(tmp_path: Path):
    out = tmp_path / "gate.json"
    with patch.object(cli, "run_gate", return_value=make_report(GateVerdict.FAIL)) as run:
        cli.main(
            [
                "gate",
                str(tmp_path),
                "--base",
                "dev",
                "--head",
                "pr",
                "--fail-on",
                "medium",
                "--fail-on-architecture",
                "--json",
                str(out),
            ]
        )

    kwargs = run.call_args.kwargs
    assert (kwargs["base"], kwargs["head"]) == ("dev", "pr")
    assert kwargs["policy"] == GatePolicy(fail_on=Severity.MEDIUM, fail_on_architecture=True)
    assert json.loads(out.read_text(encoding="utf-8"))["verdict"] == "fail"


def test_cli_reports_git_errors_as_usage_errors(tmp_path: Path, capsys):
    with patch.object(cli, "run_gate", side_effect=HistoryError("Unknown commit or branch: x")):
        assert cli.main(["gate", str(tmp_path), "--base", "x"]) == cli.EXIT_USAGE_ERROR
    assert "Unknown commit" in capsys.readouterr().err


def test_one_issue_found_by_two_scanners_counts_once(repo: Path):
    def two_tool_scan(root: Path, **kwargs) -> RepositoryScanResult:
        result = fake_scan(root, **kwargs)
        doubled = []
        for finding in result.findings:
            doubled.append(finding)
            if finding.rule_id == "B605":  # semgrep reports the same os.system call
                doubled.append(
                    finding.model_copy(
                        update={"tool": "semgrep", "rule_id": "os-system", "finding_id": "x"}
                    )
                )
        return result.model_copy(
            update={"findings": doubled, "security_debt": score_findings(doubled)}
        )

    commit(repo, {"util.py": "import os\nos.system(user)\n"}, "add command")

    report = gate(repo, scan=two_tool_scan)

    assert report.verdict == GateVerdict.FAIL
    assert len(report.blocking) == 2
    assert report.blocking_issues == 1
    assert report.existing_issues == 1 and report.existing_count == 2
    assert "1 issue(s) (2 scanner findings)" in report.reasons[0]
