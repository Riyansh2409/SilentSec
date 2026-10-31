"""HTML report: content, safety, and the 'silentsec report' command."""

import shutil
import subprocess
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

import pytest

from silentsec import cli
from silentsec.history.timeline import FindingChange, TimelinePoint, TimelineReport
from silentsec.remediation.ai_fix import AIFixReport, AIFixStatus
from silentsec.remediation.verify import FindingSummary, FixVerdict, FixVerificationReport
from silentsec.report import generate_report, load_fix_report, render_report
from silentsec.report.html import SCRIPT, SCRIPT_HASH
from silentsec.scanners.results import ScannerRunResult, ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult
from silentsec.schemas import Finding, FindingCategory, Severity
from silentsec.scoring import score_findings

PAYLOAD = '<script>alert("x")</script><img src=x onerror=alert(1)>'
SECRET = "ghp_" + "1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4rS5tU"
NOW = datetime(2026, 10, 31, 12, 0)


def finding(**overrides) -> Finding:
    values = {
        "fingerprint": "fp-1",
        "tool": "semgrep",
        "rule_id": "sql",
        "file_path": "app/db.py",
        "start_line": 10,
        "category": FindingCategory.SECURITY,
        "severity": Severity.HIGH,
        "message": "SQL built with string formatting",
        "cwe_id": "CWE-89",
    }
    values.update(overrides)
    return Finding(**values)


def scan_of(findings, status=ScannerStatus.SUCCESS) -> RepositoryScanResult:
    return RepositoryScanResult(
        repo_path="/repo",
        languages=["Python"],
        status=status,
        scanners=[ScannerRunResult(scanner="semgrep", status=status, duration_seconds=0)],
        findings=findings,
        duration_seconds=0,
        security_debt=score_findings(findings),
        security_debt_complete=status == ScannerStatus.SUCCESS,
    )


def timeline(subject: str = "Add feature") -> TimelineReport:
    change = FindingChange(
        tool="bandit",
        rule_id="B608",
        file_path="app/db.py",
        start_line=10,
        severity=Severity.MEDIUM,
        category=FindingCategory.SECURITY,
    )
    points = [
        TimelinePoint(
            commit_sha="a" * 40, short_sha="aaaaaaaa", committed_at="2026-10-01T00:00:00+00:00",
            subject="Initial", score=0, raw_score=0, security_points=0, architecture_points=0,
            unique_issues=0, complete=True, attribution="baseline",
        ),
        TimelinePoint(
            commit_sha="b" * 40, short_sha="bbbbbbbb", committed_at="2026-10-02T00:00:00+00:00",
            subject=subject, score=14.2, raw_score=14.2, security_points=14.2,
            architecture_points=0, unique_issues=1, complete=True, introduced=[change],
        ),
    ]
    return TimelineReport(
        repo_path="/repo", branch="main", analysis_version="v", database="db", points=points
    )


def fix_report(verdict=FixVerdict.VERIFIED_FIX, diff="--- a/x\n+++ b/x\n") -> FixVerificationReport:
    item = FindingSummary(
        fingerprint="fp-1", tool="semgrep", rule_id="sql", file_path="app/db.py",
        start_line=10, severity=Severity.HIGH,
    )
    return FixVerificationReport(
        verdict=verdict, reasons=["All 1 targeted finding(s) are resolved."], resolved=[item],
        score_before=14.2, score_after=0.0, raw_score_before=14.2, raw_score_after=0.0,
        checks_run=["semgrep (success)"], diff_text=diff, patch_files=["app/db.py"],
        limitations=["Passing scans and tests do not prove the absence of vulnerabilities."],
    )


class _TagCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[tuple[str, dict]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def tags(document: str) -> list[tuple[str, dict]]:
    parser = _TagCollector()
    parser.feed(document)
    return parser.tags


# --- content ----------------------------------------------------------------


def test_report_contains_verdict_issues_history_and_fixes():
    document = render_report(
        scan_of([finding()]),
        repo_name="demo",
        generated_at=NOW,
        snippets={"fp-1": "10: conn.execute(q % name)"},
        timeline=timeline(),
        fixes=[fix_report()],
    )

    assert "Security risk is" in document
    assert "SQL built with string formatting" in document
    assert "10: conn.execute(q % name)" in document
    assert "Over time" in document and "<svg" in document
    assert "Verified fix" in document
    assert "Score 14.2 to 0.0" in document


def test_clean_scan_and_missing_history_explain_themselves():
    document = render_report(
        scan_of([]), repo_name="demo", generated_at=NOW, timeline_note="History is not available: x"
    )

    assert "No open security debt was found." in document
    assert "History is not available" in document


def test_incomplete_scan_shows_a_warning():
    document = render_report(scan_of([], ScannerStatus.FAILED), repo_name="demo", generated_at=NOW)

    assert "did not finish successfully" in document


def test_capped_score_is_explained():
    many = [finding(fingerprint=f"fp-{i}", file_path=f"f{i}.py", severity=Severity.CRITICAL) for i in range(8)]

    document = render_report(scan_of(many), repo_name="demo", generated_at=NOW)

    assert "The score is capped at 100; the uncapped total is" in document


def test_ai_fix_and_failed_ai_fix_are_rendered():
    proposed = AIFixReport(
        status=AIFixStatus.PROPOSED, finding_location="app/db.py:10", verification=fix_report(),
        proposal={
            "fingerprint": "fp-1", "provider": "groq:model", "explanation": "Use parameters.",
            "edits": [{"start_line": 10, "end_line": 10, "replacement": "x"}], "diff_text": "d",
        },
    )
    failed = AIFixReport(
        status=AIFixStatus.NO_PROPOSAL, finding_location="app/x.py:1",
        errors=["No AI provider is configured."],
    )

    document = render_report(scan_of([]), repo_name="demo", generated_at=NOW, fixes=[proposed, failed])

    assert "AI fix for app/db.py:10" in document
    assert "Proposed by groq:model" in document
    assert "No AI fix: app/x.py:1" in document


# --- safety -----------------------------------------------------------------


def test_untrusted_repository_content_is_escaped_everywhere():
    hostile = finding(message=PAYLOAD, file_path=f"{PAYLOAD}.py", rule_id=PAYLOAD)

    document = render_report(
        scan_of([hostile]),
        repo_name=PAYLOAD,
        generated_at=NOW,
        snippets={"fp-1": PAYLOAD},
        timeline=timeline(subject=PAYLOAD),
        fixes=[fix_report(diff=PAYLOAD)],
    )

    assert PAYLOAD not in document
    assert "&lt;script&gt;" in document
    scripts = [attrs for tag, attrs in tags(document) if tag == "script"]
    assert len(scripts) == 1
    assert not any(tag == "img" for tag, _ in tags(document))
    # The payload appears only as escaped text: no real event-handler attribute exists.
    assert not any(name.startswith("on") for _, attrs in tags(document) for name in attrs)


def test_strict_content_security_policy_allows_only_the_bundled_script():
    document = render_report(scan_of([]), repo_name="demo", generated_at=NOW)

    csp = next(
        attrs["content"]
        for tag, attrs in tags(document)
        if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy"
    )
    assert "default-src 'none'" in csp
    assert f"'sha256-{SCRIPT_HASH}'" in csp
    assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert f"<script>{SCRIPT}</script>" in document


def test_report_loads_nothing_from_the_network():
    document = render_report(scan_of([finding()]), repo_name="demo", generated_at=NOW, timeline=timeline())

    for tag, attrs in tags(document):
        for name in ("src", "href"):
            assert not str(attrs.get(name, "")).startswith(("http:", "https:", "//")), (tag, attrs)
    assert "@import" not in document


def test_secret_code_is_withheld_and_values_never_appear(tmp_path: Path):
    (tmp_path / "settings.py").write_text(f'TOKEN = "{SECRET}"\n', encoding="utf-8")
    secret_finding = finding(
        fingerprint="fp-secret", tool="gitleaks", rule_id="github-pat", file_path="settings.py",
        start_line=1, category=FindingCategory.SECRET, message="Potential secret detected.",
    )

    def fake_scan(root, **kwargs):
        return scan_of([secret_finding])

    document, _, _ = generate_report(
        tmp_path, include_history=False, scan=fake_scan, now=lambda: NOW
    )

    assert SECRET not in document
    assert "Code withheld: this is a possible secret." in document


def test_code_snippets_are_redacted(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        f'API_KEY = "{SECRET}"\nquery = "SELECT * FROM t WHERE n = %s" % name\n', encoding="utf-8"
    )
    sql = finding(file_path="app.py", start_line=2)

    document, _, _ = generate_report(
        tmp_path, include_history=False, scan=lambda root, **kw: scan_of([sql]), now=lambda: NOW
    )

    assert "SELECT * FROM t WHERE n = %s" in document
    assert SECRET not in document


# --- loading fix reports ----------------------------------------------------


def test_load_fix_report_detects_both_kinds(tmp_path: Path):
    verify_path = tmp_path / "verify.json"
    verify_path.write_text(fix_report().model_dump_json(), encoding="utf-8")
    ai_path = tmp_path / "ai.json"
    ai_path.write_text(
        AIFixReport(status=AIFixStatus.REFUSED, errors=["x"]).model_dump_json(), encoding="utf-8"
    )

    assert isinstance(load_fix_report(verify_path), FixVerificationReport)
    assert isinstance(load_fix_report(ai_path), AIFixReport)


def test_load_fix_report_rejects_other_json(tmp_path: Path):
    path = tmp_path / "other.json"
    path.write_text('{"hello": 1}', encoding="utf-8")

    with pytest.raises(ValueError):
        load_fix_report(path)


# --- CLI --------------------------------------------------------------------


def test_cli_writes_report_without_touching_the_repository(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    before = sorted(p.name for p in repo.rglob("*"))
    out = tmp_path / "out" / "report.html"
    out.parent.mkdir()

    with patch("silentsec.report.scan_repository"), patch(
        "silentsec.report.generate_report",
        return_value=("<!doctype html><title>x</title>", scan_of([]), None),
    ), patch.object(cli, "generate_report", return_value=("<!doctype html>", scan_of([]), None)) as gen:
        code = cli.main(["report", str(repo), "--out", str(out), "--no-history"])

    assert code == cli.EXIT_OK
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert gen.call_args.kwargs["include_history"] is False
    assert gen.call_args.kwargs["enable_ai_triage"] is False
    assert sorted(p.name for p in repo.rglob("*")) == before


def test_cli_rejects_bad_fix_report_and_options(tmp_path: Path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")

    assert cli.main(["report", str(tmp_path), "--fix-report", str(bad)]) == cli.EXIT_USAGE_ERROR
    assert cli.main(["report", str(tmp_path), "--fix-report", str(tmp_path / "nope.json")]) == (
        cli.EXIT_USAGE_ERROR
    )
    assert cli.main(["report", str(tmp_path), "--commits", "0"]) == cli.EXIT_USAGE_ERROR


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_report_on_a_real_git_repository_includes_history(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    handler = "def load(p):\n    try:\n        return open(p).read()\n    except Exception:\n        pass\n"
    (repo / "app.py").write_text(handler, encoding="utf-8")
    for args in (["add", "-A"], ["commit", "-q", "-m", "Add loader"]):
        subprocess.run(
            ["git", "-C", str(repo), "-c", "user.name=d", "-c", "user.email=d@e.x", *args],
            check=True,
        )

    def skipped(name):
        return lambda *a, **k: ScannerRunResult(scanner=name, status=ScannerStatus.SKIPPED, duration_seconds=0)

    with (
        patch("silentsec.scanners.scanner_service.run_semgrep", skipped("semgrep")),
        patch("silentsec.scanners.scanner_service.run_bandit", skipped("bandit")),
        patch("silentsec.scanners.scanner_service.run_gitleaks", skipped("gitleaks")),
        patch("silentsec.history.store.default_database_path", return_value=tmp_path / "h.db"),
        patch("silentsec.history.timeline.default_database_path", return_value=tmp_path / "h.db"),
    ):
        document, _, report = generate_report(repo, now=lambda: NOW)

    assert report is not None and len(report.points) == 1
    assert "Add loader" in document
    assert "SSEC-ARCH-002" in document


def test_incomplete_history_points_show_unknown_change_and_reason():
    report = timeline()
    last = report.points[-1].model_copy(
        update={
            "complete": False,
            "attribution": "unknown",
            "scanner_problems": ["semgrep (partial): Timeout <b>x</b>"],
        }
    )
    report = report.model_copy(update={"points": [report.points[0], last]})

    document = render_report(scan_of([]), repo_name="demo", generated_at=NOW, timeline=report)

    assert "semgrep (partial): Timeout &lt;b&gt;x&lt;/b&gt;" in document
    assert 'class="dot incomplete"' in document
    assert ">?</span>" in document
    assert "+14.2" not in document
