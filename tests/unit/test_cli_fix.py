"""CLI tests for 'silentsec fix'."""

from pathlib import Path
from unittest.mock import patch

import pytest

from silentsec import cli
from silentsec.remediation import FindingSummary, FixVerdict, FixVerificationReport
from silentsec.remediation.ai_fix import AIFixProposal, AIFixReport, AIFixStatus, LineEdit
from silentsec.schemas import Severity

PATCH = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a\n+b\n"


def make_report(verdict: FixVerdict) -> FixVerificationReport:
    resolved = FindingSummary(
        fingerprint="fp",
        tool="semgrep",
        rule_id="sql",
        file_path="app.py",
        start_line=3,
        severity=Severity.HIGH,
    )
    return FixVerificationReport(
        verdict=verdict,
        reasons=["because"],
        resolved=[resolved],
        score_before=14.2,
        score_after=0.0,
        checks_run=["semgrep (success)"],
        limitations=["Passing scans and tests do not prove the absence of vulnerabilities."],
    )

def make_ai_report(status: AIFixStatus, verdict: FixVerdict | None = None) -> AIFixReport:
    proposal = AIFixProposal(
        fingerprint="fp",
        provider="groq:model",
        explanation="Use a parameterized query.",
        edits=[LineEdit(start_line=1, end_line=1, replacement="b")],
        diff_text=PATCH,
    )
    return AIFixReport(
        status=status,
        finding_fingerprint="fp",
        finding_rule="semgrep sql",
        finding_location="app.py:1",
        proposal=proposal if status == AIFixStatus.PROPOSED else None,
        verification=make_report(verdict) if verdict else None,
        errors=[] if status == AIFixStatus.PROPOSED else ["No AI provider is configured."],
    )


@pytest.mark.parametrize(
    ("report", "code"),
    [
        (make_ai_report(AIFixStatus.PROPOSED, FixVerdict.VERIFIED_FIX), cli.EXIT_OK),
        (make_ai_report(AIFixStatus.PROPOSED, FixVerdict.REGRESSION), cli.EXIT_FIX_NOT_CONFIRMED),
        (make_ai_report(AIFixStatus.PROPOSED, FixVerdict.NOT_VERIFIED), cli.EXIT_NOT_VERIFIED),
        (make_ai_report(AIFixStatus.NO_PROPOSAL), cli.EXIT_NOT_VERIFIED),
        (make_ai_report(AIFixStatus.REFUSED), cli.EXIT_NOT_VERIFIED),
    ],
)
def test_fix_exit_codes(tmp_path: Path, report: AIFixReport, code: int):
    with patch.object(cli, "ai_fix_and_verify", return_value=report):
        assert cli.main(["fix", str(tmp_path)]) == code


def test_fix_prints_proposal_and_saves_patch_without_applying(tmp_path: Path, capsys):
    out = tmp_path / "fix.diff"
    report = make_ai_report(AIFixStatus.PROPOSED, FixVerdict.VERIFIED_FIX)

    with patch.object(cli, "ai_fix_and_verify", return_value=report) as fix:
        cli.main(["fix", str(tmp_path), "--finding", "fp", "--out", str(out)])

    output = capsys.readouterr().out
    assert "requires human review" in output
    assert "Verdict: VERIFIED FIX" in output
    assert "(not applied)" in output
    assert out.read_text(encoding="utf-8") == PATCH
    assert fix.call_args.kwargs["fingerprint"] == "fp"
    assert fix.call_args.kwargs["run_tests"] is False


def test_fix_without_provider_explains_why(tmp_path: Path, capsys):
    with patch.object(cli, "ai_fix_and_verify", return_value=make_ai_report(AIFixStatus.NO_PROPOSAL)):
        cli.main(["fix", str(tmp_path)])

    assert "No AI provider is configured" in capsys.readouterr().out
