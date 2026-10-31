"""Tests for merging the same issue reported under rules with different CWEs."""

import pytest

from silentsec.schemas.finding import Finding, FindingCategory, Severity
from silentsec.scoring import score_findings
from silentsec.scoring.correlation import correlate_findings

SEMGREP = "silentsec.python."


def finding(
    tool: str,
    rule_id: str,
    *,
    line: int = 10,
    file_path: str = "app.py",
    severity: Severity = Severity.HIGH,
    category: FindingCategory = FindingCategory.SECURITY,
    cwe: str | None = None,
) -> Finding:
    return Finding(
        fingerprint=f"{tool}-{rule_id}-{file_path}-{line}",
        tool=tool,
        rule_id=rule_id,
        file_path=file_path,
        start_line=line,
        category=category,
        severity=severity,
        message=f"{rule_id} message",
        cwe_id=cwe,
        confidence=0.9,
    )


@pytest.mark.parametrize(
    ("bandit_rule", "semgrep_rule"),
    [
        ("B307", "code-injection.eval-exec"),
        ("B102", "code-injection.eval-exec"),
        ("B605", "command-injection.subprocess-getoutput"),
        ("B606", "command-injection.exec-spawn"),
        ("B506", "deserialization.yaml-unsafe-load"),
        ("B306", "tempfile.mktemp"),
        ("B201", "flask.debug-enabled"),
    ],
)
def test_equivalent_rules_on_the_same_line_merge(bandit_rule, semgrep_rule):
    findings = [
        finding("bandit", bandit_rule, severity=Severity.MEDIUM, cwe="CWE-78"),
        finding("semgrep", SEMGREP + semgrep_rule, cwe="CWE-95"),
    ]

    groups = correlate_findings(findings)

    assert len(groups) == 1
    assert groups[0].correlation_type == "equivalent_rule"
    assert groups[0].representative.tool == "semgrep"  # the higher severity
    assert "same line" in groups[0].reason


def test_equivalent_rules_on_different_lines_stay_separate():
    findings = [
        finding("bandit", "B307", line=10),
        finding("semgrep", SEMGREP + "code-injection.eval-exec", line=11),
    ]

    assert len(correlate_findings(findings)) == 2


def test_equivalent_rules_in_different_files_stay_separate():
    findings = [
        finding("bandit", "B307", file_path="a.py"),
        finding("semgrep", SEMGREP + "code-injection.eval-exec", file_path="b.py"),
    ]

    assert len(correlate_findings(findings)) == 2


def test_bandit_b605_on_os_system_still_merges_by_cwe():
    # B605 is in the getoutput pair, but without the getoutput rule on the line
    # it must fall through to the normal cross-tool matching.
    findings = [
        finding("bandit", "B605", cwe="CWE-78"),
        finding("semgrep", SEMGREP + "command-injection.os-system", cwe="CWE-78"),
    ]
    findings[0] = findings[0].model_copy(update={"message": "Starting a process with a shell"})
    findings[1] = findings[1].model_copy(update={"message": "os.system starts a shell process"})

    groups = correlate_findings(findings)

    assert len(groups) == 1
    assert groups[0].correlation_type == "cross_tool"


def test_unrelated_rule_on_the_same_line_is_not_merged():
    findings = [
        finding("bandit", "B113", severity=Severity.MEDIUM),  # request without timeout
        finding("semgrep", SEMGREP + "tls.requests-verify-disabled"),
    ]

    assert len(correlate_findings(findings)) == 2


def test_one_secret_matched_by_several_rules_is_one_issue():
    findings = [
        finding("gitleaks", "generic-api-key", category=FindingCategory.SECRET),
        finding("gitleaks", "github-pat", category=FindingCategory.SECRET),
        finding("bandit", "B105", severity=Severity.LOW),
    ]

    groups = correlate_findings(findings)

    assert len(groups) == 1
    assert groups[0].correlation_type == "same_secret"
    assert len(groups[0].findings) == 3


def test_secrets_on_different_lines_stay_separate():
    findings = [
        finding("gitleaks", "generic-api-key", line=3, category=FindingCategory.SECRET),
        finding("gitleaks", "github-pat", line=4, category=FindingCategory.SECRET),
    ]

    assert len(correlate_findings(findings)) == 2


def test_score_counts_merged_issue_once_and_reports_it():
    eval_pair = [
        finding("bandit", "B307", severity=Severity.MEDIUM),
        finding("semgrep", SEMGREP + "code-injection.eval-exec"),
    ]
    secret_pair = [
        finding("gitleaks", "generic-api-key", line=3, category=FindingCategory.SECRET),
        finding("gitleaks", "github-pat", line=3, category=FindingCategory.SECRET),
    ]

    report = score_findings(eval_pair + secret_pair)
    single = score_findings([eval_pair[1], secret_pair[0]])

    assert report.unique_open_findings_count == 2
    assert report.equivalent_rule_duplicates_removed == 2
    assert report.duplicate_findings_removed == 2
    assert report.raw_score == pytest.approx(single.raw_score)
