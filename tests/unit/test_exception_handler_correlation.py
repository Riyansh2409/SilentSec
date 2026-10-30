"""Tests for merging equivalent exception-handler findings."""

from pathlib import Path

from silentsec.architecture.analyzer import run_architecture_analyzer
from silentsec.schemas.finding import Finding, FindingCategory, Severity
from silentsec.scoring import score_findings
from silentsec.scoring.correlation import correlate_findings


def handler_finding(
    tool: str,
    rule_id: str,
    *,
    line: int = 20,
    end_line: int = 21,
    file_path: str = "app/db.py",
    severity: Severity = Severity.LOW,
    category: FindingCategory = FindingCategory.MAINTAINABILITY,
) -> Finding:
    return Finding(
        fingerprint=f"{tool}-{rule_id}-{file_path}-{line}",
        tool=tool,
        rule_id=rule_id,
        file_path=file_path,
        start_line=line,
        end_line=end_line,
        category=category,
        severity=severity,
        message=f"{rule_id} message",
    )


def bandit_b110(**kwargs) -> Finding:
    return handler_finding(
        "bandit",
        "B110",
        category=FindingCategory.SECURITY,
        **kwargs,
    )


def test_same_handler_rules_become_one_group():
    findings = [
        bandit_b110(),
        handler_finding("silentsec-arch", "SSEC-ARCH-001"),
        handler_finding("silentsec-arch", "SSEC-ARCH-002", severity=Severity.MEDIUM),
    ]

    groups = correlate_findings(findings)

    assert len(groups) == 1
    assert groups[0].correlation_type == "same_exception_handler"
    assert len(groups[0].findings) == 3
    # The highest-severity finding represents the group.
    assert groups[0].representative.rule_id == "SSEC-ARCH-002"


def test_different_handlers_stay_separate():
    findings = [
        handler_finding("silentsec-arch", "SSEC-ARCH-001", line=20),
        handler_finding("silentsec-arch", "SSEC-ARCH-002", line=40, end_line=41),
    ]

    assert [group.correlation_type for group in correlate_findings(findings)] == [
        "single",
        "single",
    ]


def test_nested_handler_is_not_merged_with_outer_handler():
    # The outer handler's range (10-30) contains the inner one (15-16), but
    # they are different handlers.
    findings = [
        handler_finding("silentsec-arch", "SSEC-ARCH-001", line=10, end_line=30),
        handler_finding("silentsec-arch", "SSEC-ARCH-002", line=15, end_line=16),
    ]

    assert len(correlate_findings(findings)) == 2


def test_same_line_in_different_files_is_not_merged():
    findings = [
        handler_finding("silentsec-arch", "SSEC-ARCH-001", file_path="a.py"),
        handler_finding("silentsec-arch", "SSEC-ARCH-002", file_path="b.py"),
    ]

    assert len(correlate_findings(findings)) == 2


def test_unrelated_rule_on_same_line_is_not_merged():
    findings = [
        handler_finding("silentsec-arch", "SSEC-ARCH-001"),
        handler_finding(
            "bandit",
            "B602",
            severity=Severity.HIGH,
            category=FindingCategory.SECURITY,
        ),
    ]

    assert len(correlate_findings(findings)) == 2


def test_score_counts_one_handler_once():
    findings = [
        bandit_b110(),
        handler_finding("silentsec-arch", "SSEC-ARCH-001"),
        handler_finding("silentsec-arch", "SSEC-ARCH-002", severity=Severity.MEDIUM),
    ]

    report = score_findings(findings)

    assert report.unique_open_findings_count == 1
    assert report.same_handler_duplicates_removed == 2
    assert report.duplicate_findings_removed == 2
    assert len(report.scored_findings) == 1


def test_real_analyzer_handler_merges_with_bandit_b110(tmp_path: Path):
    source = "def load():\n    try:\n        return open('cfg').read()\n    except Exception:\n        pass\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")

    architecture = run_architecture_analyzer(tmp_path).findings
    assert {finding.rule_id for finding in architecture} == {"SSEC-ARCH-001", "SSEC-ARCH-002"}

    # Bandit reports B110 on the except line, like the analyzer does.
    bandit = bandit_b110(file_path="app.py", line=4, end_line=5)

    report = score_findings([*architecture, bandit])

    assert report.unique_open_findings_count == 1
    assert report.correlation_groups[0].correlation_type == "same_exception_handler"
