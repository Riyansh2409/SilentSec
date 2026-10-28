
from silentsec.schemas.finding import Finding, FindingStatus, Severity
from silentsec.scoring import RiskLevel, score_findings


def make_finding(
    *,
    fingerprint: str = "fingerprint-1",
    severity: Severity = Severity.MEDIUM,
    confidence: float | None = 0.75,
    status: FindingStatus = FindingStatus.OPEN,
    rule_id: str = "TEST001",
    category="security",
) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        tool="test-scanner",
        rule_id=rule_id,
        file_path=f"src/{rule_id.lower()}.py",
        start_line=10,
        end_line=12,
        category=category,
        severity=severity,
        message="Test security finding",
        confidence=confidence,
        status=status,
    )


def test_empty_findings_have_zero_score_and_no_risk():
    report = score_findings([])

    assert report.score == 0
    assert report.raw_score == 0
    assert report.risk_level == RiskLevel.NONE
    assert report.scored_findings == []


def test_score_uses_severity_and_confidence():
    finding = make_finding(
        severity=Severity.MEDIUM,
        confidence=0.8,
    )

    report = score_findings([finding])

    assert report.score == 7.2
    assert report.scored_findings[0].base_points == 8
    assert report.scored_findings[0].effective_confidence == 0.8
    assert "7.200 points" in report.scored_findings[0].explanation


def test_missing_confidence_uses_documented_default():
    finding = make_finding(
        severity=Severity.LOW,
        confidence=None,
    )

    report = score_findings([finding])

    assert report.score == 2.625
    assert report.scored_findings[0].effective_confidence == 0.75
    assert "defaulted confidence" in report.scored_findings[0].explanation


def test_duplicate_fingerprint_keeps_strongest_finding():
    low = make_finding(
        fingerprint="same-issue",
        severity=Severity.LOW,
        confidence=1.0,
        rule_id="LOW001",
    )
    high = make_finding(
        fingerprint="same-issue",
        severity=Severity.HIGH,
        confidence=1.0,
        rule_id="HIGH001",
    )

    report = score_findings([low, high])

    assert report.input_findings_count == 2
    assert report.unique_open_findings_count == 1
    assert report.duplicate_findings_removed == 1
    assert report.scored_findings[0].finding.severity == Severity.HIGH
    assert report.score == 15


def test_fixed_and_suppressed_findings_are_excluded():
    fixed = make_finding(
        fingerprint="fixed",
        status=FindingStatus.FIXED,
        severity=Severity.CRITICAL,
    )
    suppressed = make_finding(
        fingerprint="suppressed",
        status=FindingStatus.SUPPRESSED,
        severity=Severity.HIGH,
    )
    open_finding = make_finding(
        fingerprint="open",
        status=FindingStatus.OPEN,
        severity=Severity.MEDIUM,
    )

    report = score_findings([fixed, suppressed, open_finding])

    assert report.fixed_findings_excluded == 1
    assert report.suppressed_findings_excluded == 1
    assert report.unique_open_findings_count == 1
    assert report.score == 7


def test_repository_score_is_capped_at_100():
    findings = [
        make_finding(
            fingerprint=f"critical-{index}",
            severity=Severity.CRITICAL,
        )
        for index in range(5)
    ]

    report = score_findings(findings)

    assert report.raw_score == 109.375
    assert report.score == 100
    assert report.risk_level == RiskLevel.CRITICAL


def test_findings_are_sorted_by_score_descending():
    findings = [
        make_finding(
            fingerprint="low",
            severity=Severity.LOW,
            confidence=1.0,
        ),
        make_finding(
            fingerprint="critical",
            severity=Severity.CRITICAL,
            confidence=1.0,
        ),
        make_finding(
            fingerprint="medium",
            severity=Severity.MEDIUM,
            confidence=1.0,
        ),
    ]

    report = score_findings(findings)

    assert [
        item.finding.severity for item in report.scored_findings
    ] == [
        Severity.CRITICAL,
        Severity.MEDIUM,
        Severity.LOW,
    ]
    assert report.highest_severity == Severity.CRITICAL


def test_cross_tool_duplicates_are_scored_once():
    bandit = make_finding(
        fingerprint="bandit-shell",
        severity=Severity.HIGH,
        confidence=1.0,
        rule_id="B602",
    ).model_copy(
        update={
            "tool": "bandit",
            "file_path": "src/app.py",
            "start_line": 10,
            "end_line": 10,
            "cwe_id": "CWE-78",
            "message": "subprocess call with shell=True",
        }
    )
    semgrep = make_finding(
        fingerprint="semgrep-shell",
        severity=Severity.HIGH,
        confidence=1.0,
        rule_id="subprocess-shell-true",
    ).model_copy(
        update={
            "tool": "semgrep",
            "file_path": "src/app.py",
            "start_line": 10,
            "end_line": 10,
            "cwe_id": "CWE-78",
            "message": "subprocess call with shell=True",
        }
    )

    report = score_findings([bandit, semgrep])

    assert report.input_findings_count == 2
    assert report.unique_open_findings_count == 1
    assert report.duplicate_findings_removed == 1
    assert len(report.scored_findings) == 1
    assert report.scored_findings[0].score == 15
    assert len(report.correlation_groups[0].findings) == 2


def test_same_cwe_at_different_lines_is_scored_separately():
    first = make_finding(
        fingerprint="first-shell",
        severity=Severity.HIGH,
        confidence=1.0,
        rule_id="B602",
    ).model_copy(
        update={
            "tool": "bandit",
            "file_path": "src/app.py",
            "start_line": 10,
            "end_line": 10,
            "cwe_id": "CWE-78",
            "message": "subprocess call with shell=True",
        }
    )
    second = make_finding(
        fingerprint="second-shell",
        severity=Severity.HIGH,
        confidence=1.0,
        rule_id="subprocess-shell-true",
    ).model_copy(
        update={
            "tool": "semgrep",
            "file_path": "src/app.py",
            "start_line": 20,
            "end_line": 20,
            "cwe_id": "CWE-78",
            "message": "subprocess call with shell=True",
        }
    )

    report = score_findings([first, second])

    assert report.unique_open_findings_count == 2
    assert report.duplicate_findings_removed == 0
    assert len(report.scored_findings) == 2
    assert report.score == 30






def test_report_exposes_separate_duplicate_counts():
    bandit = make_finding(
        fingerprint="bandit-metrics",
        rule_id="B602",
    )

    bandit = bandit.model_copy(update={"cwe_id": "CWE-78"})
    semgrep = bandit.model_copy(
        update={
            "fingerprint": "semgrep-metrics",
            "tool": "semgrep",
            "rule_id": "subprocess-shell-true",
        }
    )

    report = score_findings([bandit, semgrep])

    assert report.exact_duplicates_removed == 0
    assert report.cross_tool_duplicates_removed == 1
    assert report.duplicate_findings_removed == 1


def test_report_duplicate_counts_are_zero_without_duplicates():
    finding = make_finding(fingerprint="unique-metrics")

    report = score_findings([finding])

    assert report.exact_duplicates_removed == 0
    assert report.cross_tool_duplicates_removed == 0
    assert report.duplicate_findings_removed == 0

def test_report_serializes_correlation_evidence():
    bandit = make_finding(
        fingerprint="bandit-evidence",
        severity=Severity.HIGH,
        confidence=1.0,
        rule_id="B602",
    ).model_copy(
        update={
            "tool": "bandit",
            "file_path": "src/app.py",
            "start_line": 10,
            "end_line": 10,
            "cwe_id": "CWE-78",
            "message": "subprocess call with shell=True",
        }
    )
    semgrep = make_finding(
        fingerprint="semgrep-evidence",
        severity=Severity.HIGH,
        confidence=1.0,
        rule_id="subprocess-shell-true",
    ).model_copy(
        update={
            "tool": "semgrep",
            "file_path": "src/app.py",
            "start_line": 10,
            "end_line": 10,
            "cwe_id": "CWE-78",
            "message": "subprocess call with shell=True",
        }
    )

    report = score_findings([bandit, semgrep])
    payload = report.model_dump(mode="json")

    assert len(payload["correlation_groups"]) == 1

    group = payload["correlation_groups"][0]
    evidence = group["evidence"]

    assert group["correlation_type"] == "cross_tool"
    assert evidence["exact_fingerprint_match"] is False
    assert evidence["shared_cwe"] is True
    assert evidence["same_file"] is True
    assert evidence["overlapping_lines"] is True
    assert {"subprocess", "shell", "true"}.issubset(
        set(evidence["shared_tokens"])
    )

def test_architecture_debt_is_capped_at_25_points():
    findings = [
        make_finding(
            fingerprint=f"architecture-{index}",
            severity=Severity.CRITICAL,
            confidence=1.0,
            rule_id=f"ARCH{index:03}",
            category="architecture",
        )
        for index in range(15)
    ]

    report = score_findings(findings)

    assert report.architecture_debt_points == 25.0
    assert report.score == 25.0
    assert report.risk_level != RiskLevel.CRITICAL
    assert "capped at 25.0" in report.architecture_debt_explanation


def test_security_points_remain_unchanged_by_architecture_cap():
    security_finding = make_finding(
        fingerprint="security-critical",
        severity=Severity.CRITICAL,
        confidence=1.0,
        rule_id="SEC001",
        category="security",
    )
    architecture_findings = [
        make_finding(
            fingerprint=f"architecture-{index}",
            severity=Severity.CRITICAL,
            confidence=1.0,
            rule_id=f"ARCH{index:03}",
            category="architecture",
        )
        for index in range(15)
    ]

    report = score_findings([security_finding, *architecture_findings])

    assert report.security_points == 25.0
    assert report.architecture_debt_points == 25.0
    assert report.score == 50.0
    assert report.risk_level == RiskLevel.CRITICAL


def test_maintainability_findings_share_architecture_debt_cap():
    findings = [
        make_finding(
            fingerprint=f"maintainability-{index}",
            severity=Severity.CRITICAL,
            confidence=1.0,
            rule_id=f"MAINT{index:03}",
            category="maintainability",
        )
        for index in range(15)
    ]

    report = score_findings(findings)

    assert report.architecture_debt_points == 25.0
    assert report.security_points == 0.0
    assert report.score == 25.0
    assert report.risk_level != RiskLevel.CRITICAL
