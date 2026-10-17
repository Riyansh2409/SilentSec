
from silentsec.schemas.finding import Finding, FindingStatus, Severity
from silentsec.scoring import RiskLevel, score_findings


def make_finding(
    *,
    fingerprint: str = "fingerprint-1",
    severity: Severity = Severity.MEDIUM,
    confidence: float | None = 0.75,
    status: FindingStatus = FindingStatus.OPEN,
    rule_id: str = "TEST001",
) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        tool="test-scanner",
        rule_id=rule_id,
        file_path=f"src/{rule_id.lower()}.py",
        start_line=10,
        end_line=12,
        category="security",
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
