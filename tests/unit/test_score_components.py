from pathlib import Path

from silentsec.schemas.finding import Finding, FindingStatus, Severity
from silentsec.scoring import score_findings


def make_finding(
    *,
    fingerprint: str,
    file_path: str = "src/app.py",
    rule_id: str = "TEST001",
    severity: Severity = Severity.MEDIUM,
    category: str = "security",
    cwe_id: str | None = None,
    tool: str = "test-scanner",
    message: str = "Test finding",
) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        tool=tool,
        rule_id=rule_id,
        file_path=file_path,
        start_line=1,
        end_line=1,
        category=category,
        severity=severity,
        message=message,
        confidence=0.75,
        status=FindingStatus.OPEN,
        cwe_id=cwe_id,
    )


def test_non_informational_components_sum_to_existing_score() -> None:
    findings = [
        make_finding(
            fingerprint=f"critical-{i}",
            file_path=f"src/app_{i}.py",
            severity=Severity.CRITICAL,
        )
        for i in range(5)
    ]
    report = score_findings(findings)
    assert sum(c.points for c in report.components if not c.informational) == report.score
    assert report.score == 100


def test_recurrence_component_is_informational_and_capped_at_15() -> None:
    findings = [
        make_finding(
            fingerprint=f"recurring-{i}",
            file_path=f"src/file_{i}.py",
            rule_id="REPEATED001",
        )
        for i in range(10)
    ]
    report = score_findings(findings)
    recurrence = next(c for c in report.components if c.name == "recurrence")
    assert recurrence.informational is True
    assert recurrence.points == 15
    assert recurrence.max_points == 15
    assert report.score == 70


def test_remediation_effort_mapping_and_summary() -> None:
    findings = [
        make_finding(fingerprint="secret", category="secret"),
        make_finding(fingerprint="cycle", rule_id="SSEC-ARCH-004", category="architecture"),
        make_finding(fingerprint="complexity", rule_id="SSEC-ARCH-003", category="maintainability"),
        make_finding(fingerprint="injection", cwe_id="CWE-89"),
        make_finding(fingerprint="default"),
    ]
    report = score_findings(findings)
    efforts = {sf.finding.fingerprint: sf.remediation_effort for sf in report.scored_findings}
    assert efforts["secret"] == "medium"
    assert efforts["cycle"] == "high"
    assert efforts["complexity"] == "medium"
    assert efforts["injection"] == "medium"
    assert efforts["default"] == "low"
    assert report.remediation_effort_summary == {"low": 1, "medium": 3, "high": 1}


def test_effort_is_independent_of_score_and_risk() -> None:
    finding = make_finding(
        fingerprint="cycle",
        rule_id="SSEC-ARCH-004",
        category="architecture",
        severity=Severity.HIGH,
    )
    report = score_findings([finding])
    scored = report.scored_findings[0]
    assert scored.remediation_effort == "high"
    assert scored.score == 13.125
    assert report.score == 13.125
    assert report.risk_level.value == "none"
    assert report.architecture_risk_level.value == "moderate"


def test_repository_density_counts_nonblank_eligible_source_lines(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import os\n\nvalue = 1\n", encoding="utf-8")
    (tmp_path / "client.js").write_text("const x = 1;\n\nconsole.log(x);\n", encoding="utf-8")
    excluded = tmp_path / ".tox"
    excluded.mkdir()
    (excluded / "ignored.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
    report = score_findings([make_finding(fingerprint="density")], repo_root=str(tmp_path))
    assert report.analyzed_lines == 4
    assert report.debt_density_per_kloc == 250.0


def test_zero_line_repository_has_zero_density(tmp_path: Path) -> None:
    (tmp_path / "blank.py").write_text("\n  \n", encoding="utf-8")
    report = score_findings([], repo_root=str(tmp_path))
    assert report.analyzed_lines == 0
    assert report.debt_density_per_kloc == 0.0


def test_density_is_none_without_repository_root() -> None:
    report = score_findings([])
    assert report.analyzed_lines is None
    assert report.debt_density_per_kloc is None
