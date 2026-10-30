from silentsec.schemas.finding import Finding, Severity
from silentsec.scoring.correlation import CorrelationGroup, correlate_findings
from silentsec.scoring.recurrence import detect_recurring_patterns


def make_finding(
    *,
    fingerprint: str,
    file_path: str,
    start_line: int = 1,
    tool: str = "scanner-a",
    rule_id: str = "RULE001",
    cwe_id: str | None = None,
) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        tool=tool,
        rule_id=rule_id,
        file_path=file_path,
        start_line=start_line,
        end_line=start_line,
        category="security",
        severity=Severity.MEDIUM,
        message=f"Repeated issue for {rule_id}",
        confidence=1.0,
        cwe_id=cwe_id,
    )


def groups(*findings: Finding) -> list[CorrelationGroup]:
    return correlate_findings(findings)


def test_same_rule_in_three_files_is_recurring():
    findings = [
        make_finding(fingerprint=f"fp-{i}", file_path=f"src/file{i}.py")
        for i in range(3)
    ]

    patterns = detect_recurring_patterns(groups(*findings))

    assert len(patterns) == 1
    assert patterns[0].file_count == 3
    assert patterns[0].occurrence_count == 3
    assert patterns[0].files == [
        "src/file0.py",
        "src/file1.py",
        "src/file2.py",
    ]


def test_same_rule_twice_in_one_file_is_not_recurring():
    findings = [
        make_finding(fingerprint="fp-1", file_path="src/app.py", start_line=1),
        make_finding(fingerprint="fp-2", file_path="src/app.py", start_line=10),
    ]

    assert detect_recurring_patterns(groups(*findings)) == []


def test_same_rule_three_locations_in_one_file_is_recurring():
    findings = [
        make_finding(
            fingerprint=f"fp-{i}",
            file_path="src/app.py",
            start_line=i * 10,
        )
        for i in range(1, 4)
    ]

    patterns = detect_recurring_patterns(groups(*findings))

    assert len(patterns) == 1
    assert patterns[0].file_count == 1
    assert patterns[0].occurrence_count == 3


def test_same_cwe_across_tools_is_grouped():
    findings = [
        make_finding(
            fingerprint="fp-a",
            file_path="src/a.py",
            tool="scanner-a",
            rule_id="A001",
            cwe_id="CWE-89",
        ),
        make_finding(
            fingerprint="fp-b",
            file_path="src/b.py",
            tool="scanner-b",
            rule_id="B001",
            cwe_id="CWE-89",
        ),
    ]

    patterns = detect_recurring_patterns(groups(*findings))
    cwe_patterns = [pattern for pattern in patterns if pattern.cwe_id]

    assert len(cwe_patterns) == 1
    assert cwe_patterns[0].cwe_id == "CWE-89"
    assert cwe_patterns[0].file_count == 2
    assert cwe_patterns[0].rule_ids == ["A001", "B001"]


def test_correlated_duplicates_are_not_double_counted():
    finding = make_finding(fingerprint="same", file_path="src/a.py")
    duplicate = finding.model_copy(update={"tool": "scanner-b"})

    correlated = correlate_findings([finding, duplicate])
    assert len(correlated) == 1

    patterns = detect_recurring_patterns(correlated)
    assert patterns == []


def test_recurring_patterns_are_deterministic():
    findings = [
        make_finding(fingerprint="fp-c", file_path="src/c.py"),
        make_finding(fingerprint="fp-a", file_path="src/a.py"),
        make_finding(fingerprint="fp-b", file_path="src/b.py"),
    ]

    first = detect_recurring_patterns(groups(*findings))
    second = detect_recurring_patterns(groups(*reversed(findings)))

    assert [item.model_dump() for item in first] == [
        item.model_dump() for item in second
    ]
