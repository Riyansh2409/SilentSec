"""NEW-finding detection: a fix must not hide the issues it introduces."""

from silentsec.schemas import Finding, FindingCategory, Severity
from silentsec.verification import VerificationHistory, VerificationStatus, compare_findings


def make_finding(
    *,
    rule_id: str = "B602",
    file_path: str = "src/app.py",
    start_line: int = 10,
    fingerprint: str | None = None,
) -> Finding:
    return Finding(
        fingerprint=fingerprint or f"{rule_id}-{file_path}-{start_line}",
        tool="bandit",
        rule_id=rule_id,
        file_path=file_path,
        start_line=start_line,
        end_line=start_line,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message="m",
    )


def test_fix_that_adds_another_issue_reports_it_as_new():
    old = make_finding(rule_id="B602")
    introduced = make_finding(rule_id="B608", start_line=20)

    report = compare_findings([old], [introduced], scan_complete=True)

    assert report.results[0].status == VerificationStatus.RESOLVED
    assert report.new_findings == [introduced]
    assert report.new_count == 1


def test_incomplete_scan_never_reports_new_findings():
    report = compare_findings(
        [make_finding()],
        [make_finding(rule_id="B608", start_line=20)],
        scan_complete=False,
    )

    assert report.new_findings == []


def test_unchanged_findings_are_not_new_even_if_lines_shift():
    old = make_finding(start_line=10)
    shifted = make_finding(start_line=14)

    report = compare_findings([old], [shifted], scan_complete=True)

    assert report.results[0].status == VerificationStatus.STILL_OPEN
    assert report.new_findings == []


def test_extra_occurrence_of_same_rule_in_same_file_is_new():
    baseline = [make_finding(start_line=10)]
    current = [make_finding(start_line=10), make_finding(start_line=30)]

    report = compare_findings(baseline, current, scan_complete=True)

    # The occurrence on a line range absent from the baseline is the new one.
    assert [finding.start_line for finding in report.new_findings] == [30]


def test_same_rule_in_a_different_file_is_new():
    report = compare_findings(
        [make_finding(file_path="a.py")],
        [make_finding(file_path="a.py"), make_finding(file_path="b.py")],
        scan_complete=True,
    )

    assert [finding.file_path for finding in report.new_findings] == ["b.py"]


def test_new_detection_is_deterministic():
    baseline: list[Finding] = []
    current = [make_finding(start_line=line) for line in (30, 10, 20)]

    first = compare_findings(baseline, current, scan_complete=True)
    second = compare_findings(baseline, list(reversed(current)), scan_complete=True)

    assert [f.start_line for f in first.new_findings] == [10, 20, 30]
    assert first.new_findings == second.new_findings


def test_reintroduced_finding_is_not_also_counted_as_new():
    history = VerificationHistory()
    finding = make_finding()

    history.compare([finding], [], scan_complete=True)
    report = history.compare([], [finding], scan_complete=True)

    assert any(r.status == VerificationStatus.REINTRODUCED for r in report.results)
    assert report.new_findings == []
