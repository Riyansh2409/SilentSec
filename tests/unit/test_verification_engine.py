import pytest

from silentsec.schemas import Finding, FindingCategory, Severity
from silentsec.verification import (
    VerificationHistory,
    VerificationStatus,
    compare_findings,
)


def make_finding(
    *,
    tool: str = "bandit",
    rule_id: str = "B602",
    file_path: str = "src/app.py",
    start_line: int = 10,
    fingerprint: str = "baseline-fingerprint",
) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        tool=tool,
        rule_id=rule_id,
        file_path=file_path,
        start_line=start_line,
        end_line=start_line,
        category=FindingCategory.SECURITY,
        severity=Severity.HIGH,
        message="Unsafe subprocess call",
    )


def test_matching_finding_is_still_open():
    baseline = [make_finding()]
    current = [make_finding(start_line=12, fingerprint="new-fingerprint")]

    report = compare_findings(baseline, current, scan_complete=True)

    assert report.still_open_count == 1
    assert report.resolved_count == 0
    assert report.results[0].status == VerificationStatus.STILL_OPEN


def test_missing_finding_in_complete_scan_is_resolved():
    report = compare_findings(
        [make_finding()],
        [],
        scan_complete=True,
    )

    assert report.resolved_count == 1
    assert report.results[0].status == VerificationStatus.RESOLVED


def test_missing_finding_in_incomplete_scan_is_not_resolved():
    report = compare_findings(
        [make_finding()],
        [],
        scan_complete=False,
    )

    assert report.incomplete_count == 1
    assert report.resolved_count == 0
    assert report.results[0].status == VerificationStatus.INCOMPLETE


@pytest.mark.parametrize(
    ("current",),
    [
        ([make_finding(tool="semgrep")],),
        ([make_finding(rule_id="B603")],),
        ([make_finding(file_path="src/other.py")],),
    ],
)
def test_different_rule_identity_or_file_does_not_match(current):
    report = compare_findings(
        [make_finding()],
        current,
        scan_complete=True,
    )

    assert report.resolved_count == 1


def test_empty_baseline_has_no_verification_results():
    report = compare_findings([], [], scan_complete=True)

    assert report.results == []
    assert report.baseline_count == 0
    assert report.current_count == 0
    assert report.resolved_count == 0
    assert report.still_open_count == 0
    assert report.incomplete_count == 0


def test_ambiguous_findings_are_not_marked_resolved():
    baseline = [
        make_finding(start_line=10, fingerprint="old-1"),
        make_finding(start_line=11, fingerprint="old-2"),
    ]
    current = [make_finding(start_line=10, fingerprint="new-1")]

    report = compare_findings(baseline, current, scan_complete=True)

    assert report.incomplete_count == 2
    assert report.resolved_count == 0


def test_incomplete_scan_does_not_claim_verification():
    report = compare_findings(
        [make_finding()],
        [make_finding(fingerprint="current-fingerprint")],
        scan_complete=False,
    )

    assert report.incomplete_count == 1
    assert report.still_open_count == 0
    assert report.resolved_count == 0


def test_history_detects_reintroduced_finding():
    history = VerificationHistory()
    original = make_finding(fingerprint="original")

    first = history.compare([original], [], scan_complete=True)
    assert first.resolved_count == 1

    returned = make_finding(
        start_line=15,
        fingerprint="returned",
    )

    second = history.compare([], [returned], scan_complete=True)

    assert second.reintroduced_count == 1
    assert second.results[0].status == VerificationStatus.REINTRODUCED
    assert second.results[0].current_finding == returned


def test_incomplete_scan_does_not_record_resolution():
    history = VerificationHistory()
    original = make_finding()

    report = history.compare([original], [], scan_complete=False)

    assert report.incomplete_count == 1
    assert not history.resolved_identities


def test_history_can_be_reused_after_resolution():
    history = VerificationHistory()
    original = make_finding()

    history.compare([original], [], scan_complete=True)

    returned = make_finding(fingerprint="returned")
    report = history.compare([original], [returned], scan_complete=True)

    assert report.reintroduced_count == 1


def test_reintroduced_finding_is_reported_in_baseline_comparison():
    history = VerificationHistory()
    original = make_finding(fingerprint="original")

    resolved = history.compare([original], [], scan_complete=True)
    assert resolved.resolved_count == 1

    returned = make_finding(fingerprint="returned")
    report = history.compare(
        [original],
        [returned],
        scan_complete=True,
    )

    assert report.reintroduced_count == 1
    assert report.results[0].status == VerificationStatus.REINTRODUCED


def test_ambiguous_comparison_does_not_change_resolution_history():
    history = VerificationHistory()
    original = make_finding(fingerprint="original")

    history.compare([original], [], scan_complete=True)
    before = set(history.resolved_identities)

    duplicate_baseline = [
        make_finding(start_line=10, fingerprint="old-1"),
        make_finding(start_line=10, fingerprint="old-2"),
    ]
    duplicate_current = [
        make_finding(start_line=10, fingerprint="new-1"),
        make_finding(start_line=10, fingerprint="new-2"),
    ]

    report = history.compare(
        duplicate_baseline,
        duplicate_current,
        scan_complete=True,
    )

    assert report.incomplete_count == 2
    assert history.resolved_identities == before


def test_reintroduced_finding_is_removed_from_resolved_history():
    history = VerificationHistory()
    original = make_finding(fingerprint="original")

    # First complete scan confirms resolution.
    first = history.compare([original], [], scan_complete=True)
    assert first.resolved_count == 1

    # The finding returns while the baseline is empty.
    returned = make_finding(fingerprint="returned")
    second = history.compare([], [returned], scan_complete=True)

    assert second.reintroduced_count == 1

    # Once reintroduced, it should no longer be stored as resolved.
    identity = ("bandit", "b602", "src/app.py")
    assert identity not in history.resolved_identities
    assert identity not in history.resolved_findings


def test_reintroduced_finding_stays_open_on_subsequent_scan():
    history = VerificationHistory()
    original = make_finding(fingerprint="original")

    # First scan confirms the finding is resolved.
    history.compare([original], [], scan_complete=True)

    # Second scan detects that the finding has returned.
    returned = make_finding(fingerprint="returned")
    second = history.compare([], [returned], scan_complete=True)
    assert second.reintroduced_count == 1

    # Third scan still reports the finding.
    current = make_finding(
        start_line=15,
        fingerprint="still-present",
    )
    third = history.compare([returned], [current], scan_complete=True)

    assert third.still_open_count == 1
    assert third.reintroduced_count == 0
    assert third.results[0].status == VerificationStatus.STILL_OPEN

    identity = ("bandit", "b602", "src/app.py")
    assert identity not in history.resolved_identities
    assert identity not in history.resolved_findings


def test_history_preserves_resolution_after_ambiguous_comparison():
    history = VerificationHistory()
    original = make_finding(fingerprint="original")

    # A complete scan confirms the original finding is resolved.
    first = history.compare([original], [], scan_complete=True)
    assert first.resolved_count == 1

    identity = ("bandit", "b602", "src/app.py")
    assert identity in history.resolved_identities

    # An ambiguous comparison must not erase the prior resolution.
    duplicate_baseline = [
        make_finding(start_line=10, fingerprint="old-1"),
        make_finding(start_line=10, fingerprint="old-2"),
    ]
    duplicate_current = [
        make_finding(start_line=10, fingerprint="new-1"),
        make_finding(start_line=10, fingerprint="new-2"),
    ]

    ambiguous = history.compare(
        duplicate_baseline,
        duplicate_current,
        scan_complete=True,
    )

    assert ambiguous.incomplete_count == 2
    assert identity in history.resolved_identities

    # With no baseline, the same identity is ambiguous again in current results.
    # It must not be reported as reintroduced without a unique match.
    next_report = history.compare(
        [],
        duplicate_current,
        scan_complete=True,
    )

    assert next_report.reintroduced_count == 0
    assert identity in history.resolved_identities

def test_duplicate_identity_is_matched_when_line_ranges_are_unique():
    baseline = [
        make_finding(start_line=10, fingerprint="old-1"),
        make_finding(start_line=20, fingerprint="old-2"),
    ]
    current = [
        make_finding(start_line=10, fingerprint="new-1"),
        make_finding(start_line=20, fingerprint="new-2"),
    ]

    report = compare_findings(baseline, current, scan_complete=True)

    assert report.still_open_count == 2
    assert report.incomplete_count == 0
    assert report.resolved_count == 0

def test_duplicate_identity_with_extra_current_finding_is_incomplete():
    baseline = [
        make_finding(start_line=10, fingerprint="old-1"),
        make_finding(start_line=20, fingerprint="old-2"),
    ]
    current = [
        make_finding(start_line=10, fingerprint="new-1"),
        make_finding(start_line=20, fingerprint="new-2"),
        make_finding(start_line=30, fingerprint="new-3"),
    ]

    report = compare_findings(baseline, current, scan_complete=True)

    assert report.incomplete_count == 2
    assert report.still_open_count == 0
    assert report.resolved_count == 0