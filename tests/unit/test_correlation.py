
from silentsec.schemas.finding import Finding, Severity
from silentsec.scoring.correlation import correlate_findings


def make_finding(
    *,
    fingerprint: str,
    tool: str,
    rule_id: str,
    message: str,
    line: int = 10,
    cwe_id: str | None = "CWE-78",
    file_path: str = "src/app.py",
) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        tool=tool,
        rule_id=rule_id,
        file_path=file_path,
        start_line=line,
        end_line=line,
        category="security",
        severity=Severity.HIGH,
        message=message,
        cwe_id=cwe_id,
    )


def test_correlates_matching_cross_tool_evidence():
    bandit = make_finding(
        fingerprint="bandit-1",
        tool="bandit",
        rule_id="B602",
        message="subprocess call with shell=True",
    )
    semgrep = make_finding(
        fingerprint="semgrep-1",
        tool="semgrep",
        rule_id="subprocess-shell-true",
        message="subprocess call with shell=True",
    )

    groups = correlate_findings([bandit, semgrep])

    assert len(groups) == 1
    assert groups[0].correlation_type == "cross_tool"
    assert {item.tool for item in groups[0].findings} == {
        "bandit",
        "semgrep",
    }


def test_does_not_correlate_different_lines():
    first = make_finding(
        fingerprint="first",
        tool="bandit",
        rule_id="B602",
        message="subprocess call with shell=True",
        line=10,
    )
    second = make_finding(
        fingerprint="second",
        tool="semgrep",
        rule_id="subprocess-shell-true",
        message="subprocess call with shell=True",
        line=20,
    )

    groups = correlate_findings([first, second])

    assert len(groups) == 2


def test_does_not_correlate_when_cwe_is_missing():
    first = make_finding(
        fingerprint="first",
        tool="bandit",
        rule_id="B602",
        message="subprocess call with shell=True",
    )
    second = make_finding(
        fingerprint="second",
        tool="semgrep",
        rule_id="subprocess-shell-true",
        message="subprocess call with shell=True",
        cwe_id=None,
    )

    assert len(correlate_findings([first, second])) == 2


def test_preserves_exact_fingerprint_duplicates():
    first = make_finding(
        fingerprint="same",
        tool="bandit",
        rule_id="B602",
        message="subprocess call with shell=True",
    )
    second = make_finding(
        fingerprint="same",
        tool="semgrep",
        rule_id="subprocess-shell-true",
        message="different scanner wording",
    )

    groups = correlate_findings([first, second])

    assert len(groups) == 1
    assert groups[0].correlation_type == "exact_fingerprint"
    assert len(groups[0].findings) == 2


def test_does_not_correlate_different_cwes():
    first = make_finding(
        fingerprint="first",
        tool="bandit",
        rule_id="B602",
        message="subprocess call with shell=True",
        cwe_id="CWE-78",
    )
    second = make_finding(
        fingerprint="second",
        tool="semgrep",
        rule_id="subprocess-shell-true",
        message="subprocess call with shell=True",
        cwe_id="CWE-89",
    )

    assert len(correlate_findings([first, second])) == 2



def test_does_not_merge_multiple_findings_from_same_tool():
    bandit_first = make_finding(
        fingerprint="bandit-1",
        tool="bandit",
        rule_id="B602",
        message="subprocess call with shell=True",
        line=10,
    )
    bandit_second = make_finding(
        fingerprint="bandit-2",
        tool="bandit",
        rule_id="B603",
        message="subprocess call with shell=True",
        line=10,
    )
    semgrep = make_finding(
        fingerprint="semgrep-1",
        tool="semgrep",
        rule_id="subprocess-shell-true",
        message="subprocess call with shell=True",
        line=10,
    )

    groups = correlate_findings(
        [bandit_first, bandit_second, semgrep]
    )

    assert len(groups) == 2
    assert sum(
        group.correlation_type == "cross_tool"
        for group in groups
    ) == 1

    cross_tool_group = next(
        group
        for group in groups
        if group.correlation_type == "cross_tool"
    )

    assert len(cross_tool_group.findings) == 2
    assert len(
        {finding.tool.casefold() for finding in cross_tool_group.findings}
    ) == 2

