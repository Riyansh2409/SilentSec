"""SARIF 2.1.0 export, the format GitHub code scanning and most CI tools read.

A scan exports one SARIF result per unique issue (findings that several
scanners reported are merged, and the other reports are named in the
message). A gate result exports only the findings the change introduced, so
a pull request shows the new problems and not the existing debt.

Upload with ``github/codeql-action/upload-sarif`` to show the results in the
repository's Security tab and as annotations on pull requests.
"""

from collections.abc import Iterable
from importlib import metadata
from typing import Any

from silentsec.gate import GateFinding, GateReport
from silentsec.scanners.common import create_fingerprint
from silentsec.scanners.scanner_service import RepositoryScanResult
from silentsec.schemas import FindingCategory, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Riyansh2409/SilentSec"

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub maps this 0-10 value to its Critical/High/Medium/Low labels.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _version() -> str:
    try:
        return metadata.version("silentsec")
    except metadata.PackageNotFoundError:
        return "0.0.0"


class _Issue:
    """What one SARIF result needs, from either a scan or a gate."""

    def __init__(
        self,
        *,
        tool: str,
        rule_id: str,
        file_path: str,
        start_line: int,
        end_line: int | None,
        severity: Severity,
        category: FindingCategory,
        message: str,
        fingerprint: str,
        cwe_id: str | None = None,
        also_reported_by: Iterable[str] = (),
        points: float | None = None,
        exposure: str | None = None,
        exposure_path: Iterable[str] = (),
    ) -> None:
        self.tool = tool
        self.rule_id = rule_id
        self.file_path = file_path.replace("\\", "/").removeprefix("./")
        self.start_line = max(1, start_line)
        self.end_line = max(self.start_line, end_line or self.start_line)
        self.severity = severity
        self.category = category
        self.message = message
        self.fingerprint = fingerprint
        self.cwe_id = cwe_id
        self.also_reported_by = sorted(set(also_reported_by))
        self.points = points
        self.exposure = exposure
        self.exposure_path = list(exposure_path)

    @property
    def sarif_rule_id(self) -> str:
        return f"{self.tool}/{self.rule_id}"


def _rule(issue: _Issue) -> dict[str, Any]:
    tags = []
    if issue.category in {FindingCategory.SECURITY, FindingCategory.SECRET}:
        tags.append("security")
    tags.append(issue.category.value)
    if issue.cwe_id:
        tags.append(f"external/cwe/{issue.cwe_id.lower()}")
    tags = list(dict.fromkeys(tags))  # SARIF requires unique tags
    rule: dict[str, Any] = {
        "id": issue.sarif_rule_id,
        "name": issue.rule_id,
        "shortDescription": {"text": f"{issue.tool} {issue.rule_id}"},
        "properties": {"tags": tags, "precision": "medium"},
    }
    if issue.category in {FindingCategory.SECURITY, FindingCategory.SECRET}:
        rule["properties"]["security-severity"] = SECURITY_SEVERITY[issue.severity]
    return rule


def _result(issue: _Issue, rule_index: int) -> dict[str, Any]:
    text = issue.message.strip() or f"{issue.tool} {issue.rule_id}"
    if issue.also_reported_by:
        text += f" (Also reported by {', '.join(issue.also_reported_by)}.)"
    properties: dict[str, Any] = {
        "severity": issue.severity.value,
        "category": issue.category.value,
    }
    if issue.points is not None:
        properties["silentsecPoints"] = round(issue.points, 1)
    if issue.exposure is not None:
        # "reachable": a web route reaches the function in the call graph; a
        # call path in the code, not proof of exploitability.
        properties["exposure"] = issue.exposure
        if issue.exposure_path:
            properties["exposurePath"] = issue.exposure_path
    return {
        "ruleId": issue.sarif_rule_id,
        "ruleIndex": rule_index,
        "level": LEVEL[issue.severity],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": issue.file_path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": issue.start_line, "endLine": issue.end_line},
                }
            }
        ],
        "partialFingerprints": {"silentsec/v1": issue.fingerprint},
        "properties": properties,
    }


def _document(issues: list[_Issue], *, invocation_ok: bool, notes: list[str]) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    index_of: dict[str, int] = {}
    results = []
    for issue in issues:
        if issue.sarif_rule_id not in index_of:
            index_of[issue.sarif_rule_id] = len(rules)
            rules.append(_rule(issue))
        results.append(_result(issue, index_of[issue.sarif_rule_id]))
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SilentSec",
                        "semanticVersion": _version(),
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": "silentsec/"},
                "invocations": [
                    {
                        "executionSuccessful": invocation_ok,
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": note}} for note in notes
                        ],
                    }
                ],
                "results": results,
            }
        ],
    }


def scan_to_sarif(result: RepositoryScanResult) -> dict[str, Any]:
    """One SARIF result per unique issue of a scan."""
    debt = result.security_debt
    issues: list[_Issue] = []
    if debt is not None:
        groups = {group.representative.fingerprint: group for group in debt.correlation_groups}
        for item in debt.scored_findings:
            finding = item.finding
            group = groups.get(finding.fingerprint)
            others = [
                f"{member.tool} {member.rule_id}"
                for member in (group.findings if group is not None else [])
                if member.fingerprint != finding.fingerprint
                or (member.tool, member.rule_id) != (finding.tool, finding.rule_id)
            ]
            issues.append(
                _Issue(
                    tool=finding.tool,
                    rule_id=finding.rule_id,
                    file_path=finding.file_path,
                    start_line=finding.start_line,
                    end_line=finding.end_line,
                    severity=finding.severity,
                    category=finding.category,
                    message=finding.message,
                    fingerprint=finding.fingerprint,
                    cwe_id=finding.cwe_id,
                    also_reported_by=others,
                    points=item.score,
                    exposure=item.exposure,
                    exposure_path=item.exposure_path,
                )
            )
    notes = [
        f"{scanner.scanner} {scanner.status.value}: {error}"
        for scanner in result.scanners
        for error in scanner.errors[:1]
        if scanner.status.value not in {"success", "skipped"}
    ]
    return _document(issues, invocation_ok=result.security_debt_complete, notes=notes)


def _gate_issue(item: GateFinding) -> _Issue:
    return _Issue(
        tool=item.tool,
        rule_id=item.rule_id,
        file_path=item.file_path,
        start_line=item.start_line,
        end_line=item.end_line,
        severity=item.severity,
        category=item.category,
        message=item.message,
        fingerprint=item.fingerprint
        or create_fingerprint(item.tool, item.rule_id, item.file_path, item.start_line),
        cwe_id=item.cwe_id,
    )


def gate_to_sarif(report: GateReport) -> dict[str, Any]:
    """Only the findings the change introduced: blocking, warnings and below-threshold."""
    issues = [_gate_issue(item) for item in [*report.blocking, *report.warnings, *report.other_new]]
    return _document(
        issues,
        invocation_ok=report.verdict.value != "incomplete",
        notes=list(report.scanner_problems),
    )
