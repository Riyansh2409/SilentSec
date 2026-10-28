"""Deterministic recurring-pattern detection for correlated findings."""

from collections import defaultdict
from collections.abc import Iterable

from pydantic import BaseModel, Field

from silentsec.schemas.finding import Finding, Severity
from silentsec.scoring.correlation import CorrelationGroup


class RecurringPattern(BaseModel):
    """A repeated rule or cross-tool CWE pattern across repository locations."""

    pattern_key: str
    rule_ids: list[str] = Field(default_factory=list)
    cwe_id: str | None = None
    occurrence_count: int = Field(ge=1)
    file_count: int = Field(ge=1)
    files: list[str] = Field(default_factory=list)
    representative_message: str
    highest_severity: Severity
    finding_fingerprints: list[str] = Field(default_factory=list)


def _path_key(path: str) -> str:
    """Normalize path separators and case for deterministic comparisons."""
    return path.replace("\\", "/").casefold().removeprefix("./")


def _pattern_from_group(
    pattern_key: str,
    findings: list[Finding],
    *,
    cwe_id: str | None,
) -> RecurringPattern | None:
    """Build a pattern only when it meets the recurrence threshold."""
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.fingerprint, finding)

    items = sorted(
        unique.values(),
        key=lambda finding: (
            _path_key(finding.file_path),
            finding.start_line,
            finding.end_line or finding.start_line,
            finding.tool.casefold(),
            finding.rule_id,
            finding.fingerprint,
        ),
    )
    if not items:
        return None

    files_by_key: dict[str, str] = {}
    for finding in items:
        files_by_key.setdefault(_path_key(finding.file_path), finding.file_path)
    files = sorted(files_by_key.values(), key=_path_key)

    locations = {
        (
            _path_key(finding.file_path),
            finding.start_line,
            finding.end_line or finding.start_line,
        )
        for finding in items
    }

    if len(files) < 2 and len(locations) < 3:
        return None

    severity_order = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }
    representative = min(
        items,
        key=lambda finding: (
            -severity_order[finding.severity],
            _path_key(finding.file_path),
            finding.start_line,
            finding.rule_id,
            finding.fingerprint,
        ),
    )

    return RecurringPattern(
        pattern_key=pattern_key,
        rule_ids=sorted({finding.rule_id for finding in items}),
        cwe_id=cwe_id,
        occurrence_count=len(items),
        file_count=len(files),
        files=files,
        representative_message=representative.message,
        highest_severity=max(items, key=lambda f: severity_order[f.severity]).severity,
        finding_fingerprints=sorted(finding.fingerprint for finding in items),
    )


def detect_recurring_patterns(
    groups: Iterable[CorrelationGroup],
) -> list[RecurringPattern]:
    """Detect repeated rule patterns and cross-tool CWE patterns.

    Inputs must be correlation groups produced by the scoring pipeline. Each
    group's representative is used once, so correlated duplicates do not
    inflate recurrence counts.
    """
    representatives = sorted(
        (group.representative for group in groups),
        key=lambda finding: (
            finding.tool.casefold(),
            finding.rule_id,
            _path_key(finding.file_path),
            finding.start_line,
            finding.fingerprint,
        ),
    )

    rule_groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    cwe_groups: dict[str, list[Finding]] = defaultdict(list)

    for finding in representatives:
        rule_groups[(finding.tool.casefold(), finding.rule_id)].append(finding)
        if finding.cwe_id:
            cwe_groups[finding.cwe_id.casefold()].append(finding)

    patterns: dict[str, RecurringPattern] = {}

    for (tool, rule_id), findings in sorted(rule_groups.items()):
        pattern_key = f"rule:{tool}:{rule_id}"
        pattern = _pattern_from_group(pattern_key, findings, cwe_id=None)
        if pattern is not None:
            patterns[pattern_key] = pattern

    for cwe_key, findings in sorted(cwe_groups.items()):
        tools = {finding.tool.casefold() for finding in findings}
        if len(tools) < 2:
            continue
        cwe_id = min(
            (finding.cwe_id for finding in findings if finding.cwe_id),
            key=str.casefold,
        )
        pattern_key = f"cwe:{cwe_key}"
        pattern = _pattern_from_group(pattern_key, findings, cwe_id=cwe_id)
        if pattern is not None:
            patterns[pattern_key] = pattern

    return sorted(
        patterns.values(),
        key=lambda pattern: (
            -pattern.file_count,
            -pattern.occurrence_count,
            pattern.pattern_key,
        ),
    )
