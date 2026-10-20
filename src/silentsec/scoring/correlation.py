
"""Evidence-based correlation of findings reported by security tools."""

import re
from collections.abc import Iterable

from pydantic import BaseModel, Field

from silentsec.schemas.finding import Finding, Severity


class CorrelationGroup(BaseModel):
    """Original findings linked to one logical security issue."""

    representative: Finding
    findings: list[Finding] = Field(min_length=1)
    correlation_type: str
    reason: str


def _normalized_path(path: str) -> str:
    """Normalize path separators and case for comparisons."""
    return path.replace("\\", "/").casefold().removeprefix("./")


def _line_ranges_overlap(first: Finding, second: Finding) -> bool:
    """Return whether two finding locations overlap."""
    first_end = first.end_line or first.start_line
    second_end = second.end_line or second.start_line

    return (
        first.start_line <= second_end
        and second.start_line <= first_end
    )


def _evidence_tokens(finding: Finding) -> set[str]:
    """Extract meaningful evidence tokens from rule IDs and messages."""
    text = f"{finding.rule_id} {finding.message}".casefold()
    tokens = set(re.findall(r"[a-z][a-z0-9_+#.-]{2,}", text))

    generic_tokens = {
        "the", "and", "for", "with", "from", "this", "that",
        "issue", "security", "detected", "found", "potential",
        "rule", "line", "use", "unsafe",
    }
    return tokens - generic_tokens


def _has_cross_tool_evidence(
    first: Finding,
    second: Finding,
) -> bool:
    """Require location, CWE, and textual evidence before correlation."""
    if first.tool.casefold() == second.tool.casefold():
        return False

    if _normalized_path(first.file_path) != _normalized_path(
        second.file_path
    ):
        return False

    if not _line_ranges_overlap(first, second):
        return False

    if not first.cwe_id or not second.cwe_id:
        return False

    if first.cwe_id.casefold() != second.cwe_id.casefold():
        return False

    shared_tokens = _evidence_tokens(first) & _evidence_tokens(second)
    return bool(shared_tokens)


def _representative_key(finding: Finding) -> tuple:
    """Prefer higher severity, then confidence, deterministically."""
    severity_order = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }
    confidence = (
        finding.confidence
        if finding.confidence is not None
        else 0.75
    )

    return (
        -severity_order[finding.severity],
        -confidence,
        finding.file_path.casefold(),
        finding.start_line,
        finding.rule_id,
        finding.tool,
        finding.finding_id,
    )


def _stable_key(finding: Finding) -> tuple:
    """Provide deterministic ordering for findings."""
    return (
        _normalized_path(finding.file_path),
        finding.start_line,
        finding.tool.casefold(),
        finding.rule_id,
        finding.fingerprint,
    )


def correlate_findings(
    findings: Iterable[Finding],
) -> list[CorrelationGroup]:
    """Group exact duplicates and conservative cross-tool matches."""
    items = list(findings)
    exact_groups: dict[str, list[Finding]] = {}

    for finding in items:
        exact_groups.setdefault(finding.fingerprint, []).append(finding)

    groups: list[CorrelationGroup] = []
    singleton_findings: list[Finding] = []

    # Collapse exact fingerprints first.
    for fingerprint in sorted(exact_groups):
        members = exact_groups[fingerprint]
        representative = min(members, key=_representative_key)

        if len(members) == 1:
            singleton_findings.append(representative)
        else:
            groups.append(
                CorrelationGroup(
                    representative=representative,
                    findings=sorted(members, key=_stable_key),
                    correlation_type="exact_fingerprint",
                    reason="Findings share the same fingerprint.",
                )
            )

    singleton_findings.sort(key=_stable_key)

    # Build conservative groups. Every member must match every other
    # member, and a group cannot contain multiple findings from one tool.
    consumed_fingerprints: set[str] = set()

    for index, first in enumerate(singleton_findings):
        if first.fingerprint in consumed_fingerprints:
            continue

        matches = [first]
        tools_in_group = {first.tool.casefold()}

        for candidate in singleton_findings[index + 1 :]:
            if candidate.fingerprint in consumed_fingerprints:
                continue

            candidate_tool = candidate.tool.casefold()

            if candidate_tool in tools_in_group:
                continue

            if all(
                _has_cross_tool_evidence(member, candidate)
                for member in matches
            ):
                matches.append(candidate)
                tools_in_group.add(candidate_tool)

        if len(matches) == 1:
            groups.append(
                CorrelationGroup(
                    representative=first,
                    findings=[first],
                    correlation_type="single",
                    reason="No sufficiently strong correlation evidence.",
                )
            )
            continue

        representative = min(matches, key=_representative_key)

        groups.append(
            CorrelationGroup(
                representative=representative,
                findings=sorted(matches, key=_stable_key),
                correlation_type="cross_tool",
                reason=(
                    "Different tools reported matching CWE and "
                    "overlapping locations with shared issue evidence."
                ),
            )
        )

        consumed_fingerprints.update(
            member.fingerprint for member in matches
        )

    return sorted(
        groups,
        key=lambda group: _stable_key(group.representative),
    )
