"""Evidence-based correlation of findings reported by security tools."""

import re
from collections.abc import Iterable

from pydantic import BaseModel, Field

from silentsec.architecture.import_analyzer import (
    ImportDependency,
    module_name_for_file,
)
from silentsec.schemas.finding import Finding, Severity


class CorrelationEvidence(BaseModel):
    """Structured evidence supporting a finding correlation."""

    exact_fingerprint_match: bool = False
    shared_cwe: bool = False
    same_file: bool = False
    overlapping_lines: bool = False
    shared_tokens: list[str] = Field(default_factory=list)
    architecture_dependency: bool = False

class CorrelationGroup(BaseModel):
    """Original findings linked to one logical security issue."""

    representative: Finding
    findings: list[Finding] = Field(min_length=1)
    correlation_type: str
    reason: str
    evidence: CorrelationEvidence = Field(default_factory=CorrelationEvidence)


def _normalized_path(path: str) -> str:
    """Normalize path separators and case for comparisons."""
    return path.replace("\\", "/").casefold().removeprefix("./")


def _line_ranges_overlap(first: Finding, second: Finding) -> bool:
    """Return whether two finding locations overlap."""
    first_end = first.end_line or first.start_line
    second_end = second.end_line or second.start_line

    return first.start_line <= second_end and second.start_line <= first_end


def _evidence_tokens(finding: Finding) -> set[str]:
    """Extract meaningful evidence tokens from rule IDs and messages."""
    text = f"{finding.rule_id} {finding.message}".casefold()
    tokens = set(re.findall(r"[a-z][a-z0-9_+#.-]{2,}", text))

    generic_tokens = {
        "the",
        "and",
        "for",
        "with",
        "from",
        "this",
        "that",
        "issue",
        "security",
        "detected",
        "found",
        "potential",
        "rule",
        "line",
        "use",
        "unsafe",
    }
    return tokens - generic_tokens



def _has_cross_tool_evidence(
    first: Finding,
    second: Finding,
    *,
    dependency_edges: set[tuple[str, str]] | None = None,
    repo_root: str | None = None,
) -> bool:
    """Require strong evidence before correlating findings across tools."""
    if first.tool.casefold() == second.tool.casefold():
        return False

    if not first.cwe_id or not second.cwe_id:
        return False

    if first.cwe_id.casefold() != second.cwe_id.casefold():
        return False

    shared_tokens = _evidence_tokens(first) & _evidence_tokens(second)
    if not shared_tokens:
        return False

    same_file = (
        _normalized_path(first.file_path)
        == _normalized_path(second.file_path)
    )

    if same_file:
        return _line_ranges_overlap(first, second)

    # Cross-file correlation requires a confirmed direct import dependency.
    if not dependency_edges or not repo_root:
        return False

    first_module = module_name_for_file(first.file_path, repo_root)
    second_module = module_name_for_file(second.file_path, repo_root)

    if not first_module or not second_module:
        return False

    return (
        (first_module, second_module) in dependency_edges
        or (second_module, first_module) in dependency_edges
    )



def _build_evidence(
    findings: list[Finding],
    *,
    exact_fingerprint_match: bool = False,
    architecture_dependency: bool = False,
) -> CorrelationEvidence:
    """Build auditable evidence from the findings in a group."""
    shared_cwe = (
        len(findings) > 1
        and all(finding.cwe_id for finding in findings)
        and len({finding.cwe_id.casefold() for finding in findings}) == 1
    )

    same_file = len({_normalized_path(finding.file_path) for finding in findings}) == 1

    overlapping_lines = (
        len(findings) > 1
        and all(_line_ranges_overlap(findings[0], finding) for finding in findings[1:])
        and all(
            _line_ranges_overlap(first, second)
            for index, first in enumerate(findings)
            for second in findings[index + 1 :]
        )
    )

    shared_tokens = (
        sorted(set.intersection(*(_evidence_tokens(finding) for finding in findings)))
        if len(findings) > 1
        else []
    )

    return CorrelationEvidence(
        exact_fingerprint_match=exact_fingerprint_match,
        shared_cwe=bool(shared_cwe),
        same_file=same_file,
        overlapping_lines=overlapping_lines,
        shared_tokens=shared_tokens,
        architecture_dependency=architecture_dependency,
    )


# Rules that all describe the same broad or silent exception handler. When
# several of these fire on the same handler, they are one logical issue.
# Keys are (tool, rule_id), both compared case-insensitively.
EXCEPTION_HANDLER_RULES: frozenset[tuple[str, str]] = frozenset(
    {
        ("silentsec-arch", "ssec-arch-001"),  # broad / bare except
        ("silentsec-arch", "ssec-arch-002"),  # swallowed exception
        ("bandit", "b110"),  # try_except_pass
        ("bandit", "b112"),  # try_except_continue
    }
)


def _is_exception_handler_rule(finding: Finding) -> bool:
    return (finding.tool.casefold(), finding.rule_id.casefold()) in EXCEPTION_HANDLER_RULES


def _group_same_exception_handler(
    findings: list[Finding],
) -> tuple[list[CorrelationGroup], list[Finding]]:
    """Merge handler findings that start on the same line of the same file.

    Requiring the same start line, not just overlapping ranges, keeps an
    outer handler separate from a handler nested inside it.
    """
    by_location: dict[tuple[str, int], list[Finding]] = {}
    remaining: list[Finding] = []

    for finding in findings:
        if _is_exception_handler_rule(finding):
            key = (_normalized_path(finding.file_path), finding.start_line)
            by_location.setdefault(key, []).append(finding)
        else:
            remaining.append(finding)

    groups: list[CorrelationGroup] = []

    for key in sorted(by_location):
        members = by_location[key]

        if len(members) == 1:
            remaining.extend(members)
            continue

        groups.append(
            CorrelationGroup(
                representative=min(members, key=_representative_key),
                findings=sorted(members, key=_stable_key),
                correlation_type="same_exception_handler",
                reason=(
                    "Equivalent broad or silent exception-handler rules were "
                    "reported for the same handler."
                ),
                evidence=_build_evidence(members),
            )
        )

    return groups, remaining


def _representative_key(finding: Finding) -> tuple:
    """Prefer higher severity, then confidence, deterministically."""
    severity_order = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }
    confidence = finding.confidence if finding.confidence is not None else 0.75

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
    *,
    dependencies: Iterable[ImportDependency] = (),
    repo_root: str | None = None,
) -> list[CorrelationGroup]:
    """Group exact duplicates and conservative cross-tool matches."""
    items = list(findings)
    dependency_edges = {
    (dependency.source_module, dependency.imported_module)
    for dependency in dependencies
    }
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
                    evidence=_build_evidence(
                        members,
                        exact_fingerprint_match=True,
                    ),
                )
            )

    handler_groups, singleton_findings = _group_same_exception_handler(
        singleton_findings
    )
    groups.extend(handler_groups)

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
                    _has_cross_tool_evidence(
                        member,
                        candidate,
                        dependency_edges=dependency_edges,
                        repo_root=repo_root,
                    )
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
        architecture_dependency = False

        if repo_root and dependency_edges and len(matches) > 1:
            modules = [
                module_name_for_file(finding.file_path, repo_root)
                for finding in matches
            ]

            architecture_dependency = any(
                source is not None
                and target is not None
                and (
                    (source, target) in dependency_edges
                    or (target, source) in dependency_edges
                )
                for index, source in enumerate(modules)
                for target in modules[index + 1 :]
            )

        groups.append(
            CorrelationGroup(
                representative=representative,
                findings=sorted(matches, key=_stable_key),
                correlation_type="cross_tool",
                reason=(
                    "Different tools reported matching CWE and "
                    "overlapping locations with shared issue evidence."
                ),
                evidence=_build_evidence(
                    matches,
                    architecture_dependency=architecture_dependency,
                ),
            )
        )

        consumed_fingerprints.update(member.fingerprint for member in matches)

    return sorted(
        groups,
        key=lambda group: _stable_key(group.representative),
    )
