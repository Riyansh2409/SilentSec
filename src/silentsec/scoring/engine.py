"""Deterministic and explainable repository security-debt scoring."""

import os
from collections import Counter
from collections.abc import Iterable
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from silentsec.architecture.analyzer import (
    EXCLUDED_DIRECTORIES as ARCHITECTURE_EXCLUDED_DIRECTORIES,
)
from silentsec.architecture.analyzer import MAX_FILE_BYTES
from silentsec.architecture.import_analyzer import analyze_python_imports
from silentsec.languages.detector import EXTENSION_TO_LANGUAGE
from silentsec.schemas.finding import Finding, FindingCategory, FindingStatus, Severity
from silentsec.scoring.correlation import CorrelationGroup, correlate_findings
from silentsec.scoring.recurrence import RecurringPattern, detect_recurring_patterns

# These are SilentSec v1 product heuristics, not an industry standard.
BASE_POINTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 1,
}
DEFAULT_CONFIDENCE = 0.75
MAX_REPOSITORY_SCORE = 100.0
ARCHITECTURE_DEBT_CAP = 25.0
RECURRENCE_POINTS_PER_EXTRA_FILE = 2.0
RECURRENCE_POINTS_CAP = 15.0
MIN_LINES_FOR_DENSITY = 500
ARCHITECTURE_RISK_THRESHOLDS = {
    "low": 10.0,
    "moderate": 20.0,
    "high": 20.0,
}
RemediationEffort = Literal["low", "medium", "high"]


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class ScoreComponent(BaseModel):
    """One transparent contribution to the existing repository score."""

    name: str
    points: float
    max_points: float
    explanation: str
    informational: bool = False


class ScoredFinding(BaseModel):
    """A finding with score calculation and independent remediation effort."""

    finding: Finding
    base_points: int = Field(ge=1)
    effective_confidence: float = Field(ge=0.0, le=1.0)
    score: float = Field(ge=0.0)
    explanation: str
    remediation_effort: RemediationEffort = "low"


class SecurityDebtReport(BaseModel):
    """Explainable security-debt summary for repository findings."""

    score: float = Field(ge=0.0, le=MAX_REPOSITORY_SCORE)
    raw_score: float = Field(ge=0.0)
    risk_level: RiskLevel
    architecture_risk_level: RiskLevel
    risk_explanation: str
    input_findings_count: int = Field(ge=0)
    unique_open_findings_count: int = Field(ge=0)
    duplicate_findings_removed: int = Field(ge=0)
    fixed_findings_excluded: int = Field(ge=0)
    suppressed_findings_excluded: int = Field(ge=0)
    exact_duplicates_removed: int = Field(ge=0, default=0)
    cross_tool_duplicates_removed: int = Field(ge=0, default=0)
    same_handler_duplicates_removed: int = Field(ge=0, default=0)
    highest_severity: Severity | None = None
    scored_findings: list[ScoredFinding] = Field(default_factory=list)
    correlation_groups: list[CorrelationGroup] = Field(default_factory=list)
    architecture_debt_points: float = Field(
        default=0.0, ge=0.0, le=ARCHITECTURE_DEBT_CAP
    )
    security_points: float = Field(default=0.0, ge=0.0)
    architecture_debt_explanation: str = (
        "Architecture and maintainability contributions are capped at 25.0 points."
    )
    recurring_patterns: list[RecurringPattern] = Field(default_factory=list)
    components: list[ScoreComponent] = Field(default_factory=list)
    analyzed_lines: int | None = Field(default=None, ge=0)
    debt_density_per_kloc: float | None = Field(default=None, ge=0.0)
    remediation_effort_summary: dict[str, int] = Field(default_factory=dict)


def _effective_confidence(finding: Finding) -> float:
    if finding.confidence is None:
        return DEFAULT_CONFIDENCE
    return finding.confidence


def _representative_sort_key(finding: Finding) -> tuple:
    return (
        -BASE_POINTS[finding.severity],
        -_effective_confidence(finding),
        finding.file_path.casefold(),
        finding.start_line,
        finding.rule_id,
        finding.tool,
        finding.finding_id,
    )


def _risk_level_for_score(score: float) -> RiskLevel:
    if score <= 0:
        return RiskLevel.NONE
    if score < 10:
        return RiskLevel.LOW
    if score < 20:
        return RiskLevel.MODERATE
    if score < 40:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _architecture_risk_level_for_score(score: float) -> RiskLevel:
    if score <= 0:
        return RiskLevel.NONE
    if score < ARCHITECTURE_RISK_THRESHOLDS["low"]:
        return RiskLevel.LOW
    if score < ARCHITECTURE_RISK_THRESHOLDS["moderate"]:
        return RiskLevel.MODERATE
    return RiskLevel.HIGH


def _remediation_effort(finding: Finding) -> RemediationEffort:
    """Static effort estimate; this never participates in risk or scoring."""
    rule = finding.rule_id.upper()
    cwe = (finding.cwe_id or "").upper().removeprefix("CWE-")

    if finding.category == FindingCategory.SECRET:
        return "medium"
    if rule in {"ARCH-004", "SSEC-ARCH-004", "SSEC-ARCH-006"}:
        return "high"
    if rule in {"ARCH-003", "SSEC-ARCH-003", "SSEC-ARCH-005"}:
        return "medium"
    if rule in {
        "ARCH-001", "ARCH-002", "SSEC-ARCH-001", "SSEC-ARCH-002"
    }:
        return "low"
    if cwe in {"78", "89", "94"}:
        return "medium"
    return "low"


def _score_finding(finding: Finding) -> ScoredFinding:
    """Calculate one finding's unchanged security-debt contribution."""
    base_points = BASE_POINTS[finding.severity]
    confidence = _effective_confidence(finding)
    confidence_factor = 0.5 + (0.5 * confidence)
    points = round(base_points * confidence_factor, 3)
    confidence_source = (
        "reported" if finding.confidence is not None else "defaulted"
    )
    explanation = (
        f"{finding.severity.value.title()} severity contributes "
        f"{base_points} base points; {confidence_source} confidence "
        f"{confidence:.2f} applies a {confidence_factor:.3f} factor, "
        f"for {points:.3f} points."
    )
    return ScoredFinding(
        finding=finding,
        base_points=base_points,
        effective_confidence=confidence,
        score=points,
        explanation=explanation,
        remediation_effort=_remediation_effort(finding),
    )


def _count_nonblank_source_lines(repo_root: str | Path) -> int:
    """Count eligible source lines without executing or parsing source files."""
    root = Path(repo_root).expanduser().resolve()
    if not root.is_dir():
        return 0

    total = 0
    for current_dir, directories, filenames in os.walk(
        root, topdown=True, followlinks=False
    ):
        directories[:] = sorted(
            name
            for name in directories
            if name not in ARCHITECTURE_EXCLUDED_DIRECTORIES
            and not (Path(current_dir) / name).is_symlink()
        )
        base = Path(current_dir)
        for filename in sorted(filenames):
            path = base / filename
            if path.is_symlink() or path.suffix.lower() not in EXTENSION_TO_LANGUAGE:
                continue
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
                if not resolved.is_file() or resolved.stat().st_size > MAX_FILE_BYTES:
                    continue
                content = resolved.read_bytes()
                if b"\x00" in content:
                    continue
                text = content.decode("utf-8-sig")
            except (OSError, UnicodeError, ValueError, RuntimeError):
                continue
            total += sum(1 for line in text.splitlines() if line.strip())
    return total


def score_findings(
    findings: Iterable[Finding],
    *,
    repo_root: str | None = None,
) -> SecurityDebtReport:
    """Score logical open issues and expose recurrence and explainability data."""
    items = list(findings)
    fixed_count = sum(f.status == FindingStatus.FIXED for f in items)
    suppressed_count = sum(f.status == FindingStatus.SUPPRESSED for f in items)
    open_findings = [f for f in items if f.status == FindingStatus.OPEN]

    if repo_root is not None:
        import_analysis = analyze_python_imports(repo_root)
        correlation_groups = correlate_findings(
            open_findings,
            dependencies=import_analysis.dependencies,
            repo_root=repo_root,
        )
    else:
        correlation_groups = correlate_findings(open_findings)

    scored_findings = [
        _score_finding(group.representative) for group in correlation_groups
    ]
    scored_findings.sort(
        key=lambda item: (
            -item.score,
            -item.base_points,
            item.finding.file_path.casefold(),
            item.finding.start_line,
            item.finding.rule_id,
            item.finding.fingerprint,
        )
    )

    architecture_categories = {
        FindingCategory.ARCHITECTURE,
        FindingCategory.MAINTAINABILITY,
    }
    security_categories = {FindingCategory.SECURITY, FindingCategory.SECRET}

    architecture_raw_points = round(
        sum(
            item.score
            for item in scored_findings
            if item.finding.category in architecture_categories
        ),
        3,
    )
    architecture_debt_points = round(
        min(architecture_raw_points, ARCHITECTURE_DEBT_CAP), 3
    )
    security_points = round(
        sum(
            item.score
            for item in scored_findings
            if item.finding.category in security_categories
        ),
        3,
    )
    other_points = round(
        sum(
            item.score
            for item in scored_findings
            if item.finding.category not in architecture_categories
            and item.finding.category not in security_categories
        ),
        3,
    )
    raw_score = round(
        architecture_debt_points + security_points + other_points, 3
    )
    repository_score = round(min(raw_score, MAX_REPOSITORY_SCORE), 3)
    architecture_debt_explanation = (
        f"Architecture and maintainability findings contribute "
        f"{architecture_raw_points:.3f} raw points; capped at "
        f"{ARCHITECTURE_DEBT_CAP:.1f}, resulting in "
        f"{architecture_debt_points:.3f} points."
    )

    security_risk_level = _risk_level_for_score(security_points)
    architecture_risk_level = _architecture_risk_level_for_score(
        architecture_debt_points
    )
    risk_explanation = (
        f"Security risk is {security_risk_level.value.upper()} based on "
        f"{security_points:.1f} security points; architectural debt is "
        f"{architecture_risk_level.value.upper()} "
        f"({architecture_debt_points:.1f} of "
        f"{ARCHITECTURE_DEBT_CAP:.1f} capped points)."
    )

    recurring_patterns = detect_recurring_patterns(correlation_groups)
    recurrence_points = round(
        min(
            sum(
                max(0, pattern.file_count - 1)
                * RECURRENCE_POINTS_PER_EXTRA_FILE
                for pattern in recurring_patterns
            ),
            RECURRENCE_POINTS_CAP,
        ),
        3,
    )

    # Preserve the existing capped score. This explicit adjustment makes the
    # component invariant hold even when the uncapped raw score exceeds 100.
    score_cap_adjustment = round(repository_score - raw_score, 3)
    components = [
        ScoreComponent(
            name="security_severity",
            points=security_points,
            max_points=MAX_REPOSITORY_SCORE,
            explanation="Existing security and secret finding contributions.",
        ),
        ScoreComponent(
            name="architectural_fragility",
            points=architecture_debt_points,
            max_points=ARCHITECTURE_DEBT_CAP,
            explanation=architecture_debt_explanation,
        ),
        ScoreComponent(
            name="other_findings",
            points=other_points,
            max_points=MAX_REPOSITORY_SCORE,
            explanation="Existing contributions from other finding categories.",
        ),
    ]
    if score_cap_adjustment:
        components.append(
            ScoreComponent(
                name="score_cap_adjustment",
                points=score_cap_adjustment,
                max_points=0.0,
                explanation=(
                    "Adjustment applied only to reconcile the existing "
                    "100-point repository cap."
                ),
            )
        )
    components.append(
        ScoreComponent(
            name="recurrence",
            points=recurrence_points,
            max_points=RECURRENCE_POINTS_CAP,
            explanation=(
                "Informational: 2 points per extra file spanned by recurring "
                "patterns, capped at 15. Not added to the repository score."
            ),
            informational=True,
        )
    )

    analyzed_lines = (
        _count_nonblank_source_lines(repo_root) if repo_root is not None else None
    )
    # Density is only meaningful once a repository has enough code; below the
    # threshold a handful of findings would look like an alarming rate.
    debt_density = (
        round(len(correlation_groups) / (analyzed_lines / 1000), 2)
        if analyzed_lines is not None and analyzed_lines >= MIN_LINES_FOR_DENSITY
        else None
    )
    effort_summary = dict(
        sorted(Counter(item.remediation_effort for item in scored_findings).items())
    )
    for effort in ("low", "medium", "high"):
        effort_summary.setdefault(effort, 0)

    highest_severity = max(
        (item.finding.severity for item in scored_findings),
        key=lambda severity: BASE_POINTS[severity],
        default=None,
    )
    exact_duplicates_removed = sum(
        len(group.findings) - 1
        for group in correlation_groups
        if group.correlation_type == "exact_fingerprint"
    )
    cross_tool_duplicates_removed = sum(
        len(group.findings) - 1
        for group in correlation_groups
        if group.correlation_type == "cross_tool"
    )
    same_handler_duplicates_removed = sum(
        len(group.findings) - 1
        for group in correlation_groups
        if group.correlation_type == "same_exception_handler"
    )

    return SecurityDebtReport(
        score=repository_score,
        raw_score=raw_score,
        risk_level=security_risk_level,
        architecture_risk_level=architecture_risk_level,
        risk_explanation=risk_explanation,
        input_findings_count=len(items),
        unique_open_findings_count=len(correlation_groups),
        duplicate_findings_removed=(
            exact_duplicates_removed
            + cross_tool_duplicates_removed
            + same_handler_duplicates_removed
        ),
        same_handler_duplicates_removed=same_handler_duplicates_removed,
        fixed_findings_excluded=fixed_count,
        suppressed_findings_excluded=suppressed_count,
        highest_severity=highest_severity,
        scored_findings=scored_findings,
        correlation_groups=correlation_groups,
        architecture_debt_points=architecture_debt_points,
        security_points=security_points,
        architecture_debt_explanation=architecture_debt_explanation,
        exact_duplicates_removed=exact_duplicates_removed,
        cross_tool_duplicates_removed=cross_tool_duplicates_removed,
        recurring_patterns=recurring_patterns,
        components=components,
        analyzed_lines=analyzed_lines,
        debt_density_per_kloc=debt_density,
        remediation_effort_summary=effort_summary,
    )
