
"""Deterministic and explainable repository security-debt scoring."""

from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, Field

from silentsec.schemas.finding import Finding, FindingStatus, Severity

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


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class ScoredFinding(BaseModel):
    """A finding with its score and human-readable calculation."""

    finding: Finding
    base_points: int = Field(ge=1)
    effective_confidence: float = Field(ge=0.0, le=1.0)
    score: float = Field(ge=0.0)
    explanation: str


class SecurityDebtReport(BaseModel):
    """Explainable security-debt summary for a collection of findings."""

    score: float = Field(ge=0.0, le=MAX_REPOSITORY_SCORE)
    raw_score: float = Field(ge=0.0)
    risk_level: RiskLevel

    input_findings_count: int = Field(ge=0)
    unique_open_findings_count: int = Field(ge=0)
    duplicate_findings_removed: int = Field(ge=0)
    fixed_findings_excluded: int = Field(ge=0)
    suppressed_findings_excluded: int = Field(ge=0)

    highest_severity: Severity | None = None
    scored_findings: list[ScoredFinding] = Field(default_factory=list)


def _effective_confidence(finding: Finding) -> float:
    """Use a documented default when a scanner provides no confidence."""
    if finding.confidence is None:
        return DEFAULT_CONFIDENCE
    return finding.confidence


def _representative_sort_key(finding: Finding) -> tuple:
    """Prefer the strongest finding when multiple findings share a fingerprint."""
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
    """Classify the capped aggregate score."""
    if score <= 0:
        return RiskLevel.NONE
    elif score < 10:
        return RiskLevel.LOW
    elif score < 20:
        return RiskLevel.MODERATE
    elif score < 40:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL


def _score_finding(finding: Finding) -> ScoredFinding:
    """Calculate and explain one finding's contribution to security debt."""
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
    )


def score_findings(findings: Iterable[Finding]) -> SecurityDebtReport:
    """Score unique, open findings and return an explainable debt report.

    Formula:
        finding score = severity base points * (0.5 + 0.5 * confidence)

    Exact fingerprints are deduplicated. When duplicates disagree, the
    highest-severity finding is retained, with confidence used as a tie-breaker.
    Fixed and suppressed findings are excluded from active security debt.
    """
    items = list(findings)

    fixed_count = sum(
        finding.status == FindingStatus.FIXED for finding in items
    )
    suppressed_count = sum(
        finding.status == FindingStatus.SUPPRESSED for finding in items
    )
    open_findings = [
        finding for finding in items if finding.status == FindingStatus.OPEN
    ]

    grouped: dict[str, list[Finding]] = {}
    for finding in open_findings:
        grouped.setdefault(finding.fingerprint, []).append(finding)

    # Select one Finding object per fingerprint, not a list of findings.
    unique_findings = [
        min(group, key=_representative_sort_key)
        for group in grouped.values()
    ]

    scored_findings = [
        _score_finding(finding) for finding in unique_findings
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

    raw_score = round(
        sum(item.score for item in scored_findings),
        3,
    )
    repository_score = round(
        min(raw_score, MAX_REPOSITORY_SCORE),
        3,
    )

    highest_severity = max(
        (item.finding.severity for item in scored_findings),
        key=lambda severity: BASE_POINTS[severity],
        default=None,
    )

    return SecurityDebtReport(
        score=repository_score,
        raw_score=raw_score,
        risk_level=_risk_level_for_score(repository_score),
        input_findings_count=len(items),
        unique_open_findings_count=len(unique_findings),
        duplicate_findings_removed=len(open_findings) - len(unique_findings),
        fixed_findings_excluded=fixed_count,
        suppressed_findings_excluded=suppressed_count,
        highest_severity=highest_severity,
        scored_findings=scored_findings,
    )
