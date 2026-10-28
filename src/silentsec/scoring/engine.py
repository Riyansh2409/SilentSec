
"""Deterministic and explainable repository security-debt scoring."""

from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, Field

from silentsec.architecture.import_analyzer import analyze_python_imports
from silentsec.schemas.finding import Finding, FindingCategory, FindingStatus, Severity
from silentsec.scoring.correlation import CorrelationGroup, correlate_findings

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
ARCHITECTURE_RISK_THRESHOLDS = {
    "low": 10.0,
    "moderate": 20.0,
    "high": 20.0,
}


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
    architecture_risk_level: RiskLevel
    risk_explanation: str

    input_findings_count: int = Field(ge=0)
    unique_open_findings_count: int = Field(ge=0)
    duplicate_findings_removed: int = Field(ge=0)
    fixed_findings_excluded: int = Field(ge=0)
    suppressed_findings_excluded: int = Field(ge=0)
    exact_duplicates_removed: int = Field(ge=0, default=0)
    cross_tool_duplicates_removed: int = Field(ge=0, default=0)

    highest_severity: Severity | None = None
    scored_findings: list[ScoredFinding] = Field(default_factory=list)
    correlation_groups: list[CorrelationGroup] = Field(default_factory=list)
    architecture_debt_points: float = Field(default=0.0, ge=0.0, le=ARCHITECTURE_DEBT_CAP)
    security_points: float = Field(default=0.0, ge=0.0)
    architecture_debt_explanation: str = "Architecture and maintainability contributions are capped at 25.0 points."



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


def _architecture_risk_level_for_score(score: float) -> RiskLevel:
    """Classify architectural debt separately; it can never be critical."""
    if score <= 0:
        return RiskLevel.NONE
    if score < ARCHITECTURE_RISK_THRESHOLDS["low"]:
        return RiskLevel.LOW
    if score < ARCHITECTURE_RISK_THRESHOLDS["moderate"]:
        return RiskLevel.MODERATE
    return RiskLevel.HIGH


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



def score_findings(
    findings: Iterable[Finding],
    *,
    repo_root: str | None = None,
) -> SecurityDebtReport:
    """Score logical open issues using exact and cross-tool correlation."""
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
        _score_finding(group.representative)
        for group in correlation_groups
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
    architecture_raw_points = round(
        sum(
            item.score
            for item in scored_findings
            if item.finding.category in architecture_categories
        ),
        3,
    )
    architecture_debt_points = round(
        min(architecture_raw_points, ARCHITECTURE_DEBT_CAP),
        3,
    )
    security_points = round(
        sum(
            item.score
            for item in scored_findings
            if item.finding.category
            in {FindingCategory.SECURITY, FindingCategory.SECRET}
        ),
        3,
    )
    other_points = round(
        sum(
            item.score
            for item in scored_findings
            if item.finding.category not in architecture_categories
            and item.finding.category
            not in {FindingCategory.SECURITY, FindingCategory.SECRET}
        ),
        3,
    )
    raw_score = round(
        architecture_debt_points + security_points + other_points,
        3,
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

    return SecurityDebtReport(
        score=repository_score,
        raw_score=raw_score,
        risk_level=security_risk_level,
        architecture_risk_level=architecture_risk_level,
        risk_explanation=risk_explanation,
        input_findings_count=len(items),
        unique_open_findings_count=len(correlation_groups),
        duplicate_findings_removed=(
            exact_duplicates_removed + cross_tool_duplicates_removed
        ),
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
    )
