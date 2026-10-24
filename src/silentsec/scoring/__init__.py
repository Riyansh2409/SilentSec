"""Security-debt scoring public interface."""

from .correlation import (
    CorrelationEvidence,
    CorrelationGroup,
    correlate_findings,
)
from .engine import (
    BASE_POINTS,
    DEFAULT_CONFIDENCE,
    MAX_REPOSITORY_SCORE,
    RiskLevel,
    ScoredFinding,
    SecurityDebtReport,
    score_findings,
)

__all__ = [
    "BASE_POINTS",
    "DEFAULT_CONFIDENCE",
    "MAX_REPOSITORY_SCORE",
    "CorrelationEvidence",
    "CorrelationGroup",
    "RiskLevel",
    "ScoredFinding",
    "SecurityDebtReport",
    "correlate_findings",
    "score_findings",
]