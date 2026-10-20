"""Security-debt scoring public interface."""

from .correlation import CorrelationGroup, correlate_findings
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
    "CorrelationGroup",
    "RiskLevel",
    "ScoredFinding",
    "SecurityDebtReport",
    "correlate_findings",
    "score_findings",
]