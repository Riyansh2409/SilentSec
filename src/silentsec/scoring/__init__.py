"""Security-debt scoring public interface."""

from .correlation import (
    CorrelationEvidence,
    CorrelationGroup,
    correlate_findings,
)
from .engine import (
    RiskLevel,
    ScoreComponent,
    ScoredFinding,
    SecurityDebtReport,
    score_findings,
)
from .recurrence import RecurringPattern, detect_recurring_patterns

__all__ = [
    "CorrelationEvidence",
    "CorrelationGroup",
    "RecurringPattern",
    "RiskLevel",
    "ScoreComponent",
    "ScoredFinding",
    "SecurityDebtReport",
    "correlate_findings",
    "detect_recurring_patterns",
    "score_findings",
]
