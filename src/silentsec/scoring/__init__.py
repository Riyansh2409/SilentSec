"""Security-debt scoring public interface."""

from .correlation import (
    CorrelationEvidence,
    CorrelationGroup,
    correlate_findings,
)
from .engine import (
    RiskLevel,
    ScoredFinding,
    SecurityDebtReport,
    score_findings,
)

__all__ = [
    "CorrelationEvidence",
    "CorrelationGroup",
    "RiskLevel",
    "ScoredFinding",
    "SecurityDebtReport",
    "correlate_findings",
    "score_findings",
]
