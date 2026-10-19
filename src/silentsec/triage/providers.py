
"""Provider contract for SilentSec finding triage."""

from typing import Protocol

from silentsec.schemas.finding import Finding

from .schemas import TriageResult


class TriageProvider(Protocol):
    """Interface implemented by mock and real LLM triage providers."""

    def triage(
        self,
        *,
        finding: Finding,
        context: str = "",
    ) -> TriageResult:
        """Analyze a finding and return validated triage output."""
        ...
