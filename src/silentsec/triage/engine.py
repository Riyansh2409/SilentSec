
"""Provider-independent orchestration for finding triage."""

from silentsec.schemas.finding import Finding

from .providers import TriageProvider
from .schemas import TriageResult


class TriageEngine:
    """Run triage through an injected provider and validate its response."""

    def __init__(self, provider: TriageProvider) -> None:
        self._provider = provider

    def triage_finding(
        self,
        finding: Finding,
        context: str = "",
    ) -> TriageResult:
        """Triage one finding without losing its original identity."""

        result = self._provider.triage(
            finding=finding,
            context=context,
        )

        if not isinstance(result, TriageResult):
            raise TypeError(
                "Triage provider must return a validated TriageResult."
            )

        if result.finding_id != finding.finding_id:
            raise ValueError(
                "Triage result finding_id does not match the original finding."
            )

        if result.fingerprint != finding.fingerprint:
            raise ValueError(
                "Triage result fingerprint does not match the original finding."
            )

        if not result.requires_human_review:
            raise ValueError(
                "AI triage results must require human review."
            )

        return result
