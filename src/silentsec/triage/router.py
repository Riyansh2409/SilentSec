"""Fallback routing across AI triage providers."""

import logging
from collections.abc import Sequence

from pydantic import ValidationError

from silentsec.schemas.finding import Finding

from .providers import TriageProvider
from .sanitization import (
    prepare_context_for_triage,
    prepare_finding_for_triage,
)
from .schemas import TriageResult

logger = logging.getLogger(__name__)

RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}


class TriageRoutingError(RuntimeError):
    """Raised when all configured triage providers fail."""


class TriageRouter:
    """Try providers in order and fall back when a provider fails."""

    def __init__(
        self,
        providers: Sequence[tuple[str, TriageProvider]],
    ) -> None:
        if not providers:
            raise ValueError("At least one triage provider is required.")

        self._providers = tuple(providers)

        for name, _ in self._providers:
            if not name.strip():
                raise ValueError("Provider names cannot be empty.")

    def triage(
        self,
        *,
        finding: Finding,
        context: str = "",
    ) -> TriageResult:
        """Return the first valid result, using fallbacks when appropriate."""

        failures: list[tuple[str, Exception]] = []
        safe_finding = prepare_finding_for_triage(finding)
        safe_context = prepare_context_for_triage(finding, context)

        for name, provider in self._providers:
            try:
                result = provider.triage(
                    finding=safe_finding,
                    context=safe_context,
                )

                if not isinstance(result, TriageResult):
                    raise TypeError("Provider must return a validated TriageResult.")

                if result.finding_id != finding.finding_id:
                    raise ValueError("Provider returned a mismatched finding_id.")

                if result.fingerprint != finding.fingerprint:
                    raise ValueError("Provider returned a mismatched fingerprint.")

                if not result.requires_human_review:
                    raise ValueError("AI triage results must require human review.")

                logger.info("Triage completed using provider %s", name)

                return result

            except Exception as exc:
                if not self._should_fallback(exc):
                    raise

                failures.append((name, exc))
                logger.warning(
                    "Triage provider %s failed with %s; trying the next provider.",
                    name,
                    type(exc).__name__,
                )

        attempted = ", ".join(f"{name} ({type(exc).__name__})" for name, exc in failures)
        error = TriageRoutingError(f"All configured triage providers failed: {attempted}")

        if failures:
            raise error from failures[-1][1]

        raise error

    @staticmethod
    def _should_fallback(exc: Exception) -> bool:
        """Identify API failures and invalid model responses worth bypassing."""

        if isinstance(
            exc,
            (
                TimeoutError,
                ConnectionError,
                ValueError,
                TypeError,
                ValidationError,
            ),
        ):
            return True

        status = getattr(exc, "status_code", None)
        if status is None:
            status = getattr(exc, "code", None)

        try:
            status_code = int(status)
        except (TypeError, ValueError):
            return False

        if status_code in RETRYABLE_STATUS_CODES:
            return True

        # HTTP errors are not retried on the same provider, but another
        # configured provider may have a different key or API.
        return 400 <= status_code <= 499
