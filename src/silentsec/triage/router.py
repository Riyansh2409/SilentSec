"""Fallback routing across AI triage providers.

For each finding the router:

1. returns a cached result when one exists (no API call);
2. otherwise tries providers in order. A transient failure (timeout,
   connection error, HTTP 408/429/5xx) is retried on the same provider a
   bounded number of times with exponential backoff; other recoverable
   failures move straight to the next provider;
3. stops when the per-router call budget is spent.

Retries are always bounded, and authentication or request errors are never
retried on the same provider.
"""

import logging
import time
from collections.abc import Callable, Sequence

from pydantic import ValidationError

from silentsec.schemas.finding import Finding

from .cache import TriageCache, cache_key
from .providers import TriageProvider
from .sanitization import (
    prepare_context_for_triage,
    prepare_finding_for_triage,
)
from .schemas import TriageResult

logger = logging.getLogger(__name__)

RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
MAX_RETRIES_LIMIT = 5
MAX_BACKOFF_SECONDS = 10.0


class TriageRoutingError(RuntimeError):
    """Raised when all configured triage providers fail."""


class TriageBudgetExceededError(TriageRoutingError):
    """Raised when the router has used its allowed number of provider calls."""


class TriageRouter:
    """Try providers in order and fall back when a provider fails."""

    def __init__(
        self,
        providers: Sequence[tuple[str, TriageProvider]],
        *,
        max_retries: int = 0,
        backoff_seconds: float = 0.5,
        max_provider_calls: int | None = None,
        cache: TriageCache | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not providers:
            raise ValueError("At least one triage provider is required.")

        self._providers = tuple(providers)

        for name, _ in self._providers:
            if not name.strip():
                raise ValueError("Provider names cannot be empty.")

        if not 0 <= max_retries <= MAX_RETRIES_LIMIT:
            raise ValueError(f"max_retries must be between 0 and {MAX_RETRIES_LIMIT}.")
        if backoff_seconds < 0:
            raise ValueError("backoff_seconds cannot be negative.")
        if max_provider_calls is not None and max_provider_calls <= 0:
            raise ValueError("max_provider_calls must be positive.")

        self._max_retries = max_retries
        self._backoff_seconds = backoff_seconds
        self._max_provider_calls = max_provider_calls
        self._cache = cache
        self._sleep = sleep
        self.provider_calls = 0

    @property
    def provider_signature(self) -> str:
        """Identify the provider chain (names and models) for cache keys."""
        return "|".join(
            f"{name}:{getattr(provider, 'model', '') or ''}" for name, provider in self._providers
        )

    @property
    def cache(self) -> TriageCache | None:
        return self._cache

    def triage(
        self,
        *,
        finding: Finding,
        context: str = "",
    ) -> TriageResult:
        """Return the first valid result, using cache, retries and fallbacks."""

        safe_finding = prepare_finding_for_triage(finding)
        safe_context = prepare_context_for_triage(finding, context)

        key: str | None = None
        if self._cache is not None:
            key = cache_key(
                finding=finding,
                sanitized_message=safe_finding.message,
                sanitized_context=safe_context,
                provider_signature=self.provider_signature,
            )
            cached = self._cache.get(key, finding=finding)
            if cached is not None:
                logger.info("Triage cache hit for fingerprint %s", finding.fingerprint)
                return cached

        failures: list[tuple[str, Exception]] = []

        for name, provider in self._providers:
            attempt = 0

            while True:
                self._spend_call()

                try:
                    result = provider.triage(
                        finding=safe_finding,
                        context=safe_context,
                    )
                    self._validate(result, finding)
                except Exception as exc:
                    if not self._should_fallback(exc):
                        raise

                    if self._is_transient(exc) and attempt < self._max_retries:
                        delay = min(self._backoff_seconds * (2**attempt), MAX_BACKOFF_SECONDS)
                        attempt += 1
                        logger.warning(
                            "Triage provider %s failed with %s; retry %d of %d in %.1fs.",
                            name,
                            type(exc).__name__,
                            attempt,
                            self._max_retries,
                            delay,
                        )
                        self._sleep(delay)
                        continue

                    failures.append((name, exc))
                    logger.warning(
                        "Triage provider %s failed with %s; trying the next provider.",
                        name,
                        type(exc).__name__,
                    )
                    break

                logger.info("Triage completed using provider %s", name)

                if self._cache is not None and key is not None:
                    self._cache.put(key, result)

                return result

        attempted = ", ".join(f"{name} ({type(exc).__name__})" for name, exc in failures)
        error = TriageRoutingError(f"All configured triage providers failed: {attempted}")

        if failures:
            raise error from failures[-1][1]

        raise error

    def _spend_call(self) -> None:
        if self._max_provider_calls is not None and self.provider_calls >= self._max_provider_calls:
            raise TriageBudgetExceededError(
                f"AI triage call budget of {self._max_provider_calls} provider calls is used up."
            )
        self.provider_calls += 1

    @staticmethod
    def _validate(result: object, finding: Finding) -> None:
        if not isinstance(result, TriageResult):
            raise TypeError("Provider must return a validated TriageResult.")

        if result.finding_id != finding.finding_id:
            raise ValueError("Provider returned a mismatched finding_id.")

        if result.fingerprint != finding.fingerprint:
            raise ValueError("Provider returned a mismatched fingerprint.")

        if not result.requires_human_review:
            raise ValueError("AI triage results must require human review.")

    @staticmethod
    def _status_code(exc: Exception) -> int | None:
        status = getattr(exc, "status_code", None)
        if status is None:
            status = getattr(exc, "code", None)
        try:
            return int(status)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _is_transient(cls, exc: Exception) -> bool:
        """Failures worth retrying on the SAME provider."""
        if isinstance(exc, (TimeoutError, ConnectionError)):
            return True
        return cls._status_code(exc) in RETRYABLE_STATUS_CODES

    @classmethod
    def _should_fallback(cls, exc: Exception) -> bool:
        """Identify API failures and invalid model responses worth bypassing."""

        if isinstance(exc, TriageBudgetExceededError):
            return False

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

        status_code = cls._status_code(exc)

        if status_code is None:
            return False

        if status_code in RETRYABLE_STATUS_CODES:
            return True

        # HTTP errors are not retried on the same provider, but another
        # configured provider may have a different key or API.
        return 400 <= status_code <= 499
