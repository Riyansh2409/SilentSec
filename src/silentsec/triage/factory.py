"""Factory for configuring available SilentSec triage providers."""

import os

from .cache import TriageCache, default_cache
from .gemini_provider import GeminiTriageProvider
from .groq_provider import GroqTriageProvider
from .providers import TriageProvider
from .router import TriageRouter

# Production defaults: one bounded retry for transient errors per provider.
DEFAULT_MAX_RETRIES = 1
DEFAULT_BACKOFF_SECONDS = 1.0
_USE_DEFAULT_CACHE = object()


def build_default_router(
    *,
    max_provider_calls: int | None = None,
    cache: TriageCache | None | object = _USE_DEFAULT_CACHE,
) -> TriageRouter | None:
    """Build the provider chain from configured API credentials.

    ``max_provider_calls`` caps API calls for this router (one scan).
    ``cache`` defaults to the environment-configured cache; pass None to
    disable caching.
    """

    providers: list[tuple[str, TriageProvider]] = []

    gemini_key = os.getenv("GEMINI_API_KEY")

    if gemini_key:
        primary_model = os.getenv(
            "GEMINI_PRIMARY_MODEL",
            "gemini-3.6-flash",
        ).strip()

        fallback_model = os.getenv(
            "GEMINI_FALLBACK_MODEL",
            "gemini-2.5-flash",
        ).strip()

        if primary_model:
            providers.append(
                (
                    "gemini-primary",
                    GeminiTriageProvider(
                        api_key=gemini_key,
                        model=primary_model,
                    ),
                )
            )

        if fallback_model and fallback_model != primary_model:
            providers.append(
                (
                    "gemini-fallback",
                    GeminiTriageProvider(
                        api_key=gemini_key,
                        model=fallback_model,
                    ),
                )
            )

    groq_key = os.getenv("GROQ_API_KEY")

    if groq_key:
        providers.append(
            (
                "groq",
                GroqTriageProvider(api_key=groq_key),
            )
        )

    if not providers:
        return None

    return TriageRouter(
        providers,
        max_retries=DEFAULT_MAX_RETRIES,
        backoff_seconds=DEFAULT_BACKOFF_SECONDS,
        max_provider_calls=max_provider_calls,
        cache=default_cache() if cache is _USE_DEFAULT_CACHE else cache,
    )