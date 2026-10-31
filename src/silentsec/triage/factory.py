"""Factory for configuring available SilentSec triage providers."""

import os

from .cache import TriageCache, default_cache
from .gemini_provider import GeminiTriageProvider
from .groq_provider import GroqTriageProvider
from .ollama_provider import OllamaTriageProvider
from .providers import TriageProvider, configured_provider_order
from .router import TriageRouter

# Production defaults: one bounded retry for transient errors per provider.
DEFAULT_MAX_RETRIES = 1
DEFAULT_BACKOFF_SECONDS = 1.0
_USE_DEFAULT_CACHE = object()


def _gemini_providers() -> list[tuple[str, TriageProvider]]:
    gemini_key = os.getenv("GEMINI_API_KEY")
    if not gemini_key:
        return []

    providers: list[tuple[str, TriageProvider]] = []
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
    return providers


def _groq_providers() -> list[tuple[str, TriageProvider]]:
    groq_key = os.getenv("GROQ_API_KEY")
    if not groq_key:
        return []
    return [("groq", GroqTriageProvider(api_key=groq_key))]


def _ollama_providers() -> list[tuple[str, TriageProvider]]:
    # No key: Ollama is used whenever it is listed in SILENTSEC_AI_PROVIDERS.
    return [("ollama", OllamaTriageProvider())]


_BUILDERS = {
    "gemini": _gemini_providers,
    "groq": _groq_providers,
    "ollama": _ollama_providers,
}
# Without SILENTSEC_AI_PROVIDERS: today's order, only providers with keys.
DEFAULT_ORDER = ("gemini", "groq")


def build_default_providers() -> list[tuple[str, TriageProvider]]:
    """Providers in SILENTSEC_AI_PROVIDERS order, or the default order.

    Raises AIProviderConfigError for an unknown name or a disallowed
    OLLAMA_HOST. Listed cloud providers without an API key are skipped.
    """
    order = configured_provider_order() or DEFAULT_ORDER
    return [provider for name in order for provider in _BUILDERS[name]()]


def build_default_router(
    *,
    max_provider_calls: int | None = None,
    cache: TriageCache | None | object = _USE_DEFAULT_CACHE,
) -> TriageRouter | None:
    """Build the provider chain from SILENTSEC_AI_PROVIDERS and API credentials.

    ``max_provider_calls`` caps API calls for this router (one scan).
    ``cache`` defaults to the environment-configured cache; pass None to
    disable caching.
    """

    providers = build_default_providers()

    if not providers:
        return None

    return TriageRouter(
        providers,
        max_retries=DEFAULT_MAX_RETRIES,
        backoff_seconds=DEFAULT_BACKOFF_SECONDS,
        max_provider_calls=max_provider_calls,
        cache=default_cache() if cache is _USE_DEFAULT_CACHE else cache,
    )
