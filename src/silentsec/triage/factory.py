"""Factory for configuring available SilentSec triage providers."""

import os

from .gemini_provider import GeminiTriageProvider
from .groq_provider import GroqTriageProvider
from .providers import TriageProvider
from .router import TriageRouter


def build_default_router() -> TriageRouter | None:
    """Build the provider chain from configured API credentials."""

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

    return TriageRouter(providers)