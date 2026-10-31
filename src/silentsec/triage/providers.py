"""Provider contract for SilentSec finding triage."""

import os
from typing import Protocol

from silentsec.schemas.finding import Finding

from .schemas import TriageResult

AI_PROVIDERS_ENV = "SILENTSEC_AI_PROVIDERS"
KNOWN_AI_PROVIDERS = ("gemini", "groq", "ollama")
# Providers that run on the user's machine; code never leaves it.
LOCAL_AI_PROVIDERS = {"ollama"}


class AIProviderConfigError(ValueError):
    """The AI provider configuration is invalid; the message is safe to show."""


class ProviderUnavailableError(ConnectionError):
    """A provider cannot be reached at all; the message is safe to show.

    Unlike a plain ConnectionError this is not retried on the same provider:
    a server that is not running will not start within a backoff delay.
    """


def configured_provider_order() -> list[str] | None:
    """Provider names from SILENTSEC_AI_PROVIDERS, or None when it is not set.

    None keeps the default order (Gemini, then Groq, for configured keys).
    """
    raw = os.getenv(AI_PROVIDERS_ENV, "").strip()
    if not raw:
        return None

    names: list[str] = []
    for item in raw.split(","):
        name = item.strip().lower()
        if not name:
            continue
        if name not in KNOWN_AI_PROVIDERS:
            raise AIProviderConfigError(
                f"Unknown AI provider '{item.strip()}' in {AI_PROVIDERS_ENV}. "
                f"Use a comma-separated list of: {', '.join(KNOWN_AI_PROVIDERS)}."
            )
        if name not in names:
            names.append(name)
    if not names:
        raise AIProviderConfigError(f"{AI_PROVIDERS_ENV} is set but names no provider.")
    return names


def is_local_provider(label: str) -> bool:
    """True for a provider label such as 'ollama qwen2.5-coder:7b'."""
    return label.split(" ", 1)[0] in LOCAL_AI_PROVIDERS


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
