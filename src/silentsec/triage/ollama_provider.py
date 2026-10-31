"""Ollama adapter: AI triage with a model running on this machine.

No API key is needed and, with the default loopback host, the finding and
code never leave the computer. A non-loopback OLLAMA_HOST is refused unless
SILENTSEC_OLLAMA_ALLOW_REMOTE=1, because code would then be sent elsewhere.
"""

import ipaddress
import os
from typing import Any
from urllib.parse import urlsplit

import httpx

from silentsec.schemas.finding import Finding

from .chat_prompt import TRIAGE_SYSTEM_PROMPT, parse_triage_reply, triage_user_content
from .providers import AI_PROVIDERS_ENV, AIProviderConfigError, ProviderUnavailableError
from .schemas import TriageResult

DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5-coder:7b"
DEFAULT_TIMEOUT_SECONDS = 120.0
ALLOW_REMOTE_ENV = "SILENTSEC_OLLAMA_ALLOW_REMOTE"


class OllamaHTTPError(RuntimeError):
    """Ollama answered with an HTTP error status."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


def _is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def validate_host(host: str, *, allow_remote: bool) -> str:
    """Return the normalized base URL, or raise if it is not allowed."""
    host = host.strip().rstrip("/")
    parts = urlsplit(host)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise AIProviderConfigError(
            f"OLLAMA_HOST must be a URL such as {DEFAULT_HOST}, not '{host}'."
        )
    if parts.path or parts.query or parts.fragment or parts.username or parts.password:
        raise AIProviderConfigError(
            f"OLLAMA_HOST must be only scheme, host and port, such as {DEFAULT_HOST}."
        )
    if not allow_remote and not _is_loopback(parts.hostname):
        raise AIProviderConfigError(
            f"OLLAMA_HOST '{host}' is not on this machine, so code would be sent off it. "
            f"Use localhost, or set {ALLOW_REMOTE_ENV}=1 to allow it."
        )
    return host


class OllamaClient:
    """Minimal client for Ollama's /api/chat that returns the reply text."""

    def __init__(
        self,
        *,
        host: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        allow_remote = os.getenv(ALLOW_REMOTE_ENV, "").strip() == "1"
        self.host = validate_host(host or os.getenv("OLLAMA_HOST") or DEFAULT_HOST,
                                  allow_remote=allow_remote)
        self.model = (model or os.getenv("OLLAMA_MODEL") or DEFAULT_MODEL).strip()

        if timeout_seconds is None:
            raw = os.getenv("OLLAMA_TIMEOUT", "").strip()
            try:
                timeout_seconds = float(raw) if raw else DEFAULT_TIMEOUT_SECONDS
            except ValueError as exc:
                raise AIProviderConfigError("OLLAMA_TIMEOUT must be a number of seconds.") from exc
        if timeout_seconds <= 0:
            raise AIProviderConfigError("OLLAMA_TIMEOUT must be positive.")
        self.timeout_seconds = timeout_seconds

        # trust_env=False: never route through HTTP(S)_PROXY, which could send
        # code off the machine even for a localhost URL. No redirects either.
        self._client = httpx.Client(
            base_url=self.host,
            timeout=timeout_seconds,
            trust_env=False,
            follow_redirects=False,
            transport=transport,
        )

    def chat(self, *, system: str, user: str) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
        }
        try:
            response = self._client.post("/api/chat", json=payload)
        except httpx.ConnectError as exc:
            raise ProviderUnavailableError(
                f"Ollama is not running at {self.host}. "
                f"Start it or remove it from {AI_PROVIDERS_ENV}."
            ) from exc
        except httpx.TimeoutException as exc:
            raise TimeoutError(
                f"Ollama did not answer within {self.timeout_seconds:g} seconds."
            ) from exc
        except httpx.HTTPError as exc:
            raise ConnectionError(f"Could not talk to Ollama at {self.host}.") from exc

        if response.status_code == 404:
            # Shown to the user like "not running": retrying will not help.
            raise ProviderUnavailableError(
                f"Ollama has no model '{self.model}'. Run: ollama pull {self.model}"
            )
        if response.status_code != 200:
            raise OllamaHTTPError(
                f"Ollama returned HTTP {response.status_code}.", response.status_code
            )

        try:
            content = response.json()["message"]["content"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError("Ollama returned an unexpected response structure.") from exc
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Ollama returned an empty response.")
        return content


class OllamaTriageProvider:
    """Generate validated security-triage results with a local Ollama model."""

    def __init__(self, *, client: OllamaClient | None = None, **settings: Any) -> None:
        self._client = client or OllamaClient(**settings)

    @property
    def model(self) -> str:
        """Model name, used to keep cache entries per model."""
        return self._client.model

    def triage(
        self,
        *,
        finding: Finding,
        context: str = "",
    ) -> TriageResult:
        """Analyze a finding and validate Ollama's JSON response."""
        content = self._client.chat(
            system=TRIAGE_SYSTEM_PROMPT,
            user=triage_user_content(finding, context),
        )
        return parse_triage_reply(content, "Ollama")
