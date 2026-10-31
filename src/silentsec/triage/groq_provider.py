"""Groq API adapter for SilentSec AI finding triage."""

import os
from typing import Any

from groq import APIConnectionError, APITimeoutError, Groq

from silentsec.schemas.finding import Finding

from .chat_prompt import TRIAGE_SYSTEM_PROMPT, parse_triage_reply, triage_user_content
from .schemas import TriageResult


class GroqTriageProvider:
    """Generate validated security-triage results using Groq."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        client: Any | None = None,
    ) -> None:
        resolved_key = api_key or os.getenv("GROQ_API_KEY")

        if client is None and not resolved_key:
            raise ValueError(
                "Groq API key is missing. Set GROQ_API_KEY."
            )

        self._model = (
            model
            or os.getenv("GROQ_MODEL")
            or "openai/gpt-oss-20b"
        )
        self._client = client or Groq(api_key=resolved_key)

    @property
    def model(self) -> str:
        """Model name, used to keep cache entries per model."""
        return self._model

    def triage(
        self,
        *,
        finding: Finding,
        context: str = "",
    ) -> TriageResult:
        """Analyze a finding and validate Groq's JSON response."""

        # Sanitize the finding and context before sending them to Groq.
        user_content = triage_user_content(finding, context)
        system_prompt = TRIAGE_SYSTEM_PROMPT

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {
                        "role": "system",
                        "content": system_prompt,
                    },
                    {
                        "role": "user",
                        "content": user_content,
                    },
                ],
                response_format={"type": "json_object"},
                max_completion_tokens=2000,
            )
        except APITimeoutError as exc:
            raise TimeoutError(
                "Groq triage request timed out."
            ) from exc
        except APIConnectionError as exc:
            raise ConnectionError(
                "Could not connect to Groq."
            ) from exc

        try:
            content = response.choices[0].message.content
        except (AttributeError, IndexError, TypeError) as exc:
            raise ValueError(
                "Groq returned an unexpected response structure."
            ) from exc

        return parse_triage_reply(content, "Groq")
