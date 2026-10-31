
"""Validated data contracts for AI-assisted finding triage."""

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

NonEmptyText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=500),
]


class TriagePriority(str, Enum):
    """AI-recommended remediation priority, not scanner severity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TriageResult(BaseModel):
    """Structured triage output associated with an existing finding."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    finding_id: NonEmptyText = Field(
        description="ID of the original SilentSec finding."
    )
    fingerprint: NonEmptyText = Field(
        description="Fingerprint of the original finding."
    )

    priority: TriagePriority = Field(
        description="Suggested remediation priority."
    )
    summary: NonEmptyText = Field(
        description="Short explanation of the potential issue."
    )
    rationale: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=1,
            max_length=2000,
        ),
    ] = Field(
        description="Why this priority is recommended, using available evidence."
    )

    remediation_steps: list[NonEmptyText] = Field(
        min_length=1,
        max_length=8,
        description="Ordered, actionable remediation recommendations.",
    )
    evidence: list[NonEmptyText] = Field(
        default_factory=list,
        max_length=10,
        description="Supporting evidence from the finding or provided context.",
    )
    limitations: list[NonEmptyText] = Field(
        default_factory=list,
        max_length=10,
        description="Unverified assumptions or missing context.",
    )

    requires_human_review: bool = Field(
        default=True,
        description="AI recommendations require human verification.",
    )


class TriageAttribution(BaseModel):
    """Which provider and model produced a triage result.

    Kept outside TriageResult on purpose: TriageResult validates the model's
    own JSON reply, and a model must never be able to claim to be local.
    """

    model_config = ConfigDict(extra="forbid")

    provider: str | None = Field(default=None, min_length=1, max_length=100)
    model: str | None = Field(default=None, max_length=200)
    local: bool = False
    cached: bool = False

    @property
    def label(self) -> str | None:
        """'ollama qwen2.5-coder:7b', or None when the provider is unknown."""
        if self.provider is None:
            return None
        return f"{self.provider} {self.model or ''}".strip()
