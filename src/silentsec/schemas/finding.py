
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    SECURITY = "security"
    ARCHITECTURE = "architecture"
    MAINTAINABILITY = "maintainability"
    SECRET = "secret"  # nosec B105: category label, not a credential


class FindingStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    SUPPRESSED = "suppressed"


class Finding(BaseModel):
    """Normalized finding shared by all SilentSec analysis modules."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    fingerprint: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)

    file_path: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)

    category: FindingCategory
    severity: Severity
    message: str = Field(min_length=1)

    cwe_id: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    status: FindingStatus = FindingStatus.OPEN

    @model_validator(mode="after")
    def validate_line_range(self):
        if self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("end_line cannot be before start_line")
        return self
