
from enum import Enum

from pydantic import BaseModel, Field

from silentsec.schemas import Finding


class ScannerStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class ScannerRunResult(BaseModel):
    """Standard result returned by every scanner adapter."""

    scanner: str
    status: ScannerStatus
    findings: list[Finding] = Field(default_factory=list)
    duration_seconds: float = Field(ge=0)
    exit_code: int | None = None
    errors: list[str] = Field(default_factory=list)
