"""Fix + Verify: validate, apply and check proposed patches in isolation."""

from silentsec.remediation.patch import PatchValidation, validate_patch
from silentsec.remediation.sandbox import (
    IsolatedCopy,
    PatchApplyResult,
    apply_patch,
    create_isolated_copy,
    sanitized_environment,
)
from silentsec.remediation.verify import (
    FindingSummary,
    FixVerdict,
    FixVerificationReport,
    TestRunResult,
    verify_fix,
)

__all__ = [
    "FindingSummary",
    "FixVerdict",
    "FixVerificationReport",
    "IsolatedCopy",
    "PatchApplyResult",
    "PatchValidation",
    "TestRunResult",
    "apply_patch",
    "create_isolated_copy",
    "sanitized_environment",
    "validate_patch",
    "verify_fix",
]
