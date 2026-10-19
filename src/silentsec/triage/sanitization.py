"""Best-effort redaction for data sent to AI triage providers."""

import re

from silentsec.schemas.finding import Finding, FindingCategory

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r".*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)

_BEARER_RE = re.compile(
    r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"
)

_ASSIGNMENT_RE = re.compile(
    r"""(?i)["']?\b(api[_-]?key|access[_-]?token|auth[_-]?token|"""
    r"""client[_-]?secret|password|passwd|secret|token)\b["']?"""
    r"""(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)"""
)

_KNOWN_TOKEN_RE = re.compile(
    r"\b(?:"
    r"gh[pousr]_[A-Za-z0-9_]{12,}"
    r"|github_pat_[A-Za-z0-9_]{12,}"
    r"|sk-[A-Za-z0-9_-]{16,}"
    r"|AIza[0-9A-Za-z_-]{16,}"
    r"|AKIA[0-9A-Z]{16}"
    r")\b"
)


def redact_sensitive_text(text: str) -> str:
    """Redact recognizable credentials and private-key blocks."""
    text = _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        text,
    )
    return _KNOWN_TOKEN_RE.sub("[REDACTED TOKEN]", text)


def prepare_finding_for_triage(finding: Finding) -> Finding:
    """Create a sanitized copy without changing finding identity."""
    if finding.category == FindingCategory.SECRET:
        message = (
            "A potential secret was detected. "
            "The original value has been withheld."
        )
    else:
        message = redact_sensitive_text(finding.message)

    return finding.model_copy(update={"message": message})


def prepare_context_for_triage(
    finding: Finding,
    context: str,
) -> str:
    """Redact supplied context or withhold it for secret findings."""
    if finding.category == FindingCategory.SECRET:
        return "Context withheld because this is a secret finding."

    return redact_sensitive_text(context)