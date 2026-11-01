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
    r"""(?i)["']?\b((?:[a-z0-9]+[_-])*(?:"""
    r"api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|password|passwd|secret|token|"
    r"aws_secret_access_key|aws_session_token|"
    r"database_url|db_url|connection_string"
    r"""))\b["']?"""
    r"""(\s*[:=]\s*)"""
    r"""((?:[rRbBuUfF]{1,2})?(?:"[^"]*"|'[^']*')|[^\s,;]+)"""
)

# Shape of an unquoted code expression. It only counts as code (not redacted)
# when it also has attribute access, a call or a subscript; see below.
_CODE_EXPRESSION_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:[(\[].*)?")
_HIGH_ENTROPY_RE = re.compile(r"(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9_+/=.-]{16,}")
_LONG_NUMBER_RE = re.compile(r"[0-9]{8,}")


def _looks_like_secret_value(value: str) -> bool:
    """False only for code: attribute access, a call or a subscript.

    Any bare word is treated as a literal whatever the name's case, so
    `password=hunter2` and `passwd=admin` are redacted (and so is
    `password = password`, which is the safe side).
    """
    if value[:1] in "\"'" or value[1:2] in "\"'" or value[2:3] in "\"'":
        return True  # quoted string literal, including r"", b"", f"" prefixes
    if _HIGH_ENTROPY_RE.fullmatch(value) or _LONG_NUMBER_RE.fullmatch(value):
        return True
    is_code = _CODE_EXPRESSION_RE.fullmatch(value) is not None and any(
        marker in value for marker in ".(["
    )
    return not is_code


def _redact_assignment(match: re.Match[str]) -> str:
    if not _looks_like_secret_value(match.group(3)):
        return match.group(0)
    return f"{match.group(1)}{match.group(2)}[REDACTED]"


_KNOWN_TOKEN_RE = re.compile(
    r"\b(?:"
    r"gh[pousr]_[A-Za-z0-9_]{12,}"
    r"|github_pat_[A-Za-z0-9_]{12,}"
    r"|sk-[A-Za-z0-9_-]{16,}"
    r"|gsk_[A-Za-z0-9]{20,}"
    r"|AIza[0-9A-Za-z_-]{16,}"
    r"|AKIA[0-9A-Z]{16}"
    r")\b"
)


def redact_sensitive_text(text: str) -> str:
    """Redact recognizable credentials and private-key blocks."""
    text = _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _ASSIGNMENT_RE.sub(_redact_assignment, text)
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