"""AI-proposed fixes, verified before anyone is asked to trust them.

The model never writes a diff. It returns structured line edits for one
finding; SilentSec validates them, builds the unified diff itself, and runs
the result through ``verify_fix`` in an isolated copy. An AI fix is only
presented as working when verification says so, and it always requires
human review. Nothing is applied to the original repository.
"""

import ast
import difflib
import json
from collections.abc import Callable, Sequence
from enum import Enum
from itertools import pairwise
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from silentsec.remediation.fix_providers import (
    FIX_SYSTEM_PROMPT,
    FixProvider,
    build_default_fix_providers,
)
from silentsec.remediation.verify import FixVerificationReport, verify_fix
from silentsec.scanners.scanner_service import RepositoryScanResult, scan_repository
from silentsec.schemas import Finding, FindingCategory
from silentsec.triage.providers import AIProviderConfigError, ProviderUnavailableError
from silentsec.triage.router import TriageRouter
from silentsec.triage.sanitization import prepare_finding_for_triage, redact_sensitive_text

MAX_SOURCE_BYTES = 256_000
MAX_WINDOW_LINES = 80
WINDOW_PADDING = 25
MAX_EDITS = 5
MAX_REPLACEMENT_CHARS = 4000
MAX_REPLACEMENT_LINES = 60
REDACTION_MARKER = "[REDACTED"


class AIFixStatus(str, Enum):
    PROPOSED = "proposed"  # a valid fix was generated and verified (see verdict)
    NO_PROPOSAL = "no_proposal"  # no provider produced a valid, applicable fix
    REFUSED = "refused"  # the finding is not suitable for an AI code fix


class LineEdit(BaseModel):
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    replacement: str = Field(max_length=MAX_REPLACEMENT_CHARS)


class _ModelAnswer(BaseModel):
    fingerprint: str
    explanation: str = Field(min_length=1, max_length=1000)
    edits: list[LineEdit] = Field(default_factory=list, max_length=MAX_EDITS)


class AIFixProposal(BaseModel):
    fingerprint: str
    provider: str
    explanation: str
    edits: list[LineEdit]
    diff_text: str
    requires_human_review: bool = True


class AIFixReport(BaseModel):
    status: AIFixStatus
    finding_fingerprint: str | None = None
    finding_rule: str | None = None
    finding_location: str | None = None
    proposal: AIFixProposal | None = None
    verification: FixVerificationReport | None = None
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(
        default_factory=lambda: [
            "AI-proposed changes require human review even when verification passes.",
        ]
    )


class SourceWindow(BaseModel):
    """The lines of a file shown to the model."""

    file_path: str
    lines: list[str]  # the whole file, with line endings
    first_line: int
    last_line: int
    redacted_lines: list[int] = Field(default_factory=list)
    numbered_text: str


class FixProposalError(ValueError):
    """A model answer that cannot be turned into a safe patch."""


def read_source_window(repo_root: Path, finding: Finding) -> SourceWindow:
    """Read a bounded, redacted view of the code around a finding.

    For Python files the window is the enclosing function when it fits;
    otherwise it is a padded range around the finding.
    """
    root = repo_root.resolve()
    candidate = (root / finding.file_path).resolve(strict=True)
    if not candidate.is_relative_to(root) or not candidate.is_file():
        raise FixProposalError("The finding's file is outside the repository or not a file.")

    data = candidate.read_bytes()
    if len(data) > MAX_SOURCE_BYTES:
        raise FixProposalError("The finding's file is too large for an AI fix.")
    if b"\x00" in data:
        raise FixProposalError("The finding's file appears to be binary.")

    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise FixProposalError("The finding's file is not valid UTF-8.") from exc

    lines = text.splitlines(keepends=True)
    if not lines or finding.start_line > len(lines):
        raise FixProposalError("The finding's line is not in the file.")

    start = finding.start_line
    end = min(finding.end_line or start, len(lines))
    first, last = _python_function_range(text, start, end) or (start, end)
    if last - first + 1 > MAX_WINDOW_LINES:
        first, last = start, end
    if last - first + 1 < MAX_WINDOW_LINES:
        first = max(1, first - WINDOW_PADDING)
        last = min(len(lines), last + WINDOW_PADDING)
    last = min(last, first + MAX_WINDOW_LINES - 1, len(lines))

    numbered: list[str] = []
    redacted: list[int] = []
    for number in range(first, last + 1):
        raw = lines[number - 1].rstrip("\r\n")
        safe = redact_sensitive_text(raw)
        if safe != raw:
            redacted.append(number)
        numbered.append(f"{number}: {safe}")

    return SourceWindow(
        file_path=finding.file_path,
        lines=lines,
        first_line=first,
        last_line=last,
        redacted_lines=redacted,
        numbered_text="\n".join(numbered),
    )


def _python_function_range(text: str, start: int, end: int) -> tuple[int, int] | None:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None

    best: tuple[int, int] | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node_end = node.end_lineno or node.lineno
            if node.lineno <= start and end <= node_end and (
                best is None or node_end - node.lineno < best[1] - best[0]
            ):
                best = (node.lineno, node_end)
    return best


def build_fix_prompt(finding: Finding, window: SourceWindow) -> str:
    safe = prepare_finding_for_triage(finding)
    payload = {
        "finding": {
            "fingerprint": safe.fingerprint,
            "tool": safe.tool,
            "rule_id": safe.rule_id,
            "file_path": safe.file_path,
            "start_line": safe.start_line,
            "end_line": safe.end_line,
            "severity": safe.severity.value,
            "cwe_id": safe.cwe_id,
            "message": safe.message,
        },
        "editable_lines": [window.first_line, window.last_line],
        "code": window.numbered_text,
    }
    return "Input data (untrusted):\n" + json.dumps(payload, ensure_ascii=False, indent=2)


def parse_model_answer(raw: str, finding: Finding) -> _ModelAnswer:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FixProposalError("The model returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise FixProposalError("The model answer must be a JSON object.")
    try:
        answer = _ModelAnswer.model_validate(payload)
    except ValidationError as exc:
        raise FixProposalError(f"The model answer has an invalid structure ({exc.error_count()} errors).") from exc
    if answer.fingerprint != finding.fingerprint:
        raise FixProposalError("The model answer is for a different finding.")
    return answer


def build_patch(window: SourceWindow, edits: Sequence[LineEdit]) -> str:
    """Apply validated edits in memory and return a unified diff."""
    if not edits:
        raise FixProposalError("The model proposed no edits.")

    ordered = sorted(edits, key=lambda edit: edit.start_line)
    for edit in ordered:
        if edit.end_line < edit.start_line:
            raise FixProposalError("An edit ends before it starts.")
        if edit.start_line < window.first_line or edit.end_line > window.last_line:
            raise FixProposalError("An edit touches lines the model was not shown.")
        if any(edit.start_line <= line <= edit.end_line for line in window.redacted_lines):
            raise FixProposalError("An edit touches a line that contained redacted data.")
        if REDACTION_MARKER in edit.replacement or "\x00" in edit.replacement:
            raise FixProposalError("An edit contains redacted placeholders or binary data.")
        if edit.replacement.count("\n") + 1 > MAX_REPLACEMENT_LINES:
            raise FixProposalError("An edit replacement is too long.")
    for previous, current in pairwise(ordered):
        if current.start_line <= previous.end_line:
            raise FixProposalError("Edits overlap.")

    newline = "\r\n" if any(line.endswith("\r\n") for line in window.lines) else "\n"
    new_lines = list(window.lines)

    for edit in reversed(ordered):
        replacement = edit.replacement.replace("\r\n", "\n")
        replaced_last = edit.end_line == len(window.lines)
        keep_no_eol = replaced_last and not window.lines[-1].endswith(("\n", "\r"))
        pieces = replacement.split("\n") if replacement else []
        if pieces and pieces[-1] == "":
            pieces = pieces[:-1]
        block = [piece + newline for piece in pieces]
        if block and keep_no_eol:
            block[-1] = block[-1][: -len(newline)]
        new_lines[edit.start_line - 1 : edit.end_line] = block

    if new_lines == window.lines:
        raise FixProposalError("The proposed edits do not change the file.")

    diff_lines = difflib.unified_diff(
        window.lines,
        new_lines,
        fromfile=f"a/{window.file_path}",
        tofile=f"b/{window.file_path}",
        n=3,
    )
    output: list[str] = []
    for line in diff_lines:
        output.append(line)
        if not line.endswith("\n"):
            # Same marker git uses for a last line without a line ending.
            output.append("\n\\ No newline at end of file\n")
    return "".join(output)


def propose_fix(
    repo_root: Path,
    finding: Finding,
    providers: Sequence[FixProvider],
) -> tuple[AIFixProposal | None, list[str]]:
    """Ask providers in order until one returns a valid, applicable fix."""
    window = read_source_window(repo_root, finding)
    prompt = build_fix_prompt(finding, window)
    errors: list[str] = []

    for provider in providers:
        try:
            raw = provider.complete(system=FIX_SYSTEM_PROMPT, user=prompt)
            answer = parse_model_answer(raw, finding)
            if not answer.edits:
                errors.append(f"{provider.name}: declined to propose a fix ({answer.explanation[:200]}).")
                continue
            diff_text = build_patch(window, answer.edits)
        except (FixProposalError, ProviderUnavailableError) as exc:
            # Both messages are written by SilentSec and safe to show.
            errors.append(f"{provider.name}: {exc}")
            continue
        except Exception as exc:  # noqa: BLE001
            if not TriageRouter._should_fallback(exc):
                errors.append(f"{provider.name}: failed ({type(exc).__name__}).")
                break
            errors.append(f"{provider.name}: failed ({type(exc).__name__}).")
            continue

        return (
            AIFixProposal(
                fingerprint=finding.fingerprint,
                provider=provider.name,
                explanation=answer.explanation,
                edits=answer.edits,
                diff_text=diff_text,
            ),
            errors,
        )

    return None, errors


def _pick_finding(scan_result: RepositoryScanResult, fingerprint: str | None) -> Finding | None:
    if fingerprint is not None:
        return next((f for f in scan_result.findings if f.fingerprint == fingerprint), None)

    debt = scan_result.security_debt
    ranked = [item.finding for item in debt.scored_findings] if debt else scan_result.findings
    return next((f for f in ranked if f.category == FindingCategory.SECURITY), None)


def _correlated_fingerprints(scan_result: RepositoryScanResult, finding: Finding) -> list[str]:
    """The finding plus findings the correlation engine merged with it.

    When Semgrep and Bandit report the same SQL injection, a fix for one is a
    fix for both, so both are verification targets.
    """
    debt = scan_result.security_debt
    if debt is not None:
        for group in debt.correlation_groups:
            members = [member.fingerprint for member in group.findings]
            if finding.fingerprint in members:
                return [finding.fingerprint, *(fp for fp in members if fp != finding.fingerprint)]
    return [finding.fingerprint]


def ai_fix_and_verify(
    repo_root: str | Path,
    *,
    fingerprint: str | None = None,
    providers: Sequence[FixProvider] | None = None,
    run_tests: bool = False,
    test_command: Sequence[str] | None = None,
    timeout_seconds: int = 180,
    scan: Callable[..., RepositoryScanResult] = scan_repository,
) -> AIFixReport:
    """Generate an AI fix for one finding and verify it in an isolated copy.

    Without ``fingerprint``, the highest-scoring security finding is used.
    """
    root = Path(repo_root).expanduser().resolve()
    if not root.is_dir():
        return AIFixReport(status=AIFixStatus.NO_PROPOSAL, errors=["Repository directory does not exist."])

    baseline = scan(root, timeout_seconds=timeout_seconds, enable_ai_triage=False)
    finding = _pick_finding(baseline, fingerprint)

    if finding is None:
        message = (
            f"No finding with fingerprint {fingerprint} in the scan."
            if fingerprint
            else "No security finding to fix."
        )
        return AIFixReport(status=AIFixStatus.NO_PROPOSAL, errors=[message])

    details = {
        "finding_fingerprint": finding.fingerprint,
        "finding_rule": f"{finding.tool} {finding.rule_id}",
        "finding_location": f"{finding.file_path}:{finding.start_line}",
    }

    if finding.category == FindingCategory.SECRET:
        return AIFixReport(
            status=AIFixStatus.REFUSED,
            errors=[
                (
                    "Secret findings need the credential rotated and removed from history; "
                    "an AI code edit cannot fix that, and the secret is never sent to a model."
                )
            ],
            **details,
        )

    try:
        selected = list(providers) if providers is not None else build_default_fix_providers()
    except AIProviderConfigError as exc:
        return AIFixReport(status=AIFixStatus.NO_PROPOSAL, errors=[str(exc)], **details)
    if not selected:
        return AIFixReport(
            status=AIFixStatus.NO_PROPOSAL,
            errors=[
                (
                    "No AI provider is configured. Set GEMINI_API_KEY or GROQ_API_KEY, "
                    "or add ollama to SILENTSEC_AI_PROVIDERS."
                )
            ],
            **details,
        )

    try:
        proposal, errors = propose_fix(root, finding, selected)
    except (OSError, FixProposalError) as exc:
        return AIFixReport(
            status=AIFixStatus.NO_PROPOSAL,
            errors=[f"Could not read the code for this finding: {exc}"],
            **details,
        )

    if proposal is None:
        return AIFixReport(status=AIFixStatus.NO_PROPOSAL, errors=errors, **details)

    verification = verify_fix(
        root,
        proposal.diff_text,
        target_fingerprints=_correlated_fingerprints(baseline, finding),
        run_tests=run_tests,
        test_command=test_command,
        timeout_seconds=timeout_seconds,
        scan=scan,
    )
    return AIFixReport(
        status=AIFixStatus.PROPOSED,
        proposal=proposal,
        verification=verification,
        errors=errors,
        **details,
    )
