
"""Safely extract bounded source context for SilentSec AI triage."""

from pathlib import Path, PureWindowsPath

from silentsec.schemas.finding import Finding, FindingCategory
from silentsec.triage.sanitization import prepare_context_for_triage

DEFAULT_LINES_BEFORE = 8
DEFAULT_LINES_AFTER = 8
DEFAULT_MAX_FILE_BYTES = 256_000
MAX_CONTEXT_LINES = 40


def build_source_context(
    repo_root: str | Path,
    finding: Finding,
    *,
    lines_before: int = DEFAULT_LINES_BEFORE,
    lines_after: int = DEFAULT_LINES_AFTER,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> str:
    """Extract a small, sanitized source window for one finding.

    Only regular files resolved inside the repository are eligible.
    Errors return a safe explanation instead of aborting repository scans.
    """
    if lines_before < 0 or lines_after < 0:
        raise ValueError("Context line limits must be non-negative.")

    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be positive.")

    root = Path(repo_root).expanduser().resolve()

    if not root.is_dir():
        return "Source context unavailable: repository root is invalid."

    raw_path = finding.file_path

    # Reject absolute paths on both Windows and POSIX.
    if Path(raw_path).is_absolute() or PureWindowsPath(raw_path).is_absolute():
        return "Source context unavailable: absolute paths are not allowed."

    try:
        candidate = (root / raw_path).resolve(strict=True)

        # Reject traversal and symlinks resolving outside the repository.
        if not candidate.is_relative_to(root):
            return "Source context unavailable: path is outside the repository."

        if not candidate.is_file():
            return "Source context unavailable: target is not a regular file."

        if candidate.stat().st_size > max_file_bytes:
            return "Source context unavailable: file exceeds the size limit."

        content = candidate.read_bytes()

    except (OSError, RuntimeError, ValueError):
        return "Source context unavailable: file could not be read safely."

    # Recheck after reading in case the file changed between stat and read.
    if len(content) > max_file_bytes:
        return "Source context unavailable: file exceeds the size limit."

    # Avoid sending binary data or compiled content to an LLM.
    if b"\x00" in content:
        return "Source context unavailable: file appears to be binary."

    text = content.decode("utf-8", errors="replace")
    source_lines = text.splitlines()

    if not source_lines:
        return "Source context unavailable: file is empty."

    if finding.category == FindingCategory.SECRET:
        return prepare_context_for_triage(finding, "")

    end_line = finding.end_line or finding.start_line

    if finding.start_line < 1 or end_line < finding.start_line:
        return "Source context unavailable: finding line range is invalid."

    if finding.start_line > len(source_lines):
        return "Source context unavailable: finding starts beyond the end of the file."

    start_line = finding.start_line
    end_line = max(start_line, end_line)

    # Keep the total window bounded even if a finding spans many lines.
    window_size = min(
        lines_before + lines_after + 1,
        MAX_CONTEXT_LINES,
    )
    center_line = start_line
    first_line = max(1, center_line - lines_before)
    last_line = min(len(source_lines), first_line + window_size - 1)

    # Shift the window backwards near the end of the file.
    first_line = max(1, last_line - window_size + 1)

    extracted = source_lines[first_line - 1 : last_line]

    numbered_context = "\n".join(
        f"{line_number}: {line}"
        for line_number, line in enumerate(extracted, start=first_line)
    )

    # Mark whether the finding's full range is visible in the extracted window.
    if start_line < first_line or end_line > last_line:
        numbered_context = (
            f"[Finding range: lines {start_line}-{end_line}; "
            f"extracted window: lines {first_line}-{last_line}]\n"
            f"{numbered_context}"
        )

    # Secret findings are withheld by the existing sanitizer.
    return prepare_context_for_triage(finding, numbered_context)
