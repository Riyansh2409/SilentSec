"""Build the SilentSec HTML report from a scan, history, and fix results."""

import json
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from silentsec.context import build_source_context
from silentsec.history import HistoryError, TimelineReport, build_timeline
from silentsec.remediation.ai_fix import AIFixReport
from silentsec.remediation.verify import FixVerificationReport
from silentsec.report.html import render_report
from silentsec.scanners.scanner_service import RepositoryScanResult, scan_repository
from silentsec.schemas import FindingCategory

__all__ = ["generate_report", "load_fix_report", "render_report"]

UNAVAILABLE_PREFIX = "Source context unavailable"


def load_fix_report(path: Path) -> FixVerificationReport | AIFixReport:
    """Load a JSON report written by 'silentsec verify --json' or 'silentsec fix --json'.

    Raises TypeError or ValueError when the file is not such a report.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"{path} is not a SilentSec fix report.")
    try:
        if "status" in data and "verdict" not in data:
            return AIFixReport.model_validate(data)
        return FixVerificationReport.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"{path} is not a SilentSec fix report ({exc.error_count()} errors).") from exc


def _snippets(root: Path, scan: RepositoryScanResult) -> dict[str, str]:
    """Redacted code around each reported issue; secrets are never shown."""
    snippets: dict[str, str] = {}
    if scan.security_debt is None:
        return snippets
    for item in scan.security_debt.scored_findings:
        finding = item.finding
        if finding.category == FindingCategory.SECRET:
            snippets[finding.fingerprint] = "Code withheld: this is a possible secret."
            continue
        context = build_source_context(root, finding, secret_findings=scan.findings)
        if not context.startswith(UNAVAILABLE_PREFIX):
            snippets[finding.fingerprint] = context
    return snippets


def generate_report(
    repo_path: str | Path,
    *,
    commits: int = 10,
    include_history: bool = True,
    fixes: Sequence[FixVerificationReport | AIFixReport] = (),
    enable_ai_triage: bool = False,
    timeout_seconds: int = 180,
    scan: Callable[..., RepositoryScanResult] = scan_repository,
    now: Callable[[], datetime] = datetime.now,
) -> tuple[str, RepositoryScanResult, TimelineReport | None]:
    """Scan, optionally build the timeline, and render the HTML report."""
    root = Path(repo_path).expanduser().resolve()
    result = scan(root, timeout_seconds=timeout_seconds, enable_ai_triage=enable_ai_triage)

    timeline: TimelineReport | None = None
    note: str | None = None
    if include_history:
        try:
            timeline = build_timeline(
                root, commits=commits, timeout_seconds=timeout_seconds, scan=scan
            )
        except HistoryError as exc:
            note = f"History is not available: {exc}"
    else:
        note = "History was not included in this report."

    document = render_report(
        result,
        repo_name=root.name,
        generated_at=now(),
        snippets=_snippets(root, result),
        timeline=timeline,
        timeline_note=note,
        fixes=fixes,
    )
    return document, result, timeline
