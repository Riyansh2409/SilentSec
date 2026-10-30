"""Command-line entry point: ``silentsec scan <path>``."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from silentsec.scanners.results import ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult, scan_repository

# Exit codes let CI pipelines react to the scan outcome.
EXIT_OK = 0
EXIT_SCAN_INCOMPLETE = 2
EXIT_USAGE_ERROR = 64


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="silentsec",
        description="Explainable security and architectural debt scanner.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="Scan a local repository folder.")
    scan.add_argument("path", type=Path, help="Repository folder to scan.")
    scan.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        help="Also write the full report as JSON to this file.",
    )
    scan.add_argument(
        "--ai-triage",
        action="store_true",
        help="Triage top findings with configured AI providers (needs API keys).",
    )
    scan.add_argument(
        "--max-ai-findings",
        type=int,
        default=20,
        help="Maximum findings sent to AI triage (default: 20).",
    )
    scan.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Per-scanner timeout in seconds (default: 180).",
    )
    scan.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top findings to print (default: 10).",
    )
    return parser


def format_summary(result: RepositoryScanResult, *, top: int = 10) -> str:
    """Render a short, human-readable report."""
    lines = [f"SilentSec scan: {result.repo_path}", ""]

    lines.append("Scanners:")
    for scanner in result.scanners:
        lines.append(
            f"  {scanner.scanner:<13} {scanner.status.value:<8} "
            f"{len(scanner.findings):>3} findings  {scanner.duration_seconds:.1f}s"
        )
        for error in scanner.errors[:2]:
            lines.append(f"      ! {error}")

    debt = result.security_debt
    if debt is not None:
        security_risk = debt.risk_level.value.upper()
        architecture_risk = debt.architecture_risk_level.value.upper()
        lines += [
            "",
            f"Score: {debt.score:.1f} / 100",
            f"Security risk: {security_risk}   Architecture debt: {architecture_risk}",
            (
                f"Unique issues: {debt.unique_open_findings_count} "
                f"({debt.duplicate_findings_removed} duplicates merged)"
            ),
        ]

        if not result.security_debt_complete:
            lines.append(
                "Note: at least one scanner did not succeed, so this score is incomplete."
            )

        if debt.scored_findings:
            lines += ["", f"Top findings (of {len(debt.scored_findings)}):"]
            for item in debt.scored_findings[:top]:
                finding = item.finding
                lines.append(
                    f"  [{finding.severity.value.upper():<8}] {finding.file_path}:"
                    f"{finding.start_line}  {finding.rule_id}"
                )

        if debt.recurring_patterns:
            lines += ["", "Recurring patterns:"]
            for pattern in debt.recurring_patterns[:5]:
                lines.append(
                    f"  {pattern.pattern_key}: {pattern.occurrence_count} occurrences "
                    f"in {pattern.file_count} files"
                )

    if result.triage_attempted:
        lines += ["", f"AI triage: {len(result.triage_results)} findings triaged"]
        for error in result.triage_errors[:3]:
            lines.append(f"  ! {error}")

    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.timeout <= 0 or args.max_ai_findings <= 0 or args.top < 0:
        parser.print_usage(sys.stderr)
        print("silentsec: numeric options must be positive.", file=sys.stderr)
        return EXIT_USAGE_ERROR

    if not args.path.is_dir():
        print(f"silentsec: not a directory: {args.path}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    result = scan_repository(
        args.path,
        timeout_seconds=args.timeout,
        enable_ai_triage=args.ai_triage,
        max_ai_triage_findings=args.max_ai_findings,
    )

    print(format_summary(result, top=args.top))

    if args.json_path is not None:
        args.json_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nJSON report written to {args.json_path}")

    if result.status == ScannerStatus.SUCCESS and result.security_debt_complete:
        return EXIT_OK
    return EXIT_SCAN_INCOMPLETE


if __name__ == "__main__":
    raise SystemExit(main())
