"""Command-line entry point: ``silentsec scan`` and ``silentsec verify``."""

import argparse
import json
import os
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

from silentsec.gate import GateFinding, GatePolicy, GateReport, GateVerdict, run_gate
from silentsec.history import HistoryError, TimelineReport, build_timeline
from silentsec.remediation import FindingSummary, FixVerdict, FixVerificationReport, verify_fix
from silentsec.remediation.ai_fix import AIFixReport, AIFixStatus, ai_fix_and_verify
from silentsec.remediation.verify import DEFAULT_REGRESSION_SEVERITY
from silentsec.report import generate_report, load_fix_report
from silentsec.report.sarif import gate_to_sarif, scan_to_sarif
from silentsec.scanners.results import ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult, scan_repository
from silentsec.schemas import Severity

# Exit codes let CI pipelines react to the outcome.
EXIT_OK = 0  # scan: every scanner succeeded / verify: VERIFIED_FIX
EXIT_FIX_NOT_CONFIRMED = 1  # verify: PARTIAL, UNRESOLVED or REGRESSION
EXIT_SCAN_INCOMPLETE = 2  # scan: incomplete
EXIT_NOT_VERIFIED = 2  # verify: NOT_VERIFIED
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
        "--sarif",
        dest="sarif_path",
        type=Path,
        help="Write unique issues as SARIF 2.1.0 (for GitHub code scanning).",
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
        "--no-triage-cache",
        action="store_true",
        help="Do not reuse or store cached AI triage results.",
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

    verify = subcommands.add_parser(
        "verify",
        help="Apply a patch to an isolated copy and check whether it fixes findings.",
    )
    verify.add_argument("path", type=Path, help="Repository folder (never modified).")
    verify.add_argument(
        "--patch",
        type=Path,
        required=True,
        help="Unified diff to verify, e.g. from 'git diff --output=fix.diff'.",
    )
    verify.add_argument(
        "--target",
        dest="targets",
        action="append",
        metavar="FINGERPRINT",
        help=(
            "Fingerprint of a finding the patch should fix (repeatable). "
            "Default: every finding in a file the patch touches."
        ),
    )
    verify.add_argument(
        "--run-tests",
        action="store_true",
        help="Also run the repository's tests in the copy. This executes repository code.",
    )
    verify.add_argument(
        "--test-command",
        help='Test command to run instead of "python -m pytest -q" (implies --run-tests).',
    )
    verify.add_argument(
        "--strict",
        action="store_true",
        help="Treat any new finding as a regression (default: medium severity or higher).",
    )
    verify.add_argument("--json", dest="json_path", type=Path, help="Write the report as JSON.")
    verify.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Per-scanner timeout in seconds (default: 180).",
    )
    verify.add_argument(
        "--test-timeout",
        type=int,
        default=300,
        help="Test command timeout in seconds (default: 300).",
    )

    fix = subcommands.add_parser(
        "fix",
        help="Ask an AI provider for a fix and verify it in an isolated copy.",
    )
    fix.add_argument("path", type=Path, help="Repository folder (never modified).")
    fix.add_argument(
        "--finding",
        metavar="FINGERPRINT",
        help="Finding to fix (from 'silentsec scan --json'). Default: top security finding.",
    )
    fix.add_argument(
        "--out",
        type=Path,
        help="Save the proposed patch here for review (apply it yourself with git apply).",
    )
    fix.add_argument(
        "--run-tests",
        action="store_true",
        help="Also run the repository's tests on the patched copy. Executes repository code.",
    )
    fix.add_argument("--json", dest="json_path", type=Path, help="Write the report as JSON.")

    history = subcommands.add_parser(
        "history",
        help="Show how security debt changed across recent commits (Time Machine).",
    )
    history.add_argument("path", type=Path, help="Git repository (never modified).")
    history.add_argument(
        "--commits",
        type=int,
        default=10,
        help="Number of recent commits on the current branch to scan (1-50, default: 10).",
    )
    history.add_argument(
        "--db",
        type=Path,
        help="SQLite file for stored scans (default: ~/.cache/silentsec/history/).",
    )
    history.add_argument(
        "--no-cache",
        action="store_true",
        help="Rescan every commit instead of reusing stored scans.",
    )
    history.add_argument("--json", dest="json_path", type=Path, help="Write the timeline as JSON.")
    history.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Per-scanner timeout in seconds (default: 180).",
    )
    fix.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Per-scanner timeout in seconds (default: 180).",
    )

    report = subcommands.add_parser(
        "report",
        help="Write a self-contained HTML report (score, issues, history, fixes).",
    )
    report.add_argument("path", type=Path, help="Repository folder (never modified).")
    report.add_argument(
        "--out",
        type=Path,
        default=Path("silentsec-report.html"),
        help="Where to write the report (default: silentsec-report.html).",
    )
    report.add_argument(
        "--commits",
        type=int,
        default=10,
        help="Commits to include in the history section (1-50, default: 10).",
    )
    report.add_argument(
        "--no-history",
        action="store_true",
        help="Leave out the history section.",
    )
    report.add_argument(
        "--fix-report",
        dest="fix_reports",
        type=Path,
        action="append",
        default=[],
        help="JSON from 'silentsec verify --json' or 'silentsec fix --json' to include (repeatable).",
    )
    report.add_argument(
        "--ai-triage",
        action="store_true",
        help="Include AI triage for top findings (needs API keys).",
    )
    report.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Per-scanner timeout in seconds (default: 180).",
    )

    gate = subcommands.add_parser(
        "gate",
        help="Fail if a change (head) adds new security findings compared with base.",
    )
    gate.add_argument("path", type=Path, help="Git repository folder (never modified).")
    gate.add_argument(
        "--base", default="main", help="Branch or commit to compare against (default: main)."
    )
    gate.add_argument("--head", default="HEAD", help="Branch or commit to check (default: HEAD).")
    gate.add_argument(
        "--fail-on",
        choices=[severity.value for severity in Severity],
        default=Severity.HIGH.value,
        help="Lowest severity of a NEW security finding that fails the gate (default: high).",
    )
    gate.add_argument(
        "--fail-on-architecture",
        action="store_true",
        help="Also fail on new architecture/maintainability findings (default: warn only).",
    )
    gate.add_argument("--json", dest="json_path", type=Path, help="Write the gate result as JSON.")
    gate.add_argument(
        "--sarif",
        dest="sarif_path",
        type=Path,
        help="Write the findings this change introduces as SARIF 2.1.0.",
    )
    gate.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Per-scanner timeout in seconds (default: 180).",
    )

    serve = subcommands.add_parser(
        "serve",
        help="Start the HTTP API for a web frontend (docs at /docs).",
    )
    serve.add_argument(
        "--host",
        default="127.0.0.1",
        help="Address to listen on (default: 127.0.0.1, this computer only).",
    )
    serve.add_argument("--port", type=int, default=8000, help="Port (default: 8000).")
    serve.add_argument(
        "--cors-origin",
        dest="cors_origins",
        action="append",
        default=[],
        help="Frontend origin allowed to call the API, e.g. http://localhost:5173 "
        "(repeatable; default: localhost ports 3000 and 5173). Also read from "
        "SILENTSEC_API_CORS_ORIGINS (comma-separated).",
    )
    return parser


TIMEOUT_HINT = "Try --timeout 600 for large repositories."


def _is_timeout(error: str) -> bool:
    # Matches run_json_command's "Scanner timed out after N seconds." message.
    return "timed out after" in error


def _score_line(score: float, raw_score: float) -> str:
    """The capped score, plus the uncapped value when the cap hides it."""
    line = f"Score: {score:.1f} / 100"
    if raw_score > score:
        line += f"  (uncapped {raw_score:.1f}; the score is capped at 100)"
    return line


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
    if any(_is_timeout(error) for scanner in result.scanners for error in scanner.errors):
        lines.append(TIMEOUT_HINT)

    debt = result.security_debt
    if debt is not None:
        security_risk = debt.risk_level.value.upper()
        architecture_risk = debt.architecture_risk_level.value.upper()
        lines += [
            "",
            _score_line(debt.score, debt.raw_score),
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
                # Reachable from a web route in the call graph (not proof of exploitability).
                reachable = "  [reachable]" if item.exposure == "reachable" else ""
                lines.append(
                    f"  [{finding.severity.value.upper():<8}] {finding.file_path}:"
                    f"{finding.start_line}  {finding.rule_id}{reachable}"
                )

        if debt.recurring_patterns:
            lines += ["", "Recurring patterns:"]
            for pattern in debt.recurring_patterns[:5]:
                lines.append(
                    f"  {pattern.pattern_key}: {pattern.occurrence_count} occurrences "
                    f"in {pattern.file_count} files"
                )

    if result.triage_attempted:
        # Which provider answered, e.g. "ollama qwen2.5-coder:7b: 12; ".
        answered: dict[str, int] = {}
        for label in result.triage_providers.values():
            answered[label] = answered.get(label, 0) + 1
        by_provider = "".join(f"{label}: {count}; " for label, count in answered.items())
        lines += [
            "",
            (
                f"AI triage: {len(result.triage_results)} findings triaged "
                f"({by_provider}{result.triage_cache_hits} from cache, "
                f"{result.triage_provider_calls} provider calls)"
            ),
        ]
        for error in result.triage_errors[:3]:
            lines.append(f"  ! {error}")

    return "\n".join(lines)


def read_patch_file(path: Path) -> str:
    """Read a patch, accepting the encodings Windows tools commonly produce.

    In Windows PowerShell 5, ``git diff > fix.diff`` writes UTF-16 with a
    byte-order mark, which ``git apply`` cannot read directly.
    """
    data = path.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8")
    return data.decode("utf-8")


def format_verification(report: FixVerificationReport) -> str:
    """Render a Fix + Verify report for a human reviewer."""
    verdict = report.verdict.value.upper().replace("_", " ")
    lines = [f"Verdict: {verdict}"]
    lines += [f"  {reason}" for reason in report.reasons]

    if report.score_before is not None and report.score_after is not None:
        score_change = f"Score: {report.score_before:.1f} -> {report.score_after:.1f}"
        raw_before, raw_after = report.raw_score_before, report.raw_score_after
        if raw_before is not None and raw_after is not None and max(raw_before, raw_after) > 100:
            score_change += f"  (uncapped {raw_before:.1f} -> {raw_after:.1f})"
        lines += ["", score_change]

    def section(title: str, items: list[FindingSummary]) -> None:
        if not items:
            return
        lines.extend(["", f"{title} ({len(items)}):"])
        for item in items:
            lines.append(
                f"  [{item.severity.value.upper():<8}] {item.file_path}:{item.start_line}"
                f"  {item.tool} {item.rule_id}"
            )

    section("Resolved", report.resolved)
    section("Remaining", report.remaining)
    section("New", report.new)

    if report.checks_run:
        lines += ["", "Checks run on the patched copy:"]
        lines += [f"  {check}" for check in report.checks_run]

    if report.tests is not None and report.tests.output_tail and not report.tests.passed:
        lines += ["", "Test output (last lines):"]
        lines += [f"  {line}" for line in report.tests.output_tail.splitlines()[-15:]]

    lines += ["", "Limitations:"]
    lines += [f"  - {item}" for item in report.limitations]
    return "\n".join(lines)


def _run_verify(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.timeout <= 0 or args.test_timeout <= 0:
        parser.print_usage(sys.stderr)
        print("silentsec: numeric options must be positive.", file=sys.stderr)
        return EXIT_USAGE_ERROR

    if not args.path.is_dir():
        print(f"silentsec: not a directory: {args.path}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    try:
        diff_text = read_patch_file(args.patch)
    except FileNotFoundError:
        print(f"silentsec: patch file not found: {args.patch}", file=sys.stderr)
        return EXIT_USAGE_ERROR
    except (OSError, UnicodeError) as exc:
        print(f"silentsec: could not read patch file ({type(exc).__name__}).", file=sys.stderr)
        return EXIT_USAGE_ERROR

    test_command = (
        shlex.split(args.test_command, posix=os.name != "nt") if args.test_command else None
    )

    report = verify_fix(
        args.path,
        diff_text,
        target_fingerprints=args.targets or None,
        run_tests=args.run_tests or test_command is not None,
        test_command=test_command,
        timeout_seconds=args.timeout,
        test_timeout_seconds=args.test_timeout,
        regression_severity=Severity.INFO if args.strict else DEFAULT_REGRESSION_SEVERITY,
    )

    print(format_verification(report))

    if args.json_path is not None:
        args.json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nJSON report written to {args.json_path}")

    if report.verdict == FixVerdict.VERIFIED_FIX:
        return EXIT_OK
    if report.verdict == FixVerdict.NOT_VERIFIED:
        return EXIT_NOT_VERIFIED
    return EXIT_FIX_NOT_CONFIRMED


def format_ai_fix(report: AIFixReport) -> str:
    """Render an AI fix report: the finding, the proposal, and its verification."""
    lines: list[str] = []
    if report.finding_location:
        lines.append(f"Finding: {report.finding_rule} at {report.finding_location}")
        lines.append(f"Fingerprint: {report.finding_fingerprint}")

    if report.status != AIFixStatus.PROPOSED or report.proposal is None:
        status = report.status.value.upper().replace("_", " ")
        lines += ["", f"No verified AI fix: {status}"]
        lines += [f"  {error}" for error in report.errors]
        return "\n".join(lines)

    proposal = report.proposal
    lines += [
        "",
        f"AI proposal from {proposal.provider} (requires human review):",
        f"  {proposal.explanation}",
        "",
        proposal.diff_text.rstrip("\n"),
    ]
    if report.errors:
        lines += ["", "Providers tried before this one:"]
        lines += [f"  {error}" for error in report.errors]
    if report.verification is not None:
        lines += ["", format_verification(report.verification)]
    lines += [f"  - {item}" for item in report.limitations]
    return "\n".join(lines)


def _run_fix(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.timeout <= 0:
        parser.print_usage(sys.stderr)
        print("silentsec: numeric options must be positive.", file=sys.stderr)
        return EXIT_USAGE_ERROR

    if not args.path.is_dir():
        print(f"silentsec: not a directory: {args.path}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    report = ai_fix_and_verify(
        args.path,
        fingerprint=args.finding,
        run_tests=args.run_tests,
        timeout_seconds=args.timeout,
    )

    print(format_ai_fix(report))

    if args.out is not None and report.proposal is not None:
        args.out.write_text(report.proposal.diff_text, encoding="utf-8")
        print(f"\nProposed patch written to {args.out} (not applied).")

    if args.json_path is not None:
        args.json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        print(f"JSON report written to {args.json_path}")

    if report.status != AIFixStatus.PROPOSED or report.verification is None:
        return EXIT_NOT_VERIFIED
    if report.verification.verdict == FixVerdict.VERIFIED_FIX:
        return EXIT_OK
    if report.verification.verdict == FixVerdict.NOT_VERIFIED:
        return EXIT_NOT_VERIFIED
    return EXIT_FIX_NOT_CONFIRMED


def format_timeline(report: TimelineReport) -> str:
    """Render the Time Machine as a table, one row per commit."""
    lines = [
        f"SilentSec Time Machine: {report.repo_path}",
        f"Branch {report.branch}, last {len(report.points)} commit(s), oldest first.",
        "Scores are uncapped so changes stay visible.",
        "",
        (
            f"{'Commit':<9} {'Date':<10} {'Score':>7} {'Change':>7} {'Issues':>6}  "
            f"{'New':>4} {'Fixed':>5}  Subject"
        ),
    ]

    previous = None
    for point in report.points:
        if previous is None:
            change = ""
        elif previous.complete and point.complete:
            change = f"{point.raw_score - previous.raw_score:+.1f}"
        else:
            # A failed scanner changes the score without any code change.
            change = "?"
        if point.attribution == "baseline":
            new = fixed = "-"
        elif point.attribution == "unknown":
            new = fixed = "?"
        else:
            new, fixed = str(len(point.introduced)), str(len(point.fixed))
        marker = "" if point.complete else "  [incomplete scan]"
        subject = point.subject if len(point.subject) <= 50 else point.subject[:47] + "..."
        lines.append(
            f"{point.short_sha:<9} {point.committed_at[:10]:<10} {point.raw_score:>7.1f} "
            f"{change:>7} {point.unique_issues:>6}  {new:>4} {fixed:>5}  {subject}{marker}"
        )
        for problem in point.scanner_problems:
            lines.append(f"{'':<9} ! {problem}")
        previous = point
    if any(_is_timeout(problem) for point in report.points for problem in point.scanner_problems):
        lines.append(TIMEOUT_HINT)

    came_back = report.reintroduced
    if came_back:
        lines += ["", f"Came back after a fix ({len(came_back)}):"]
        for point, change in came_back[:10]:
            lines.append(
                f"  ! [{change.severity.value.upper():<8}] {change.file_path}:{change.start_line}"
                f"  {change.tool} {change.rule_id}  (fixed in {change.previously_fixed_in}, "
                f"back in {point.short_sha})"
            )

    peak = report.biggest_increase
    if peak is not None:
        index = report.points.index(peak)
        delta = peak.raw_score - report.points[index - 1].raw_score
        lines += ["", f"Biggest increase: {peak.short_sha} \"{peak.subject}\" ({delta:+.1f})"]
        for change in peak.introduced[:8]:
            lines.append(
                f"  + [{change.severity.value.upper():<8}] {change.file_path}:{change.start_line}"
                f"  {change.tool} {change.rule_id}"
            )

    cached = sum(point.from_cache for point in report.points)
    lines += ["", f"Stored scans: {report.database} ({cached} reused)", "", "Limitations:"]
    lines += [f"  - {item}" for item in report.limitations]
    return "\n".join(lines)


def _run_history(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.timeout <= 0 or not 1 <= args.commits <= 50:
        parser.print_usage(sys.stderr)
        print("silentsec: --commits must be 1-50 and --timeout positive.", file=sys.stderr)
        return EXIT_USAGE_ERROR

    def show_progress(index: int, total: int, sha: str, cached: bool) -> None:
        if cached:
            print(f"Using stored scan {index}/{total} ({sha})", file=sys.stderr)
        else:
            print(f"Scanning commit {index}/{total} ({sha})...", file=sys.stderr)

    try:
        report = build_timeline(
            args.path,
            commits=args.commits,
            database=args.db,
            use_cache=not args.no_cache,
            timeout_seconds=args.timeout,
            progress=show_progress,
        )
    except HistoryError as exc:
        print(f"silentsec: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    print(format_timeline(report))

    if args.json_path is not None:
        args.json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nJSON timeline written to {args.json_path}")

    return EXIT_OK if all(point.complete for point in report.points) else EXIT_SCAN_INCOMPLETE


def _run_report(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.timeout <= 0 or not 1 <= args.commits <= 50:
        parser.print_usage(sys.stderr)
        print("silentsec: --commits must be 1-50 and --timeout positive.", file=sys.stderr)
        return EXIT_USAGE_ERROR

    if not args.path.is_dir():
        print(f"silentsec: not a directory: {args.path}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    fixes = []
    for path in args.fix_reports:
        try:
            fixes.append(load_fix_report(path))
        except FileNotFoundError:
            print(f"silentsec: fix report not found: {path}", file=sys.stderr)
            return EXIT_USAGE_ERROR
        except (OSError, TypeError, ValueError) as exc:
            print(f"silentsec: {exc}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    print("Scanning and building the report...", file=sys.stderr)
    document, result, _ = generate_report(
        args.path,
        commits=args.commits,
        include_history=not args.no_history,
        fixes=fixes,
        enable_ai_triage=args.ai_triage,
        timeout_seconds=args.timeout,
    )
    args.out.write_text(document, encoding="utf-8")
    print(f"Report written to {args.out.resolve()}")
    print("Open it in a browser; it works offline and loads nothing from the internet.")

    if result.status == ScannerStatus.SUCCESS and result.security_debt_complete:
        return EXIT_OK
    return EXIT_SCAN_INCOMPLETE


EXIT_GATE_FAILED = 1
EXIT_GATE_INCOMPLETE = 2


def _gate_line(item: GateFinding) -> str:
    return (
        f"  [{item.severity.value.upper():<8}] {item.file_path}:{item.start_line}  "
        f"{item.tool} {item.rule_id}"
    )


def format_gate(report: GateReport) -> str:
    """Human-readable gate result."""
    title = {
        GateVerdict.PASS: "PASS",
        GateVerdict.FAIL: "FAIL",
        GateVerdict.INCOMPLETE: "INCOMPLETE (cannot decide)",
    }[report.verdict]
    lines = [
        (
            f"SilentSec gate: {report.head_ref} ({report.head_sha[:8]}) vs "
            f"{report.base_ref} ({report.base_sha[:8]})"
        ),
        f"Policy: fail on new security findings >= {report.policy.fail_on.value}"
        + ("; architecture findings also fail" if report.policy.fail_on_architecture else ""),
        "",
        f"Gate: {title}",
    ]
    lines += [f"  {reason}" for reason in report.reasons]
    if report.verdict != GateVerdict.INCOMPLETE and report.base_sha != report.head_sha:
        lines.append(
            f"\nScore (uncapped): {report.score_before:.1f} -> {report.score_after:.1f}  "
            f"| new issues {report.new_issues}, resolved {len(report.resolved)} findings, "
            f"existing issues {report.existing_issues}"
        )
    sections = [
        ("Blocking (new)", report.blocking),
        ("Warnings (new architecture debt)", report.warnings),
        ("New, below threshold", report.other_new),
        ("Resolved by this change", report.resolved),
    ]
    for heading, items in sections:
        if items:
            lines.append(f"\n{heading} ({len(items)}):")
            lines += [_gate_line(item) for item in items]
    if report.scanner_problems:
        lines.append("\nScanner problems:")
        lines += [f"  ! {problem}" for problem in report.scanner_problems]
        if any(_is_timeout(problem) for problem in report.scanner_problems):
            lines.append(TIMEOUT_HINT)
    lines.append("\nLimitations:")
    lines += [f"  - {item}" for item in report.limitations]
    return "\n".join(lines)


def _run_gate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.timeout <= 0:
        parser.print_usage(sys.stderr)
        print("silentsec: --timeout must be positive.", file=sys.stderr)
        return EXIT_USAGE_ERROR
    policy = GatePolicy(
        fail_on=Severity(args.fail_on), fail_on_architecture=args.fail_on_architecture
    )
    print(f"Scanning {args.base} and {args.head}...", file=sys.stderr)
    try:
        report = run_gate(
            args.path,
            base=args.base,
            head=args.head,
            policy=policy,
            timeout_seconds=args.timeout,
        )
    except HistoryError as exc:
        print(f"silentsec: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    print(format_gate(report))
    if args.json_path is not None:
        args.json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nJSON result written to {args.json_path}")
    if args.sarif_path is not None:
        _write_sarif(args.sarif_path, gate_to_sarif(report))

    if report.verdict == GateVerdict.PASS:
        return EXIT_OK
    if report.verdict == GateVerdict.FAIL:
        return EXIT_GATE_FAILED
    return EXIT_GATE_INCOMPLETE


def _write_sarif(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    print(f"SARIF written to {path}")


def _run_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn

        from silentsec.api.app import DEFAULT_CORS_ORIGINS, create_app
    except ImportError:
        print(
            'silentsec: the API needs extra packages. Run: pip install -e ".[api]"',
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR

    origins = list(args.cors_origins)
    from_env = os.environ.get("SILENTSEC_API_CORS_ORIGINS", "")
    origins += [origin.strip() for origin in from_env.split(",") if origin.strip()]
    if not origins:
        origins = list(DEFAULT_CORS_ORIGINS)

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print(
            f"Warning: listening on {args.host} lets other computers on this network "
            "start scans. Use it only on a network you trust.",
            file=sys.stderr,
        )
    print(f"SilentSec API: http://{args.host}:{args.port}/docs", file=sys.stderr)
    print(f"Allowed frontend origins: {', '.join(origins)}", file=sys.stderr)
    uvicorn.run(create_app(cors_origins=origins), host=args.host, port=args.port)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "verify":
        return _run_verify(args, parser)
    if args.command == "fix":
        return _run_fix(args, parser)
    if args.command == "history":
        return _run_history(args, parser)
    if args.command == "report":
        return _run_report(args, parser)
    if args.command == "serve":
        return _run_serve(args)
    if args.command == "gate":
        return _run_gate(args, parser)

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
        use_triage_cache=not args.no_triage_cache,
    )

    print(format_summary(result, top=args.top))

    if args.json_path is not None:
        args.json_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nJSON report written to {args.json_path}")
    if args.sarif_path is not None:
        _write_sarif(args.sarif_path, scan_to_sarif(result))

    if result.status == ScannerStatus.SUCCESS and result.security_debt_complete:
        return EXIT_OK
    return EXIT_SCAN_INCOMPLETE


if __name__ == "__main__":
    raise SystemExit(main())
