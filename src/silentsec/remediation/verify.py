"""Fix + Verify: apply a proposed patch to an isolated copy and re-check it.

The flow is:

1. validate the patch;
2. copy the repository to a temporary directory;
3. scan the copy (baseline);
4. apply the patch to the copy;
5. scan the copy again, and optionally run the repository's tests;
6. compare the scans and classify the result.

The original repository is never modified. Passing scans and tests are
evidence, not proof: the report states exactly which checks ran.
"""

import subprocess  # nosec B404
import sys
from collections.abc import Callable, Iterable, Sequence
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from silentsec.remediation.patch import validate_patch
from silentsec.remediation.sandbox import (
    apply_patch,
    create_isolated_copy,
    sanitized_environment,
)
from silentsec.scanners.results import ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult, scan_repository
from silentsec.schemas import Finding, Severity
from silentsec.triage.sanitization import redact_sensitive_text
from silentsec.verification import VerificationStatus, compare_findings

TEST_OUTPUT_TAIL_CHARS = 2000

SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
# New findings at or above this severity make a fix a REGRESSION. Lower ones
# are still reported under "new", but do not override the verdict.
DEFAULT_REGRESSION_SEVERITY = Severity.MEDIUM

ALWAYS_LIMITATIONS = (
    (
        "Passing scans and tests do not prove the absence of vulnerabilities; "
        "they only show what the listed checks detected."
    ),
    (
        "The patch was applied only to an isolated copy; the original "
        "repository was not modified."
    ),
    (
        "Isolation is file-level: commands in the copy run as the current user "
        "with network access, though credential-like environment variables "
        "are removed."
    ),
    (
        "Local .env files, virtual environments, build and cache folders are "
        "not copied, so findings in them are not verified."
    ),
)


class FixVerdict(str, Enum):
    """Overall outcome of verifying a patch."""

    VERIFIED_FIX = "verified_fix"  # every targeted finding resolved, nothing new
    PARTIAL = "partial"  # some targets resolved, some remain, nothing new
    UNRESOLVED = "unresolved"  # complete checks, but no target was resolved
    REGRESSION = "regression"  # new findings appeared or tests failed
    NOT_VERIFIED = "not_verified"  # the result could not be established


class FindingSummary(BaseModel):
    """Compact, secret-free description of one finding."""

    fingerprint: str
    tool: str
    rule_id: str
    file_path: str
    start_line: int
    severity: Severity
    status: VerificationStatus | None = None


class TestRunResult(BaseModel):
    """Outcome of running the repository's tests in the copy."""

    __test__ = False  # not a pytest test class

    command: list[str]
    exit_code: int | None = None
    passed: bool = False
    timed_out: bool = False
    output_tail: str = ""


class FixVerificationReport(BaseModel):
    """Everything a reviewer needs to judge a proposed fix."""

    verdict: FixVerdict
    reasons: list[str] = Field(default_factory=list)
    patch_files: list[str] = Field(default_factory=list)
    targets: list[FindingSummary] = Field(default_factory=list)
    resolved: list[FindingSummary] = Field(default_factory=list)
    remaining: list[FindingSummary] = Field(default_factory=list)
    new: list[FindingSummary] = Field(default_factory=list)
    score_before: float | None = None
    score_after: float | None = None
    scanners_before: dict[str, str] = Field(default_factory=dict)
    scanners_after: dict[str, str] = Field(default_factory=dict)
    checks_run: list[str] = Field(default_factory=list)
    tests: TestRunResult | None = None
    line_endings_normalized: bool = False
    diff_text: str = ""
    limitations: list[str] = Field(default_factory=list)


ScanFunction = Callable[..., RepositoryScanResult]


def _summary(finding: Finding, status: VerificationStatus | None = None) -> FindingSummary:
    return FindingSummary(
        fingerprint=finding.fingerprint,
        tool=finding.tool,
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        start_line=finding.start_line,
        severity=finding.severity,
        status=status,
    )


def _scanner_statuses(result: RepositoryScanResult) -> dict[str, str]:
    return {scanner.scanner: scanner.status.value for scanner in result.scanners}


def _scan_is_complete(result: RepositoryScanResult) -> bool:
    """A scan counts as complete when no scanner failed or ran partially.

    SKIPPED is accepted: Bandit, for example, skips a repository without
    Python files, and such a scan is still complete for what it covers.
    """
    if not result.scanners:
        return False
    return all(
        scanner.status in {ScannerStatus.SUCCESS, ScannerStatus.SKIPPED}
        for scanner in result.scanners
    )


def _incomplete_scanners(result: RepositoryScanResult) -> list[str]:
    return [
        f"{scanner.scanner} ({scanner.status.value})"
        for scanner in result.scanners
        if scanner.status not in {ScannerStatus.SUCCESS, ScannerStatus.SKIPPED}
    ]


def _score(result: RepositoryScanResult) -> float | None:
    return result.security_debt.score if result.security_debt is not None else None


def _run_tests(
    root: Path,
    command: Sequence[str],
    timeout_seconds: int,
) -> TestRunResult:
    """Run repository tests in the copy. This executes repository code."""
    try:
        completed = subprocess.run(  # nosec B603
            list(command),
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            shell=False,
            env=sanitized_environment(),
        )
    except subprocess.TimeoutExpired:
        return TestRunResult(command=list(command), timed_out=True)
    except FileNotFoundError:
        return TestRunResult(
            command=list(command),
            output_tail=f"Test command not found: {command[0]!r}.",
        )

    output = f"{completed.stdout}\n{completed.stderr}".strip()
    return TestRunResult(
        command=list(command),
        exit_code=completed.returncode,
        passed=completed.returncode == 0,
        output_tail=redact_sensitive_text(output)[-TEST_OUTPUT_TAIL_CHARS:],
    )


def _not_verified(
    reasons: list[str],
    *,
    diff_text: str,
    patch_files: Iterable[str] = (),
    limitations: Iterable[str] = (),
    **extra,
) -> FixVerificationReport:
    return FixVerificationReport(
        verdict=FixVerdict.NOT_VERIFIED,
        reasons=reasons,
        patch_files=list(patch_files),
        diff_text=diff_text,
        limitations=[*ALWAYS_LIMITATIONS, *limitations],
        **extra,
    )


def verify_fix(
    repo_root: str | Path,
    diff_text: str,
    *,
    target_fingerprints: Iterable[str] | None = None,
    run_tests: bool = False,
    test_command: Sequence[str] | None = None,
    timeout_seconds: int = 180,
    test_timeout_seconds: int = 300,
    regression_severity: Severity = DEFAULT_REGRESSION_SEVERITY,
    scan: ScanFunction = scan_repository,
) -> FixVerificationReport:
    """Verify a proposed patch without touching the original repository.

    Targets are the findings the patch is meant to fix. When
    ``target_fingerprints`` is None, the targets are the baseline findings on
    lines the patch changes. New findings at or above ``regression_severity``
    make the verdict REGRESSION; pass ``Severity.INFO`` to treat any new
    finding as a regression. ``run_tests=True`` executes the repository's own
    test command inside the copy; it is off by default because it runs
    repository code.
    """
    if timeout_seconds <= 0 or test_timeout_seconds <= 0:
        raise ValueError("Timeouts must be positive.")

    extra_limitations: list[str] = []
    if not run_tests:
        extra_limitations.append("Repository tests were not run (run_tests=False).")

    validation = validate_patch(diff_text)
    if not validation.ok:
        return _not_verified(
            ["The patch failed validation.", *validation.errors],
            diff_text=diff_text,
            limitations=extra_limitations,
        )

    try:
        copy = create_isolated_copy(repo_root)
    except (OSError, ValueError) as exc:
        return _not_verified(
            [f"Could not create an isolated copy ({type(exc).__name__}): {exc}"],
            diff_text=diff_text,
            patch_files=validation.touched_files,
            limitations=extra_limitations,
        )

    with copy:
        if copy.skipped_symlinks:
            extra_limitations.append(
                f"{copy.skipped_symlinks} symlink(s) were not copied and not verified."
            )

        # The baseline is scanned from the same copy the patch is applied to,
        # so both scans see exactly the same set of files.
        baseline = scan(copy.root, timeout_seconds=timeout_seconds, enable_ai_triage=False)

        if target_fingerprints is None:
            targets = _findings_on_changed_lines(baseline.findings, validation.changed_lines)
        else:
            wanted = list(dict.fromkeys(target_fingerprints))
            by_fingerprint = {finding.fingerprint: finding for finding in baseline.findings}
            unknown = [fingerprint for fingerprint in wanted if fingerprint not in by_fingerprint]
            if unknown:
                return _not_verified(
                    [
                        "These target fingerprints are not in the baseline scan: "
                        + ", ".join(unknown)
                    ],
                    diff_text=diff_text,
                    patch_files=validation.touched_files,
                    limitations=extra_limitations,
                    score_before=_score(baseline),
                    scanners_before=_scanner_statuses(baseline),
                )
            targets = [by_fingerprint[fingerprint] for fingerprint in wanted]

        applied = apply_patch(copy, diff_text, strip_level=validation.strip_level)
        if not applied.ok:
            return _not_verified(
                ["The patch could not be applied to the isolated copy.", *applied.errors],
                diff_text=diff_text,
                patch_files=validation.touched_files,
                limitations=extra_limitations,
                targets=[_summary(finding) for finding in targets],
                score_before=_score(baseline),
                scanners_before=_scanner_statuses(baseline),
            )

        after = scan(copy.root, timeout_seconds=timeout_seconds, enable_ai_triage=False)

        tests: TestRunResult | None = None
        if run_tests:
            command = list(test_command or [sys.executable, "-m", "pytest", "-q"])
            tests = _run_tests(copy.root, command, test_timeout_seconds)

    scans_complete = _scan_is_complete(baseline) and _scan_is_complete(after)
    comparison = compare_findings(baseline.findings, after.findings, scan_complete=scans_complete)

    status_by_fingerprint = {
        result.baseline_finding.fingerprint: result.status for result in comparison.results
    }
    target_summaries = [
        _summary(finding, status_by_fingerprint.get(finding.fingerprint)) for finding in targets
    ]
    resolved = [item for item in target_summaries if item.status == VerificationStatus.RESOLVED]
    remaining = [item for item in target_summaries if item.status != VerificationStatus.RESOLVED]
    new = [_summary(finding, VerificationStatus.NEW) for finding in comparison.new_findings]
    threshold = SEVERITY_RANK[regression_severity]
    serious_new = [item for item in new if SEVERITY_RANK[item.severity] >= threshold]
    minor_new = [item for item in new if SEVERITY_RANK[item.severity] < threshold]

    checks_run = [
        f"{scanner.scanner} ({scanner.status.value})"
        for scanner in after.scanners
        if scanner.status in {ScannerStatus.SUCCESS, ScannerStatus.PARTIAL}
    ]
    if tests is not None:
        checks_run.append("tests: " + " ".join(tests.command))

    reasons: list[str] = []

    if not scans_complete:
        verdict = FixVerdict.NOT_VERIFIED
        incomplete = _incomplete_scanners(baseline) + _incomplete_scanners(after)
        reasons.append(
            "At least one scanner did not complete, so resolution cannot be confirmed: "
            + ", ".join(dict.fromkeys(incomplete))
        )
    elif tests is not None and tests.timed_out:
        verdict = FixVerdict.NOT_VERIFIED
        reasons.append(f"The test command timed out after {test_timeout_seconds} seconds.")
    elif serious_new or (tests is not None and not tests.passed):
        verdict = FixVerdict.REGRESSION
        if serious_new:
            reasons.append(
                f"The patch introduced {len(serious_new)} new finding(s) of "
                f"{regression_severity.value} severity or higher."
            )
        if tests is not None and not tests.passed:
            reasons.append(f"The test command failed (exit code {tests.exit_code}).")
    elif not targets:
        verdict = FixVerdict.NOT_VERIFIED
        reasons.append(
            "No targeted findings: the patch changes no line with a baseline finding. "
            "Pass target fingerprints explicitly if the fix is elsewhere."
        )
    elif not remaining:
        verdict = FixVerdict.VERIFIED_FIX
        reasons.append(f"All {len(resolved)} targeted finding(s) are resolved.")
    elif resolved:
        verdict = FixVerdict.PARTIAL
        reasons.append(f"{len(resolved)} of {len(targets)} targeted finding(s) are resolved.")
    else:
        verdict = FixVerdict.UNRESOLVED
        reasons.append("None of the targeted findings were resolved.")

    if minor_new and verdict != FixVerdict.NOT_VERIFIED:
        reasons.append(
            f"{len(minor_new)} new lower-severity finding(s) appeared; review them under 'new' "
            f"(below the {regression_severity.value} regression threshold)."
        )

    if applied.line_endings_normalized:
        extra_limitations.append(
            "The patch had Windows (CRLF) line endings and was applied after converting to LF."
        )

    return FixVerificationReport(
        verdict=verdict,
        reasons=reasons,
        patch_files=validation.touched_files,
        targets=target_summaries,
        resolved=resolved,
        remaining=remaining,
        new=new,
        score_before=_score(baseline),
        score_after=_score(after),
        scanners_before=_scanner_statuses(baseline),
        scanners_after=_scanner_statuses(after),
        checks_run=checks_run,
        tests=tests,
        line_endings_normalized=applied.line_endings_normalized,
        diff_text=diff_text,
        limitations=[*ALWAYS_LIMITATIONS, *extra_limitations],
    )


def _findings_on_changed_lines(
    findings: Iterable[Finding],
    changed_lines: dict[str, list[int]],
) -> list[Finding]:
    """Select findings whose line range overlaps a line the patch changes."""
    selected: list[Finding] = []
    for finding in findings:
        lines = changed_lines.get(finding.file_path)
        if not lines:
            continue
        end = finding.end_line or finding.start_line
        if any(finding.start_line <= line <= end for line in lines):
            selected.append(finding)
    return selected
