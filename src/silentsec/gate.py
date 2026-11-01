"""Pull-request security gate: does a change ADD security debt?

``silentsec gate . --base main --head HEAD`` scans two versions of the code
and sorts every finding into:

* NEW       present in head but not in base (the change introduced it)
* EXISTING  present in both (old debt; never blocks the change)
* RESOLVED  present in base but gone in head

The change FAILS when it introduces a security or secret finding at or above
the ``fail_on`` severity (default: high). New architecture/maintainability
findings are warnings unless ``fail_on_architecture`` is set. If either scan
is incomplete the gate cannot decide and says so (exit code 2) instead of
passing.

Like the Time Machine, both versions are exported with ``git archive`` into
temporary folders; the repository and its working tree are never modified.
Base is compared at the merge base of base and head, so changes that landed
on the base branch after the head branch was created are not blamed on it.
"""

import shutil
import tempfile
from collections.abc import Callable
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from silentsec.history.timeline import HistoryError, _git, _scanner_problems, export_commit
from silentsec.remediation.verify import SEVERITY_RANK
from silentsec.scanners.results import ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult, scan_repository
from silentsec.schemas import Finding, FindingCategory, Severity
from silentsec.scope import IGNORE_FILE_NAME
from silentsec.scoring.correlation import correlate_findings
from silentsec.verification import VerificationStatus, compare_findings

SECURITY_CATEGORIES = {FindingCategory.SECURITY, FindingCategory.SECRET}


class GateVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INCOMPLETE = "incomplete"


class GateFinding(BaseModel):
    tool: str
    rule_id: str
    file_path: str
    start_line: int
    severity: Severity
    category: FindingCategory
    message: str
    end_line: int | None = None
    cwe_id: str | None = None
    fingerprint: str | None = None


class GatePolicy(BaseModel):
    fail_on: Severity = Severity.HIGH
    fail_on_architecture: bool = False
    # Findings in test/sample code (tests/, fixtures/, examples/ ...) only
    # count when this is set.
    include_tests: bool = False


class GateReport(BaseModel):
    verdict: GateVerdict
    reasons: list[str] = Field(default_factory=list)
    policy: GatePolicy
    base_ref: str
    head_ref: str
    base_sha: str  # the merge base that was actually scanned
    head_sha: str
    blocking: list[GateFinding] = Field(default_factory=list)
    warnings: list[GateFinding] = Field(default_factory=list)
    other_new: list[GateFinding] = Field(default_factory=list)
    resolved: list[GateFinding] = Field(default_factory=list)
    existing_count: int = 0  # scanner findings
    # Unique issues: one issue reported by several scanners counts once.
    blocking_issues: int = 0
    new_issues: int = 0
    existing_issues: int = 0
    score_before: float = 0.0  # uncapped, so changes stay visible
    score_after: float = 0.0
    scanner_problems: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @property
    def new_count(self) -> int:
        return len(self.blocking) + len(self.warnings) + len(self.other_new)


ScanFunction = Callable[..., RepositoryScanResult]


def _gate_finding(finding: Finding) -> GateFinding:
    return GateFinding(
        tool=finding.tool,
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        start_line=finding.start_line,
        severity=finding.severity,
        category=finding.category,
        message=finding.message,
        end_line=finding.end_line,
        cwe_id=finding.cwe_id,
        fingerprint=finding.fingerprint,
    )


def _complete(result: RepositoryScanResult) -> bool:
    return bool(result.scanners) and all(
        scanner.status in {ScannerStatus.SUCCESS, ScannerStatus.SKIPPED}
        for scanner in result.scanners
    )


def _raw_score(result: RepositoryScanResult) -> float:
    return result.security_debt.raw_score if result.security_debt else 0.0


def _resolve(repo: Path, ref: str) -> str:
    if ref.startswith("-"):
        raise HistoryError(f"Invalid revision: {ref}")
    try:
        return _git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").stdout.strip()
    except HistoryError as exc:
        raise HistoryError(f"Unknown commit or branch: {ref}") from exc


def _scan_commit(
    repo: Path,
    sha: str,
    scan: ScanFunction,
    timeout_seconds: int,
    ignore_text: str | None = None,
    use_ignore_text: bool = False,
):
    """Scan one commit. Returns (result, skipped_entries, its .silentsecignore text).

    With ``use_ignore_text`` the snapshot's .silentsecignore is replaced by
    ``ignore_text`` (None removes it), so a change cannot hide its own
    findings by editing the ignore file.
    """
    workspace = Path(tempfile.mkdtemp(prefix="silentsec-gate-"))
    try:
        snapshot = workspace / "repo"
        snapshot.mkdir()
        skipped = export_commit(repo, sha, snapshot)
        ignore_path = snapshot / IGNORE_FILE_NAME
        own_text = (
            ignore_path.read_text(encoding="utf-8-sig", errors="replace")
            if ignore_path.is_file() and not ignore_path.is_symlink()
            else None
        )
        if use_ignore_text:
            ignore_path.unlink(missing_ok=True)
            if ignore_text is not None:
                ignore_path.write_text(ignore_text, encoding="utf-8")
        result = scan(snapshot, timeout_seconds=timeout_seconds, enable_ai_triage=False)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
    return result, skipped, own_text


def _gated_findings(result: RepositoryScanResult, policy: GatePolicy) -> list[Finding]:
    """Findings the gate compares: test/sample code only with include_tests."""
    test_findings = getattr(result, "test_findings", None) or []
    return list(result.findings) + (list(test_findings) if policy.include_tests else [])


def run_gate(
    repo_path: str | Path,
    *,
    base: str = "main",
    head: str = "HEAD",
    policy: GatePolicy | None = None,
    timeout_seconds: int = 180,
    scan: ScanFunction = scan_repository,
) -> GateReport:
    """Scan base and head and decide whether head adds security debt."""
    policy = policy or GatePolicy()
    repo = Path(repo_path).expanduser().resolve()
    if not repo.is_dir():
        raise HistoryError("Repository directory does not exist.")
    try:
        top_level = Path(_git(repo, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    except HistoryError as exc:
        raise HistoryError(f"Not a Git repository: {repo}") from exc

    head_sha = _resolve(top_level, head)
    base_tip = _resolve(top_level, base)
    try:
        base_sha = _git(top_level, "merge-base", base_tip, head_sha).stdout.strip()
    except HistoryError as exc:
        raise HistoryError(f"{base} and {head} have no common history.") from exc

    limitations = [
        "Only committed files are compared; uncommitted changes are ignored.",
        (
            "Findings are matched by tool, rule and file, so moving code between files "
            "shows as one resolved and one new finding."
        ),
        (
            "Passing the gate means the listed scanners found nothing new at the policy "
            "threshold; it does not prove the change is secure."
        ),
    ]
    if base_sha != base_tip:
        limitations.append(
            f"Compared against the merge base {base_sha[:8]} of {base} and {head}, "
            f"not the current tip of {base}."
        )

    report = GateReport(
        verdict=GateVerdict.PASS,
        policy=policy,
        base_ref=base,
        head_ref=head,
        base_sha=base_sha,
        head_sha=head_sha,
        limitations=limitations,
    )
    if base_sha == head_sha:
        report.reasons.append(f"{head} has no changes compared with {base}.")
        return report

    base_result, skipped_base, base_ignore = _scan_commit(
        top_level, base_sha, scan, timeout_seconds
    )
    # The head is scanned with the base's .silentsecignore.
    head_result, skipped_head, head_ignore = _scan_commit(
        top_level, head_sha, scan, timeout_seconds, base_ignore, use_ignore_text=True
    )
    if head_ignore != base_ignore:
        report.limitations.append(
            f"{head} changes {IGNORE_FILE_NAME}; the version from {base} was used for both "
            "scans, so the change cannot hide its own findings."
        )
    if skipped_base or skipped_head:
        report.limitations.append(
            "Some unsafe archive entries (such as symlinks pointing outside the "
            "repository) were skipped and not scanned."
        )

    report.score_before = _raw_score(base_result)
    report.score_after = _raw_score(head_result)
    report.scanner_problems = [f"base: {problem}" for problem in _scanner_problems(base_result)] + [
        f"head: {problem}" for problem in _scanner_problems(head_result)
    ]

    if not (_complete(base_result) and _complete(head_result)):
        report.verdict = GateVerdict.INCOMPLETE
        report.reasons.append(
            "A scanner did not finish on one of the versions, so new findings cannot be "
            "confirmed. Fix the scanner problem (or raise --timeout) and run the gate again."
        )
        return report

    comparison = compare_findings(
        _gated_findings(base_result, policy),
        _gated_findings(head_result, policy),
        scan_complete=True,
    )
    if not policy.include_tests:
        test_new = compare_findings(
            getattr(base_result, "test_findings", None) or [],
            getattr(head_result, "test_findings", None) or [],
            scan_complete=True,
        ).new_findings
        if test_new:
            report.limitations.append(
                f"{len(test_new)} new finding(s) in test or sample code were not counted "
                "(use --include-tests to gate on them)."
            )
    threshold = SEVERITY_RANK[policy.fail_on]

    blocking_findings: list[Finding] = []
    for finding in comparison.new_findings:
        item = _gate_finding(finding)
        if finding.category in SECURITY_CATEGORIES:
            if SEVERITY_RANK[finding.severity] >= threshold:
                report.blocking.append(item)
                blocking_findings.append(finding)
            else:
                report.other_new.append(item)
        elif policy.fail_on_architecture:
            report.blocking.append(item)
            blocking_findings.append(finding)
        else:
            report.warnings.append(item)

    existing_findings: list[Finding] = []
    for result in comparison.results:
        if result.status == VerificationStatus.RESOLVED:
            report.resolved.append(_gate_finding(result.baseline_finding))
        elif result.status in {VerificationStatus.STILL_OPEN, VerificationStatus.REINTRODUCED}:
            report.existing_count += 1
            existing_findings.append(result.current_finding or result.baseline_finding)

    report.blocking_issues = len(correlate_findings(blocking_findings))
    report.new_issues = len(correlate_findings(comparison.new_findings))
    report.existing_issues = len(correlate_findings(existing_findings))

    def issues(count: int, findings: int) -> str:
        text = f"{count} issue(s)"
        return text if count == findings else f"{text} ({findings} scanner findings)"

    if report.blocking:
        report.verdict = GateVerdict.FAIL
        report.reasons.append(
            f"The change introduces {issues(report.blocking_issues, len(report.blocking))} "
            f"at or above the policy threshold ({policy.fail_on.value}"
            + (", or architecture" if policy.fail_on_architecture else "")
            + ")."
        )
    else:
        report.reasons.append(
            f"No new security findings at or above {policy.fail_on.value} severity."
        )
    if report.warnings:
        report.reasons.append(
            f"Warning: {len(report.warnings)} new architecture/maintainability finding(s)."
        )
    if report.existing_count:
        report.reasons.append(
            f"{issues(report.existing_issues, report.existing_count)} already existed in "
            f"{base}; they do not block this change."
        )
    return report
