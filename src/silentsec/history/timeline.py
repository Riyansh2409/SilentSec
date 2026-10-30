"""Security Debt Time Machine: how debt changed across recent commits.

For each of the last N commits on the current branch (first-parent), the
committed files are exported with ``git archive`` into a temporary folder and
scanned. Consecutive scans are compared to show which findings each commit
introduced and which it fixed.

Nothing in the repository is modified: ``git archive``, ``git log`` and
``git rev-parse`` only read it, and results are stored outside the repo.
Only committed content is scanned; uncommitted changes are ignored.
"""

import io
import shutil
import subprocess  # nosec B404
import tarfile
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, Field

from silentsec.history.store import (
    HistoryStore,
    StoredScan,
    analysis_version,
    default_database_path,
)
from silentsec.remediation.sandbox import sanitized_environment
from silentsec.scanners.results import ScannerStatus
from silentsec.scanners.scanner_service import RepositoryScanResult, scan_repository
from silentsec.schemas import Finding, FindingCategory, Severity
from silentsec.triage.sanitization import redact_sensitive_text
from silentsec.verification import VerificationStatus, compare_findings

MAX_COMMITS = 50
MAX_ARCHIVE_BYTES = 300 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 120


class HistoryError(RuntimeError):
    """The repository history cannot be read."""


class FindingChange(BaseModel):
    tool: str
    rule_id: str
    file_path: str
    start_line: int
    severity: Severity
    category: FindingCategory


class TimelinePoint(BaseModel):
    commit_sha: str
    short_sha: str
    committed_at: str  # ISO 8601, UTC
    subject: str
    score: float
    raw_score: float
    security_points: float
    architecture_points: float
    unique_issues: int
    complete: bool
    from_cache: bool = False
    # "baseline" for the oldest commit in the window (earlier history is not
    # scanned), "unknown" when either scan was incomplete, else "known".
    attribution: str = "known"
    introduced: list[FindingChange] = Field(default_factory=list)
    fixed: list[FindingChange] = Field(default_factory=list)


class TimelineReport(BaseModel):
    repo_path: str
    branch: str
    analysis_version: str
    database: str
    points: list[TimelinePoint] = Field(default_factory=list)
    shallow_clone: bool = False
    limitations: list[str] = Field(default_factory=list)

    @property
    def biggest_increase(self) -> TimelinePoint | None:
        """The commit with the largest rise in uncapped score."""
        best: tuple[float, TimelinePoint] | None = None
        for previous, current in zip(self.points, self.points[1:], strict=False):
            delta = current.raw_score - previous.raw_score
            if delta > 0 and (best is None or delta > best[0]):
                best = (delta, current)
        return best[1] if best else None


ScanFunction = Callable[..., RepositoryScanResult]


def _git(repo: Path, *args: str, binary: bool = False) -> subprocess.CompletedProcess:
    try:
        # A fixed argument list without a shell; only read-only git commands.
        completed = subprocess.run(  # nosec B603
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=not binary,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            shell=False,
            env=sanitized_environment(),
        )
    except FileNotFoundError as exc:
        raise HistoryError("Git was not found. Install Git and make sure 'git' is on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise HistoryError(f"git {args[0]} timed out.") from exc

    if completed.returncode != 0:
        stderr = completed.stderr
        detail = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else stderr
        raise HistoryError(f"git {args[0]} failed: {(detail or '').strip()[-300:]}")
    return completed


def list_commits(repo: Path, count: int) -> list[tuple[str, int, str]]:
    """Return (sha, unix time, subject) for the last ``count`` commits, oldest first."""
    output = _git(
        repo,
        "log",
        "--first-parent",
        f"--max-count={count}",
        "--format=%H%x1f%ct%x1f%s",
        "HEAD",
    ).stdout
    commits = []
    for line in output.splitlines():
        sha, timestamp, subject = line.split("\x1f", 2)
        commits.append((sha, int(timestamp), subject))
    return list(reversed(commits))


def export_commit(repo: Path, sha: str, destination: Path) -> int:
    """Write the committed files of ``sha`` into ``destination``.

    Returns the number of archive entries skipped as unsafe (for example a
    symlink pointing outside the repository); those are never written.
    """
    archive = _git(repo, "archive", "--format=tar", sha, binary=True).stdout
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise HistoryError(f"Commit {sha[:12]} is larger than the archive size limit.")

    skipped = 0
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar:
            if hasattr(tarfile, "data_filter"):
                try:
                    # Rejects absolute paths, '..', links leaving the folder, devices.
                    tar.extract(member, destination, filter="data")
                except tarfile.FilterError:
                    skipped += 1
            else:  # pragma: no cover - Python < 3.11.4
                name = PurePosixPath(member.name)
                if (member.isfile() or member.isdir()) and not name.is_absolute() and (
                    ".." not in name.parts
                ):
                    tar.extract(member, destination)  # nosec B202
                else:
                    skipped += 1
    return skipped


def _to_stored(sha: str, committed_at: int, subject: str, result: RepositoryScanResult) -> StoredScan:
    debt = result.security_debt
    complete = bool(result.scanners) and all(
        scanner.status in {ScannerStatus.SUCCESS, ScannerStatus.SKIPPED}
        for scanner in result.scanners
    )
    return StoredScan(
        commit_sha=sha,
        committed_at=committed_at,
        subject=subject,
        score=debt.score if debt else 0.0,
        raw_score=debt.raw_score if debt else 0.0,
        security_points=debt.security_points if debt else 0.0,
        architecture_points=debt.architecture_debt_points if debt else 0.0,
        unique_issues=debt.unique_open_findings_count if debt else 0,
        complete=complete,
        scanner_statuses={scanner.scanner: scanner.status.value for scanner in result.scanners},
        # Stored on disk, so messages are redacted once more as a safety net.
        findings=[
            finding.model_copy(update={"message": redact_sensitive_text(finding.message)})
            for finding in result.findings
        ],
    )


def _change(finding: Finding) -> FindingChange:
    return FindingChange(
        tool=finding.tool,
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        start_line=finding.start_line,
        severity=finding.severity,
        category=finding.category,
    )


def build_timeline(
    repo_path: str | Path,
    *,
    commits: int = 10,
    database: str | Path | None = None,
    use_cache: bool = True,
    timeout_seconds: int = 180,
    scan: ScanFunction = scan_repository,
    progress: Callable[[int, int, str], None] | None = None,
) -> TimelineReport:
    """Scan the last ``commits`` commits and attribute debt changes to them."""
    if not 1 <= commits <= MAX_COMMITS:
        raise ValueError(f"commits must be between 1 and {MAX_COMMITS}.")

    repo = Path(repo_path).expanduser().resolve()
    if not repo.is_dir():
        raise HistoryError("Repository directory does not exist.")

    try:
        top_level = Path(_git(repo, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    except HistoryError as exc:
        if "not a git repository" in str(exc).lower():
            raise HistoryError(f"Not a Git repository: {repo}") from exc
        raise
    branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    shallow = _git(repo, "rev-parse", "--is-shallow-repository").stdout.strip() == "true"
    history = list_commits(top_level, commits)

    version = analysis_version()
    db_path = Path(database).expanduser() if database else default_database_path(top_level)
    store = HistoryStore(db_path)

    limitations = [
        "Only committed files are scanned; uncommitted changes are ignored.",
        "Commits are followed along the first parent; merged branches appear as one step.",
    ]
    if shallow:
        limitations.append(
            "This is a shallow clone, so older commits are missing. "
            "Run 'git fetch --unshallow' for the full history."
        )
    if len(history) < commits:
        limitations.append(f"Only {len(history)} commit(s) exist on this branch.")

    stored_scans: list[tuple[StoredScan, bool]] = []
    skipped_entries = 0

    for index, (sha, committed_at, subject) in enumerate(history, start=1):
        if progress is not None:
            progress(index, len(history), sha[:12])

        cached = store.get(sha, version) if use_cache else None
        if cached is not None:
            stored_scans.append((cached, True))
            continue

        workspace = Path(tempfile.mkdtemp(prefix="silentsec-history-"))
        try:
            snapshot = workspace / "repo"
            snapshot.mkdir()
            skipped_entries += export_commit(top_level, sha, snapshot)
            result = scan(snapshot, timeout_seconds=timeout_seconds, enable_ai_triage=False)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

        stored = _to_stored(sha, committed_at, subject, result)
        # Incomplete scans are not cached, so a later run can complete them.
        if stored.complete:
            store.put(stored, version)
        stored_scans.append((stored, False))

    points: list[TimelinePoint] = []
    previous: StoredScan | None = None

    for stored, from_cache in stored_scans:
        point = TimelinePoint(
            commit_sha=stored.commit_sha,
            short_sha=stored.commit_sha[:8],
            committed_at=datetime.fromtimestamp(stored.committed_at, tz=UTC).isoformat(),
            subject=stored.subject,
            score=stored.score,
            raw_score=stored.raw_score,
            security_points=stored.security_points,
            architecture_points=stored.architecture_points,
            unique_issues=stored.unique_issues,
            complete=stored.complete,
            from_cache=from_cache,
        )

        if previous is None:
            point.attribution = "baseline"
        elif not (previous.complete and stored.complete):
            point.attribution = "unknown"
        else:
            comparison = compare_findings(previous.findings, stored.findings, scan_complete=True)
            point.introduced = [_change(finding) for finding in comparison.new_findings]
            point.fixed = [
                _change(result.baseline_finding)
                for result in comparison.results
                if result.status == VerificationStatus.RESOLVED
            ]

        points.append(point)
        previous = stored

    if skipped_entries:
        limitations.append(
            f"{skipped_entries} unsafe archive entr(ies) (such as symlinks pointing outside "
            "the repository) were skipped and not scanned."
        )

    if any(not point.complete for point in points):
        limitations.append(
            "Some commits had an incomplete scan (a scanner failed); "
            "changes next to them are marked unknown."
        )

    return TimelineReport(
        repo_path=str(top_level),
        branch=branch,
        analysis_version=version,
        database=str(db_path),
        points=points,
        shallow_clone=shallow,
        limitations=limitations,
    )
