"""HTTP API so a web frontend can run SilentSec scans.

Start it with ``silentsec serve`` and open http://127.0.0.1:8000/docs for the
interactive documentation. Endpoints:

    GET  /api/health                 versions and which scanners are installed
    POST /api/scan/github            {"url": "https://github.com/owner/repo"}
    POST /api/scan/upload            multipart form, field "file" (.zip or one source file)
    POST /api/verify/github          {"url": ..., "patch": "<unified diff>"}
    POST /api/verify/upload          multipart form, fields "file" and "patch"
    GET  /api/scans                  recent scans (newest first)
    GET  /api/scans/{id}             the full JSON result of one scan
    GET  /api/scans/{id}/report      the self-contained HTML report

Scans run synchronously: the POST returns when the scan is done (usually a
few seconds; up to a few minutes for large repositories). Results are kept
in memory only, for the most recent scans, and are lost when the server
stops. Temporary copies of the code are deleted as soon as a scan finishes.
"""

import shutil
import tempfile
import threading
import uuid
from collections import OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from silentsec.api.sources import (
    MAX_UPLOAD_BYTES,
    PreparedSource,
    SourceError,
    clone_github,
    extract_upload,
)
from silentsec.history import HistoryError, TimelineReport, build_timeline
from silentsec.remediation.verify import (
    FindingSummary,
    FixVerdict,
    FixVerificationReport,
    verify_fix,
)
from silentsec.report import _snippets
from silentsec.report.html import render_report
from silentsec.scanners.scanner_service import RepositoryScanResult, scan_repository

DEFAULT_CORS_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)
MAX_STORED_SCANS = 20
MAX_CONCURRENT_SCANS = 2
MAX_HISTORY_COMMITS = 20
MAX_PATCH_BYTES = 1024 * 1024


# --- request and response models ---------------------------------------------


class GitHubScanRequest(BaseModel):
    url: str = Field(examples=["https://github.com/owner/repo"])
    history_commits: int = Field(
        default=10,
        ge=0,
        le=MAX_HISTORY_COMMITS,
        description="How many recent commits the Time Machine scans; 0 turns history off.",
    )
    timeout_seconds: int = Field(default=180, ge=10, le=900)


class GitHubVerifyRequest(BaseModel):
    url: str = Field(examples=["https://github.com/owner/repo"])
    patch: str = Field(
        description="A unified diff, e.g. from 'git diff --relative', with paths "
        "relative to the repository root.",
        max_length=MAX_PATCH_BYTES,
    )
    targets: list[str] | None = Field(
        default=None,
        description="Fingerprints of the issues the patch should fix. Default: the "
        "issues on the lines the patch changes.",
    )
    timeout_seconds: int = Field(default=180, ge=10, le=900)


class SourceInfo(BaseModel):
    type: Literal["github", "upload"]
    name: str
    url: str | None = None


class ScannerInfo(BaseModel):
    name: str
    status: str
    findings: int
    duration_seconds: float
    errors: list[str] = Field(default_factory=list)


class Summary(BaseModel):
    score: float
    raw_score: float
    security_risk: str
    architecture_risk: str
    security_points: float
    architecture_points: float
    unique_issues: int
    duplicates_merged: int
    highest_severity: str | None
    complete: bool
    languages: list[str]
    duration_seconds: float
    explanation: str


class IssueSource(BaseModel):
    tool: str
    rule_id: str


class Issue(BaseModel):
    fingerprint: str
    severity: str
    category: str
    title: str
    file_path: str
    start_line: int
    end_line: int | None
    cwe_id: str | None
    points: float
    fix_effort: str
    score_explanation: str
    sources: list[IssueSource]
    merge_reason: str | None = None
    exposure: Literal["reachable", "not_reachable", "unknown"] = Field(
        default="unknown",
        description="'reachable' when a web route reaches the enclosing function in the "
        "call graph. A call path exists in the code; it does not prove exploitability.",
    )
    exposure_path: list[str] = Field(
        default_factory=list, description='Shortest call chain, e.g. ["GET /search -> search()"].'
    )
    code: str | None = Field(
        default=None, description="Code around the issue; withheld for possible secrets."
    )


class ScanResponse(BaseModel):
    id: str
    created_at: str
    source: SourceInfo
    summary: Summary | None
    scanners: list[ScannerInfo]
    issues: list[Issue]
    timeline: TimelineReport | None = None
    timeline_note: str | None = None
    report_url: str


class ScanListItem(BaseModel):
    id: str
    created_at: str
    source: SourceInfo
    score: float | None
    security_risk: str | None
    unique_issues: int | None


class HealthResponse(BaseModel):
    status: str
    silentsec_version: str
    tools: dict[str, bool]


# --- building responses ------------------------------------------------------


def _version() -> str:
    try:
        return metadata.version("silentsec")
    except metadata.PackageNotFoundError:
        return "unknown"


def _issues(result: RepositoryScanResult, snippets: dict[str, str]) -> list[Issue]:
    debt = result.security_debt
    if debt is None:
        return []
    groups = {group.representative.fingerprint: group for group in debt.correlation_groups}
    issues: list[Issue] = []
    for item in debt.scored_findings:
        finding = item.finding
        group = groups.get(finding.fingerprint)
        members = group.findings if group is not None else [finding]
        sources = sorted({(member.tool, member.rule_id) for member in members})
        issues.append(
            Issue(
                fingerprint=finding.fingerprint,
                severity=finding.severity.value,
                category=finding.category.value,
                title=finding.message,
                file_path=finding.file_path,
                start_line=finding.start_line,
                end_line=finding.end_line,
                cwe_id=finding.cwe_id,
                points=round(item.score, 1),
                fix_effort=item.remediation_effort,
                score_explanation=item.explanation,
                sources=[IssueSource(tool=tool, rule_id=rule) for tool, rule in sources],
                merge_reason=group.reason if group is not None and len(members) > 1 else None,
                exposure=item.exposure,
                exposure_path=item.exposure_path,
                code=snippets.get(finding.fingerprint),
            )
        )
    return issues


def _summary(result: RepositoryScanResult) -> Summary | None:
    debt = result.security_debt
    if debt is None:
        return None
    return Summary(
        score=debt.score,
        raw_score=debt.raw_score,
        security_risk=debt.risk_level.value,
        architecture_risk=debt.architecture_risk_level.value,
        security_points=debt.security_points,
        architecture_points=debt.architecture_debt_points,
        unique_issues=debt.unique_open_findings_count,
        duplicates_merged=debt.duplicate_findings_removed,
        highest_severity=debt.highest_severity.value if debt.highest_severity else None,
        complete=result.security_debt_complete,
        languages=result.languages,
        duration_seconds=round(result.duration_seconds, 1),
        explanation=debt.risk_explanation,
    )


class VerifyResponse(BaseModel):
    id: str
    created_at: str
    source: "SourceInfo"
    verdict: FixVerdict
    reasons: list[str]
    patch_files: list[str]
    targets: list[FindingSummary]
    resolved: list[FindingSummary]
    remaining: list[FindingSummary]
    new: list[FindingSummary]
    score_before: float | None
    score_after: float | None
    raw_score_before: float | None
    raw_score_after: float | None
    checks_run: list[str]
    line_endings_normalized: bool
    limitations: list[str]


def decode_patch(data: bytes) -> str:
    """Decode a patch, accepting the encodings Windows tools commonly produce."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    return data.decode("utf-8-sig")


class _StoredScan(BaseModel):
    response: ScanResponse
    html: str


# --- the app -----------------------------------------------------------------


ScanFunction = Callable[..., RepositoryScanResult]
CloneFunction = Callable[..., PreparedSource]


def create_app(
    *,
    cors_origins: tuple[str, ...] | list[str] = DEFAULT_CORS_ORIGINS,
    scan: ScanFunction = scan_repository,
    clone: CloneFunction = clone_github,
    verify: Callable[..., FixVerificationReport] = verify_fix,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> FastAPI:
    app = FastAPI(
        title="SilentSec API",
        version=_version(),
        description=(
            "Scan a public GitHub repository or an uploaded file for security and "
            "architecture debt. Scanners find known patterns; a clean result is "
            "evidence, not proof, that code is secure."
        ),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cors_origins),
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    stored: OrderedDict[str, _StoredScan] = OrderedDict()
    store_lock = threading.Lock()
    scan_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)

    def run(
        prepare: Callable[[Path], PreparedSource],
        source: SourceInfo,
        *,
        history_commits: int,
        timeout_seconds: int,
    ) -> ScanResponse:
        if not scan_slots.acquire(blocking=False):
            raise HTTPException(429, "The server is busy with other scans. Try again shortly.")
        workspace = Path(tempfile.mkdtemp(prefix="silentsec-api-"))
        try:
            try:
                prepared = prepare(workspace / "src")
            except SourceError as exc:
                raise HTTPException(400, str(exc)) from exc
            source = source.model_copy(update={"name": prepared.name})

            result = scan(prepared.root, timeout_seconds=timeout_seconds, enable_ai_triage=False)
            snippets = _snippets(prepared.root, result)

            timeline: TimelineReport | None = None
            note: str | None = None
            if not prepared.is_git:
                note = "History is only available for GitHub repositories."
            elif history_commits == 0:
                note = "History was not requested."
            else:
                try:
                    timeline = build_timeline(
                        prepared.root,
                        commits=history_commits,
                        database=workspace / "history.db",
                        timeout_seconds=timeout_seconds,
                        scan=scan,
                    )
                    # Do not reveal server paths to the caller.
                    timeline = timeline.model_copy(
                        update={"repo_path": prepared.name, "database": ""}
                    )
                except HistoryError as exc:
                    note = f"History is not available: {exc}"
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
            scan_slots.release()

        display = result.model_copy(update={"repo_path": prepared.name})
        scan_id = uuid.uuid4().hex
        created = now()
        response = ScanResponse(
            id=scan_id,
            created_at=created.isoformat(),
            source=source,
            summary=_summary(result),
            scanners=[
                ScannerInfo(
                    name=scanner.scanner,
                    status=scanner.status.value,
                    findings=len(scanner.findings),
                    duration_seconds=round(scanner.duration_seconds, 1),
                    errors=scanner.errors[:3],
                )
                for scanner in result.scanners
            ],
            issues=_issues(result, snippets),
            timeline=timeline,
            timeline_note=note,
            report_url=f"/api/scans/{scan_id}/report",
        )
        html = render_report(
            display,
            repo_name=prepared.name,
            generated_at=created,
            snippets=snippets,
            timeline=timeline,
            timeline_note=note,
        )
        with store_lock:
            stored[scan_id] = _StoredScan(response=response, html=html)
            while len(stored) > MAX_STORED_SCANS:
                stored.popitem(last=False)
        return response

    def lookup(scan_id: str) -> _StoredScan:
        with store_lock:
            item = stored.get(scan_id)
        if item is None:
            raise HTTPException(404, "Scan not found. Results are kept only for recent scans.")
        return item

    @app.get("/api/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        tools = {
            name: shutil.which(name) is not None
            for name in ("git", "semgrep", "bandit", "gitleaks")
        }
        return HealthResponse(status="ok", silentsec_version=_version(), tools=tools)

    @app.post("/api/scan/github", response_model=ScanResponse)
    def scan_github(request: GitHubScanRequest) -> ScanResponse:
        depth = max(1, request.history_commits)
        return run(
            lambda destination: clone(request.url, destination, depth=depth),
            SourceInfo(type="github", name=request.url, url=request.url.strip()),
            history_commits=request.history_commits,
            timeout_seconds=request.timeout_seconds,
        )

    @app.post("/api/scan/upload", response_model=ScanResponse)
    def scan_upload(file: UploadFile = File(...)) -> ScanResponse:  # noqa: B008
        data = file.file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                413, f"Uploads are limited to {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
            )
        file_name = file.filename or "upload"
        return run(
            lambda destination: extract_upload(file_name, data, destination),
            SourceInfo(type="upload", name=file_name),
            history_commits=0,
            timeout_seconds=180,
        )

    def run_verify(
        prepare: Callable[[Path], PreparedSource],
        source: SourceInfo,
        patch_text: str,
        *,
        targets: list[str] | None,
        timeout_seconds: int,
    ) -> VerifyResponse:
        if not patch_text.strip():
            raise HTTPException(400, "The patch is empty.")
        if not scan_slots.acquire(blocking=False):
            raise HTTPException(429, "The server is busy with other scans. Try again shortly.")
        workspace = Path(tempfile.mkdtemp(prefix="silentsec-api-"))
        try:
            try:
                prepared = prepare(workspace / "src")
            except SourceError as exc:
                raise HTTPException(400, str(exc)) from exc
            # Repository tests are never run: that would execute untrusted code.
            report = verify(
                prepared.root,
                patch_text,
                target_fingerprints=targets,
                run_tests=False,
                timeout_seconds=timeout_seconds,
                scan=scan,
            )
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
            scan_slots.release()

        return VerifyResponse(
            id=uuid.uuid4().hex,
            created_at=now().isoformat(),
            source=source.model_copy(update={"name": prepared.name}),
            **report.model_dump(
                include={
                    "verdict",
                    "reasons",
                    "patch_files",
                    "targets",
                    "resolved",
                    "remaining",
                    "new",
                    "score_before",
                    "score_after",
                    "raw_score_before",
                    "raw_score_after",
                    "checks_run",
                    "line_endings_normalized",
                    "limitations",
                }
            ),
        )

    @app.post("/api/verify/github", response_model=VerifyResponse)
    def verify_github(request: GitHubVerifyRequest) -> VerifyResponse:
        return run_verify(
            lambda destination: clone(request.url, destination, depth=1),
            SourceInfo(type="github", name=request.url, url=request.url.strip()),
            request.patch,
            targets=request.targets,
            timeout_seconds=request.timeout_seconds,
        )

    @app.post("/api/verify/upload", response_model=VerifyResponse)
    def verify_upload(
        file: UploadFile = File(...),  # noqa: B008
        patch: UploadFile = File(...),  # noqa: B008
    ) -> VerifyResponse:
        data = file.file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                413, f"Uploads are limited to {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
            )
        patch_bytes = patch.file.read(MAX_PATCH_BYTES + 1)
        if len(patch_bytes) > MAX_PATCH_BYTES:
            raise HTTPException(413, "The patch is larger than 1 MB.")
        try:
            patch_text = decode_patch(patch_bytes)
        except UnicodeDecodeError as exc:
            raise HTTPException(400, "The patch is not UTF-8 or UTF-16 text.") from exc
        file_name = file.filename or "upload"
        return run_verify(
            lambda destination: extract_upload(file_name, data, destination),
            SourceInfo(type="upload", name=file_name),
            patch_text,
            targets=None,
            timeout_seconds=180,
        )

    @app.get("/api/scans", response_model=list[ScanListItem])
    def list_scans() -> list[ScanListItem]:
        with store_lock:
            items = list(stored.values())
        return [
            ScanListItem(
                id=item.response.id,
                created_at=item.response.created_at,
                source=item.response.source,
                score=item.response.summary.score if item.response.summary else None,
                security_risk=item.response.summary.security_risk
                if item.response.summary
                else None,
                unique_issues=item.response.summary.unique_issues
                if item.response.summary
                else None,
            )
            for item in reversed(items)
        ]

    @app.get("/api/scans/{scan_id}", response_model=ScanResponse)
    def get_scan(scan_id: str) -> ScanResponse:
        return lookup(scan_id).response

    @app.get("/api/scans/{scan_id}/report", response_class=HTMLResponse)
    def get_report(scan_id: str) -> HTMLResponse:
        return HTMLResponse(lookup(scan_id).html)

    return app
