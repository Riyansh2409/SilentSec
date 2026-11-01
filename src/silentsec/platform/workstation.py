"""Original UI contract over authenticated, durable, tenant-owned platform jobs.

Local roots are operator registered and development only; no HTTP endpoint can
register a server path. Uploaded source/patches live outside the database.
"""

import base64
import json
import os
import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import func, select

from . import billing, jobs
from .access import identity, require_member, tenant_object
from .db import audit, digest, lock_org
from .models import (
    LedgerEntry,
    OperationQuota,
    OperationRequest,
    OperationResult,
    ScanJob,
    WorkstationRepository,
    now,
    uid,
)
from .routes import validated_key

router = APIRouter(prefix="/api/v1/workstation")
ROOT = Path(__file__).resolve().parents[3]
LOCAL = {"scan", "history", "verify", "fix", "report", "gate"}
STANDARD = {"scan", "report", "github", "upload"}


def adapter_modules():
    # This is application code from this checkout, never a scanned source path.
    import sys

    frontend = str(ROOT / "frontend")
    if frontend not in sys.path:
        sys.path.append(frontend)
    from local_api import adapter, server

    return adapter, server


def canonical(value):
    # Compare strings before probing the filesystem. No user-supplied path is
    # resolved until ownership of the exact registered root is established.
    # One matching pair of quotes is dropped, as Windows "Copy as path" adds them
    # (same rule as the standalone server's clean_path).
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    return os.path.normcase(os.path.normpath(text))


def quota_limits(limits):
    return {
        "verification": limits.get(
            "monthly_verifications", 20 if limits["plan"] == "free" else 200
        ),
        "pr_gate": limits.get("monthly_pr_checks", 30 if limits["plan"] == "free" else 300),
        "history_commit": limits.get("monthly_history_commits", limits["history_commits"] * 20),
        "ai_finding": limits["ai_findings"],
    }


def reserve_quotas(db, org, job, units, limits):
    start, end, _ = billing.month_window(org)
    for operation, amount in units.items():
        if not amount:
            continue
        maximum = quota_limits(limits)[operation]
        used = db.scalar(
            select(func.coalesce(func.sum(OperationQuota.units), 0)).where(
                OperationQuota.organization_id == org.id,
                OperationQuota.operation == operation,
                OperationQuota.period_start == start,
                OperationQuota.state.in_(["reserved", "committed"]),
            )
        )
        if amount + used > maximum:
            raise HTTPException(
                403,
                {
                    "code": "operation_quota_exhausted",
                    "feature": operation,
                    "message": f"The {operation} allowance is unavailable or exhausted for this plan.",
                },
            )
        row = OperationQuota(
            organization_id=org.id,
            job_id=job.id,
            operation=operation,
            units=amount,
            period_start=start,
            expires_at=min(end, now() + 86400),
        )
        db.add(row)
        db.flush()
        db.add(
            LedgerEntry(
                organization_id=org.id,
                job_id=job.id,
                operation=operation,
                kind="reserve",
                units=-amount,
                idempotency_key="operation:reserve:" + row.id,
            )
        )


def expire_quotas(db, org_id):
    pending = (
        db.scalars(
            select(ScanJob)
            .join(OperationQuota, OperationQuota.job_id == ScanJob.id)
            .where(
                ScanJob.organization_id == org_id,
                ScanJob.status == "queued",
                OperationQuota.state == "reserved",
                OperationQuota.expires_at <= now(),
            )
        )
        .unique()
        .all()
    )
    for job in pending:
        jobs.cancel(db, job, None, uid())
        job.error_code = "operation_reservation_expired"


def settle_quotas(db, job, state):
    rows = db.scalars(
        select(OperationQuota).where(
            OperationQuota.job_id == job.id,
            OperationQuota.organization_id == job.organization_id,
            OperationQuota.state == "reserved",
        )
    )
    for row in rows:
        row.state = state
        db.add(
            LedgerEntry(
                organization_id=job.organization_id,
                job_id=job.id,
                operation=row.operation,
                kind=state,
                units=row.units if state in {"released", "expired"} else 0,
                idempotency_key="operation:" + state + ":" + row.id,
            )
        )


def view(db, job):
    op = db.get(OperationRequest, job.id)
    return {
        "id": job.id,
        "operation": op.operation,
        "repo_path": op.arguments.get("repo_path", job.source_name),
        "status": job.status,
        "started_at": job.started_at or job.created_at,
        "finished_at": job.finished_at,
        "error": job.error_code,
        "cost": {"standard_scan": int(op.operation in STANDARD), **op.arguments.get("_units", {})},
    }


@router.get("/health")
def health(request: Request):
    adapter, _ = adapter_modules()
    import shutil

    from .worker import scanner_path

    backend = adapter.probe()
    backend["scanners"] = {
        name: bool(shutil.which(name, path=scanner_path())) for name in backend["scanners"]
    }
    with request.app.state.factory.begin() as db:
        principal = identity(request, db, scope="scans:read")
        require_member(principal)
        limits = billing.entitlements(db, principal.org_id)
        roots = db.scalars(
            select(WorkstationRepository).where(
                WorkstationRepository.organization_id == principal.org_id,
                WorkstationRepository.enabled.is_(True),
            )
        ).all()
        if not request.app.state.settings.workstation_enabled:
            roots = []
            backend["capabilities"].update(dict.fromkeys(LOCAL, False))
        org = lock_org(db, principal.org_id)
        usage = billing.usage(db, org)
        if principal.key_id and "billing:read" not in principal.scopes:
            usage = None
        quota = []
        start, _, _ = billing.month_window(org)
        for operation, maximum in quota_limits(limits).items():
            used = db.scalar(
                select(func.coalesce(func.sum(OperationQuota.units), 0)).where(
                    OperationQuota.organization_id == org.id,
                    OperationQuota.operation == operation,
                    OperationQuota.period_start == start,
                    OperationQuota.state.in_(["reserved", "committed"]),
                )
            )
            quota.append({"operation": operation, "limit": maximum, "used": used})
        return {
            "backend_ready": True,
            "backend": backend,
            "api_version": 1,
            "platform": {
                "usage": usage,
                "entitlements": limits,
                "quotas": quota,
                "repositories": [{"path": r.root_path, "name": r.name} for r in roots],
            },
        }


def submit(request, body, key):
    validated_key(key)
    if not isinstance(body, dict) or not isinstance(body.get("args"), dict):
        raise HTTPException(400, "Invalid operation request.")
    operation, arguments = body.get("operation"), dict(body["args"])
    adapter, server = adapter_modules()
    settings = request.app.state.settings
    input_path = None
    try:
        with request.app.state.factory.begin() as db:
            principal = identity(request, db, mutation=True, scope="scans:write")
            require_member(principal, write=True)
            org = lock_org(db, principal.org_id)
            if org.status != "active":
                raise HTTPException(403, "Organization unavailable.")
            limits = billing.entitlements(db, org.id)
            repository = None
            if operation in LOCAL:
                if not settings.workstation_enabled or settings.environment == "production":
                    raise HTTPException(
                        403,
                        "Local-folder operations require an operator-enabled development workstation.",
                    )
                candidates = db.scalars(
                    select(WorkstationRepository).where(
                        WorkstationRepository.organization_id == org.id,
                        WorkstationRepository.enabled.is_(True),
                    )
                )
                repository = next(
                    (
                        r
                        for r in candidates
                        if canonical(r.root_path) == canonical(arguments.get("repo_path", ""))
                    ),
                    None,
                )
                if not repository:
                    raise HTTPException(
                        403,
                        "This repository is not registered for your organization. Register it locally using the platform command.",
                    )
                if Path(repository.root_path).resolve() != Path(repository.root_path):
                    raise HTTPException(
                        403,
                        "Registered repository location changed; register its resolved location again.",
                    )
                arguments["repo_path"] = repository.root_path
            if arguments.get("run_tests"):
                raise HTTPException(
                    400,
                    "Repository code and tests cannot run through the web interface. CLI test verification remains available to trusted local users.",
                )
            try:
                operation, arguments = server.validate_request(
                    {"operation": operation, "args": arguments}
                )
            except (server.InputError, TypeError, ValueError) as exc:
                raise HTTPException(
                    400, "Invalid operation settings. No credit was charged."
                ) from exc
            arguments["timeout"] = min(arguments.get("timeout", 180), limits["scan_timeout"])
            commits = (
                arguments.get("commits", 10)
                if operation == "history" or arguments.get("include_history")
                else arguments.get("commits", 0)
                if operation == "github"
                else 0
            )
            if commits > limits["history_commits"]:
                raise HTTPException(
                    403,
                    {
                        "code": "plan_required",
                        "feature": "history",
                        "message": "Requested history exceeds this plan’s commit limit.",
                    },
                )
            ai = operation == "fix" or arguments.get("ai_triage", False)
            if ai and not adapter.provider_configuration()["ai_configured"]:
                raise HTTPException(
                    409, "Configure an AI provider locally before requesting AI operations."
                )
            units = {
                "history_commit": commits,
                "verification": int(
                    operation in {"verify", "verify_github", "verify_upload", "fix"}
                ),
                "pr_gate": int(operation == "gate"),
                "ai_finding": arguments.get("max_ai_findings", 20) if ai else 0,
            }
            fingerprint = digest({"operation": operation, "args": arguments})
            previous = db.scalar(
                select(ScanJob).where(
                    ScanJob.organization_id == org.id, ScanJob.idempotency_key == key
                )
            )
            if previous:
                if previous.request_hash != fingerprint:
                    raise HTTPException(409, "Idempotency key already used for another request.")
                return view(db, previous)
            # Validate ZIP contents before reserving or persisting source.
            if operation in {"upload", "verify_upload"}:
                from silentsec.api.sources import SourceError, extract_upload

                try:
                    with tempfile.TemporaryDirectory(prefix="ssec-validate-") as temp:
                        extract_upload(
                            arguments["filename"],
                            base64.b64decode(arguments["content"], validate=True),
                            Path(temp) / "source",
                        )
                except SourceError as exc:
                    raise HTTPException(
                        400, "Unsafe or invalid upload. No credit was charged."
                    ) from exc
            # Fix report IDs must belong to the same organization AND checkout.
            for fix_id in arguments.get("fix_job_ids", []):
                fix_job = tenant_object(db, ScanJob, fix_id, org.id)
                fix_request = db.get(OperationRequest, fix_job.id)
                fix_result = db.get(OperationResult, fix_job.id)
                if (
                    not fix_request
                    or fix_request.operation not in {"fix", "verify"}
                    or fix_request.repository_id != (repository.id if repository else None)
                    or not fix_result
                    or fix_result.expires_at <= now()
                ):
                    raise HTTPException(400, "Fix report is not available for this repository.")
            name = (
                repository.name
                if repository
                else arguments.get("url", arguments.get("filename", "source"))
            )
            job = jobs.submit(
                db,
                org,
                principal.user_id or org.owner_id,
                "workstation",
                "private",
                name,
                key,
                fingerprint,
                request.state.request_id,
                standard=operation in STANDARD,
            )
            db.flush()
            reserve_quotas(db, org, job, units, limits)
            private = {k: arguments.pop(k) for k in ("patch", "content") if k in arguments}
            input_ref = None
            if private:
                input_ref = uid()
                inbox = settings.data_dir.resolve() / "inbox"
                inbox.mkdir(parents=True, exist_ok=True, mode=0o700)
                input_path = inbox / (input_ref + ".payload")
                input_path.write_text(json.dumps(private), encoding="utf-8")
                input_path.chmod(0o600)
            arguments["_units"] = units
            db.add(
                OperationRequest(
                    job_id=job.id,
                    organization_id=org.id,
                    operation=operation,
                    arguments=arguments,
                    repository_id=repository.id if repository else None,
                    input_ref=input_ref,
                )
            )
            db.flush()
            output = view(db, job)
        jobs.notify(settings, job.id)
        return output
    except BaseException:
        if input_path:
            input_path.unlink(missing_ok=True)
        raise


@router.post("/jobs", status_code=202)
async def create_job(request: Request, idempotency_key: str = Header("")):
    return submit(request, await request.json(), idempotency_key)


@router.post("/upload", status_code=202)
async def upload_job(
    request: Request,
    file: Annotated[UploadFile, File()],
    metadata: str = Form(),
    idempotency_key: str = Header(""),
):
    content = await file.read(20 * 1024 * 1024 + 1)
    await file.close()
    if not 0 < len(content) <= 20 * 1024 * 1024 or len(metadata) > 1_100_000:
        raise HTTPException(413, "Upload exceeds its limit.")
    try:
        body = json.loads(metadata)
        if body.get("operation") not in {"upload", "verify_upload"}:
            raise ValueError
        body["args"].update(filename=file.filename, content=base64.b64encode(content).decode())
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(400, "Invalid upload metadata.") from exc
    return submit(request, body, idempotency_key)


@router.get("/jobs")
def list_jobs(request: Request):
    with request.app.state.factory() as db:
        principal = identity(request, db, scope="scans:read")
        require_member(principal)
        rows = db.scalars(
            select(ScanJob)
            .join(OperationRequest, OperationRequest.job_id == ScanJob.id)
            .where(ScanJob.organization_id == principal.org_id)
            .order_by(ScanJob.created_at.desc())
            .limit(100)
        )
        return {"jobs": [view(db, j) for j in rows]}


@router.get("/jobs/{job_id}")
def get_job(request: Request, job_id: str):
    with request.app.state.factory() as db:
        principal = identity(request, db, scope="scans:read")
        require_member(principal)
        job = tenant_object(db, ScanJob, job_id, principal.org_id)
        if not db.get(OperationRequest, job_id):
            raise HTTPException(404, "Operation not found.")
        return view(db, job)


@router.get("/jobs/{job_id}/{artifact}")
def result(request: Request, job_id: str, artifact: str):
    with request.app.state.factory.begin() as db:
        principal = identity(
            request, db, scope="reports:read" if artifact in {"report", "sarif"} else "scans:read"
        )
        require_member(principal)
        tenant_object(db, ScanJob, job_id, principal.org_id)
        row = db.scalar(
            select(OperationResult).where(
                OperationResult.job_id == job_id,
                OperationResult.organization_id == principal.org_id,
                OperationResult.expires_at > now(),
            )
        )
        if not row:
            raise HTTPException(404, "Retained result unavailable.")
        if artifact == "result":
            return row.payload
        if artifact not in {"report", "sarif"} or not getattr(row, artifact):
            raise HTTPException(404, "Export unavailable for this operation.")
        audit(
            db, principal.user_id, "scan.export", job_id, request.state.request_id, principal.org_id
        )
        if artifact == "sarif":
            return JSONResponse(
                row.sarif, headers={"Content-Disposition": 'attachment; filename="silentsec.sarif"'}
            )
        return HTMLResponse(
            row.report,
            headers={
                "Content-Disposition": 'attachment; filename="silentsec-report.html"',
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            },
        )


@router.post("/context")
async def context(request: Request):
    body = await request.json()
    with request.app.state.factory() as db:
        principal = identity(request, db, mutation=True, scope="scans:read")
        require_member(principal)
        tenant_object(db, ScanJob, body.get("job_id"), principal.org_id)
        return {
            "context": "Source excerpts are withheld in the account workspace. Review the recorded file and line in your own checkout. Possible secrets are never displayed."
        }
