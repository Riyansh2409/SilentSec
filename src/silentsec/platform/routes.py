"""Tenant API. Every object lookup includes its organization before serialization."""

import hashlib
import secrets
import tempfile
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from silentsec.api.sources import (
    MAX_UPLOAD_BYTES,
    SourceError,
    extract_upload,
    parse_github_url,
    safe_file_name,
)

from . import billing, jobs
from .access import identity, require_member, tenant_object
from .db import audit, digest, idem_start, lock_org
from .models import (
    ApiKey,
    AuditEvent,
    LedgerEntry,
    Membership,
    ScanJob,
    ScanResult,
    Subscription,
    User,
    now,
    uid,
)

router = APIRouter(prefix="/api/v1")


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GithubInput(Input):
    url: str = Field(max_length=500)


def validated_key(key):
    import re

    if not re.fullmatch(r"[A-Za-z0-9_-]{8,100}", key or ""):
        raise HTTPException(400, "Provide a unique Idempotency-Key (8–100 safe characters).")
    return key


def prepare_submission(request, db, key):
    principal = identity(request, db, mutation=True, scope="scans:write")
    require_member(principal, write=True)
    org = lock_org(db, principal.org_id)
    if org.status != "active":
        raise HTTPException(403, "Organization unavailable.")
    return principal, org


@router.get("/billing/entitlements")
def get_entitlements(request: Request):
    with request.app.state.factory() as db:
        principal = identity(request, db, scope="billing:read")
        require_member(principal)
        limits = billing.entitlements(db, principal.org_id)
        return {
            **limits,
            "integrations": {
                "public_github": True,
                "zip": True,
                "private_repositories": False,
                "gitlab": False,
                "payments": False,
                "cloud_ai": False,
            },
            "notice": "Paid integrations require separate provider configuration; standard scans do not use AI quota.",
        }


@router.get("/billing/usage")
def get_usage(request: Request, offset: int = Query(0, ge=0), limit: int = Query(30, ge=1, le=100)):
    with request.app.state.factory.begin() as db:
        principal = identity(request, db, scope="billing:read")
        require_member(principal)
        org = lock_org(db, principal.org_id)
        result = billing.usage(db, org)
        entries = db.scalars(
            select(LedgerEntry)
            .where(LedgerEntry.organization_id == org.id)
            .order_by(LedgerEntry.created_at.desc(), LedgerEntry.id)
            .offset(offset)
            .limit(limit)
        ).all()
        result["activity"] = [
            {
                "id": e.id,
                "kind": e.kind,
                "operation": e.operation,
                "units": e.units,
                "job_id": e.job_id,
                "created_at": e.created_at,
            }
            for e in entries
        ]
        subscription = db.scalar(select(Subscription).where(Subscription.organization_id == org.id))
        result["subscription"] = {
            "status": subscription.status,
            "cancel_at_period_end": subscription.cancel_at_period_end,
            "period_end": subscription.period_end,
        }
        return result


@router.post("/scan/github", status_code=202)
def scan_github(body: GithubInput, request: Request, idempotency_key: str = Header("")):
    validated_key(idempotency_key)
    try:
        owner, repo = parse_github_url(body.url)
    except SourceError as exc:
        raise HTTPException(400, str(exc)) from exc
    canonical = f"https://github.com/{owner}/{repo}"
    with request.app.state.factory.begin() as db:
        principal, org = prepare_submission(request, db, idempotency_key)
        job = jobs.submit(
            db,
            org,
            principal.user_id or org.owner_id,
            "github",
            canonical,
            f"{owner}/{repo}",
            idempotency_key,
            digest({"kind": "github", "url": canonical}),
            request.state.request_id,
        )
        db.flush()
        response = jobs.job_view(job)
    jobs.notify(request.app.state.settings, response["id"])
    return response


@router.post("/scan/upload", status_code=202)
async def scan_upload(
    request: Request, file: Annotated[UploadFile, File()], idempotency_key: str = Header("")
):
    validated_key(idempotency_key)
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if not data or len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            413, "Upload must be nonempty and at most 20 MB. No credit was charged."
        )
    name = safe_file_name(file.filename or "upload.zip")
    try:
        with tempfile.TemporaryDirectory(prefix="ssec-validate-") as temp:
            extract_upload(name, data, Path(temp) / "source")
    except SourceError as exc:
        raise HTTPException(400, str(exc)) from exc
    saved = None
    try:
        with request.app.state.factory.begin() as db:
            principal, org = prepare_submission(request, db, idempotency_key)
            previous = db.scalar(
                select(ScanJob).where(
                    ScanJob.organization_id == org.id, ScanJob.idempotency_key == idempotency_key
                )
            )
            fingerprint = digest({"kind": "upload", "name": name, "content": digest(data)})
            if previous:
                if previous.request_hash != fingerprint:
                    raise HTTPException(409, "Idempotency key was used with different source.")
                return jobs.job_view(previous)
            inbox = request.app.state.settings.data_dir.resolve() / "inbox"
            inbox.mkdir(parents=True, exist_ok=True, mode=0o700)
            saved = inbox / (uid() + ".payload")
            saved.write_bytes(data)
            saved.chmod(0o600)
            job = jobs.submit(
                db,
                org,
                principal.user_id or org.owner_id,
                "upload",
                str(saved),
                name,
                idempotency_key,
                fingerprint,
                request.state.request_id,
            )
            db.flush()
            response = jobs.job_view(job)
    except Exception:
        if saved:
            saved.unlink(missing_ok=True)
        raise
    jobs.notify(request.app.state.settings, response["id"])
    return response


@router.get("/scans")
def scans(request: Request, offset: int = Query(0, ge=0), limit: int = Query(30, ge=1, le=100)):
    with request.app.state.factory() as db:
        principal = identity(request, db, scope="scans:read")
        require_member(principal)
        rows = db.scalars(
            select(ScanJob)
            .where(ScanJob.organization_id == principal.org_id)
            .order_by(ScanJob.created_at.desc(), ScanJob.id)
            .offset(offset)
            .limit(limit)
        ).all()
        return {"items": [jobs.job_view(row) for row in rows], "offset": offset, "limit": limit}


def authorized_result(db, request, job_id, scope="scans:read"):
    principal = identity(request, db, scope=scope)
    require_member(principal)
    job = tenant_object(db, ScanJob, job_id, principal.org_id)
    result = db.scalar(
        select(ScanResult).where(
            ScanResult.job_id == job.id,
            ScanResult.organization_id == principal.org_id,
            ScanResult.expires_at > now(),
        )
    )
    if not result:
        raise HTTPException(404, "Result not ready or retention has expired.")
    return principal, job, result


@router.get("/scans/{job_id}")
def scan(request: Request, job_id: str):
    with request.app.state.factory() as db:
        principal = identity(request, db, scope="scans:read")
        require_member(principal)
        job = tenant_object(db, ScanJob, job_id, principal.org_id)
        result = db.scalar(
            select(ScanResult).where(
                ScanResult.job_id == job.id,
                ScanResult.organization_id == principal.org_id,
                ScanResult.expires_at > now(),
            )
        )
        return {
            **jobs.job_view(job),
            "summary": result.summary if result else None,
            "result_available": result is not None,
        }


@router.get("/scans/{job_id}/findings")
def findings(
    request: Request,
    job_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    severity: str | None = None,
    q: str = Query("", max_length=100),
):
    with request.app.state.factory() as db:
        _, _, result = authorized_result(db, request, job_id)
        items = [
            f
            for f in result.findings
            if (not severity or f["severity"] == severity)
            and (not q or q.casefold() in (f["title"] + f["file_path"]).casefold())
        ]
        return {
            "items": items[offset : offset + limit],
            "total": len(items),
            "offset": offset,
            "limit": limit,
        }


@router.get("/scans/{job_id}/report", response_class=HTMLResponse)
def report(request: Request, job_id: str):
    with request.app.state.factory.begin() as db:
        principal, _, result = authorized_result(db, request, job_id, "reports:read")
        audit(
            db,
            principal.user_id,
            "report.export",
            job_id,
            request.state.request_id,
            principal.org_id,
        )
        return HTMLResponse(
            result.report,
            headers={
                "Content-Disposition": 'attachment; filename="silentsec-report.html"',
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            },
        )


@router.get("/scans/{job_id}/architecture-graph")
def architecture_graph(
    request: Request,
    job_id: str,
    module: str | None = Query(None, max_length=100),
    compare: str | None = Query(None, max_length=36),
):
    with request.app.state.factory() as db:
        principal, job, result = authorized_result(db, request, job_id)
        output = dict(result.graph)
        limits = billing.entitlements(db, principal.org_id)
        if not limits["graph_detail"]:
            output["nodes"] = [
                n for n in output["nodes"] if n["kind"] in {"module", "repository", "package"}
            ]
            valid = {n["id"] for n in output["nodes"]}
            output["edges"] = [
                e for e in output["edges"] if e["source"] in valid and e["target"] in valid
            ]
            output["level"] = "module"
        if module:
            ids = {module} | {e["target"] for e in output["edges"] if e["source"] == module}
            output["nodes"] = [n for n in output["nodes"] if n["id"] in ids]
            output["edges"] = [
                e for e in output["edges"] if e["source"] in ids and e["target"] in ids
            ]
        if compare:
            if not limits["graph_detail"]:
                raise HTTPException(403, {"code": "plan_required", "feature": "graph_comparison"})
            other = tenant_object(db, ScanJob, compare, principal.org_id)
            if other.source_kind != job.source_kind or other.source_name != job.source_name:
                raise HTTPException(400, "Compare scans of the same source.")
            baseline = db.scalar(
                select(ScanResult).where(
                    ScanResult.job_id == other.id,
                    ScanResult.organization_id == principal.org_id,
                    ScanResult.expires_at > now(),
                )
            )
            if not baseline:
                raise HTTPException(404, "Comparison result unavailable.")
            before, after = (
                {n["id"] for n in baseline.graph["nodes"]},
                {n["id"] for n in result.graph["nodes"]},
            )
            output["comparison"] = {
                "baseline": compare,
                "nodes_added": sorted(after - before),
                "nodes_removed": sorted(before - after),
            }
        return output


@router.get("/scans/{job_id}/patterns")
def scan_patterns(request: Request, job_id: str):
    with request.app.state.factory() as db:
        _, _, result = authorized_result(db, request, job_id)
        return result.patterns


@router.post("/scans/{job_id}/cancel")
def cancel(request: Request, job_id: str, idempotency_key: str = Header("")):
    with request.app.state.factory.begin() as db:
        principal = identity(request, db, mutation=True, scope="scans:write")
        require_member(principal, write=True)
        lock_org(db, principal.org_id)
        job = tenant_object(db, ScanJob, job_id, principal.org_id)
        record, replay = idem_start(
            db, principal.org_id + ":cancel", idempotency_key, {"job": job_id}
        )
        if replay:
            return record.response
        jobs.cancel(db, job, principal.user_id, request.state.request_id)
        record.response = jobs.job_view(job)
        return record.response


@router.get("/team")
def team(request: Request):
    with request.app.state.factory() as db:
        principal = identity(request, db)
        require_member(principal, manage=True)
        rows = db.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.organization_id == principal.org_id)
        ).all()
        return {"items": [{"user_id": u.id, "email": u.email, "role": m.role} for m, u in rows]}


class MemberInput(Input):
    email: str = Field(max_length=254)
    role: Literal["admin", "member", "viewer"]
    reason: str = Field(min_length=5, max_length=500)


@router.post("/team")
def set_member(request: Request, body: MemberInput, idempotency_key: str = Header("")):
    with request.app.state.factory.begin() as db:
        principal = identity(request, db, mutation=True)
        require_member(principal, manage=True)
        lock_org(db, principal.org_id)
        if not billing.entitlements(db, principal.org_id)["team"]:
            raise HTTPException(403, {"code": "plan_required", "feature": "organization_teams"})
        record, replay = idem_start(
            db, principal.org_id + ":membership", idempotency_key, body.model_dump()
        )
        if replay:
            return record.response
        user = db.scalar(
            select(User).where(User.email == body.email.strip().casefold(), User.status == "active")
        )
        if not user:
            raise HTTPException(404, "User must sign in before joining a workspace.")
        member = db.scalar(
            select(Membership).where(
                Membership.organization_id == principal.org_id, Membership.user_id == user.id
            )
        )
        if member and member.role == "owner":
            raise HTTPException(403, "Owner transfer requires a separate verified workflow.")
        if body.role == "admin" and principal.role != "owner":
            raise HTTPException(403, "Only an owner may appoint administrators.")
        if member:
            member.role = body.role
        else:
            db.add(Membership(organization_id=principal.org_id, user_id=user.id, role=body.role))
        audit(
            db,
            principal.user_id,
            "membership.change",
            user.id,
            request.state.request_id,
            principal.org_id,
            role=body.role,
            reason=body.reason,
        )
        record.response = {"ok": True}
        return record.response


@router.get("/audit")
def audit_events(
    request: Request, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100)
):
    with request.app.state.factory() as db:
        principal = identity(request, db)
        require_member(principal, manage=True)
        rows = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.organization_id == principal.org_id)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id)
            .offset(offset)
            .limit(limit)
        ).all()
        return {
            "items": [
                {
                    "id": r.id,
                    "action": r.action,
                    "target": r.target,
                    "actor_id": r.actor_id,
                    "created_at": r.created_at,
                    "metadata": r.safe_metadata,
                }
                for r in rows
            ]
        }


class KeyInput(Input):
    key: str = Field(pattern=r"^ssec_[a-f0-9]{8}_[a-f0-9]{64}$")
    scopes: list[Literal["scans:read", "scans:write", "reports:read", "billing:read"]] = Field(
        min_length=1, max_length=4
    )
    expires_in_days: int = Field(default=30, ge=1, le=90)
    reason: str = Field(min_length=5, max_length=500)


@router.get("/api-keys")
def list_keys(request: Request):
    with request.app.state.factory() as db:
        principal = identity(request, db)
        require_member(principal, manage=True)
        rows = db.scalars(select(ApiKey).where(ApiKey.organization_id == principal.org_id)).all()
        return {
            "items": [
                {
                    "id": k.id,
                    "prefix": k.prefix,
                    "scopes": k.scopes,
                    "expires_at": k.expires_at,
                    "revoked_at": k.revoked_at,
                }
                for k in rows
            ]
        }


@router.post("/api-keys", status_code=201)
def create_key(request: Request, body: KeyInput, idempotency_key: str = Header("")):
    with request.app.state.factory.begin() as db:
        principal = identity(request, db, mutation=True)
        require_member(principal, manage=True)
        lock_org(db, principal.org_id)
        # Keys are generated on the caller's device. The server never returns
        # the full key, even once, and only persists a salted slow hash.
        record, replay = idem_start(
            db,
            principal.org_id + ":keys",
            idempotency_key,
            {
                "hash": digest(body.key.encode()),
                "scopes": body.scopes,
                "days": body.expires_in_days,
            },
        )
        if replay:
            return record.response
        active_count = db.scalar(
            select(func.count(ApiKey.id)).where(
                ApiKey.organization_id == principal.org_id,
                ApiKey.revoked_at.is_(None),
                ApiKey.expires_at > now(),
            )
        )
        if active_count >= 20:
            raise HTTPException(429, "At most 20 active API keys are allowed per organization.")
        salt = secrets.token_hex(32)
        key = ApiKey(
            organization_id=principal.org_id,
            prefix=body.key[:13],
            salt=salt,
            key_hash=hashlib.scrypt(
                body.key.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1
            ).hex(),
            scopes=body.scopes,
            expires_at=now() + body.expires_in_days * 86400,
        )
        db.add(key)
        db.flush()
        audit(
            db,
            principal.user_id,
            "api_key.create",
            key.id,
            request.state.request_id,
            principal.org_id,
            reason=body.reason,
        )
        record.response = {
            "id": key.id,
            "prefix": key.prefix,
            "scopes": key.scopes,
            "expires_at": key.expires_at,
        }
        return record.response


class ReasonInput(Input):
    reason: str = Field(min_length=5, max_length=500)


@router.post("/api-keys/{key_id}/revoke")
def revoke_key(request: Request, key_id: str, body: ReasonInput, idempotency_key: str = Header("")):
    with request.app.state.factory.begin() as db:
        principal = identity(request, db, mutation=True)
        require_member(principal, manage=True)
        lock_org(db, principal.org_id)
        row, replay = idem_start(
            db,
            principal.org_id + ":revoke-key",
            idempotency_key,
            {"key": key_id, "reason": body.reason},
        )
        if replay:
            return row.response
        key = tenant_object(db, ApiKey, key_id, principal.org_id)
        key.revoked_at = now()
        audit(
            db,
            principal.user_id,
            "api_key.revoke",
            key.id,
            request.state.request_id,
            principal.org_id,
            reason=body.reason,
        )
        row.response = {"ok": True}
        return row.response
