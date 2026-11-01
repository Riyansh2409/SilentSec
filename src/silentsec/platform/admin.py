"""Explicit internal administration: safe projections, MFA, reasons and audit."""

from typing import Literal

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, update

from . import billing, jobs, worker
from .access import identity, require_admin
from .db import audit, digest, idem_start, lock_org
from .models import (
    ApiKey,
    AuditEvent,
    Membership,
    Organization,
    PatternPack,
    Plan,
    Repository,
    ScanJob,
    ScanResult,
    Session,
    Subscription,
    User,
    WebhookEvent,
    now,
)

router = APIRouter(prefix="/api/v1/admin")


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_type: Literal["organization", "user", "job", "api_key"]
    target_id: str = Field(min_length=36, max_length=36)
    action: Literal[
        "suspend", "reactivate", "plan", "credits", "retention", "cancel", "retry", "revoke"
    ]
    reason: str = Field(min_length=5, max_length=500)
    amount: int | None = Field(None, ge=-10000, le=10000)
    plan: Literal["free", "pro", "enterprise"] | None = None
    retention_days: int | None = Field(None, ge=1, le=3650)


@router.get("/{entity}")
def listing(
    request: Request,
    entity: str,
    q: str = Query("", max_length=100),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
):
    with request.app.state.factory.begin() as db:
        principal = identity(request, db)
        require_admin(principal, request.app.state.settings)
        tables = {
            "users": (User, ["id", "email", "name", "status", "created_at"]),
            "organizations": (
                Organization,
                ["id", "name", "slug", "status", "owner_id", "retention_days", "billing_timezone"],
            ),
            "memberships": (Membership, ["id", "organization_id", "user_id", "role"]),
            "subscriptions": (
                Subscription,
                [
                    "id",
                    "organization_id",
                    "plan_key",
                    "status",
                    "period_end",
                    "cancel_at_period_end",
                ],
            ),
            "plans": (Plan, ["key", "name", "version", "entitlements"]),
            "jobs": (
                ScanJob,
                [
                    "id",
                    "organization_id",
                    "status",
                    "created_at",
                    "attempt_count",
                    "error_code",
                    "execution_started",
                ],
            ),
            "audit-events": (
                AuditEvent,
                [
                    "id",
                    "organization_id",
                    "actor_id",
                    "action",
                    "target",
                    "created_at",
                    "request_id",
                    "safe_metadata",
                ],
            ),
            "api-keys": (
                ApiKey,
                ["id", "organization_id", "prefix", "scopes", "expires_at", "revoked_at"],
            ),
            "repositories": (Repository, ["id", "organization_id", "provider", "visibility"]),
            "webhooks": (WebhookEvent, ["provider_event_id", "received_at", "status"]),
        }
        if entity == "health":
            import shutil

            import redis

            redis_ready = False
            try:
                if request.app.state.settings.redis_url.get_secret_value():
                    with redis.Redis.from_url(
                        request.app.state.settings.redis_url.get_secret_value(), socket_timeout=1
                    ) as queue:
                        redis_ready = bool(queue.ping())
            except redis.RedisError:
                pass
            audit(db, principal.user_id, "admin.read", "health", request.state.request_id)
            return {
                "database": "connected",
                "redis": redis_ready,
                "auto_worker_configured": request.app.state.settings.auto_worker,
                "local_worker_alive": bool(
                    getattr(request.app.state, "worker_thread", None)
                    and request.app.state.worker_thread.is_alive()
                ),
                "scanners": {
                    name: bool(shutil.which(name, path=worker.scanner_path()))
                    for name in ("semgrep", "bandit", "gitleaks")
                },
                "scanner_health_scope": "Executable discovery on this host, using the worker PATH. Real scans verify execution; remote-worker health requires separate deployment monitoring.",
                "running_jobs": db.scalar(
                    select(func.count(ScanJob.id)).where(ScanJob.status == "running")
                ),
            }
        if entity not in tables:
            raise HTTPException(404, "Unknown administrator resource.")
        model, columns = tables[entity]
        statement = select(model)
        if q:
            from sqlalchemy import or_

            fields = [
                getattr(model, name)
                for name in columns
                if name in {"id", "email", "name", "organization_id", "action", "prefix"}
            ]
            statement = statement.where(
                or_(
                    *(
                        field.ilike(
                            "%" + q.replace("%", "\\%").replace("_", "\\_") + "%", escape="\\"
                        )
                        for field in fields
                    )
                )
            )
        rows = db.scalars(
            statement.order_by(getattr(model, columns[0])).offset(offset).limit(limit)
        ).all()
        audit(db, principal.user_id, "admin.read", entity, request.state.request_id)
        return {
            "items": [{name: getattr(row, name) for name in columns} for row in rows],
            "offset": offset,
            "limit": limit,
        }


@router.post("/actions")
def action(request: Request, body: Action, idempotency_key: str = Header("")):
    with request.app.state.factory.begin() as db:
        principal = identity(request, db, mutation=True)
        require_admin(principal, request.app.state.settings, elevated=True)
        # Serialize the actor's idempotency stream before touching a target.
        db.execute(update(User).where(User.id == principal.user_id).values(updated_at=now()))
        record, replay = idem_start(
            db, "admin:" + principal.user_id, idempotency_key, body.model_dump()
        )
        if replay:
            return record.response
        org_id = None
        if body.target_type == "organization":
            org = lock_org(db, body.target_id)
            org_id = org.id
            if body.action in {"suspend", "reactivate"}:
                org.status = "suspended" if body.action == "suspend" else "active"
                if org.status == "suspended":
                    for job in db.scalars(
                        select(ScanJob).where(
                            ScanJob.organization_id == org.id,
                            ScanJob.status.in_(["queued", "running"]),
                        )
                    ):
                        jobs.cancel(db, job, principal.user_id, request.state.request_id)
            elif body.action == "plan" and body.plan:
                subscription = db.scalar(
                    select(Subscription).where(Subscription.organization_id == org.id)
                )
                subscription.plan_key, subscription.status = body.plan, "active"
                org.retention_days = min(
                    org.retention_days, billing.DEFAULT_PLANS[body.plan]["retention_days"]
                )
                billing.ensure_month(db, org)
            elif body.action == "credits" and body.amount:
                billing.adjust(
                    db,
                    org,
                    body.amount,
                    idempotency_key,
                    principal.user_id,
                    body.reason,
                    request.state.request_id,
                )
            elif body.action == "retention" and body.retention_days:
                maximum = billing.entitlements(db, org.id)["retention_days"]
                if body.retention_days > maximum:
                    raise HTTPException(
                        400, "Retention exceeds the organization's current entitlement."
                    )
                org.retention_days = body.retention_days
                deadline = now() + body.retention_days * 86400
                db.execute(
                    update(ScanResult)
                    .where(ScanResult.organization_id == org.id, ScanResult.expires_at > deadline)
                    .values(expires_at=deadline)
                )
            else:
                raise HTTPException(400, "Unsupported organization action or missing value.")
        elif body.target_type == "user" and body.action in {"suspend", "reactivate"}:
            user = db.get(User, body.target_id)
            if not user:
                raise HTTPException(404, "User not found.")
            if user.id == principal.user_id:
                raise HTTPException(400, "Self-suspension is not supported.")
            user.status = "suspended" if body.action == "suspend" else "active"
            if body.action == "suspend":
                db.execute(
                    update(Session).where(Session.user_id == user.id).values(revoked_at=now())
                )
        elif body.target_type == "api_key" and body.action == "revoke":
            key = db.get(ApiKey, body.target_id)
            if not key:
                raise HTTPException(404, "Key not found.")
            org_id = key.organization_id
            lock_org(db, org_id)
            key.revoked_at = now()
        elif body.target_type == "job" and body.action in {"cancel", "retry"}:
            job = db.get(ScanJob, body.target_id)
            if not job:
                raise HTTPException(404, "Job not found.")
            org = lock_org(db, job.organization_id)
            org_id = org.id
            if body.action == "cancel":
                jobs.cancel(db, job, principal.user_id, request.state.request_id)
            else:
                if job.status not in {"failed", "cancelled"} or job.source_kind != "github":
                    raise HTTPException(
                        409,
                        "Only stopped GitHub jobs can be retried; uploads must be attached again.",
                    )
                if org.status != "active":
                    raise HTTPException(409, "Reactivate the organization before retrying.")
                retried = jobs.submit(
                    db,
                    org,
                    job.requester_id,
                    job.source_kind,
                    job.source_reference,
                    job.source_name,
                    "retry-" + digest(idempotency_key.encode()),
                    job.request_hash,
                    request.state.request_id,
                )
                db.flush()
                record.response = {
                    "ok": True,
                    "job_id": retried.id,
                    "cost": "one standard scan unit if execution starts",
                }
        else:
            raise HTTPException(400, "Unsupported administration action.")
        audit(
            db,
            principal.user_id,
            "admin." + body.action,
            body.target_id,
            request.state.request_id,
            org_id,
            reason=body.reason,
            plan=body.plan or "",
            amount=body.amount or 0,
        )
        if not record.response:
            record.response = {"ok": True}
        return record.response


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    minimum_severity: Literal["critical", "high", "medium", "low"] = "high"
    reason: str = Field(min_length=5, max_length=500)


@router.post("/organizations/{org_id}/policy")
def policy(request: Request, org_id: str, body: Policy, idempotency_key: str = Header("")):
    with request.app.state.factory.begin() as db:
        principal = identity(request, db, mutation=True)
        require_admin(principal, request.app.state.settings, elevated=True)
        org = lock_org(db, org_id)
        if not billing.entitlements(db, org.id)["custom_policies"]:
            raise HTTPException(403, "Enterprise policy entitlement required.")
        record, replay = idem_start(db, "policy:" + org.id, idempotency_key, body.model_dump())
        if not replay:
            org.policy = {
                "minimum_severity": body.minimum_severity,
                "version": org.policy.get("version", 0) + 1,
            }
            audit(
                db,
                principal.user_id,
                "policy.change",
                org.id,
                request.state.request_id,
                org.id,
                reason=body.reason,
            )
            record.response = {"policy": org.policy}
        return record.response


class Pack(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rules: list[
        Literal[
            "unsafe_subprocess",
            "deserialization",
            "query_construction",
            "auth_pattern",
            "exception_suppression",
        ]
    ] = Field(min_length=1, max_length=5)
    reason: str = Field(min_length=5, max_length=500)


@router.post("/organizations/{org_id}/pattern-packs")
def pattern_pack(request: Request, org_id: str, body: Pack, idempotency_key: str = Header("")):
    with request.app.state.factory.begin() as db:
        principal = identity(request, db, mutation=True)
        require_admin(principal, request.app.state.settings, elevated=True)
        org = lock_org(db, org_id)
        if not billing.entitlements(db, org.id)["custom_policies"]:
            raise HTTPException(403, "Enterprise entitlement required.")
        record, replay = idem_start(db, "patterns:" + org.id, idempotency_key, body.model_dump())
        if not replay:
            version = (
                db.scalar(
                    select(func.max(PatternPack.version)).where(
                        PatternPack.organization_id == org.id
                    )
                )
                or 0
            ) + 1
            pack = PatternPack(
                organization_id=org.id,
                version=version,
                rules=sorted(set(body.rules)),
                approved_by=principal.user_id,
            )
            db.add(pack)
            audit(
                db,
                principal.user_id,
                "patterns.approve",
                str(version),
                request.state.request_id,
                org.id,
                reason=body.reason,
            )
            record.response = {
                "version": version,
                "rules": pack.rules,
                "notice": "Only bounded built-in rule identifiers are accepted; executable plugins and arbitrary regex are rejected.",
            }
        return record.response
