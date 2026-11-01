"""Durable jobs, organization concurrency and metering transactions."""

import secrets

from fastapi import HTTPException
from sqlalchemy import func, select

from . import billing
from .db import audit, lock_org
from .models import EntitlementSnapshot, PatternPack, Reservation, ScanJob, ScanResult, now, uid


def submit(
    db, org, user_id, kind, reference, name, key, payload_hash, request_id, *, standard=True
):
    existing = db.scalar(
        select(ScanJob).where(ScanJob.organization_id == org.id, ScanJob.idempotency_key == key)
    )
    if existing:
        if existing.request_hash != payload_hash:
            raise HTTPException(409, "Idempotency key was used with a different scan request.")
        return existing
    limits = {**billing.entitlements(db, org.id), "policy": org.policy}
    pack = db.scalar(
        select(PatternPack)
        .where(PatternPack.organization_id == org.id)
        .order_by(PatternPack.version.desc())
        .limit(1)
    )
    if pack and limits["custom_policies"]:
        limits["pattern_rules"], limits["pattern_version"] = pack.rules, pack.version
    pending = db.scalar(
        select(func.count(ScanJob.id)).where(
            ScanJob.organization_id == org.id, ScanJob.status.in_(["queued", "running"])
        )
    )
    if pending >= limits["queue_limit"]:
        raise HTTPException(429, "Organization queue limit reached. No credit was charged.")
    snapshot = EntitlementSnapshot(
        organization_id=org.id, plan_key=limits["plan"], version=limits["version"], limits=limits
    )
    db.add(snapshot)
    db.flush()
    job_id = uid()
    reservation = billing.reserve(db, org, job_id, key, limits) if standard else None
    job = ScanJob(
        id=job_id,
        organization_id=org.id,
        requester_id=user_id,
        source_kind=kind,
        source_reference=reference,
        source_name=name[:120],
        idempotency_key=key,
        request_hash=payload_hash,
        snapshot_id=snapshot.id,
        reservation_id=reservation.id if reservation else None,
    )
    db.add(job)
    audit(db, user_id, "scan.submit", job_id, request_id, org.id)
    return job


def notify(settings, job_id):
    if not settings.redis_url.get_secret_value():
        return
    import redis

    try:
        with redis.Redis.from_url(settings.redis_url.get_secret_value(), socket_timeout=2) as queue:
            queue.lpush("silentsec:jobs:v1", job_id)
            queue.ltrim("silentsec:jobs:v1", 0, 9999)
    except redis.RedisError:
        # The committed DB row IS the durable queue, Redis is only a wake-up.
        # No user request, reservation or job is lost if this hint fails.
        return


def claim(factory):
    with factory() as db:
        candidates = db.execute(
            select(ScanJob.id, ScanJob.organization_id)
            .where(ScanJob.status == "queued")
            .order_by(ScanJob.created_at, ScanJob.id)
            .limit(100)
        ).all()
    for job_id, org_id in candidates:
        with factory.begin() as db:
            org = lock_org(db, org_id)
            if org.status != "active":
                continue
            billing.expire_reservations(db, org_id)
            from .workstation import expire_quotas

            expire_quotas(db, org_id)
            job = db.get(ScanJob, job_id, populate_existing=True)
            if job.status != "queued":
                continue
            snapshot = db.get(EntitlementSnapshot, job.snapshot_id)
            running = db.scalar(
                select(func.count(ScanJob.id)).where(
                    ScanJob.organization_id == org_id, ScanJob.status == "running"
                )
            )
            # A downgrade can tighten concurrency, never loosen a snapshot.
            concurrency = min(
                snapshot.limits["concurrency"], billing.entitlements(db, org_id)["concurrency"]
            )
            if running >= concurrency:
                continue
            job.status, job.started_at = "running", now()
            job.worker_token = secrets.token_hex(32)
            job.lease_expires_at = now() + snapshot.limits["scan_timeout"] + 300
            job.attempt_count += 1
            audit(db, None, "scan.claim", job.id, uid(), org_id)
            db.flush()
            return job.id, job.worker_token
    return None


def mark_started(factory, job_id, token):
    with factory.begin() as db:
        job = db.get(ScanJob, job_id)
        lock_org(db, job.organization_id)
        db.refresh(job)
        if job.status != "running" or job.worker_token != token or job.cancel_requested:
            return False
        if job.execution_started:
            return True
        job.execution_started = True
        if job.reservation_id:
            billing.commit(db, db.get(Reservation, job.reservation_id))
        from .workstation import settle_quotas

        settle_quotas(db, job, "committed")
        audit(db, None, "scan.start", job.id, uid(), job.organization_id)
        return True


def finish(factory, job_id, token, *, result=None, error=None):
    with factory.begin() as db:
        job = db.get(ScanJob, job_id)
        org = lock_org(db, job.organization_id)
        db.refresh(job)
        if job.status != "running" or job.worker_token != token:
            return False
        reservation = db.get(Reservation, job.reservation_id) if job.reservation_id else None
        if job.cancel_requested:
            job.status, job.error_code = "cancelled", "cancelled"
        elif result is not None:
            job.status = "succeeded"
            limits = db.get(EntitlementSnapshot, job.snapshot_id).limits
            if "operation_result" in result:
                from .models import OperationResult

                db.add(
                    OperationResult(
                        job_id=job.id,
                        organization_id=org.id,
                        expires_at=now()
                        + min(org.retention_days, limits["retention_days"]) * 86400,
                        **result["operation_result"],
                    )
                )
            if "summary" in result:
                db.add(
                    ScanResult(
                        job_id=job.id,
                        organization_id=org.id,
                        summary=result["summary"],
                        findings=result["findings"],
                        graph=result["graph"],
                        patterns=result["patterns"],
                        report=result["report"],
                        analysis_version=result["analysis_version"],
                        expires_at=now()
                        + min(org.retention_days, limits["retention_days"]) * 86400,
                    )
                )
        else:
            job.status, job.error_code = "failed", error or "worker_error"
        if not job.execution_started:
            if reservation:
                billing.release(db, reservation)
            from .workstation import settle_quotas

            settle_quotas(db, job, "released")
        job.finished_at, job.lease_expires_at, job.worker_token = now(), None, None
        audit(
            db,
            None,
            "scan." + job.status,
            job.id,
            uid(),
            org.id,
            error_code=job.error_code or "none",
        )
        return True


def cancel(db, job, actor, request_id):
    if job.status == "queued":
        job.status, job.finished_at = "cancelled", now()
        if job.reservation_id:
            billing.release(db, db.get(Reservation, job.reservation_id))
        from .workstation import settle_quotas

        settle_quotas(db, job, "released")
    elif job.status == "running":
        job.cancel_requested = True
    audit(db, actor, "scan.cancel", job.id, request_id, job.organization_id)


def recover(factory):
    with factory() as db:
        expired = db.execute(
            select(ScanJob.id, ScanJob.worker_token).where(
                ScanJob.status == "running", ScanJob.lease_expires_at <= now()
            )
        ).all()
    for job_id, token in expired:
        finish(factory, job_id, token, error="worker_lease_expired")


def job_view(job):
    from .analysis import safe_text

    return {
        "id": job.id,
        "source_kind": job.source_kind,
        "source_name": safe_text(job.source_name),
        "status": job.status,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "attempt_count": job.attempt_count,
        "error_code": job.error_code,
        "cancel_requested": job.cancel_requested,
        "execution_started": job.execution_started,
        "cost": {
            "operation": "standard_scan",
            "units": 1,
            "charge_point": "valid scan execution starts",
        },
    }
