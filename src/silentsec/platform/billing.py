"""Append-only metering. Call mutations inside a transaction holding lock_org()."""

from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import HTTPException
from sqlalchemy import func, select

from .db import audit
from .models import CreditGrant, LedgerEntry, Plan, Reservation, Subscription, now

DEFAULT_PLANS = {
    "free": {
        "name": "Free / Developer",
        "monthly_credits": 30,
        "concurrency": 1,
        "queue_limit": 10,
        "rate_per_minute": 3,
        "scan_timeout": 180,
        "retention_days": 7,
        "history_commits": 0,
        "ai_findings": 0,
        "graph_detail": False,
        "team": False,
        "custom_policies": False,
    },
    "pro": {
        "name": "Pro",
        "monthly_credits": None,
        "concurrency": 2,
        "queue_limit": 20,
        "rate_per_minute": 10,
        "scan_timeout": 300,
        "retention_days": 30,
        "history_commits": 20,
        "ai_findings": 100,
        "graph_detail": True,
        "team": False,
        "custom_policies": False,
    },
    "enterprise": {
        "name": "Enterprise",
        "monthly_credits": None,
        "concurrency": 4,
        "queue_limit": 40,
        "rate_per_minute": 20,
        "scan_timeout": 600,
        "retention_days": 90,
        "history_commits": 20,
        "ai_findings": 500,
        "graph_detail": True,
        "team": True,
        "custom_policies": True,
    },
}


def seed_plans(db):
    for key, values in DEFAULT_PLANS.items():
        if not db.get(Plan, key):
            db.add(Plan(key=key, name=values["name"], version=1, entitlements=values))


def entitlements(db, org_id):
    subscription = db.scalar(select(Subscription).where(Subscription.organization_id == org_id))
    active = subscription and subscription.status in {"active", "trialing"}
    if active and subscription.period_end:
        active = subscription.period_end > now()
    key = subscription.plan_key if active else "free"
    plan = db.get(Plan, key)
    if plan is None:
        raise HTTPException(503, "Plan configuration unavailable.")
    limits = {
        **plan.entitlements,
        "plan": key,
        "version": plan.version,
        "max_upload_bytes": 20 * 1024 * 1024,
        "max_repository_files": 20000,
        "max_repository_bytes": 200 * 1024 * 1024,
    }
    if key == "enterprise" and subscription.contract:
        for field in (
            "concurrency",
            "queue_limit",
            "rate_per_minute",
            "scan_timeout",
            "retention_days",
            "ai_findings",
            "monthly_scan_pool",
        ):
            if field in subscription.contract:
                limits[field] = subscription.contract[field]
    return limits


def month_window(org, instant=None):
    current = datetime.fromtimestamp(
        instant if instant is not None else now(), ZoneInfo(org.billing_timezone)
    )
    start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = (
        start.replace(year=start.year + 1, month=1)
        if start.month == 12
        else start.replace(month=start.month + 1)
    )
    return int(start.timestamp()), int(end.timestamp()), start.strftime("%Y-%m")


def grant(db, org_id, amount, kind, start, end, key):
    existing = db.scalar(select(CreditGrant).where(CreditGrant.idempotency_key == key))
    if existing:
        return existing
    item = CreditGrant(
        organization_id=org_id,
        amount=amount,
        grant_type=kind,
        valid_from=start,
        expires_at=end,
        idempotency_key=key,
    )
    db.add(item)
    db.flush()
    db.add(
        LedgerEntry(
            organization_id=org_id,
            grant_id=item.id,
            kind="grant",
            units=amount,
            idempotency_key="grant:" + item.id,
        )
    )
    return item


def ensure_month(db, org):
    start, end, month = month_window(org)
    # Signup is allowed one personal org; extra workspaces are an admin action.
    # Thus repeatedly creating organizations cannot mint free credits.
    if entitlements(db, org.id)["plan"] == "free":
        grant(db, org.id, 30, "monthly_free", start, end, f"monthly:{org.id}:{month}")
    return start, end


def balances(db, org_id):
    rows = db.execute(
        select(CreditGrant.id, func.coalesce(func.sum(LedgerEntry.units), 0))
        .join(LedgerEntry, LedgerEntry.grant_id == CreditGrant.id)
        .where(
            CreditGrant.organization_id == org_id,
            CreditGrant.valid_from <= now(),
            CreditGrant.expires_at > now(),
        )
        .group_by(CreditGrant.id)
        .order_by(func.min(CreditGrant.expires_at), CreditGrant.id)
    ).all()
    return [(grant_id, int(units)) for grant_id, units in rows]


def expire_reservations(db, org_id):
    rows = db.scalars(
        select(Reservation).where(
            Reservation.organization_id == org_id,
            Reservation.state == "reserved",
            Reservation.expires_at <= now(),
        )
    ).all()
    from .models import ScanJob

    for row in rows:
        job = db.get(ScanJob, row.job_id)
        if job and job.status == "running":
            continue
        release(db, row, "expired")
        if job and job.status == "queued":
            job.status, job.error_code, job.finished_at = "cancelled", "reservation_expired", now()
            from .workstation import settle_quotas

            settle_quotas(db, job, "released")


def reserve(db, org, job_id, key, limits):
    ensure_month(db, org)
    expire_reservations(db, org.id)
    grant_id = None
    if limits["plan"] == "free":
        available = [(g, n) for g, n in balances(db, org.id) if n > 0]
        if not available:
            raise HTTPException(
                402,
                {
                    "code": "scan_credits_exhausted",
                    "message": "No standard scan credits remain this month.",
                },
            )
        grant_id = available[0][0]
    elif limits.get("monthly_scan_pool") is not None:
        start, end, _ = month_window(org)
        spent = db.scalar(
            select(func.count(Reservation.id)).where(
                Reservation.organization_id == org.id,
                Reservation.created_at >= start,
                Reservation.created_at < end,
                Reservation.state.in_(["reserved", "committed"]),
            )
        )
        if spent >= limits["monthly_scan_pool"]:
            raise HTTPException(402, "Contract scan pool exhausted.")
    row = Reservation(
        organization_id=org.id,
        job_id=job_id,
        grant_id=grant_id,
        operation="standard_scan",
        units=1,
        expires_at=now() + 86400,
        idempotency_key=f"scan:{org.id}:{key}",
    )
    db.add(row)
    db.flush()
    db.add(
        LedgerEntry(
            organization_id=org.id,
            grant_id=grant_id,
            reservation_id=row.id,
            job_id=job_id,
            kind="reserve",
            units=-1 if grant_id else 0,
            idempotency_key="reserve:" + row.id,
        )
    )
    return row


def commit(db, reservation):
    if reservation.state != "reserved":
        return
    reservation.state = "committed"
    db.add(
        LedgerEntry(
            organization_id=reservation.organization_id,
            grant_id=reservation.grant_id,
            reservation_id=reservation.id,
            job_id=reservation.job_id,
            kind="commit",
            units=0,
            idempotency_key="commit:" + reservation.id,
        )
    )


def release(db, reservation, state="released"):
    if reservation.state != "reserved":
        return
    reservation.state = state
    db.add(
        LedgerEntry(
            organization_id=reservation.organization_id,
            grant_id=reservation.grant_id,
            reservation_id=reservation.id,
            job_id=reservation.job_id,
            kind=state,
            units=1 if reservation.grant_id else 0,
            idempotency_key=state + ":" + reservation.id,
        )
    )


def adjust(db, org, amount, key, actor, reason, request_id):
    if amount > 0:
        _, end, _ = month_window(org)
        grant(db, org.id, amount, "manual_adjustment", now(), end, f"manual:{org.id}:{key}")
    else:
        remaining = -amount
        available = balances(db, org.id)
        if sum(max(n, 0) for _, n in available) < remaining:
            raise HTTPException(409, "Cannot revoke reserved, spent or unavailable credits.")
        for grant_id, units in available:
            take = min(remaining, max(units, 0))
            if take:
                db.add(
                    LedgerEntry(
                        organization_id=org.id,
                        grant_id=grant_id,
                        kind="revoke",
                        units=-take,
                        idempotency_key=f"revoke:{org.id}:{key}:{grant_id}",
                    )
                )
                remaining -= take
    audit(db, actor, "credits.adjust", org.id, request_id, org.id, amount=amount, reason=reason)


def usage(db, org):
    start, end = ensure_month(db, org)
    expire_reservations(db, org.id)
    db.flush()
    used = db.scalar(
        select(func.count(Reservation.id)).where(
            Reservation.organization_id == org.id,
            Reservation.created_at >= start,
            Reservation.created_at < end,
            Reservation.state == "committed",
        )
    )
    held = db.scalar(
        select(func.count(Reservation.id)).where(
            Reservation.organization_id == org.id, Reservation.state == "reserved"
        )
    )
    limits = entitlements(db, org.id)
    return {
        "plan": limits["plan"],
        "credits_left": sum(n for _, n in balances(db, org.id)),
        "monthly_allowance": 30 if limits["plan"] == "free" else None,
        "committed_scans": used,
        "reserved_scans": held,
        "period_start": start,
        "renewal_at": end,
        "billing_timezone": org.billing_timezone,
        "units": {
            "standard_scan": "one per valid scan started",
            "ai_finding": "separate quota",
            "history_commit": "separate quota",
            "verification": "separate quota",
        },
    }
