from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("authlib")

from fastapi import HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.exc import DatabaseError

from silentsec.platform import billing, jobs
from silentsec.platform.db import lock_org
from silentsec.platform.models import (
    CreditGrant,
    LedgerEntry,
    Reservation,
    Subscription,
    now,
    uid,
)


def test_monthly_grant_is_exactly_30_and_idempotent(platform):
    _, factory, account, _ = platform
    client, _, org_id = account("monthly@example.test")
    for _ in range(3):
        assert client.get("/api/v1/billing/usage").json()["credits_left"] == 30
    with factory.begin() as db:
        org = lock_org(db, org_id)
        billing.ensure_month(db, org)
        assert db.scalar(select(func.count(CreditGrant.id))) == 1
        assert db.scalar(select(func.sum(LedgerEntry.units))) == 30


def test_reserve_commit_release_and_duplicate_submission(platform):
    _, factory, account, _ = platform
    client, _, _ = account("reserve@example.test")
    headers = {"Idempotency-Key": "my-first-scan"}
    body = {"url": "https://github.com/example/repo"}
    response = client.post("/api/v1/scan/github", json=body, headers=headers)
    assert response.status_code == 202
    job_id = response.json()["id"]
    assert client.post("/api/v1/scan/github", json=body, headers=headers).json()["id"] == job_id
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 29
    assert (
        client.post(
            "/api/v1/scans/" + job_id + "/cancel", headers={"Idempotency-Key": "cancel-first-job"}
        ).status_code
        == 200
    )
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 30
    with factory() as db:
        assert db.scalar(select(Reservation)).state == "released"


def test_atomic_concurrent_spending_cannot_exceed_balance(platform):
    _, factory, account, _ = platform
    _, _user_id, org_id = account("concurrency@example.test")

    def spend(index):
        try:
            with factory.begin() as db:
                org = lock_org(db, org_id)
                billing.reserve(
                    db, org, uid(), "concurrent-" + str(index), billing.entitlements(db, org.id)
                )
            return True
        except HTTPException as exc:
            assert exc.status_code == 402
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(spend, range(40))) == 30
    with factory() as db:
        assert sum(v for _, v in billing.balances(db, org_id)) == 0
        assert db.scalar(select(func.count(Reservation.id))) == 30


def test_started_scan_commits_once_even_on_failure(platform):
    _, factory, account, _ = platform
    client, _, _ = account("started@example.test")
    job = client.post(
        "/api/v1/scan/github",
        headers={"Idempotency-Key": "started-scan"},
        json={"url": "https://github.com/example/repo"},
    ).json()
    claim = jobs.claim(factory)
    assert claim[0] == job["id"]
    assert jobs.mark_started(factory, *claim)
    assert jobs.mark_started(factory, *claim)
    jobs.finish(factory, *claim, error="scan_failed")
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 29
    with factory() as db:
        assert (
            db.scalar(select(func.count(LedgerEntry.id)).where(LedgerEntry.kind == "commit")) == 1
        )


def test_preexecution_failure_refunds_and_pro_does_not_debit(platform):
    _, factory, account, _ = platform
    client, _, org_id = account("failures@example.test")
    client.post(
        "/api/v1/scan/github",
        headers={"Idempotency-Key": "prep-failure"},
        json={"url": "https://github.com/example/repo"},
    )
    jobs.finish(factory, *jobs.claim(factory), error="source_preparation_failed")
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 30
    with factory.begin() as db:
        sub = db.scalar(select(Subscription).where(Subscription.organization_id == org_id))
        sub.plan_key = "pro"
    client.post(
        "/api/v1/scan/github",
        headers={"Idempotency-Key": "pro-scan"},
        json={"url": "https://github.com/example/repo"},
    )
    jobs.mark_started(factory, *jobs.claim(factory))
    assert client.get("/api/v1/billing/usage").json()["credits_left"] == 30


def test_monthly_timezone_and_expired_reservation(platform, monkeypatch):
    _, factory, account, _ = platform
    _, _, org_id = account("expiry@example.test")
    with factory.begin() as db:
        org = lock_org(db, org_id)
        from types import SimpleNamespace

        calendar_org = SimpleNamespace(billing_timezone="Asia/Kolkata")
        instant = int(datetime(2026, 12, 31, 23, 59, tzinfo=ZoneInfo("Asia/Kolkata")).timestamp())
        _start, end, month = billing.month_window(calendar_org, instant)
        assert month == "2026-12"
        assert datetime.fromtimestamp(end, ZoneInfo(calendar_org.billing_timezone)).month == 1
        reservation = billing.reserve(
            db, org, uid(), "expired-scan", billing.entitlements(db, org.id)
        )
        reservation.expires_at = now() - 1
    with factory.begin() as db:
        lock_org(db, org_id)
        billing.expire_reservations(db, org_id)
    with factory() as db:
        assert sum(v for _, v in billing.balances(db, org_id)) == 30


@pytest.mark.parametrize(
    "table", ["audit_events", "credit_grants", "usage_ledger_entries", "entitlement_snapshots"]
)
def test_append_only_database_guards(platform, table):
    _, factory, account, _ = platform
    account("immutable@example.test")
    with pytest.raises(DatabaseError), factory.begin() as db:
        # Triggers fire for existing rows; snapshots are seeded through a job.
        if table == "entitlement_snapshots":
            db.execute(
                text(
                    "INSERT INTO entitlement_snapshots(id,created_at,organization_id,plan_key,version,limits) SELECT 'immutable-test',0,id,'free',1,'{}' FROM organizations LIMIT 1"
                )
            )
        db.execute(text("DELETE FROM " + table))
