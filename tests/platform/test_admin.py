import hashlib
import hmac
import json

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("authlib")

from sqlalchemy import select

from silentsec.platform.models import ApiKey, AuditEvent, Subscription, now


def test_credit_adjustment_requires_reason_and_is_idempotent(platform):
    _, factory, account, _ = platform
    admin, _, org = account("admin@example.test", admin=True, login_admin=True)
    payload = {
        "target_type": "organization",
        "target_id": org,
        "action": "credits",
        "amount": 5,
        "reason": "Approved development testing",
    }
    headers = {"Idempotency-Key": "grant-five-credits"}
    assert admin.post("/api/v1/admin/actions", headers=headers, json=payload).status_code == 200
    assert admin.post("/api/v1/admin/actions", headers=headers, json=payload).status_code == 200
    assert admin.get("/api/v1/billing/usage").json()["credits_left"] == 35
    payload["amount"] = 6
    assert admin.post("/api/v1/admin/actions", headers=headers, json=payload).status_code == 409
    payload["reason"] = ""
    assert (
        admin.post(
            "/api/v1/admin/actions", headers={"Idempotency-Key": "bad-reason"}, json=payload
        ).status_code
        == 422
    )
    with factory() as db:
        assert (
            len(db.scalars(select(AuditEvent).where(AuditEvent.action == "credits.adjust")).all())
            == 1
        )


def test_admin_does_not_receive_credentials_or_source(platform):
    _, _, account, _ = platform
    admin, _, _ = account("admin@example.test", admin=True, login_admin=True)
    for entity in (
        "users",
        "organizations",
        "subscriptions",
        "jobs",
        "api-keys",
        "repositories",
        "webhooks",
    ):
        response = admin.get("/api/v1/admin/" + entity)
        assert response.status_code == 200
        assert not any(
            k in response.text
            for k in ('"key_hash"', '"salt"', '"source_reference"', '"credential_reference"')
        )


def test_health_uses_worker_executables_not_only_api_path(platform, tmp_path, monkeypatch):
    import os

    from silentsec.platform import worker

    _, _, account, _ = platform
    admin, _, _ = account("health@example.test", admin=True, login_admin=True)
    suffix = ".exe" if os.name == "nt" else ""
    for tool in ("semgrep", "bandit", "gitleaks"):
        path = tmp_path / (tool + suffix)
        path.write_bytes(b"test-only discovery stub; never executed")
        path.chmod(0o700)
    monkeypatch.setattr(worker, "scanner_path", lambda: str(tmp_path))
    response = admin.get("/api/v1/admin/health")
    assert response.status_code == 200
    assert all(response.json()["scanners"].values())
    assert "discovery" in response.json()["scanner_health_scope"]


def test_api_key_hash_scope_expiry_and_revocation(platform):
    _, factory, account, _ = platform
    client, _, _org = account("keys@example.test")
    key = "ssec_" + "a" * 8 + "_" + "b" * 64
    response = client.post(
        "/api/v1/api-keys",
        headers={"Idempotency-Key": "create-key-test"},
        json={"key": key, "scopes": ["scans:read"], "reason": "Read-only integration"},
    )
    assert response.status_code == 201
    assert key not in response.text
    key_id = response.json()["id"]
    with factory() as db:
        stored = db.get(ApiKey, key_id)
        assert stored.key_hash != key and len(stored.salt) == 64
    assert (
        client.get("/api/v1/scans", headers={"Authorization": "Bearer " + key}).status_code == 200
    )
    assert (
        client.get("/api/v1/billing/usage", headers={"Authorization": "Bearer " + key}).status_code
        == 403
    )
    assert (
        client.get("/api/v1/admin/users", headers={"Authorization": "Bearer " + key}).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/api-keys/" + key_id + "/revoke",
            headers={"Idempotency-Key": "revoke-key-test"},
            json={"reason": "Retiring this integration"},
        ).status_code
        == 200
    )
    assert (
        client.get("/api/v1/scans", headers={"Authorization": "Bearer " + key}).status_code == 401
    )


def test_billing_event_signature_replay_and_order(platform):
    _app, factory, account, settings = platform
    admin, _, org = account("billing@example.test", admin=True, login_admin=True)
    # Pydantic does not validate assignment by default: use SecretStr explicitly.
    from pydantic import SecretStr

    settings.payment_webhook_secret = SecretStr("w" * 64)
    with factory.begin() as db:
        sub = db.scalar(select(Subscription).where(Subscription.organization_id == org))
        sub.provider_subscription_id = "test-subscription"
    body = {
        "version": 1,
        "id": "event-2",
        "sequence": 2,
        "subscription_id": "test-subscription",
        "plan": "pro",
        "status": "active",
        "period_start": now(),
        "period_end": now() + 86400,
    }

    def send(payload, signature=True):
        raw = json.dumps(payload).encode()
        stamp = str(now())
        sig = (
            hmac.new(b"w" * 64, stamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
            if signature
            else "bad"
        )
        return admin.post(
            "/api/v1/billing/webhooks/adapter",
            content=raw,
            headers={
                "Content-Type": "application/json",
                "X-Billing-Timestamp": stamp,
                "X-Billing-Signature": sig,
            },
        )

    assert send(body, False).status_code == 400
    assert send(body).json()["status"] == "processed"
    assert send(body).json()["status"] == "duplicate"
    assert (
        send({**body, "id": "event-1", "sequence": 1, "plan": "free"}).json()["status"]
        == "ignored_out_of_order"
    )
    assert admin.get("/api/v1/billing/entitlements").json()["plan"] == "pro"
