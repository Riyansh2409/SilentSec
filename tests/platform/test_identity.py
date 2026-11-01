import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("authlib")

from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select

from silentsec.platform.config import Settings
from silentsec.platform.models import Membership, Session, User, now


def test_development_and_sqlite_are_rejected_in_production():
    with pytest.raises(ValidationError):
        Settings(
            environment="production",
            session_secret="s" * 64,
            dev_login_code="dev-code-that-is-long",
        )


def test_identity_and_customer_cannot_access_admin(platform):
    app, _, account, _ = platform
    client, user, org = account("developer@example.test")
    me = client.get("/api/v1/auth/me").json()
    assert me["user"]["id"] == user
    assert me["active_organization"] == org
    assert me["organization_role"] == "owner"
    assert me["platform_roles"] == []
    assert client.get("/api/v1/admin/users").status_code == 403
    assert client.get("/admin", follow_redirects=False).headers["location"] == "/admin/login"
    anonymous = TestClient(app, base_url="http://127.0.0.1:8780")
    assert anonymous.get("/api/v1/scans").status_code == 401


def test_admin_needs_admin_login_mfa_and_recent_auth(platform):
    _, factory, account, _ = platform
    ordinary, user, _ = account("admin@example.test", admin=True)
    assert ordinary.get("/api/v1/admin/users").status_code == 403
    assert (
        ordinary.post(
            "/api/v1/auth/dev",
            json={
                "email": "admin@example.test",
                "access_code": "local-test-access-code",
                "admin": True,
            },
        ).status_code
        == 200
    )
    ordinary.headers["X-CSRF-Token"] = ordinary.get("/api/v1/auth/me").json()["csrf_token"]
    assert ordinary.get("/api/v1/admin/users").status_code == 200
    with factory.begin() as db:
        row = db.scalar(select(Session).where(Session.user_id == user, Session.admin.is_(True)))
        row.mfa_verified = False
    assert ordinary.get("/api/v1/admin/users").status_code == 403
    with factory.begin() as db:
        row = db.scalar(select(Session).where(Session.user_id == user, Session.admin.is_(True)))
        row.mfa_verified, row.authenticated_at = True, now() - 1000
    assert (
        ordinary.post(
            "/api/v1/admin/actions",
            headers={"Idempotency-Key": "recent-auth-test"},
            json={
                "target_type": "user",
                "target_id": user,
                "action": "suspend",
                "reason": "testing reauthentication",
            },
        ).status_code
        == 401
    )


def test_csrf_origin_host_and_logout(platform):
    _, _, account, _ = platform
    client, _, _ = account("csrf@example.test")
    assert client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert client.get("/api/v1/auth/me", headers={"Origin": "https://evil.test"}).status_code == 403
    assert client.get("/api/v1/auth/me", headers={"Host": "evil.test"}).status_code == 400
    assert client.post("/api/v1/auth/logout").status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_organization_switch_does_not_allow_other_tenant(platform):
    _, _, account, _ = platform
    client, _, _ = account("one@example.test")
    _, _, other = account("two@example.test")
    assert client.post("/api/v1/auth/organization/" + other).status_code == 404


def test_viewer_cannot_submit_scan(platform):
    _, factory, account, _ = platform
    client, user, _ = account("viewer@example.test")
    with factory.begin() as db:
        row = db.scalar(select(Membership).where(Membership.user_id == user))
        row.role = "viewer"
    response = client.post(
        "/api/v1/scan/github",
        headers={"Idempotency-Key": "viewer-scan"},
        json={"url": "https://github.com/example/repository"},
    )
    assert response.status_code == 403


def test_invalid_input_does_not_echo_secret(platform):
    _, _, account, _ = platform
    client, _, _ = account("validation@example.test")
    secret = "ghp_abcdefghijklmnopqrstuv"
    response = client.post(
        "/api/v1/scan/github",
        headers={"Idempotency-Key": "invalid-input"},
        json={"url": "https://github.com/owner/repo", "token": secret},
    )
    assert response.status_code == 422
    assert secret not in response.text


def test_login_rate_limit_and_no_user_enumeration(platform):
    app, _, _, settings = platform
    client = TestClient(app, base_url=settings.origin, headers={"Origin": settings.origin})
    body = {"email": "missing@example.test", "access_code": "wrong-code-but-long"}
    replies = [client.post("/api/v1/auth/dev", json=body) for _ in range(11)]
    assert replies[0].status_code == 401
    assert replies[-1].status_code == 429


def test_user_status_blocks_session(platform):
    _, factory, account, _ = platform
    client, user, _ = account("suspended@example.test")
    with factory.begin() as db:
        db.get(User, user).status = "suspended"
    assert client.get("/api/v1/auth/me").status_code == 401
