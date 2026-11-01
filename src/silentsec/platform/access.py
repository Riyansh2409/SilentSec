"""Server-side identity, organization and platform authorization."""

import hashlib
import hmac
from dataclasses import dataclass

from fastapi import HTTPException, Request
from sqlalchemy import select

from .db import digest
from .models import ApiKey, Membership, Organization, PlatformRole, Session, User, now


@dataclass
class Principal:
    user_id: str | None
    org_id: str | None
    role: str
    platform_roles: list[str]
    session: Session | None = None
    scopes: list[str] | None = None
    key_id: str | None = None


def csrf_token(raw, settings):
    return hmac.new(
        settings.session_secret.get_secret_value().encode(),
        ("csrf:" + raw).encode(),
        hashlib.sha256,
    ).hexdigest()


def identity(request: Request, db, *, mutation=False, scope=None):
    settings = request.app.state.settings
    authorization = request.headers.get("authorization", "")
    raw = request.cookies.get(settings.cookie_name, "")
    if authorization.startswith("Bearer ssec_"):
        token = authorization[7:]
        if len(token) > 200:
            raise HTTPException(401, "Invalid API key.")
        key = db.scalar(select(ApiKey).where(ApiKey.prefix == token[:13]))
        valid = key and not key.revoked_at and key.expires_at > now()
        if not valid or not hmac.compare_digest(
            key.key_hash,
            hashlib.scrypt(token.encode(), salt=bytes.fromhex(key.salt), n=16384, r=8, p=1).hex(),
        ):
            raise HTTPException(401, "Invalid API key.")
        if scope not in (key.scopes or []):
            raise HTTPException(403, "API key lacks the required scope.")
        org = db.get(Organization, key.organization_id)
        if not org or org.status != "active":
            raise HTTPException(403, "Organization unavailable.")
        return Principal(None, org.id, "member", [], scopes=key.scopes, key_id=key.id)
    if authorization.startswith("Bearer "):
        from .auth.oidc import verify_token

        if settings.auth_mode != "oidc":
            raise HTTPException(401, "Bearer JWT authentication is not enabled.")
        claims = verify_token(settings, authorization[7:], audience=settings.oidc_audience)
        user = db.scalar(
            select(User).where(User.issuer == claims["iss"], User.subject == claims["sub"])
        )
        if not user or user.status != "active":
            raise HTTPException(401, "Account unavailable.")
        # Bearer tokens cannot access elevated administration; use a short,
        # MFA-verified session there. Organization selector is still verified.
        org_id = request.headers.get("X-Organization-ID")
        member = db.scalar(
            select(Membership).where(
                Membership.user_id == user.id, Membership.organization_id == org_id
            )
        )
        if not member:
            raise HTTPException(403, "Organization membership required.")
        org = db.get(Organization, org_id)
        if org.status != "active":
            raise HTTPException(403, "Organization unavailable.")
        return Principal(user.id, org_id, member.role, [])
    session = (
        db.scalar(select(Session).where(Session.token_hash == digest(raw.encode())))
        if raw
        else None
    )
    if not session or session.revoked_at or session.expires_at <= now():
        raise HTTPException(401, "Sign in to continue.")
    user = db.get(User, session.user_id)
    if not user or user.status != "active":
        raise HTTPException(401, "Account unavailable.")
    if mutation and not hmac.compare_digest(
        request.headers.get("X-CSRF-Token", ""), csrf_token(raw, settings)
    ):
        raise HTTPException(403, "Invalid CSRF token.")
    roles = list(db.scalars(select(PlatformRole.role).where(PlatformRole.user_id == user.id)))
    member = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.organization_id == session.active_organization_id,
        )
    )
    if session.active_organization_id:
        org = db.get(Organization, session.active_organization_id)
        if (not member or not org or org.status != "active") and not request.url.path.startswith(
            "/api/v1/admin/"
        ):
            raise HTTPException(403, "Organization unavailable.")
    return Principal(
        user.id,
        session.active_organization_id,
        member.role if member else "none",
        roles,
        session=session,
    )


def require_member(principal, *, write=False, manage=False):
    allowed = (
        {"owner", "admin"}
        if manage
        else ({"owner", "admin", "member"} if write else {"owner", "admin", "member", "viewer"})
    )
    if not principal.org_id or principal.role not in allowed:
        raise HTTPException(403, "Your organization role does not permit this action.")


def require_admin(principal, settings, *, elevated=False):
    session = principal.session
    if (
        "platform_admin" not in principal.platform_roles
        or not session
        or not session.admin
        or not session.mfa_verified
    ):
        raise HTTPException(403, "A verified platform-admin session with MFA is required.")
    if now() - session.created_at >= settings.admin_session_seconds:
        raise HTTPException(401, "Admin session expired. Sign in again.")
    if elevated and now() - session.authenticated_at > settings.reauth_seconds:
        raise HTTPException(401, "Recent authentication required. Sign in again.")


def tenant_object(db, model, object_id, org_id):
    item = db.scalar(select(model).where(model.id == object_id, model.organization_id == org_id))
    if item is None:
        raise HTTPException(404, "Object not found.")
    return item
