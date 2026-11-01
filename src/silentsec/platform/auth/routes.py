"""Shared sign-in backend for customer and administrator entry points."""

import hmac
import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update

from ..access import csrf_token, identity
from ..db import audit, digest
from ..models import LoginAttempt, Membership, Organization, PlatformRole, Session, User, now, uid
from . import oidc

router = APIRouter(prefix="/api/v1/auth")


def clear_cookie(response, settings, name):
    # __Host- cookies must also carry Secure when being expired; otherwise
    # browsers reject the deletion. State cookies have the same host binding.
    response.delete_cookie(
        name, path="/", secure=settings.environment == "production", httponly=True, samesite="lax"
    )


class DevLogin(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=254)
    access_code: str = Field(max_length=200)
    admin: bool = False


def new_session(db, settings, request, user, response, *, admin=False, mfa=False, auth_time=None):
    roles = list(db.scalars(select(PlatformRole.role).where(PlatformRole.user_id == user.id)))
    if admin and (
        "platform_admin" not in roles
        or not mfa
        or now() - (auth_time or 0) > settings.reauth_seconds
    ):
        raise HTTPException(403, "Administrator role, MFA and recent authentication are required.")
    old = request.cookies.get(settings.cookie_name)
    if old:
        db.execute(
            update(Session)
            .where(Session.token_hash == digest(old.encode()))
            .values(revoked_at=now())
        )
    member = db.scalar(
        select(Membership).where(Membership.user_id == user.id).order_by(Membership.created_at)
    )
    raw = secrets.token_urlsafe(48)
    session = Session(
        token_hash=digest(raw.encode()),
        user_id=user.id,
        active_organization_id=member.organization_id if member else None,
        authenticated_at=auth_time or now(),
        mfa_verified=mfa,
        admin=admin,
        expires_at=now() + (settings.admin_session_seconds if admin else settings.session_seconds),
    )
    db.add(session)
    audit(
        db,
        user.id,
        "auth.admin_login" if admin else "auth.login",
        user.id,
        request.state.request_id,
    )
    response.set_cookie(
        settings.cookie_name,
        raw,
        httponly=True,
        secure=settings.environment == "production",
        samesite="lax",
        path="/",
        max_age=settings.admin_session_seconds if admin else settings.session_seconds,
    )
    return session


@router.get("/configuration")
def configuration(request: Request):
    settings = request.app.state.settings
    return {
        "mode": settings.auth_mode,
        "environment": settings.environment,
        "development": settings.auth_mode == "development",
    }


@router.post("/dev")
def dev_login(body: DevLogin, request: Request):
    from fastapi.responses import JSONResponse

    settings = request.app.state.settings
    if settings.environment == "production" or settings.auth_mode != "development":
        raise HTTPException(404, "Not found.")
    valid = hmac.compare_digest(body.access_code, settings.dev_login_code.get_secret_value())
    with request.app.state.factory.begin() as db:
        user = db.scalar(
            select(User).where(
                User.email == body.email.strip().casefold(), User.issuer == "development"
            )
        )
        if not valid or not user or user.status != "active":
            audit(db, None, "auth.login_failed", "development", request.state.request_id)
            failure = True
        else:
            failure = False
            response = JSONResponse({"redirect": "/admin" if body.admin else "/workspace"})
            # This is an explicitly labelled local identity-provider simulator,
            # never an assertion accepted by production authentication.
            new_session(
                db,
                settings,
                request,
                user,
                response,
                admin=body.admin,
                mfa=body.admin,
                auth_time=now(),
            )
    if failure:
        raise HTTPException(
            401, "Sign-in failed. Check your provisioned email and local access code."
        )
    return response


@router.get("/login")
async def login(request: Request, admin: bool = False):
    settings = request.app.state.settings
    if settings.auth_mode != "oidc":
        raise HTTPException(409, "Use the development sign-in form.")
    document = await oidc.metadata(settings)
    state, nonce, verifier = oidc.new_attempt()
    async with oidc.client(settings) as client:
        url, _ = client.create_authorization_url(
            document["authorization_endpoint"],
            state=state,
            nonce=nonce,
            code_verifier=verifier,
            **({"max_age": 0, "prompt": "login"} if admin else {}),
        )
    with request.app.state.factory.begin() as db:
        db.add(
            LoginAttempt(
                state_hash=digest(state.encode()),
                nonce=nonce,
                verifier=verifier,
                admin=admin,
                expires_at=now() + 300,
            )
        )
        audit(
            db, None, "auth.login_begin", "admin" if admin else "customer", request.state.request_id
        )
    response = RedirectResponse(url)
    response.set_cookie(
        settings.oidc_cookie_name,
        state,
        httponly=True,
        secure=settings.environment == "production",
        samesite="lax",
        max_age=300,
    )
    return response


@router.get("/callback")
async def callback(request: Request, state: str = "", code: str = ""):
    settings = request.app.state.settings
    if (
        settings.auth_mode != "oidc"
        or not state
        or not hmac.compare_digest(state, request.cookies.get(settings.oidc_cookie_name, ""))
    ):
        raise HTTPException(401, "Invalid sign-in state.")
    factory = request.app.state.factory
    with factory.begin() as db:
        # Atomic consume; an intercepted callback cannot be replayed.
        row = db.scalar(
            select(LoginAttempt).where(LoginAttempt.state_hash == digest(state.encode()))
        )
        if not row or row.used or row.expires_at <= now():
            raise HTTPException(401, "Sign-in attempt expired or already used.")
        changed = db.execute(
            update(LoginAttempt)
            .where(LoginAttempt.id == row.id, LoginAttempt.used.is_(False))
            .values(used=True)
        ).rowcount
        if changed != 1:
            raise HTTPException(401, "Sign-in attempt already used.")
        nonce, verifier, admin = row.nonce, row.verifier, row.admin
    document = await oidc.metadata(settings)
    try:
        async with oidc.client(settings) as client:
            tokens = await client.fetch_token(
                document["token_endpoint"], code=code, code_verifier=verifier
            )
        claims = oidc.verify_token(settings, tokens["id_token"], audience=settings.oidc_client_id)
        if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
            raise HTTPException(401, "Invalid sign-in nonce.")
        email = str(claims.get("email", "")).strip().casefold()
        if claims.get("email_verified") is not True or "@" not in email or len(email) > 254:
            raise HTTPException(401, "A verified email address is required.")
        with factory.begin() as db:
            user = db.scalar(
                select(User).where(User.issuer == claims["iss"], User.subject == claims["sub"])
            )
            if not user:
                if admin:
                    raise HTTPException(403, "Platform administrator access must be provisioned.")
                if db.scalar(select(User.id).where(User.email == email)):
                    raise HTTPException(
                        409, "This email requires explicit identity linking by an administrator."
                    )
                user = User(
                    email=email,
                    issuer=claims["iss"],
                    subject=claims["sub"],
                    name=email.split("@")[0][:120],
                )
                db.add(user)
                db.flush()
                provision_org(db, user, user.name + " workspace")
            if user.status != "active":
                raise HTTPException(403, "Account unavailable.")
            response = RedirectResponse("/admin" if admin else "/workspace", status_code=303)
            new_session(
                db,
                settings,
                request,
                user,
                response,
                admin=admin,
                mfa=oidc.mfa_verified(settings, claims),
                auth_time=int(claims.get("auth_time", 0)),
            )
            clear_cookie(response, settings, settings.oidc_cookie_name)
            return response
    except HTTPException:
        with factory.begin() as db:
            audit(db, None, "auth.login_failed", "oidc", request.state.request_id)
        raise
    except Exception as exc:
        # Never include provider responses, authorization codes or tokens.
        with factory.begin() as db:
            audit(db, None, "auth.login_failed", "oidc", request.state.request_id)
        raise HTTPException(401, "Sign-in could not be completed.") from exc


def provision_org(db, user, name, billing_timezone="UTC"):
    from zoneinfo import ZoneInfo

    ZoneInfo(billing_timezone)
    from .. import billing
    from ..models import BillingAccount, Subscription

    org = Organization(
        name=name[:120],
        slug="workspace-" + uid()[:12],
        owner_id=user.id,
        billing_timezone=billing_timezone,
    )
    db.add(org)
    db.flush()
    db.add_all(
        [
            Membership(organization_id=org.id, user_id=user.id, role="owner"),
            Subscription(organization_id=org.id, plan_key="free"),
            BillingAccount(organization_id=org.id),
        ]
    )
    db.flush()
    billing.ensure_month(db, org)
    return org


@router.get("/me")
def me(request: Request):
    with request.app.state.factory() as db:
        principal = identity(request, db)
        user = db.get(User, principal.user_id)
        orgs = db.execute(
            select(Organization, Membership.role)
            .join(Membership, Membership.organization_id == Organization.id)
            .where(Membership.user_id == user.id)
        ).all()
        return {
            "user": {"id": user.id, "email": user.email, "name": user.name},
            "active_organization": principal.org_id,
            "organization_role": principal.role,
            "platform_roles": principal.platform_roles,
            "admin_session": bool(principal.session and principal.session.admin),
            "organizations": [
                {"id": o.id, "name": o.name, "role": role, "status": o.status} for o, role in orgs
            ],
            "csrf_token": csrf_token(
                request.cookies.get(request.app.state.settings.cookie_name, ""),
                request.app.state.settings,
            ),
        }


@router.post("/organization/{org_id}")
def switch_org(org_id: str, request: Request):
    with request.app.state.factory.begin() as db:
        principal = identity(request, db, mutation=True)
        if not principal.session:
            raise HTTPException(403, "Browser session required.")
        member = db.scalar(
            select(Membership).where(
                Membership.user_id == principal.user_id, Membership.organization_id == org_id
            )
        )
        org = db.get(Organization, org_id)
        if not member or not org or org.status != "active":
            raise HTTPException(404, "Organization not found.")
        principal.session.active_organization_id = org_id
        audit(
            db, principal.user_id, "organization.switch", org_id, request.state.request_id, org_id
        )
    return {"ok": True}


@router.post("/logout")
def logout(request: Request):
    from fastapi.responses import JSONResponse

    with request.app.state.factory.begin() as db:
        principal = identity(request, db, mutation=True)
        if principal.session:
            principal.session.revoked_at = now()
        audit(db, principal.user_id, "auth.logout", principal.user_id, request.state.request_id)
    response = JSONResponse({"ok": True})
    clear_cookie(response, request.app.state.settings, request.app.state.settings.cookie_name)
    return response
