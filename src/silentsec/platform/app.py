"""Separate SaaS application. Does not mount the trusted local/demo API."""

import json
import logging
import secrets
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from time import monotonic
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.exc import IntegrityError

from . import admin, billing, payments, routes, worker, workstation
from .access import identity, require_admin
from .auth.routes import router as auth_router
from .config import Settings
from .db import database, rate_limit
from .models import uid


class BodyLimit:
    def __init__(self, app, maximum=22 * 1024 * 1024):
        self.app, self.maximum = app, maximum

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        total, response_started = 0, False
        maximum = (
            self.maximum
            if scope.get("path") in {"/api/v1/scan/upload", "/api/v1/workstation/upload"}
            else 1_100_000
            if scope.get("path") == "/api/v1/workstation/jobs"
            else 65536
        )

        async def bounded_receive():
            nonlocal total
            message = await receive()
            total += len(message.get("body", b""))
            if total > maximum:
                raise HTTPException(413, "Request exceeds the upload limit.")
            return message

        async def tracked_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, bounded_receive, tracked_send)
        except HTTPException as exc:
            if response_started:
                raise
            await JSONResponse({"detail": exc.detail}, status_code=exc.status_code)(
                scope, receive, send
            )


def create_app(settings: Settings | None = None):
    settings = settings or Settings()
    engine, factory = database(settings)
    stop = threading.Event()

    @asynccontextmanager
    async def lifespan(app):
        thread = None
        if settings.auto_worker:
            thread = threading.Thread(
                target=worker.loop, args=(factory, settings, stop), daemon=True
            )
            thread.start()
        app.state.worker_thread = thread
        yield
        stop.set()
        if thread:
            thread.join(timeout=30)
        engine.dispose()

    app = FastAPI(
        title="SilentSec platform",
        version="1",
        lifespan=lifespan,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.environment != "production" else None,
    )
    app.state.settings, app.state.engine, app.state.factory = settings, engine, factory
    app.add_middleware(BodyLimit)
    if settings.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=[
                "Content-Type",
                "X-CSRF-Token",
                "Idempotency-Key",
                "Authorization",
                "X-Organization-ID",
            ],
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic's default error includes original input (tokens, source or
        # credential-like strings). Keep only field locations and error types.
        return JSONResponse(
            {
                "detail": "Invalid request.",
                "errors": [
                    {"field": str(e["loc"][0]), "type": e["type"]} for e in exc.errors()[:20]
                ],
            },
            status_code=422,
        )

    @app.exception_handler(IntegrityError)
    async def conflict(request, exc):
        return JSONResponse(
            {"detail": "Request conflicts with an existing record."}, status_code=409
        )

    @app.exception_handler(Exception)
    async def safe_error(request, exc):
        return JSONResponse(
            {"detail": "Internal request failure.", "request_id": request.state.request_id},
            status_code=500,
        )

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        start = monotonic()
        request.state.request_id = uid()
        try:
            host = urlsplit(settings.origin).netloc
            if request.headers.get("host") != host:
                raise HTTPException(400, "Untrusted Host header.")
            origin = request.headers.get("origin")
            if origin and origin not in {settings.origin, *settings.allowed_origins}:
                raise HTTPException(403, "Untrusted request origin.")
            path = request.url.path
            mutation = request.method not in {"GET", "HEAD", "OPTIONS"}
            webhook = path == "/api/v1/billing/webhooks/adapter"
            public = (
                path
                in {
                    "/api/v1/auth/dev",
                    "/api/v1/auth/configuration",
                    "/api/v1/auth/login",
                    "/api/v1/auth/callback",
                    "/api/v1/health",
                }
                or webhook
            )
            if (
                mutation
                and not webhook
                and not request.headers.get("authorization")
                and origin != settings.origin
            ):
                raise HTTPException(403, "Same-origin mutation required.")
            ip = request.client.host if request.client else "unknown"
            if path.startswith("/api/"):
                maximum = (
                    10
                    if path.startswith("/api/v1/auth/")
                    and path not in {"/api/v1/auth/me", "/api/v1/auth/configuration"}
                    else 240
                )
                if webhook:
                    maximum = 60
                rate_limit(
                    factory, "ip:" + ip + ":" + ("login" if maximum == 10 else "api"), maximum
                )
                if not public:
                    with factory() as db:
                        principal = identity(
                            request,
                            db,
                            mutation=mutation,
                            scope="scans:write"
                            if path.startswith("/api/v1/scan/")
                            or path.endswith("/cancel")
                            or (
                                mutation
                                and path
                                in {"/api/v1/workstation/jobs", "/api/v1/workstation/upload"}
                            )
                            else "reports:read"
                            if path.endswith(("/report", "/sarif"))
                            else "billing:read"
                            if path.startswith("/api/v1/billing/")
                            else "scans:read"
                            if path.startswith(("/api/v1/scans", "/api/v1/workstation/"))
                            else None,
                        )
                        if path.startswith("/api/v1/admin/"):
                            require_admin(principal, settings, elevated=mutation)
                        limits = (
                            billing.entitlements(db, principal.org_id) if principal.org_id else None
                        )
                    if (
                        (
                            path.startswith("/api/v1/scan/")
                            or path in {"/api/v1/workstation/jobs", "/api/v1/workstation/upload"}
                        )
                        and mutation
                        and limits
                    ):
                        rate_limit(factory, "scan:" + principal.org_id, limits["rate_per_minute"])
            length = request.headers.get("content-length")
            maximum = (
                22 * 1024 * 1024
                if path in {"/api/v1/scan/upload", "/api/v1/workstation/upload"}
                else 1_100_000
                if path == "/api/v1/workstation/jobs"
                else 65536
            )
            if length and (not length.isdigit() or int(length) > maximum):
                raise HTTPException(413, "Request exceeds the upload limit.")
            response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse(
                {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
            )
        except Exception:  # noqa: BLE001 - sanitize the outer request boundary
            # Do not let SQL/driver diagnostics (including parameters) reach
            # clients or default web-server tracebacks.
            response = JSONResponse(
                {
                    "detail": "Service temporarily unavailable.",
                    "request_id": request.state.request_id,
                },
                status_code=503,
            )
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
                "X-Frame-Options": "DENY",
                "X-Request-ID": request.state.request_id,
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            }
        )
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            )
        if settings.environment == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        logging.getLogger("silentsec.platform").log(
            logging.WARNING if response.status_code >= 500 else logging.INFO,
            json.dumps(
                {
                    "event": "http_response",
                    "request_id": request.state.request_id,
                    "status": response.status_code,
                    "duration_ms": round((monotonic() - start) * 1000),
                }
            ),
        )
        return response

    app.include_router(auth_router)
    app.include_router(routes.router)
    app.include_router(admin.router)
    app.include_router(payments.router)
    app.include_router(workstation.router)

    @app.get("/api/v1/health")
    def health():
        return {"status": "ok", "mode": settings.environment, "service": "platform"}

    static = settings.static_dir or Path(__file__).resolve().parents[3] / "frontend" / "platform"
    original = Path(__file__).resolve().parents[3] / "frontend" / "web"

    @app.get("/original/{asset}", include_in_schema=False)
    def original_asset(asset: str):
        if asset not in {
            "app.js",
            "app.css",
            "api.js",
            "data.js",
            "debt-views.js",
            "account.js",
            "account.css",
        }:
            raise HTTPException(404, "Asset not found.")
        return FileResponse(original / asset)

    @app.get("/assets/{asset}")
    def static_asset(asset: str):
        allowed = {
            "platform.css",
            "tokens.css",
            "login.js",
            "shared.js",
            "workspace.js",
            "admin.js",
            "graph.js",
        }
        if asset not in allowed:
            raise HTTPException(404, "Asset not found.")
        return FileResponse(static / asset)

    @app.get("/")
    def root():
        nonce = secrets.token_urlsafe(24)
        page = (
            (original / "index.html")
            .read_text(encoding="utf-8")
            .replace("<script>", f'<script nonce="{nonce}">')
        )
        return HTMLResponse(
            page,
            headers={
                "Content-Security-Policy": f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            },
        )

    @app.get("/login")
    @app.get("/admin/login")
    def login_page():
        return FileResponse(static / "login.html")

    @app.get("/workspace")
    @app.get("/app")
    def workspace(request: Request):
        try:
            with factory() as db:
                identity(request, db)
        except HTTPException:
            return RedirectResponse("/login", status_code=303)
        page = (
            (original / "app.html")
            .read_text(encoding="utf-8")
            .replace('<html lang="en">', '<html lang="en" data-platform="true">')
        )
        for asset in ("app.css", "app.js"):
            page = page.replace('"/' + asset + '"', '"/original/' + asset + '"')
        page = page.replace(
            "</head>", '<link rel="stylesheet" href="/original/account.css"></head>'
        )
        page = page.replace(
            "</nav>",
            '<a href="#usage" data-view="usage"><span>◷</span> Usage &amp; billing</a><a href="#account" data-view="account"><span>⌘</span> Account &amp; team</a><a href="/account#scans"><span>◇</span> Architecture &amp; patterns</a></nav>',
            1,
        )
        page = page.replace("LOCAL WORKSPACE", "ORGANIZATION WORKSPACE").replace(
            "THIS SESSION", "SAVED OPERATIONS"
        )
        page = page.replace(
            '<div id="setup-notice"',
            '<section id="account-bar" class="account-bar" aria-label="Account and plan"></section><div id="setup-notice"',
        )
        return HTMLResponse(page)

    @app.get("/account")
    def account_page(request: Request):
        try:
            with factory() as db:
                identity(request, db)
        except HTTPException:
            return RedirectResponse("/login", status_code=303)
        return FileResponse(static / "workspace.html")

    @app.get("/admin")
    def admin_page(request: Request):
        try:
            with factory() as db:
                principal = identity(request, db)
                require_admin(principal, settings)
        except HTTPException:
            return RedirectResponse("/admin/login", status_code=303)
        return FileResponse(static / "admin.html")

    return app
