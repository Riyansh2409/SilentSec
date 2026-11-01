"""Local platform entry point; intentionally separate from silentsec CLI."""

import argparse
import json
import secrets
import threading
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select

from silentsec.envfile import load_env_file

from . import billing, worker
from .config import Settings
from .db import audit, database, lock_org
from .models import (
    LoginAttempt,
    OperationRequest,
    OperationResult,
    Organization,
    PlatformRole,
    RateBucket,
    ScanJob,
    ScanResult,
    Session,
    User,
    WorkstationRepository,
    now,
    uid,
)


def migrate(settings):
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    config.set_main_option(
        "sqlalchemy.url", settings.database_url.get_secret_value().replace("%", "%%")
    )
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    command.upgrade(config, "head")


def maintenance(factory, settings=None):
    with factory() as db:
        org_ids = list(db.scalars(select(Organization.id)))
    for org_id in org_ids:
        with factory.begin() as db:
            org = lock_org(db, org_id)
            if org.status == "active":
                billing.ensure_month(db, org)
            billing.expire_reservations(db, org_id)
            from .workstation import expire_quotas

            expire_quotas(db, org_id)
            count = db.execute(
                delete(ScanResult).where(
                    ScanResult.organization_id == org_id, ScanResult.expires_at <= now()
                )
            ).rowcount
            db.execute(
                delete(OperationResult).where(
                    OperationResult.organization_id == org_id, OperationResult.expires_at <= now()
                )
            )
            if count:
                audit(db, None, "retention.purge", org_id, uid(), org_id, amount=count)
    with factory.begin() as db:
        db.execute(delete(LoginAttempt).where(LoginAttempt.expires_at <= now()))
        db.execute(delete(Session).where(Session.expires_at < now() - 86400))
        db.execute(delete(RateBucket).where(RateBucket.window < now() // 60 - 1440))
        terminal = list(
            db.scalars(
                select(ScanJob.source_reference).where(
                    ScanJob.source_kind == "upload",
                    ScanJob.status.in_(["succeeded", "failed", "cancelled"]),
                )
            )
        )
        active = set(
            db.scalars(
                select(ScanJob.source_reference).where(
                    ScanJob.source_kind == "upload", ScanJob.status.in_(["queued", "running"])
                )
            )
        )
        operations = db.execute(
            select(OperationRequest.input_ref, ScanJob.status)
            .join(ScanJob, ScanJob.id == OperationRequest.job_id)
            .where(OperationRequest.input_ref.is_not(None))
        ).all()
        if settings:
            for reference, status in operations:
                path = str(settings.data_dir.resolve() / "inbox" / (reference + ".payload"))
                if status in {"queued", "running"}:
                    active.add(path)
                else:
                    terminal.append(path)
    if settings:
        inbox = settings.data_dir.resolve() / "inbox"
        if inbox.is_dir():
            for path in inbox.glob("*.payload"):
                try:
                    resolved = path.resolve()
                    if resolved.parent != inbox or str(path) in active:
                        continue
                    if str(path) in terminal or path.stat().st_mtime < now() - 86400:
                        path.unlink(missing_ok=True)
                except OSError:
                    # Another worker may remove the file between glob/stat, or
                    # a still-closing scanner handle may need a later retry.
                    continue


def main():
    parser = argparse.ArgumentParser(description="SilentSec SaaS control plane")
    parser.add_argument(
        "command",
        choices=[
            "init-db",
            "seed-dev",
            "serve",
            "worker",
            "maintain",
            "grant-admin",
            "local-config",
            "register-local",
        ],
    )
    parser.add_argument("--email")
    parser.add_argument("--name", default="Developer")
    parser.add_argument("--timezone", default="UTC")
    parser.add_argument("--admin", action="store_true")
    parser.add_argument("--reason")
    parser.add_argument("--port", type=int, default=8780)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--path")
    args = parser.parse_args()
    if args.command == "local-config":
        folder = Path(".platform")
        folder.mkdir(mode=0o700, exist_ok=True)
        path = folder / "dev-settings.json"
        if not path.exists():
            path.write_text(
                json.dumps(
                    {
                        "session_secret": secrets.token_hex(32),
                        "dev_login_code": secrets.token_urlsafe(24),
                    }
                ),
                encoding="utf-8",
            )
            path.chmod(0o600)
        print(
            "Local-only development credentials: .platform/dev-settings.json (do not share or commit)."
        )
        return
    # Optional AI keys and Ollama settings from the checkout's .env (shell
    # variables win). Children get them only for explicit AI jobs (worker.py).
    load_env_file()
    settings = Settings()
    if args.command == "init-db":
        migrate(settings)
    engine, factory = database(settings)
    if args.command == "init-db":
        with factory.begin() as db:
            billing.seed_plans(db)
        print("Platform migrations and plans are ready.")
    elif args.command == "seed-dev":
        if settings.environment == "production" or settings.auth_mode != "development":
            parser.error("Development users cannot be provisioned in production/OIDC mode.")
        if not args.email or "@" not in args.email or len(args.email) > 254:
            parser.error("Provide a development --email.")
        from .auth.routes import provision_org

        with factory.begin() as db:
            email = args.email.strip().casefold()
            user = db.scalar(select(User).where(User.email == email))
            if not user:
                user = User(email=email, issuer="development", subject=email, name=args.name[:120])
                db.add(user)
                db.flush()
                provision_org(db, user, args.name + " workspace", billing_timezone=args.timezone)
            if args.admin and not db.get(PlatformRole, (user.id, "platform_admin")):
                db.add(PlatformRole(user_id=user.id, role="platform_admin"))
                audit(
                    db,
                    None,
                    "platform_role.provision_dev",
                    user.id,
                    uid(),
                    reason="Explicit local development provisioning",
                )
        print("Development identity provisioned. Administrator simulation is local-only.")
    elif args.command == "register-local":
        if settings.environment == "production" or not settings.workstation_enabled:
            parser.error("Enable local workstation mode in development first.")
        if not args.email or not args.path:
            parser.error("Provide the workspace owner's --email and a local --path.")
        path = Path(args.path).resolve()
        if not path.is_dir() or str(path).startswith(("\\\\", "//")):
            parser.error("Repository must be an existing local folder.")
        with factory.begin() as db:
            user = db.scalar(select(User).where(User.email == args.email.strip().casefold()))
            org = (
                db.scalar(select(Organization).where(Organization.owner_id == user.id))
                if user
                else None
            )
            if not org:
                parser.error("Owner must have an existing workspace.")
            existing = db.scalar(
                select(WorkstationRepository).where(
                    WorkstationRepository.organization_id == org.id,
                    WorkstationRepository.root_path == str(path),
                )
            )
            if not existing:
                db.add(
                    WorkstationRepository(
                        organization_id=org.id, root_path=str(path), name=path.name[:120]
                    )
                )
                audit(
                    db,
                    user.id,
                    "repository.register_local",
                    org.id,
                    uid(),
                    org.id,
                    reason="Explicit operator local-workstation registration",
                )
        print("Local repository registered for the owner's workspace.")
    elif args.command == "grant-admin":
        if not args.email or not args.reason or len(args.reason) < 10:
            parser.error("Provide an existing --email and a --reason (10+ characters).")
        with factory.begin() as db:
            user = db.scalar(
                select(User).where(
                    User.email == args.email.strip().casefold(), User.status == "active"
                )
            )
            if not user:
                parser.error("The identity must first sign in through the configured provider.")
            if not db.get(PlatformRole, (user.id, "platform_admin")):
                db.add(PlatformRole(user_id=user.id, role="platform_admin"))
                audit(db, None, "platform_role.bootstrap", user.id, uid(), reason=args.reason)
        print("Role provisioned. OIDC MFA and recent authentication are still required.")
    elif args.command == "maintain":
        maintenance(factory, settings)
        print("Monthly grants, reservation expiry and result retention processed.")
    elif args.command == "worker":
        if args.once:
            worker.tick(factory, settings)
        else:
            worker.loop(factory, settings, threading.Event())
    elif args.command == "serve":
        import uvicorn

        from .app import create_app

        uvicorn.run(create_app(settings), host="127.0.0.1", port=args.port, log_level="warning")
    engine.dispose()


if __name__ == "__main__":
    main()
