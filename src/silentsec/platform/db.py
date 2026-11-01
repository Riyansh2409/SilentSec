"""Database lifecycle and transaction helpers shared by API and workers."""

import hashlib
import json
import re

from fastapi import HTTPException
from sqlalchemy import create_engine, event, select, update
from sqlalchemy.orm import sessionmaker

from .models import AuditEvent, Idempotency, Organization, now


def database(settings):
    url = settings.database_url.get_secret_value()
    if url.startswith("sqlite"):
        settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        url,
        pool_pre_ping=True,
        connect_args={"check_same_thread": False, "timeout": 30}
        if url.startswith("sqlite")
        else {},
    )
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def pragmas(connection, _):
            connection.isolation_level = None
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA journal_mode=WAL")

        @event.listens_for(engine, "begin")
        def begin(connection):
            # Local SQLite serializes transactions. PostgreSQL uses the
            # narrower organization row lock instead.
            connection.exec_driver_sql("BEGIN IMMEDIATE")

    return engine, sessionmaker(engine, expire_on_commit=False)


def lock_org(db, org_id):
    # An UPDATE acquires a PostgreSQL row lock and a SQLite write lock BEFORE
    # balance/concurrency reads. A mutable version is not a credit balance.
    count = db.execute(
        update(Organization)
        .where(Organization.id == org_id)
        .values(lock_version=Organization.lock_version + 1)
    ).rowcount
    if not count:
        raise HTTPException(404, "Organization not found.")
    return db.get(Organization, org_id, populate_existing=True)


def digest(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()


def idem_start(db, scope, key, payload):
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,100}", key or ""):
        raise HTTPException(400, "Provide an Idempotency-Key (8–100 letters, digits, _ or -).")
    previous = db.scalar(
        select(Idempotency).where(Idempotency.scope == scope, Idempotency.key == key)
    )
    hashed = digest(payload)
    if previous:
        if previous.payload_hash != hashed:
            raise HTTPException(409, "Idempotency key was already used with different input.")
        return previous, True
    row = Idempotency(scope=scope, key=key, payload_hash=hashed)
    db.add(row)
    db.flush()
    return row, False


def audit(db, actor, action, target, request_id, org_id=None, **metadata):
    # Values are an allowlist; callers must not pass source, token or exception data.
    allowed = {
        "reason",
        "role",
        "plan",
        "status",
        "amount",
        "scope",
        "expires_at",
        "error_code",
        "cached",
    }
    from .analysis import safe_text

    safe = {k: safe_text(str(v))[:500] for k, v in metadata.items() if k in allowed}
    db.add(
        AuditEvent(
            organization_id=org_id,
            actor_id=actor,
            action=action,
            target=str(target)[:255],
            request_id=request_id,
            safe_metadata=safe,
        )
    )


def rate_limit(factory, key, maximum, seconds=60):
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    from .models import RateBucket

    with factory.begin() as db:
        insert = sqlite_insert if db.bind.dialect.name == "sqlite" else pg_insert
        row = insert(RateBucket).values(key=digest(key.encode()), window=now() // seconds, count=1)
        statement = row.on_conflict_do_update(
            index_elements=["key", "window"], set_={"count": RateBucket.count + 1}
        ).returning(RateBucket.count)
        count = db.scalar(statement)
    if count > maximum:
        raise HTTPException(
            429, "Too many requests. Try again later.", headers={"Retry-After": str(seconds)}
        )
