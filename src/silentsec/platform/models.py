"""Control-plane schema. Public identifiers are opaque UUIDs, never filesystem paths."""

import time
import uuid

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def now():
    return int(time.time())


def uid():
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Record:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    created_at: Mapped[int] = mapped_column(BigInteger, default=now)


class User(Record, Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("issuer", "subject"),)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    issuer: Mapped[str] = mapped_column(String(500))
    subject: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20), default="active")
    updated_at: Mapped[int] = mapped_column(BigInteger, default=now)


class PlatformRole(Base):
    __tablename__ = "user_platform_roles"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(30), primary_key=True)


class Organization(Record, Base):
    __tablename__ = "organizations"
    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(80), unique=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(20), default="active")
    billing_timezone: Mapped[str] = mapped_column(String(80), default="UTC")
    retention_days: Mapped[int] = mapped_column(Integer, default=7)
    lock_version: Mapped[int] = mapped_column(Integer, default=0)
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[int] = mapped_column(BigInteger, default=now)


class Membership(Record, Base):
    __tablename__ = "organization_memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(20))


class Plan(Base):
    __tablename__ = "plans"
    key: Mapped[str] = mapped_column(String(30), primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    version: Mapped[int] = mapped_column(Integer, default=1)
    entitlements: Mapped[dict] = mapped_column(JSON)


class Subscription(Record, Base):
    __tablename__ = "subscriptions"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), unique=True)
    plan_key: Mapped[str] = mapped_column(ForeignKey("plans.key"), default="free")
    status: Mapped[str] = mapped_column(String(30), default="active")
    provider: Mapped[str | None] = mapped_column(String(40))
    provider_customer_id: Mapped[str | None] = mapped_column(String(255))
    provider_subscription_id: Mapped[str | None] = mapped_column(String(255), unique=True)
    period_start: Mapped[int | None] = mapped_column(BigInteger)
    period_end: Mapped[int | None] = mapped_column(BigInteger)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, default=False)
    cancelled_at: Mapped[int | None] = mapped_column(BigInteger)
    provider_event_at: Mapped[int] = mapped_column(BigInteger, default=0)
    contract: Mapped[dict] = mapped_column(JSON, default=dict)


class BillingAccount(Record, Base):
    __tablename__ = "billing_accounts"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), unique=True)


class Repository(Record, Base):
    __tablename__ = "repositories"
    __table_args__ = (UniqueConstraint("organization_id", "provider", "external_id"),)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    provider: Mapped[str] = mapped_column(String(30))
    external_id: Mapped[str] = mapped_column(String(255))
    canonical_url: Mapped[str] = mapped_column(String(500))
    visibility: Mapped[str] = mapped_column(String(20), default="public")
    credential_reference: Mapped[str | None] = mapped_column(String(255))


class ApiKey(Record, Base):
    __tablename__ = "api_keys"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    prefix: Mapped[str] = mapped_column(String(16), unique=True)
    salt: Mapped[str] = mapped_column(String(64))
    key_hash: Mapped[str] = mapped_column(String(128))
    scopes: Mapped[list] = mapped_column(JSON)
    expires_at: Mapped[int] = mapped_column(BigInteger)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger)


class AuditEvent(Record, Base):
    __tablename__ = "audit_events"
    organization_id: Mapped[str | None] = mapped_column(String(36), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(36))
    action: Mapped[str] = mapped_column(String(100))
    target: Mapped[str] = mapped_column(String(255))
    request_id: Mapped[str] = mapped_column(String(36))
    safe_metadata: Mapped[dict] = mapped_column(JSON, default=dict)


class Session(Record, Base):
    __tablename__ = "platform_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    active_organization_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"))
    expires_at: Mapped[int] = mapped_column(BigInteger)
    authenticated_at: Mapped[int] = mapped_column(BigInteger)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    admin: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger)


class LoginAttempt(Record, Base):
    __tablename__ = "oidc_attempts"
    state_hash: Mapped[str] = mapped_column(String(64), unique=True)
    nonce: Mapped[str] = mapped_column(String(100))
    verifier: Mapped[str] = mapped_column(String(128))
    admin: Mapped[bool] = mapped_column(Boolean)
    expires_at: Mapped[int] = mapped_column(BigInteger)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class RateBucket(Base):
    __tablename__ = "rate_buckets"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    window: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=1)


class Idempotency(Record, Base):
    __tablename__ = "idempotency_records"
    __table_args__ = (UniqueConstraint("scope", "key"),)
    scope: Mapped[str] = mapped_column(String(100))
    key: Mapped[str] = mapped_column(String(100))
    payload_hash: Mapped[str] = mapped_column(String(64))
    response: Mapped[dict] = mapped_column(JSON, default=dict)


class CreditGrant(Record, Base):
    __tablename__ = "credit_grants"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    amount: Mapped[int] = mapped_column(Integer)
    grant_type: Mapped[str] = mapped_column(String(30))
    valid_from: Mapped[int] = mapped_column(BigInteger)
    expires_at: Mapped[int] = mapped_column(BigInteger)
    idempotency_key: Mapped[str] = mapped_column(String(160), unique=True)


class Reservation(Record, Base):
    __tablename__ = "usage_reservations"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    job_id: Mapped[str] = mapped_column(String(36), unique=True)
    operation: Mapped[str] = mapped_column(String(40), default="standard_scan")
    units: Mapped[int] = mapped_column(Integer, default=1)
    state: Mapped[str] = mapped_column(String(20), default="reserved")
    grant_id: Mapped[str | None] = mapped_column(ForeignKey("credit_grants.id"))
    expires_at: Mapped[int] = mapped_column(BigInteger)
    idempotency_key: Mapped[str] = mapped_column(String(160), unique=True)


class LedgerEntry(Record, Base):
    __tablename__ = "usage_ledger_entries"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    grant_id: Mapped[str | None] = mapped_column(ForeignKey("credit_grants.id"))
    reservation_id: Mapped[str | None] = mapped_column(ForeignKey("usage_reservations.id"))
    job_id: Mapped[str | None] = mapped_column(String(36))
    operation: Mapped[str] = mapped_column(String(40), default="standard_scan")
    kind: Mapped[str] = mapped_column(String(30))
    units: Mapped[int] = mapped_column(Integer)
    idempotency_key: Mapped[str] = mapped_column(String(160), unique=True)


class EntitlementSnapshot(Record, Base):
    __tablename__ = "entitlement_snapshots"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    plan_key: Mapped[str] = mapped_column(String(30))
    version: Mapped[int] = mapped_column(Integer)
    limits: Mapped[dict] = mapped_column(JSON)


class ScanJob(Record, Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (UniqueConstraint("organization_id", "idempotency_key"),)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    requester_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    repository_id: Mapped[str | None] = mapped_column(ForeignKey("repositories.id"))
    source_kind: Mapped[str] = mapped_column(String(20))
    source_reference: Mapped[str] = mapped_column(String(500))
    source_name: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    idempotency_key: Mapped[str] = mapped_column(String(100))
    request_hash: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[int | None] = mapped_column(BigInteger)
    finished_at: Mapped[int | None] = mapped_column(BigInteger)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(80))
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("entitlement_snapshots.id"))
    reservation_id: Mapped[str | None] = mapped_column(ForeignKey("usage_reservations.id"))
    worker_token: Mapped[str | None] = mapped_column(String(64))
    lease_expires_at: Mapped[int | None] = mapped_column(BigInteger)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    execution_started: Mapped[bool] = mapped_column(Boolean, default=False)


class ScanResult(Base):
    __tablename__ = "scan_results"
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    summary: Mapped[dict] = mapped_column(JSON)
    findings: Mapped[list] = mapped_column(JSON)
    graph: Mapped[dict] = mapped_column(JSON)
    patterns: Mapped[dict] = mapped_column(JSON)
    report: Mapped[str] = mapped_column(Text)
    analysis_version: Mapped[str] = mapped_column(String(100))
    expires_at: Mapped[int] = mapped_column(BigInteger, index=True)


class WebhookEvent(Base):
    __tablename__ = "billing_webhook_events"
    provider_event_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    received_at: Mapped[int] = mapped_column(BigInteger, default=now)
    status: Mapped[str] = mapped_column(String(30))
    payload_hash: Mapped[str] = mapped_column(String(64))


class SupportAccess(Record, Base):
    __tablename__ = "support_access_grants"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    scope: Mapped[str] = mapped_column(String(40))
    expires_at: Mapped[int] = mapped_column(BigInteger)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger)


class PatternPack(Record, Base):
    __tablename__ = "pattern_packs"
    __table_args__ = (UniqueConstraint("organization_id", "version"),)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    rules: Mapped[list] = mapped_column(JSON)
    approved_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class WorkstationRepository(Record, Base):
    __tablename__ = "workstation_repositories"
    __table_args__ = (UniqueConstraint("organization_id", "root_path"),)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    root_path: Mapped[str] = mapped_column(String(4096))
    name: Mapped[str] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class OperationRequest(Base):
    __tablename__ = "workstation_requests"
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    operation: Mapped[str] = mapped_column(String(30))
    arguments: Mapped[dict] = mapped_column(JSON)
    repository_id: Mapped[str | None] = mapped_column(ForeignKey("workstation_repositories.id"))
    input_ref: Mapped[str | None] = mapped_column(String(36))


class OperationResult(Base):
    __tablename__ = "workstation_results"
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    payload: Mapped[dict] = mapped_column(JSON)
    contexts: Mapped[dict] = mapped_column(JSON, default=dict)
    sarif: Mapped[dict | None] = mapped_column(JSON)
    report: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[int] = mapped_column(BigInteger, index=True)


class OperationQuota(Record, Base):
    __tablename__ = "operation_quota_reservations"
    __table_args__ = (UniqueConstraint("organization_id", "job_id", "operation"),)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    operation: Mapped[str] = mapped_column(String(40))
    units: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(20), default="reserved")
    period_start: Mapped[int] = mapped_column(BigInteger)
    expires_at: Mapped[int] = mapped_column(BigInteger)
