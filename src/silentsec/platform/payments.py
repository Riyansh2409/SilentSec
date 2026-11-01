"""Signed event adapter boundary, not a checkout or a Stripe impersonation.

An external billing adapter must translate verified provider state into this
versioned contract with a monotonic sequence per subscription. Disabled by default.
"""

import hashlib
import hmac
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select

from .db import audit, digest, lock_org
from .models import Subscription, WebhookEvent, now

router = APIRouter()


class BillingEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1]
    id: str = Field(min_length=1, max_length=160)
    subscription_id: str = Field(min_length=1, max_length=255)
    sequence: int = Field(ge=1)
    plan: Literal["free", "pro", "enterprise"]
    status: Literal["active", "trialing", "past_due", "cancelled"]
    period_start: int = Field(ge=0)
    period_end: int = Field(gt=0)
    cancel_at_period_end: bool = False


@router.post("/api/v1/billing/webhooks/adapter")
async def event(request: Request):
    settings = request.app.state.settings
    secret = settings.payment_webhook_secret.get_secret_value()
    if len(secret) < 32:
        raise HTTPException(404, "Billing event adapter is not configured.")
    raw = await request.body()
    if len(raw) > 16000:
        raise HTTPException(413, "Event too large.")
    try:
        timestamp = int(request.headers.get("X-Billing-Timestamp", "0"))
        if abs(now() - timestamp) > 300:
            raise ValueError("Expired signature")
        expected = hmac.new(
            secret.encode(), str(timestamp).encode() + b"." + raw, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, request.headers.get("X-Billing-Signature", "")):
            raise ValueError("Invalid signature")
        body = BillingEvent.model_validate_json(raw)
        if body.period_end <= body.period_start:
            raise ValueError("Invalid period")
    except (ValueError, ValidationError) as exc:
        raise HTTPException(400, "Invalid signed billing event.") from exc
    with request.app.state.factory.begin() as db:
        subscription = db.scalar(
            select(Subscription).where(
                Subscription.provider_subscription_id == body.subscription_id
            )
        )
        if not subscription:
            raise HTTPException(404, "Subscription not linked to billing adapter.")
        lock_org(db, subscription.organization_id)
        db.refresh(subscription)
        previous = db.get(WebhookEvent, body.id)
        if previous:
            if previous.payload_hash != digest(raw):
                raise HTTPException(409, "Event ID reused with a different payload.")
            return {"status": "duplicate"}
        state = (
            "ignored_out_of_order"
            if body.sequence <= subscription.provider_event_at
            else "processed"
        )
        if state == "processed":
            subscription.plan_key, subscription.status = body.plan, body.status
            subscription.period_start, subscription.period_end = body.period_start, body.period_end
            subscription.cancel_at_period_end = body.cancel_at_period_end
            subscription.cancelled_at = now() if body.status == "cancelled" else None
            subscription.provider_event_at = body.sequence
        db.add(WebhookEvent(provider_event_id=body.id, payload_hash=digest(raw), status=state))
        audit(
            db,
            None,
            "billing.event",
            body.id,
            request.state.request_id,
            subscription.organization_id,
            status=state,
        )
        return {"status": state}
