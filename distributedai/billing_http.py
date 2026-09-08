# SPDX-License-Identifier: AGPL-3.0-only
"""Optional billing HTTP boundary. Checkout return URLs never grant entitlements.

A pending checkout is persisted before contacting Stripe. An ambiguous provider failure
retains it for operator reconciliation rather than silently creating another subscription.
Only a signed completion tied to that pending row can register a new subscription.
"""
import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
import json
import re
import secrets
from urllib.parse import urlparse

import httpx
from sqlalchemy import Boolean, Column, DateTime, MetaData, String, Table, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse
from starlette.routing import Route

from .billing import BillingAccount, ProviderEvent, StripeProvider
from .store import Org, Principal, ServiceError

metadata = MetaData()
pending = Table("billing_checkouts", metadata,
    Column("reference", String(64), primary_key=True),
    Column("org_id", String(32), nullable=False, unique=True),
    Column("provider", String(20), nullable=False),
    Column("price_id", String(200), nullable=False),
    Column("session_id", String(200), nullable=True, unique=True),
    Column("completed", Boolean, nullable=False, default=False),
    Column("created_at", DateTime, nullable=False))
MAX_BODY = 131072


def _error(exc):
    code = getattr(exc, "code", "provider_error")
    status = {"unknown_provider": 404, "not_supported": 501, "conflict": 409,
              "invalid_argument": 400, "webhook_verification_failed": 400,
              "invalid_webhook": 400, "unsupported_event": 400}.get(code, 503)
    return JSONResponse({"error": "Billing request could not be completed", "code": code}, status)


def _stripe_url(value):
    parsed = urlparse(value or "")
    if parsed.scheme != "https" or parsed.hostname not in {"checkout.stripe.com", "billing.stripe.com"} or parsed.username:
        raise ServiceError("provider_error", "Invalid provider URL")
    return value


def _binding(store, org_id):
    with Session(store._engine) as sess:
        account = sess.execute(select(BillingAccount).where(BillingAccount.org_id == org_id)).scalar_one_or_none()
        if account and account.provider_subscription_id:
            return account.provider, account.provider_customer_id
    return None, None


def _create_checkout(store, actor, provider, price_id, origin):
    if _binding(store, actor.org_id)[0]:
        raise ServiceError("conflict", "Use billing portal for an existing subscription")
    reference = secrets.token_urlsafe(32)
    try:
        with store._engine.begin() as conn:
            conn.execute(pending.insert().values(reference=reference, org_id=actor.org_id,
                provider=provider.name, price_id=price_id, completed=False,
                created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    except IntegrityError:
        raise ServiceError("conflict", "Checkout already pending; reconcile before retrying") from None
    # Do not retry this mutation after a network timeout. A pending row deliberately
    # remains as evidence that the provider may have created a checkout session.
    result = provider.create_checkout_session(customer_id=None, price_id=price_id,
        success_url=origin + "/manage/", cancel_url=origin + "/manage/", reference=reference)
    session_id = result.get("session_id")
    if not isinstance(session_id, str) or not re.fullmatch(r"cs_[A-Za-z0-9_]{1,190}", session_id):
        raise ServiceError("provider_error", "Invalid session ID")
    url = _stripe_url(result.get("url"))
    with store._engine.begin() as conn:
        conn.execute(update(pending).where(pending.c.reference == reference).values(session_id=session_id))
    return {"provider": provider.name, "url": url}


def _complete_checkout(store, provider, event):
    obj = event["data"]["object"]
    if obj.get("mode") != "subscription" or obj.get("status") != "complete":
        raise ServiceError("invalid_webhook", "Invalid checkout state")
    session_id, reference = obj.get("id"), obj.get("client_reference_id")
    with store._engine.connect() as conn:
        row = conn.execute(select(pending).where(pending.c.session_id == session_id,
            pending.c.reference == reference, pending.c.provider == "stripe")).mappings().first()
    if row is None:
        raise ServiceError("invalid_webhook", "Unregistered checkout")
    if row["completed"]:
        return {"received": True, "duplicate": True}
    subscription, customer = obj.get("subscription"), obj.get("customer")
    if not isinstance(subscription, str) or not re.fullmatch(r"sub_[A-Za-z0-9_]{1,190}", subscription):
        raise ServiceError("invalid_webhook", "Invalid subscription")
    if not isinstance(customer, str) or not re.fullmatch(r"cus_[A-Za-z0-9_]{1,190}", customer):
        raise ServiceError("invalid_webhook", "Invalid customer")
    # Fetch current provider state. Neither redirect parameters nor client metadata
    # supply paid status, product entitlement or an organisation binding.
    response = provider._client.get("/v1/subscriptions/" + subscription,
                                    headers={"Authorization": "Bearer " + provider._api_key})
    if response.status_code != 200 or len(response.content) > MAX_BODY:
        raise ServiceError("provider_error", "Subscription retrieval failed")
    current = response.json()
    items = current["items"]["data"]
    if (current.get("id") != subscription or current.get("customer") != customer or len(items) != 1
            or items[0]["price"]["id"] != row["price_id"]):
        raise ServiceError("invalid_webhook", "Subscription does not match checkout")
    verified = ProviderEvent(provider="stripe", event_id=str(event["id"]),
        event_time=datetime.fromtimestamp(int(event["created"]), timezone.utc).replace(tzinfo=None),
        subscription_id=subscription, customer_id=customer, status=current.get("status"),
        price_id=row["price_id"], kind="checkout.session.completed")
    with Session(store._engine) as sess, sess.begin():
        # The organisation lock serialises different checkouts/binding attempts. Pending
        # and event mutations commit together with registration and entitlement change.
        sess.execute(select(Org.id).where(Org.id == row["org_id"]).with_for_update()).scalar_one()
        locked = sess.execute(select(pending).where(pending.c.reference == reference).with_for_update()).mappings().one()
        if locked["completed"]:
            return {"received": True, "duplicate": True}
        account = sess.execute(select(BillingAccount).where(BillingAccount.org_id == row["org_id"])).scalar_one_or_none()
        if account and account.provider_subscription_id and account.provider_subscription_id != subscription:
            raise ServiceError("conflict", "Account has another subscription")
        store.billing.register_subscription(sess, row["org_id"], "stripe", customer, subscription)
        sess.flush()
        result = store.billing.process_event(sess, verified)
        sess.execute(update(pending).where(pending.c.reference == reference).values(completed=True))
        return {"received": True, "applied": bool(result.get("applied"))}


def webhook_routes(store):
    async def webhook(request):
        if not store.billing.enabled:
            return JSONResponse({"error": "Billing disabled"}, 404)
        try:
            provider = store.billing.provider(request.path_params["provider"])
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > MAX_BODY:
                    return JSONResponse({"error": "Request too large"}, 413)
            try:
                await asyncio.to_thread(store.billing_webhook, provider.name, dict(request.headers), bytes(body))
            except ServiceError as exc:
                # This branch is reachable only AFTER Stripe's signature verification.
                if exc.code != "unsupported_event" or not isinstance(provider, StripeProvider):
                    raise
                event = json.loads(body)
                if event.get("type") != "checkout.session.completed":
                    return JSONResponse({"received": True, "ignored": True})
                await asyncio.to_thread(_complete_checkout, store, provider, event)
            return JSONResponse({"received": True})
        except (ServiceError, httpx.HTTPError) as exc:
            return _error(exc)
        except (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError):
            return JSONResponse({"error": "Invalid billing event"}, 400)
        except IntegrityError:
            # Concurrent duplicate delivery: retry safely against the committed ledger.
            return JSONResponse({"error": "Retry billing event"}, 503)
    return [Route("/billing/webhooks/{provider}", webhook, methods=["POST"])]


def billing_routes(store, settings, identity, csrf):
    async def actor(request):
        value = await identity(request)
        if not isinstance(value, Principal):
            return None
        verified = await asyncio.to_thread(store.resolve_principal, value.id)
        return verified if verified and verified.is_org_admin else None

    def available():
        return {name: {"checkout": isinstance(provider, StripeProvider) and bool(provider._api_key),
                       "portal": isinstance(provider, StripeProvider) and bool(provider._api_key)}
                for name, provider in store.billing._providers.items()}

    async def options(request):
        owner = await actor(request)
        if owner is None:
            return JSONResponse({"error": "Organisation administrator required"}, 403)
        try:
            status = await asyncio.to_thread(store.dispatch, owner, "billing_status", {})
            return JSONResponse({"status": status, "plans": {name: asdict(limits) for name, limits in store.billing.plans.items()},
                                 "providers": available() if store.billing.enabled else {},
                                 "prices": [{"provider": key.split(":", 1)[0], "plan": value}
                                            for key, value in settings.billing_prices.items() if ":" in key]})
        except ServiceError as exc:
            return _error(exc)

    async def action(request):
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        owner = await actor(request)
        if owner is None:
            return JSONResponse({"error": "Organisation administrator required"}, 403)
        if not store.billing.enabled:
            return JSONResponse({"error": "Billing disabled"}, 404)
        try:
            body = await request.body()
            if len(body) > 4096:
                raise ValueError()
            data = json.loads(body)
            checkout = request.url.path.endswith("/checkout")
            if not isinstance(data, dict) or set(data) != ({"provider", "plan"} if checkout else {"provider"}):
                raise ValueError()
            name = data["provider"]
            if not isinstance(name, str):
                raise ValueError()
            provider = store.billing.provider(name)
            if not isinstance(provider, StripeProvider) or not provider._api_key:
                raise ServiceError("not_supported", "Hosted payment flow unavailable")
            parsed = urlparse(settings.public_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if checkout:
                plan = data["plan"]
                if not isinstance(plan, str) or plan not in store.billing.plans:
                    raise ValueError()
                prices = [price.split(":", 1)[1] for price, target in settings.billing_prices.items()
                          if price.startswith(name + ":") and target == plan]
                if len(prices) != 1:
                    raise ValueError()
                result = await asyncio.to_thread(_create_checkout, store, owner, provider, prices[0], origin)
            else:
                bound_provider, customer = await asyncio.to_thread(_binding, store, owner.org_id)
                if bound_provider != name or not customer:
                    raise ValueError()
                result = await asyncio.to_thread(provider.create_portal_session, customer_id=customer,
                                                return_url=origin + "/manage/")
                result = {"provider": name, "url": _stripe_url(result.get("url"))}
            return JSONResponse(result)
        except (ServiceError, httpx.HTTPError) as exc:
            return _error(exc)
        except (ValueError, TypeError, KeyError, AttributeError):
            return JSONResponse({"error": "Invalid billing request"}, 400)
    return [Route("/billing/options", options), Route("/billing/checkout", action, methods=["POST"]),
            Route("/billing/portal", action, methods=["POST"])]
