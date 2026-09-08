# SPDX-License-Identifier: AGPL-3.0-only
"""SQL-free billing use cases, injected checkout persistence and provider workflows."""
from dataclasses import asdict
from datetime import datetime, timezone
import json
import re
import secrets
from typing import Protocol
from urllib.parse import urlparse

import httpx

from .payments import ProviderEvent, StripeProvider
from ..domain import Principal, ServiceError

MAX_BODY = 131072


class CheckoutPersistence(Protocol):
    def binding(self, org_id): ...
    def reserve(self, org_id, reference, provider, price_id): ...
    def set_session(self, reference, session_id): ...
    def find(self, session_id, reference, provider): ...
    def complete(self, row, reference, event): ...
    def apply_event(self, event): ...


def _stripe_url(value):
    parsed = urlparse(value or "")
    if parsed.scheme != "https" or parsed.hostname not in {"checkout.stripe.com", "billing.stripe.com"} or parsed.username:
        raise ServiceError("provider_error", "Invalid provider URL")
    return value


class BillingApplication:
    def __init__(self, store, repository: CheckoutPersistence, settings=None):
        self._store, self._repository, self.settings = store, repository, settings

    @property
    def enabled(self):
        return self._store.billing.enabled

    def resolve_owner(self, value):
        if not isinstance(value, Principal):
            return None
        verified = self._store.resolve_principal(value.id)
        return verified if verified and verified.is_org_admin else None

    def options(self, owner):
        billing = self._store.billing
        available = {name: {"checkout": isinstance(provider, StripeProvider) and bool(provider._api_key),
                           "portal": isinstance(provider, StripeProvider) and bool(provider._api_key)}
                     for name, provider in billing._providers.items()}
        return {"status": self._store.dispatch(owner, "billing_status", {}),
                "plans": {name: asdict(limits) for name, limits in billing.plans.items()},
                "providers": available if billing.enabled else {},
                "prices": [{"provider": key.split(":", 1)[0], "plan": value}
                           for key, value in self.settings.billing_prices.items() if ":" in key]}

    def _create_checkout(self, owner, provider, price_id, origin):
        if self._repository.binding(owner.org_id)[0]:
            raise ServiceError("conflict", "Use billing portal for an existing subscription")
        reference = secrets.token_urlsafe(32)
        self._repository.reserve(owner.org_id, reference, provider.name, price_id)
        # Ambiguous failure leaves the durable pending row; never automatically retry.
        result = provider.create_checkout_session(customer_id=None, price_id=price_id,
            success_url=origin + "/manage/", cancel_url=origin + "/manage/", reference=reference)
        session_id = result.get("session_id")
        if not isinstance(session_id, str) or not re.fullmatch(r"cs_[A-Za-z0-9_]{1,190}", session_id):
            raise ServiceError("provider_error", "Invalid session ID")
        url = _stripe_url(result.get("url"))
        self._repository.set_session(reference, session_id)
        return {"provider": provider.name, "url": url}

    def action(self, owner, data, *, checkout):
        try:
            if not isinstance(data, dict) or set(data) != ({"provider", "plan"} if checkout else {"provider"}):
                raise ValueError()
            name = data["provider"]
            if not isinstance(name, str):
                raise ValueError()
            billing = self._store.billing
            provider = billing.provider(name)
            if not isinstance(provider, StripeProvider) or not provider._api_key:
                raise ServiceError("not_supported", "Hosted payment flow unavailable")
            parsed = urlparse(self.settings.public_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if checkout:
                plan = data["plan"]
                if not isinstance(plan, str) or plan not in billing.plans:
                    raise ValueError()
                prices = [price.split(":", 1)[1] for price, target in self.settings.billing_prices.items()
                          if price.startswith(name + ":") and target == plan]
                if len(prices) != 1:
                    raise ValueError()
                return self._create_checkout(owner, provider, prices[0], origin)
            bound_provider, customer = self._repository.binding(owner.org_id)
            if bound_provider != name or not customer:
                raise ValueError()
            result = provider.create_portal_session(customer_id=customer, return_url=origin + "/manage/")
            return {"provider": name, "url": _stripe_url(result.get("url"))}
        except httpx.HTTPError:
            raise ServiceError("provider_error", "Provider request failed") from None

    def complete_checkout(self, provider, event):
        obj = event["data"]["object"]
        if obj.get("mode") != "subscription" or obj.get("status") != "complete":
            raise ServiceError("invalid_webhook", "Invalid checkout state")
        reference = obj.get("client_reference_id")
        row = self._repository.find(obj.get("id"), reference, "stripe")
        if row is None:
            raise ServiceError("invalid_webhook", "Unregistered checkout")
        if row["completed"]:
            return {"received": True, "duplicate": True}
        subscription, customer = obj.get("subscription"), obj.get("customer")
        if not isinstance(subscription, str) or not re.fullmatch(r"sub_[A-Za-z0-9_]{1,190}", subscription):
            raise ServiceError("invalid_webhook", "Invalid subscription")
        if not isinstance(customer, str) or not re.fullmatch(r"cus_[A-Za-z0-9_]{1,190}", customer):
            raise ServiceError("invalid_webhook", "Invalid customer")
        # Signed event is necessary but current provider state determines entitlements.
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
        return self._repository.complete(row, reference, verified)

    def webhook(self, provider_name, headers, body):
        try:
            provider = self._store.billing.provider(provider_name)
            try:
                verified = provider.verify_and_parse(headers, body)
                self._repository.apply_event(verified)
            except ServiceError as exc:
                # unsupported_event is raised only after provider signature validation.
                if exc.code != "unsupported_event" or not isinstance(provider, StripeProvider):
                    raise
                event = json.loads(body)
                if event.get("type") != "checkout.session.completed":
                    return {"received": True, "ignored": True}
                self.complete_checkout(provider, event)
            return {"received": True}
        except httpx.HTTPError:
            raise ServiceError("provider_error", "Provider request failed") from None
