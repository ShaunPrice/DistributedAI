# SPDX-License-Identifier: AGPL-3.0-only
"""Payment provider contracts and HTTPS adapters; independent of SQL and web presentation."""
import hmac
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
import httpx
from ..domain import ServiceError

@dataclass(frozen=True)
class ProviderEvent:
    """A verified, provider-neutral subscription event."""

    provider: str
    event_id: str
    event_time: datetime  # naive UTC, matching store timestamps
    subscription_id: str
    customer_id: str | None
    status: str | None
    price_id: str | None
    kind: str


def _header(headers: dict, name: str) -> str | None:
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == name:
            return value
    return None


# ---------------------------------------------------------------------------
# Payment providers
# ---------------------------------------------------------------------------


class PaymentProvider:
    """Provider-neutral adapter. ``verify_and_parse`` MUST authenticate the webhook before
    parsing; checkout/portal are optional (root integrates the UI routes)."""

    name = "abstract"

    def verify_and_parse(self, headers: dict, body: bytes) -> ProviderEvent:
        raise NotImplementedError

    def create_checkout_session(self, *, customer_id: str | None, price_id: str,
                                success_url: str, cancel_url: str,
                                reference: str) -> dict:
        raise ServiceError("not_supported", f"{self.name} checkout adapter not implemented")

    def create_portal_session(self, *, customer_id: str, return_url: str) -> dict:
        raise ServiceError("not_supported", f"{self.name} portal adapter not implemented")


class StripeProvider(PaymentProvider):
    """Stripe with signed-webhook verification (Stripe-Signature: t=...,v1=... over
    ``{t}.{body}`` with the endpoint signing secret, constant-time compare, replay window)."""

    name = "stripe"

    def __init__(self, signing_secret: str, *, api_key: str = "", tolerance: int = 300,
                 transport: httpx.BaseTransport | None = None,
                 clock=time.time) -> None:
        if not signing_secret:
            raise ValueError("StripeProvider requires the webhook signing secret")
        self._secret = signing_secret.encode("utf-8")
        self._api_key = api_key
        self._tolerance = tolerance
        self._clock = clock
        self._client = httpx.Client(base_url="https://api.stripe.com",
                                    transport=transport, timeout=10.0)

    def verify_and_parse(self, headers: dict, body: bytes) -> ProviderEvent:
        header = _header(headers, "stripe-signature")
        if not header:
            raise ServiceError("webhook_verification_failed", "missing Stripe-Signature")
        timestamp, candidates = None, []
        for item in header.split(","):
            key, _, value = item.strip().partition("=")
            if key == "t":
                timestamp = value
            elif key == "v1":
                candidates.append(value)
        if timestamp is None or not timestamp.isdigit() or not candidates:
            raise ServiceError("webhook_verification_failed", "malformed Stripe-Signature")
        if abs(self._clock() - int(timestamp)) > self._tolerance:
            raise ServiceError("webhook_verification_failed",
                               "signature timestamp outside tolerance")
        signed = f"{timestamp}.".encode("utf-8") + body
        expected = hmac.new(self._secret, signed, "sha256").hexdigest()
        if not any(hmac.compare_digest(expected, c) for c in candidates):
            raise ServiceError("webhook_verification_failed", "signature mismatch")
        try:
            event = json.loads(body)
            event_id = event["id"]
            event_type = event["type"]
            created = int(event["created"])
            obj = event["data"]["object"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ServiceError("invalid_webhook", "unparseable Stripe event") from exc
        if not isinstance(event_type, str):
            raise ServiceError("invalid_webhook", "Invalid event type")
        if not event_type.startswith("customer.subscription."):
            raise ServiceError("unsupported_event",
                               f"unhandled Stripe event type '{event_type}'")
        try:
            price_id = obj["items"]["data"][0]["price"]["id"]
        except (KeyError, IndexError, TypeError):
            price_id = None
        return ProviderEvent(
            provider=self.name, event_id=str(event_id),
            event_time=datetime.fromtimestamp(created, tz=timezone.utc).replace(tzinfo=None),
            subscription_id=str(obj.get("id") or ""),
            customer_id=obj.get("customer"),
            status=obj.get("status"), price_id=price_id, kind=event_type,
        )

    def _api(self, path: str, data: dict) -> dict:
        if not self._api_key:
            raise ServiceError("not_supported", "Stripe API key not configured")
        response = self._client.post(path, data=data,
                                     headers={"Authorization": f"Bearer {self._api_key}"})
        if response.status_code != 200:
            raise ServiceError("provider_error", f"Stripe returned {response.status_code}")
        return response.json()

    def create_checkout_session(self, *, customer_id: str | None, price_id: str,
                                success_url: str, cancel_url: str,
                                reference: str) -> dict:
        data = {"mode": "subscription", "line_items[0][price]": price_id,
                "line_items[0][quantity]": "1", "success_url": success_url,
                "cancel_url": cancel_url, "client_reference_id": reference}
        if customer_id:
            data["customer"] = customer_id
        session = self._api("/v1/checkout/sessions", data)
        return {"provider": self.name, "session_id": session.get("id"),
                "url": session.get("url")}

    def create_portal_session(self, *, customer_id: str, return_url: str) -> dict:
        session = self._api("/v1/billing_portal/sessions",
                            {"customer": customer_id, "return_url": return_url})
        return {"provider": self.name, "url": session.get("url")}


class PayPalProvider(PaymentProvider):
    """PayPal with verification through PayPal's trusted verify-webhook-signature API
    (OAuth client credentials + POST /v1/notifications/verify-webhook-signature). PayPal
    does not offer a merchant-side shared-HMAC scheme, so none is faked here."""

    name = "paypal"

    _REQUIRED_HEADERS = ("paypal-transmission-id", "paypal-transmission-time",
                         "paypal-transmission-sig", "paypal-cert-url", "paypal-auth-algo")

    def __init__(self, client_id: str, client_secret: str, webhook_id: str, *,
                 api_base: str = "https://api-m.paypal.com",
                 transport: httpx.BaseTransport | None = None) -> None:
        if not (client_id and client_secret and webhook_id):
            raise ValueError("PayPalProvider requires client_id, client_secret, webhook_id")
        self._auth = (client_id, client_secret)
        self._webhook_id = webhook_id
        self._client = httpx.Client(base_url=api_base, transport=transport, timeout=10.0)

    def verify_and_parse(self, headers: dict, body: bytes) -> ProviderEvent:
        fields = {name: _header(headers, name) for name in self._REQUIRED_HEADERS}
        missing = [name for name, value in fields.items() if not value]
        if missing:
            raise ServiceError("webhook_verification_failed",
                               f"missing PayPal headers: {missing}")
        try:
            event = json.loads(body)
        except ValueError as exc:
            raise ServiceError("invalid_webhook", "unparseable PayPal event") from exc
        token_response = self._client.post("/v1/oauth2/token",
                                           data={"grant_type": "client_credentials"},
                                           auth=self._auth)
        if token_response.status_code != 200:
            raise ServiceError("webhook_verification_failed",
                               "could not authenticate to PayPal")
        token = token_response.json().get("access_token", "")
        verification = self._client.post(
            "/v1/notifications/verify-webhook-signature",
            json={"auth_algo": fields["paypal-auth-algo"],
                  "cert_url": fields["paypal-cert-url"],
                  "transmission_id": fields["paypal-transmission-id"],
                  "transmission_sig": fields["paypal-transmission-sig"],
                  "transmission_time": fields["paypal-transmission-time"],
                  "webhook_id": self._webhook_id,
                  "webhook_event": event},
            headers={"Authorization": f"Bearer {token}"},
        )
        if (verification.status_code != 200
                or verification.json().get("verification_status") != "SUCCESS"):
            raise ServiceError("webhook_verification_failed",
                               "PayPal rejected the webhook signature")
        event_type = event.get("event_type", "")
        if not event_type.startswith("BILLING.SUBSCRIPTION."):
            raise ServiceError("unsupported_event",
                               f"unhandled PayPal event type '{event_type}'")
        resource = event.get("resource") or {}
        raw_time = event.get("create_time") or resource.get("update_time") or ""
        try:
            event_time = datetime.fromisoformat(
                raw_time.replace("Z", "+00:00")
            ).astimezone(timezone.utc).replace(tzinfo=None)
            event_id = str(event["id"])
            subscription_id = str(resource["id"])
        except (ValueError, KeyError, TypeError) as exc:
            raise ServiceError("invalid_webhook", "malformed PayPal event fields") from exc
        return ProviderEvent(
            provider=self.name, event_id=event_id, event_time=event_time,
            subscription_id=subscription_id, customer_id=resource.get("subscriber_id"),
            status=resource.get("status"), price_id=resource.get("plan_id"),
            kind=event_type,
        )


