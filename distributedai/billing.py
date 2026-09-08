# SPDX-License-Identifier: AGPL-3.0-only
"""Optional paid accounts: plan quotas, connection/instance registries, payment providers.

Billing is OFF by default (``Store(url)`` keeps today's unmetered behaviour exactly). When a
deployment opts in (``Store(url, billing_enabled=True, plan_limits=...)``) every organisation
is metered against a plan: active users (principals), logical instances, registered active AI
connections, and stored content bytes. Organisation access controls (scopes, grants, roles)
are unchanged at every tier — a plan never grants or removes access to any scope, and no
project grant ever occurs via payment.

Design constraints honoured here:

- Connections are individually issued client credentials (hashed at rest, returned exactly
  once), not TCP sessions. The transport layer authenticates them with
  ``Store.authenticate_connection`` — an org-admin bearer token must not bypass this.
- Quota checks are atomic across replicas: every check/charge serialises on a per-organisation
  ``org_usage`` row under ``SELECT ... FOR UPDATE`` inside the caller's transaction.
- Payment providers are pluggable behind :class:`PaymentProvider`. Stripe verifies its signed
  webhook locally (HMAC over the timestamped payload); PayPal verifies through PayPal's
  trusted ``verify-webhook-signature`` API — there is no shared-HMAC shortcut for PayPal.
- Provider subscriptions bind to an organisation only via server-side registration
  (``register_subscription``); webhook metadata can never select or create a tenant.
- Webhook events are idempotent by (provider, event_id) and chronologically guarded; an
  equal-timestamp different event fails closed and flags the account for reconciliation.
- An unexpected/lapsed subscription status downgrades the account to the default plan
  (fail-closed). Data is never deleted by billing — over-quota tenants are read-only-ish
  (new writes get ``quota_exceeded``) until they upgrade or prune.
- Billing output is content-blind: account metadata, counters and stable ids only. No memory
  content, message bodies, job results, credentials or key material ever appear here.
"""
from __future__ import annotations

import hmac
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import (
    BigInteger, Boolean, DateTime, ForeignKey, String, UniqueConstraint, func, select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from .store import (
    MAX_NAME,
    AuditLog,
    Base,
    Org,
    Principal,
    PrincipalRow,
    ServiceError,
    _check_keys,
    _digest,
    _iso,
    _new_id,
    _now,
    _str_arg,
)

MIB = 1024 * 1024
GIB = 1024 * MIB

# Provider statuses that keep a subscription entitled. Anything else — including statuses
# this module has never seen — downgrades to the default plan (fail-closed, no deletion).
_ENTITLED_STATUSES = {"active", "trialing"}


# ---------------------------------------------------------------------------
# Plans
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlanLimits:
    """Per-organisation ceilings. ``None`` means unlimited for that dimension."""

    max_users: int | None
    max_instances: int | None
    max_connections: int | None
    max_storage_bytes: int | None


DEFAULT_PLANS: dict[str, PlanLimits] = {
    "free_personal": PlanLimits(1, 1, 2, 10 * MIB),
    "personal_paid": PlanLimits(1, 1, 10, 100 * MIB),
    "org_starter": PlanLimits(10, 5, 25, 1 * GIB),
    "org_business": PlanLimits(100, 25, 250, 10 * GIB),
    "org_enterprise": PlanLimits(1000, 100, 2500, 100 * GIB),
}

_LIMIT_FIELDS = ("max_users", "max_instances", "max_connections", "max_storage_bytes")


# ---------------------------------------------------------------------------
# Registry tables (extend the store's Base so Store.initialize() creates them)
# ---------------------------------------------------------------------------


class LogicalInstance(Base):
    """Tenant-scoped logical grouping of clients. Purely a registry entry — creating one
    provisions no physical container."""

    __tablename__ = "logical_instances"
    __table_args__ = (UniqueConstraint("org_id", "name"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(32), ForeignKey("orgs.id"), index=True)
    name: Mapped[str] = mapped_column(String(MAX_NAME))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class ConnectionRow(Base):
    """An individually issued client credential: separate from the owner principal's token,
    bound to a logical instance. Only the SHA-256 digest is stored."""

    __tablename__ = "connections"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(32), ForeignKey("orgs.id"), index=True)
    owner_principal_id: Mapped[str] = mapped_column(String(32), ForeignKey("principals.id"),
                                                    index=True)
    instance_id: Mapped[str] = mapped_column(String(32), ForeignKey("logical_instances.id"),
                                             index=True)
    credential_digest: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class BillingAccount(Base):
    """One row per organisation: plan, provider binding and the chronological event guard.
    Provider ids are set only by server-side registration, never from webhook payloads."""

    __tablename__ = "billing_accounts"
    __table_args__ = (UniqueConstraint("provider", "provider_subscription_id"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(32), ForeignKey("orgs.id"), unique=True)
    plan: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="registered")
    provider: Mapped[str | None] = mapped_column(String(20), nullable=True)
    provider_customer_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    provider_subscription_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    last_event_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    needs_reconciliation: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class BillingEvent(Base):
    """Processed webhook events — the idempotency ledger. Metadata only, never payloads."""

    __tablename__ = "billing_events"
    __table_args__ = (UniqueConstraint("provider", "event_id"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    provider: Mapped[str] = mapped_column(String(20))
    event_id: Mapped[str] = mapped_column(String(200))
    org_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    event_time: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    applied: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str] = mapped_column(String(100), default="")
    received_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class OrgUsage(Base):
    """Per-organisation explicit storage counter and the row every quota check locks
    (SELECT ... FOR UPDATE) so counting is serialised across replicas."""

    __tablename__ = "org_usage"
    org_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    storage_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectionAuth:
    """Successful connection-credential authentication: the owner's principal identity plus
    the connection/instance the credential is bound to."""

    principal: Principal
    connection_id: str
    instance_id: str


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


# ---------------------------------------------------------------------------
# Billing engine
# ---------------------------------------------------------------------------


class BillingEngine:
    """Quota and subscription logic. Owned by a :class:`~distributedai.store.Store` instance
    (no module-level mutable state); all methods operate inside the caller's transaction."""

    def __init__(self, *, enabled: bool = False, plan_limits: dict | None = None,
                 default_plan: str = "free_personal",
                 price_map: dict[str, str] | None = None) -> None:
        self.enabled = bool(enabled)
        self.plans = dict(DEFAULT_PLANS)
        for name, overrides in (plan_limits or {}).items():
            if not isinstance(overrides, dict):
                raise ValueError(f"plan '{name}' limits must be a dict")
            unknown = set(overrides) - set(_LIMIT_FIELDS)
            if unknown:
                raise ValueError(f"plan '{name}' has unknown limit fields {sorted(unknown)}")
            base = self.plans.get(name)
            merged = {}
            for field_name in _LIMIT_FIELDS:
                if field_name in overrides:
                    value = overrides[field_name]
                    if value is not None and (isinstance(value, bool)
                                              or not isinstance(value, int) or value < 0):
                        raise ValueError(
                            f"plan '{name}' {field_name} must be a non-negative int or None")
                    merged[field_name] = value
                elif base is not None:
                    merged[field_name] = getattr(base, field_name)
                else:
                    raise ValueError(f"new plan '{name}' must define {field_name}")
            self.plans[name] = PlanLimits(**merged)
        if default_plan not in self.plans:
            raise ValueError(f"default plan '{default_plan}' is not a configured plan")
        self.default_plan = default_plan
        # price_map: provider price/plan id (configuration, never hardcoded) -> plan name.
        self.price_map = dict(price_map or {})
        self._providers: dict[str, PaymentProvider] = {}

    # -- provider registry ---------------------------------------------------

    def register_provider(self, provider: PaymentProvider) -> None:
        if not isinstance(provider, PaymentProvider):
            raise ValueError("provider must be a PaymentProvider")
        self._providers[provider.name] = provider

    def provider(self, name: str) -> PaymentProvider:
        provider = self._providers.get(name)
        if provider is None:
            raise ServiceError("unknown_provider", f"no payment provider '{name}' registered")
        return provider

    # -- plan resolution and the cross-replica quota mutex --------------------

    def _lock_usage(self, sess: Session, org_id: str) -> OrgUsage:
        """Lock (creating on first use) the per-org usage row. Every quota check and storage
        charge serialises here, so replica A cannot admit the last free slot while replica B
        does the same — the same pattern as the store's memory mutex."""
        usage = sess.execute(
            select(OrgUsage).where(OrgUsage.org_id == org_id).with_for_update()
        ).scalar_one_or_none()
        if usage is None:
            try:
                with sess.begin_nested():
                    sess.add(OrgUsage(org_id=org_id, storage_bytes=self._storage_size(sess, org_id)))
                    sess.flush()
            except IntegrityError:
                pass  # concurrent creator won; fall through and lock the row
            usage = sess.execute(
                select(OrgUsage).where(OrgUsage.org_id == org_id).with_for_update()
            ).scalar_one()
        return usage

    def limits_for(self, sess: Session, org_id: str) -> tuple[str, PlanLimits]:
        account = sess.execute(
            select(BillingAccount).where(BillingAccount.org_id == org_id)
        ).scalar_one_or_none()
        plan = account.plan if account is not None else self.default_plan
        if account is not None and (account.needs_reconciliation or account.status != "active"):
            plan = self.default_plan
        if plan not in self.plans:  # stale/unknown plan name: fail closed to the default
            plan = self.default_plan
        return plan, self.plans[plan]

    # -- quota checks (called from Store inside the mutating transaction) -----

    def check_user_quota(self, sess: Session, org_id: str) -> None:
        if not self.enabled:
            return
        self._lock_usage(sess, org_id)
        plan, limits = self.limits_for(sess, org_id)
        if limits.max_users is None:
            return
        count = sess.execute(
            select(func.count()).select_from(PrincipalRow)
            .where(PrincipalRow.org_id == org_id, PrincipalRow.active.is_(True))
        ).scalar_one()
        if count >= limits.max_users:
            raise ServiceError("quota_exceeded",
                               f"plan '{plan}' allows {limits.max_users} active user(s)")

    def check_instance_quota(self, sess: Session, org_id: str) -> None:
        if not self.enabled:
            return
        self._lock_usage(sess, org_id)
        plan, limits = self.limits_for(sess, org_id)
        if limits.max_instances is None:
            return
        count = sess.execute(
            select(func.count()).select_from(LogicalInstance)
            .where(LogicalInstance.org_id == org_id, LogicalInstance.active.is_(True))
        ).scalar_one()
        if count >= limits.max_instances:
            raise ServiceError("quota_exceeded",
                               f"plan '{plan}' allows {limits.max_instances} "
                               "logical instance(s)")

    def check_connection_quota(self, sess: Session, org_id: str) -> None:
        if not self.enabled:
            return
        self._lock_usage(sess, org_id)
        plan, limits = self.limits_for(sess, org_id)
        if limits.max_connections is None:
            return
        count = sess.execute(
            select(func.count()).select_from(ConnectionRow)
            .where(ConnectionRow.org_id == org_id, ConnectionRow.active.is_(True))
        ).scalar_one()
        if count >= limits.max_connections:
            raise ServiceError("quota_exceeded",
                               f"plan '{plan}' allows {limits.max_connections} "
                               "active connection(s)")

    def charge_storage(self, sess: Session, org_id: str, nbytes: int) -> None:
        """Reserve ``nbytes`` against the org's storage quota, or raise ``quota_exceeded``.
        Counted as logical UTF-8 payload including provenance and findings. Ciphertext
        expansion and structural database overhead are excluded."""
        if not self.enabled or nbytes <= 0:
            return
        usage = self._lock_usage(sess, org_id)
        plan, limits = self.limits_for(sess, org_id)
        cap = limits.max_storage_bytes
        if cap is not None and usage.storage_bytes + nbytes > cap:
            raise ServiceError("quota_exceeded",
                               f"plan '{plan}' storage quota of {cap} bytes would be exceeded")
        usage.storage_bytes += nbytes
        usage.updated_at = _now()

    @staticmethod
    def _storage_size(sess: Session, org_id: str) -> int:
        from .store import Job, MemoryProposal, MemoryVersion, Message
        total = 0
        for table, fields in ((MemoryProposal, ("content", "source", "findings")),
                              (MemoryVersion, ("content", "source")),
                              (Message, ("body", "findings")),
                              (Job, ("objective", "result", "findings"))):
            for row in sess.execute(select(table).where(table.org_id == org_id)).scalars():
                total += sum(len((getattr(row, field) or "").encode("utf-8")) for field in fields)
        return total

    def recompute_usage(self, sess: Session, org_id: str) -> dict:
        """Reconcile logical UTF-8 payload bytes; encrypted ORM loads preserve the unit."""
        usage = self._lock_usage(sess, org_id)
        total = self._storage_size(sess, org_id)
        usage.storage_bytes = total
        usage.updated_at = _now()
        return {"org_id": org_id, "storage_bytes": total}

    # -- dispatch operation handlers (Store validates the principal first) ----

    @staticmethod
    def _audit(sess: Session, org_id: str, actor_id: str, action: str,
               record_id: str | None = None) -> None:
        sess.add(AuditLog(id=_new_id(), org_id=org_id, scope_id=None,
                          actor_id=actor_id, action=action, record_id=record_id))

    def op_instance_create(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"name"})
        if not dbp.is_org_admin:
            raise ServiceError("denied", "org admin only")
        name = _str_arg(args, "name")
        self.check_instance_quota(sess, dbp.org_id)
        exists = sess.execute(
            select(LogicalInstance.id).where(LogicalInstance.org_id == dbp.org_id,
                                             LogicalInstance.name == name)
        ).scalar_one_or_none()
        if exists is not None:
            raise ServiceError("conflict", "instance name already exists in this organisation")
        row = LogicalInstance(id=_new_id(), org_id=dbp.org_id, name=name)
        sess.add(row)
        self._audit(sess, dbp.org_id, dbp.id, "instance_create", record_id=row.id)
        return {"instance_id": row.id, "name": name, "active": True}

    def op_instance_list(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, set())
        rows = sess.execute(
            select(LogicalInstance).where(LogicalInstance.org_id == dbp.org_id)
            .order_by(LogicalInstance.created_at)
        ).scalars().all()
        return {"instances": [
            {"instance_id": i.id, "name": i.name, "active": i.active,
             "created_at": _iso(i.created_at)}
            for i in rows
        ]}

    def op_connection_issue(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"instance_id", "owner_principal_id"})
        instance_id = _str_arg(args, "instance_id", max_len=64)
        owner_id = _str_arg(args, "owner_principal_id", default=dbp.id, max_len=64)
        if owner_id != dbp.id and not dbp.is_org_admin:
            raise ServiceError("denied",
                               "only an org admin may issue connections for other principals")
        owner = sess.execute(
            select(PrincipalRow).where(PrincipalRow.id == owner_id,
                                       PrincipalRow.org_id == dbp.org_id,
                                       PrincipalRow.active.is_(True))
        ).scalar_one_or_none()
        if owner is None:
            raise ServiceError("not_found", "owner principal not found in this organisation")
        instance = sess.execute(
            select(LogicalInstance).where(LogicalInstance.id == instance_id,
                                          LogicalInstance.org_id == dbp.org_id,
                                          LogicalInstance.active.is_(True))
        ).scalar_one_or_none()
        if instance is None:
            raise ServiceError("not_found", "instance not found in this organisation")
        self.check_connection_quota(sess, dbp.org_id)
        credential = secrets.token_urlsafe(32)
        row = ConnectionRow(id=_new_id(), org_id=dbp.org_id, owner_principal_id=owner.id,
                            instance_id=instance.id, credential_digest=_digest(credential))
        sess.add(row)
        self._audit(sess, dbp.org_id, dbp.id, "connection_issue", record_id=row.id)
        # The plaintext credential is returned exactly once and never stored or logged.
        return {"connection_id": row.id, "credential": credential,
                "owner_principal_id": owner.id, "instance_id": instance.id}

    def op_connection_revoke(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"connection_id"})
        cid = _str_arg(args, "connection_id", max_len=64)
        row = sess.execute(
            select(ConnectionRow).where(ConnectionRow.id == cid,
                                        ConnectionRow.org_id == dbp.org_id)
            .with_for_update()
        ).scalar_one_or_none()
        if row is None:
            raise ServiceError("not_found", "connection not found in this organisation")
        if row.owner_principal_id != dbp.id and not dbp.is_org_admin:
            raise ServiceError("denied", "only the owner or an org admin may revoke")
        if not row.active:
            raise ServiceError("invalid_state", "connection is already revoked")
        row.active = False
        row.revoked_at = _now()
        self._audit(sess, dbp.org_id, dbp.id, "connection_revoke", record_id=row.id)
        return {"connection_id": row.id, "revoked": True}

    def op_connection_list(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, set())
        stmt = select(ConnectionRow).where(ConnectionRow.org_id == dbp.org_id)
        if not dbp.is_org_admin:
            stmt = stmt.where(ConnectionRow.owner_principal_id == dbp.id)
        rows = sess.execute(stmt.order_by(ConnectionRow.created_at)).scalars().all()
        # Credential digests are deliberately excluded from every read surface.
        return {"connections": [
            {"connection_id": c.id, "owner_principal_id": c.owner_principal_id,
             "instance_id": c.instance_id, "active": c.active,
             "created_at": _iso(c.created_at), "revoked_at": _iso(c.revoked_at)}
            for c in rows
        ]}

    def op_billing_status(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, set())
        if not dbp.is_org_admin:
            raise ServiceError("denied", "org admin only")
        plan, limits = self.limits_for(sess, dbp.org_id)
        account = sess.execute(
            select(BillingAccount).where(BillingAccount.org_id == dbp.org_id)
        ).scalar_one_or_none()
        usage = sess.execute(
            select(OrgUsage).where(OrgUsage.org_id == dbp.org_id)
        ).scalar_one_or_none()

        def count(table, *extra):
            return sess.execute(
                select(func.count()).select_from(table)
                .where(table.org_id == dbp.org_id, *extra)
            ).scalar_one()

        # Account metadata and counters only — content-blind by construction.
        return {
            "billing_enabled": self.enabled,
            "plan": plan,
            "status": account.status if account is not None else "unregistered",
            "needs_reconciliation": bool(account.needs_reconciliation) if account else False,
            "limits": {"max_users": limits.max_users,
                       "max_instances": limits.max_instances,
                       "max_connections": limits.max_connections,
                       "max_storage_bytes": limits.max_storage_bytes},
            "usage": {
                "users": count(PrincipalRow, PrincipalRow.active.is_(True)),
                "instances": count(LogicalInstance, LogicalInstance.active.is_(True)),
                "connections": count(ConnectionRow, ConnectionRow.active.is_(True)),
                "storage_bytes": usage.storage_bytes if usage is not None else 0,
            },
        }

    # -- connection authentication (transport integration point) --------------

    def authenticate_connection(self, sess: Session, credential: Any) -> ConnectionAuth | None:
        """Resolve a connection credential to the owner's ACTIVE principal identity. Returns
        None on any failure. This is the MCP/HTTP auth hook: transports must authenticate
        AI-client traffic with connection credentials, not org-admin bearer tokens."""
        if not isinstance(credential, str) or not credential or len(credential) > 512:
            return None
        row = sess.execute(
            select(ConnectionRow).where(
                ConnectionRow.credential_digest == _digest(credential),
                ConnectionRow.active.is_(True))
        ).scalar_one_or_none()
        if row is None:
            return None
        return self.resolve_connection(sess, row.id)

    def resolve_connection(self, sess: Session, connection_id: str) -> ConnectionAuth | None:
        if not isinstance(connection_id, str) or len(connection_id) != 32:
            return None
        row = sess.execute(select(ConnectionRow).where(ConnectionRow.id == connection_id,
            ConnectionRow.active.is_(True))).scalar_one_or_none()
        if row is None:
            return None
        owner = sess.execute(
            select(PrincipalRow).where(PrincipalRow.id == row.owner_principal_id,
                                       PrincipalRow.org_id == row.org_id,
                                       PrincipalRow.active.is_(True))
        ).scalar_one_or_none()
        if owner is None:
            return None
        instance = sess.execute(
            select(LogicalInstance.id).where(LogicalInstance.id == row.instance_id,
                                             LogicalInstance.active.is_(True))
        ).scalar_one_or_none()
        if instance is None:
            return None
        if self.enabled:
            _, limits = self.limits_for(sess, row.org_id)
            for table, ceiling, identifier in ((ConnectionRow, limits.max_connections, row.id),
                    (LogicalInstance, limits.max_instances, row.instance_id),
                    (PrincipalRow, limits.max_users, owner.id)):
                if ceiling is not None:
                    eligible = sess.execute(select(table.id).where(table.org_id == row.org_id,
                        table.active.is_(True)).order_by(table.created_at, table.id).limit(ceiling)).scalars().all()
                    if identifier not in eligible:
                        return None
        principal = Principal(id=owner.id, org_id=owner.org_id, name=owner.name,
                              is_org_admin=owner.is_org_admin)
        return ConnectionAuth(principal=principal, connection_id=row.id,
                              instance_id=row.instance_id)

    # -- offline trusted billing authority ------------------------------------

    def _get_or_create_account(self, sess: Session, org_id: str) -> BillingAccount:
        org = sess.execute(select(Org.id).where(Org.id == org_id)).scalar_one_or_none()
        if org is None:
            raise ServiceError("not_found", "organisation not found")
        account = sess.execute(
            select(BillingAccount).where(BillingAccount.org_id == org_id).with_for_update()
        ).scalar_one_or_none()
        if account is None:
            account = BillingAccount(id=_new_id(), org_id=org_id, plan=self.default_plan,
                                     status="registered")
            sess.add(account)
            sess.flush([account])
        return account

    def assign_plan(self, sess: Session, org_id: str, plan: str) -> dict:
        """OFFLINE trusted billing authority only (operator CLI / platform billing service —
        never reachable from tenant dispatch): directly set an organisation's plan."""
        if plan not in self.plans:
            raise ServiceError("invalid_argument", f"unknown plan '{plan}'")
        account = self._get_or_create_account(sess, org_id)
        account.plan = plan
        account.needs_reconciliation = False
        account.status = "active"
        account.updated_at = _now()
        return {"org_id": org_id, "plan": plan, "status": account.status}

    def register_subscription(self, sess: Session, org_id: str, provider: str,
                              customer_id: str, subscription_id: str,
                              plan: str | None = None) -> dict:
        """Server-side binding of a provider subscription/customer to an organisation. This
        is the ONLY way webhook events reach a tenant — arbitrary webhook metadata never
        selects or creates one."""
        for value, label in ((provider, "provider"), (customer_id, "customer_id"),
                             (subscription_id, "subscription_id")):
            if not isinstance(value, str) or not value or len(value) > 200:
                raise ServiceError("invalid_argument", f"{label} must be a bounded string")
        if plan is not None and plan not in self.plans:
            raise ServiceError("invalid_argument", f"unknown plan '{plan}'")
        taken = sess.execute(
            select(BillingAccount).where(
                BillingAccount.provider == provider,
                BillingAccount.provider_subscription_id == subscription_id,
                BillingAccount.org_id != org_id)
        ).scalar_one_or_none()
        if taken is not None:
            raise ServiceError("conflict",
                               "subscription is already bound to another organisation")
        account = self._get_or_create_account(sess, org_id)
        if (account.provider, account.provider_subscription_id) != (provider, subscription_id):
            account.status = "registered"
            account.last_event_at = None
            account.last_event_id = None
            account.needs_reconciliation = False
        account.provider = provider
        account.provider_customer_id = customer_id
        account.provider_subscription_id = subscription_id
        if plan is not None:
            account.plan = plan
        account.updated_at = _now()
        return {"org_id": org_id, "provider": provider, "plan": account.plan,
                "subscription_id": subscription_id}

    # -- webhook event application --------------------------------------------

    def _record_event(self, sess: Session, evt: ProviderEvent, org_id: str | None,
                      applied: bool, note: str) -> None:
        sess.add(BillingEvent(id=_new_id(), provider=evt.provider, event_id=evt.event_id,
                              org_id=org_id, event_time=evt.event_time,
                              applied=applied, note=note))

    def process_event(self, sess: Session, evt: ProviderEvent) -> dict:
        """Apply one VERIFIED provider event. Idempotent by (provider, event_id); ordered by
        the account's last-applied event time (older: ignored; equal-but-different: fail
        closed and flag reconciliation). Entitled statuses map price -> plan via the
        configured price_map; every other status downgrades to the default plan. Billing
        never deletes tenant data and never touches scopes or grants."""
        account = sess.execute(
            select(BillingAccount).where(
                BillingAccount.provider == evt.provider,
                BillingAccount.provider_subscription_id == evt.subscription_id)
            .with_for_update()
        ).scalar_one_or_none()
        duplicate = sess.execute(
            select(BillingEvent.id).where(BillingEvent.provider == evt.provider,
                                          BillingEvent.event_id == evt.event_id)
        ).scalar_one_or_none()
        if duplicate is not None:
            return {"applied": False, "reason": "duplicate_event", "event_id": evt.event_id}
        if account is None:
            self._record_event(sess, evt, None, False, "unregistered_subscription")
            return {"applied": False, "reason": "unregistered_subscription",
                    "event_id": evt.event_id}
        if account.last_event_at is not None:
            if evt.event_time < account.last_event_at:
                self._record_event(sess, evt, account.org_id, False, "out_of_order")
                return {"applied": False, "reason": "out_of_order",
                        "event_id": evt.event_id}
            if evt.event_time == account.last_event_at:
                account.needs_reconciliation = True
                account.updated_at = _now()
                self._record_event(sess, evt, account.org_id, False,
                                   "same_timestamp_fail_closed")
                return {"applied": False, "reason": "same_timestamp_fail_closed",
                        "needs_reconciliation": True, "event_id": evt.event_id}
        if evt.customer_id is not None and evt.customer_id != account.provider_customer_id:
            raise ServiceError("invalid_webhook", "Subscription customer mismatch")
        status = str(evt.status or "").lower()
        if status in _ENTITLED_STATUSES:
            plan = self.price_map.get(f"{evt.provider}:{evt.price_id or ''}")
            if plan is None or plan not in self.plans:
                # Entitled but unmappable price: fail closed, keep the current plan and
                # flag for reconciliation rather than guessing an upgrade.
                account.needs_reconciliation = True
                account.updated_at = _now()
                account.last_event_at = evt.event_time
                account.last_event_id = evt.event_id
                self._record_event(sess, evt, account.org_id, False, "unknown_price")
                return {"applied": False, "reason": "unknown_price",
                        "needs_reconciliation": True, "event_id": evt.event_id}
            account.plan = plan
            account.status = "active"
        else:
            # Lapsed, cancelled, past_due or unknown status: downgrade to the default plan.
            # Data is preserved; over-quota writes fail with quota_exceeded until resolved.
            account.plan = self.default_plan
            account.status = "delinquent"
        account.needs_reconciliation = False
        account.last_event_id = evt.event_id
        account.last_event_at = evt.event_time
        account.updated_at = _now()
        self._record_event(sess, evt, account.org_id, True, f"applied:{account.status}")
        return {"applied": True, "org_id": account.org_id, "plan": account.plan,
                "status": account.status, "event_id": evt.event_id}
