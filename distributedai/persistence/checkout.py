# SPDX-License-Identifier: AGPL-3.0-only
"""Checkout persistence and atomic subscription registration."""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, MetaData, String, Table, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..billing import BillingAccount
from ..domain import ServiceError
from ..store import Org

metadata = MetaData()
pending = Table("billing_checkouts", metadata,
    Column("reference", String(64), primary_key=True),
    Column("org_id", String(32), nullable=False, unique=True),
    Column("provider", String(20), nullable=False),
    Column("price_id", String(200), nullable=False),
    Column("session_id", String(200), nullable=True, unique=True),
    Column("completed", Boolean, nullable=False, default=False),
    Column("created_at", DateTime, nullable=False))


class CheckoutRepository:
    def __init__(self, engine, billing):
        self._engine, self._billing = engine, billing

    def binding(self, org_id):
        with Session(self._engine) as sess:
            account = sess.execute(select(BillingAccount).where(BillingAccount.org_id == org_id)).scalar_one_or_none()
            if account and account.provider_subscription_id:
                return account.provider, account.provider_customer_id
        return None, None

    def reserve(self, org_id, reference, provider, price_id):
        try:
            with self._engine.begin() as conn:
                conn.execute(pending.insert().values(reference=reference, org_id=org_id,
                    provider=provider, price_id=price_id, completed=False,
                    created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        except IntegrityError:
            raise ServiceError("conflict", "Checkout already pending; reconcile before retrying") from None

    def set_session(self, reference, session_id):
        with self._engine.begin() as conn:
            conn.execute(update(pending).where(pending.c.reference == reference).values(session_id=session_id))

    def find(self, session_id, reference, provider):
        with self._engine.connect() as conn:
            row = conn.execute(select(pending).where(pending.c.session_id == session_id,
                pending.c.reference == reference, pending.c.provider == provider)).mappings().first()
            return dict(row) if row is not None else None

    def apply_event(self, event):
        try:
            with Session(self._engine) as sess, sess.begin():
                return self._billing.process_event(sess, event)
        except IntegrityError:
            raise ServiceError("retry_event", "Retry billing event") from None

    def complete(self, row, reference, event):
        try:
            with Session(self._engine) as sess, sess.begin():
                # Org, pending, subscription and event ledger changes form one transaction.
                sess.execute(select(Org.id).where(Org.id == row["org_id"]).with_for_update()).scalar_one()
                locked = sess.execute(select(pending).where(pending.c.reference == reference).with_for_update()).mappings().one()
                if locked["completed"]:
                    return {"received": True, "duplicate": True}
                account = sess.execute(select(BillingAccount).where(BillingAccount.org_id == row["org_id"])).scalar_one_or_none()
                if account and account.provider_subscription_id and account.provider_subscription_id != event.subscription_id:
                    raise ServiceError("conflict", "Account has another subscription")
                self._billing.register_subscription(sess, row["org_id"], event.provider,
                    event.customer_id, event.subscription_id)
                sess.flush()
                result = self._billing.process_event(sess, event)
                sess.execute(update(pending).where(pending.c.reference == reference).values(completed=True))
                return {"received": True, "applied": bool(result.get("applied"))}
        except IntegrityError:
            raise ServiceError("retry_event", "Retry billing event") from None


def compose_billing_application(store, settings=None):
    """Compatibility composition boundary; production runtime should inject once."""
    from ..application.billing import BillingApplication
    service = BillingApplication(store, CheckoutRepository(store._engine, store.billing), settings)
    store.billing_application = service
    return service
