# SPDX-License-Identifier: AGPL-3.0-only
"""Engine-scoped ORM field encryption. Core SQL writes require the offline migrator.

Hooks restore plaintext after flush and refresh so service business logic sees ordinary
values. These are internal persistence hooks; Store must authorise tenant queries first.
"""
from __future__ import annotations

from functools import wraps

from sqlalchemy import event, inspect, select, update
from sqlalchemy.orm import Session, attributes

from .encryption import CryptoBox, EncryptionError
from .store import Job, MemoryProposal, MemoryRecord, MemoryVersion, Message, Org

FIELDS = {
    MemoryRecord: {"content": None, "source": ""},
    MemoryVersion: {"content": None, "source": ""},
    MemoryProposal: {"content": None, "source": "", "findings": "[]"},
    Message: {"body": None, "findings": "[]"},
    Job: {"objective": None, "result": None, "findings": "[]"},
}
_PENDING = "distributedai_encryption_pending"


def _crypto(session):
    bind = session.get_bind()
    engine = getattr(bind, "engine", bind)
    return getattr(engine, "_distributedai_crypto", None)


def _before_flush(session, flush_context, instances):
    crypto = _crypto(session)
    if crypto is None:
        return
    pending = session.info.setdefault(_PENDING, [])
    try:
        for obj in set(session.new).union(session.dirty):
            fields = FIELDS.get(type(obj))
            if fields is None or obj in session.deleted:
                continue
            for field, default in fields.items():
                value = getattr(obj, field)
                if value is None:
                    value = default
                if value is None:
                    continue
                pending.append((obj, field, value))
                setattr(obj, field, crypto.encrypt(obj.org_id, obj.id,
                    f"{obj.__tablename__}.{field}", value))
    except Exception:
        _restore(session)
        raise


def _restore(session, *args):
    for obj, field, value in session.info.pop(_PENDING, []):
        attributes.set_committed_value(obj, field, value)


def _decrypt_loaded(session, obj):
    crypto = _crypto(session)
    if crypto is None:
        return
    for field in FIELDS.get(type(obj), {}):
        # Deferred fields are handled by refresh and must not recursively trigger a load.
        if field not in inspect(obj).dict:
            continue
        value = getattr(obj, field)
        if value is not None:
            attributes.set_committed_value(obj, field, crypto.decrypt(obj.org_id, obj.id,
                f"{obj.__tablename__}.{field}", value))


def _refresh(obj, context, attrs):
    session = inspect(obj).session
    if session is None:
        return
    crypto = _crypto(session)
    if crypto is None:
        return
    for field in FIELDS[type(obj)]:
        if attrs is not None and field not in attrs:
            continue
        if field not in inspect(obj).dict:
            continue
        value = getattr(obj, field)
        if value is not None:
            attributes.set_committed_value(obj, field, crypto.decrypt(obj.org_id, obj.id,
                f"{obj.__tablename__}.{field}", value))


event.listen(Session, "before_flush", _before_flush)
event.listen(Session, "after_flush_postexec", _restore)
event.listen(Session, "after_soft_rollback", _restore)
event.listen(Session, "loaded_as_persistent", _decrypt_loaded)
for _model in FIELDS:
    event.listen(_model, "refresh", _refresh)


def enable_encryption(store, crypto: CryptoBox):
    """Enable for this Store's engine only; schema initialization is explicit.

    Reauthentication before provisioning prevents fabricated Principal organisation IDs
    from creating key material. The original dispatch still performs all access checks.
    """
    previous = getattr(store._engine, "_distributedai_crypto", None)
    if previous is not None:
        if previous is not crypto:
            raise EncryptionError("Encryption is already configured on this engine")
        return
    store._engine._distributedai_crypto = crypto
    store.crypto = crypto
    original = store.dispatch

    @wraps(original)
    def dispatch(principal, operation, arguments):
        verified = store.resolve_principal(getattr(principal, "id", None))
        if verified is not None:
            crypto.provision(verified.org_id)
        with crypto.operation():
            return original(principal, operation, arguments)

    store.dispatch = dispatch


def migrate_existing(store, crypto: CryptoBox) -> dict:
    """Offline, transactional conversion. Stop all service writers before invoking.

    Key provisioning precedes the content transaction. Existing envelopes are verified
    rather than trusted by prefix. No plaintext fallback is added to normal reads.
    Returns counts only, never content or encryption keys.
    """
    with store._engine.connect() as conn:
        org_ids = list(conn.execute(select(Org.__table__.c.id)).scalars())
    for org_id in org_ids:
        crypto.provision(org_id)
    changed_rows = 0
    verified_fields = 0
    with store._engine.begin() as conn:
        for model, fields in FIELDS.items():
            table = model.__table__
            rows = conn.execute(select(table.c.id, table.c.org_id,
                *(table.c[name] for name in fields))).mappings()
            for row in rows:
                changes = {}
                for field in fields:
                    value = row[field]
                    if value is None:
                        continue
                    aad_field = f"{table.name}.{field}"
                    if value.startswith(crypto.PREFIX):
                        crypto.decrypt(row["org_id"], row["id"], aad_field, value)
                        verified_fields += 1
                    else:
                        changes[field] = crypto.encrypt(row["org_id"], row["id"], aad_field, value)
                if changes:
                    conn.execute(update(table).where(table.c.id == row["id"]).values(**changes))
                    changed_rows += 1
    return {"encrypted_rows": changed_rows, "verified_fields": verified_fields}
