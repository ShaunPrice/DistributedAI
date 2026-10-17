# SPDX-License-Identifier: AGPL-3.0-only
"""Schema version detection, dry-run planning and the additive 0.1 -> 0.2 upgrade.

0.2 adds one table, ``memory_evidence``. No existing table, column or row is altered, so
existing ciphertext is never re-encrypted and legacy records keep unknown provenance.
Reports contain counts and names only — never content, keys or credentials.
"""
from __future__ import annotations

from sqlalchemy import func, inspect, select, text
from sqlalchemy import types as sqltypes
from sqlalchemy.engine import Engine

from .workspace import (
    _BOOTSTRAP_LOCK_KEY, Job, MemoryEvidence, MemoryProposal, MemoryRecord, MemoryVersion, Message,
)

CURRENT = "0.2"
CORE_TABLES = ("orgs", "scopes", "principals", "grants", "memory_records", "memory_versions",
               "memory_proposals", "messages", "jobs", "audit_log", "memory_locks")
PAYLOAD_FIELDS = ((MemoryRecord, ("content",)), (MemoryVersion, ("content",)),
                  (MemoryProposal, ("content",)), (Message, ("body",)), (Job, ("objective",)))
PREFIX = "enc:v1:"


class UpgradeError(RuntimeError):
    pass


def _orphaned():
    """Evidence whose proposal is gone, e.g. a key deleted while running an older server."""
    proposals = MemoryProposal.__table__
    return ~select(proposals.c.id).where(proposals.c.id == MemoryEvidence.__table__.c.proposal_id).exists()


def _category(column_type) -> str:
    if isinstance(column_type, sqltypes.Integer):
        return "integer"
    if isinstance(column_type, sqltypes.DateTime):
        return "datetime"
    if isinstance(column_type, sqltypes.String):
        return "text"
    return type(column_type).__name__


def evidence_table_problems(engine: Engine) -> list[str]:
    """Structural differences between the live memory_evidence table and schema 0.2.

    Names alone are not enough: types, nullability, the primary key, the proposal_id
    uniqueness that links evidence to exactly one proposal, indexes and tenant foreign keys
    are all checked. An empty list means the table matches.
    """
    inspector = inspect(engine)
    model = MemoryEvidence.__table__
    live = {column["name"]: column for column in inspector.get_columns("memory_evidence")}
    problems = []
    if set(live) != set(model.columns.keys()):
        problems.append("columns differ: " + ", ".join(sorted(set(live) ^ set(model.columns.keys()))))
    for column in model.columns:
        found = live.get(column.name)
        if found is None:
            continue
        if _category(found["type"]) != _category(column.type):
            problems.append(f"{column.name} has an unexpected type")
        expected_length = getattr(column.type, "length", None)
        found_length = getattr(found["type"], "length", None)
        if _category(column.type) == "text" and found_length is not None and (
                expected_length is None or found_length < expected_length):
            problems.append(f"{column.name} is too short")
        if not column.primary_key and bool(found.get("nullable")) != bool(column.nullable):
            problems.append(f"{column.name} has unexpected nullability")
    if inspector.get_pk_constraint("memory_evidence").get("constrained_columns") != ["id"]:
        problems.append("primary key is not (id)")
    indexes = inspector.get_indexes("memory_evidence")
    unique_sets = [tuple(item["column_names"]) for item in inspector.get_unique_constraints("memory_evidence")]
    unique_sets += [tuple(item["column_names"]) for item in indexes if item.get("unique")]
    if ("proposal_id",) not in unique_sets:
        problems.append("proposal_id is not unique")
    leading = {tuple(item["column_names"])[:1] for item in indexes}
    for name in ("org_id", "scope_id"):
        if (name,) not in leading:
            problems.append(f"{name} is not indexed")
    references = {(tuple(fk["constrained_columns"]), fk["referred_table"])
                  for fk in inspector.get_foreign_keys("memory_evidence")}
    for name, table in (("org_id", "orgs"), ("scope_id", "scopes")):
        if ((name,), table) not in references:
            problems.append(f"{name} does not reference {table}")
    return problems


def detect(engine: Engine) -> dict:
    names = set(inspect(engine).get_table_names())
    core = [name for name in CORE_TABLES if name in names]
    if not core:
        return {"version": "empty", "missing_core_tables": list(CORE_TABLES)}
    missing = [name for name in CORE_TABLES if name not in names]
    if missing:
        return {"version": "unknown", "missing_core_tables": missing,
                "reason": "partial DistributedAI schema; restore from backup or investigate"}
    if "memory_evidence" not in names:
        return {"version": "0.1", "missing_core_tables": []}
    problems = evidence_table_problems(engine)
    if problems:
        return {"version": "unknown", "missing_core_tables": [],
                "reason": "memory_evidence exists but does not match schema 0.2; preserve it "
                          "(rename or restore from backup) before upgrading",
                "problems": problems}
    return {"version": "0.2", "missing_core_tables": []}


def _counts(engine: Engine, detected: dict) -> dict:
    if detected["version"] not in {"0.1", "0.2"}:
        return {}
    out = {"encrypted_fields": 0, "plaintext_fields": 0}
    with engine.connect() as conn:
        out["memory_records"] = conn.execute(select(func.count()).select_from(MemoryRecord.__table__)).scalar_one()
        for model, fields in PAYLOAD_FIELDS:
            table = model.__table__
            for field in fields:
                column = table.c[field]
                out["encrypted_fields"] += conn.execute(select(func.count()).where(
                    column.is_not(None), column.like(PREFIX + "%"))).scalar_one()
                out["plaintext_fields"] += conn.execute(select(func.count()).where(
                    column.is_not(None), ~column.like(PREFIX + "%"))).scalar_one()
        if detected["version"] == "0.2":
            table = MemoryEvidence.__table__
            out["evidence_rows"] = conn.execute(select(func.count()).select_from(table)).scalar_one()
            out["evidence_plaintext_rows"] = conn.execute(select(func.count()).where(
                ~table.c.payload.like(PREFIX + "%"))).scalar_one()
            out["orphan_evidence_rows"] = conn.execute(select(func.count()).where(_orphaned())).scalar_one()
    return out


def plan(engine: Engine) -> dict:
    """Dry run: what ``apply`` would do. Never changes the database."""
    detected = detect(engine)
    report = {"current_schema": detected["version"], "target_schema": CURRENT,
              "detected": detected, "dry_run": True, "counts": _counts(engine, detected),
              "actions": [], "warnings": [],
              "backup": "Take and verify an encrypted backup first (scripts/db_backup.py backup); "
                        "apply requires --confirm-backup.",
              "provenance": "Existing records are not backfilled; their provenance stays unknown."}
    version = detected["version"]
    if version == "0.1":
        report["actions"] = ["create table memory_evidence with its indexes (additive; no existing "
                             "table, column or row changes)"]
    elif version == "0.2":
        report["actions"] = []
    elif version == "empty":
        report["warnings"].append("No DistributedAI schema found; use 'distributedai init' for a new install.")
    else:
        report["warnings"].append("Schema is not a recognised version; refusing to upgrade.")
    counts = report["counts"]
    if counts.get("plaintext_fields"):
        report["warnings"].append("Plaintext payloads exist; the configured server requires encryption. "
                                  "Run 'distributedai encrypt-existing' offline before serving.")
    if counts.get("orphan_evidence_rows"):
        report["actions"].append(f"delete {counts['orphan_evidence_rows']} evidence rows whose memory "
                                 "proposal was deleted (left by an older server after rollback)")
    if counts.get("evidence_plaintext_rows"):
        report["warnings"].append("Unencrypted evidence rows exist; run 'distributedai encrypt-existing' offline.")
    return report


def apply(engine: Engine, *, confirm_backup: bool) -> dict:
    """Idempotent: creates only what is missing, inside one serialised transaction."""
    if not confirm_backup:
        raise UpgradeError("refusing to change the schema without --confirm-backup")
    before = detect(engine)
    if before["version"] not in {"0.1", "0.2"}:
        raise UpgradeError(f"cannot upgrade schema '{before['version']}'")
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _BOOTSTRAP_LOCK_KEY})
        MemoryEvidence.__table__.create(conn, checkfirst=True)
        # Deleting memory must delete its provenance; finish deletions an older server missed.
        pruned = conn.execute(MemoryEvidence.__table__.delete().where(_orphaned())).rowcount
    after = detect(engine)
    if after["version"] != CURRENT:
        raise UpgradeError("post-upgrade verification failed")
    return {"previous_schema": before["version"], "current_schema": after["version"],
            "changed": before["version"] != after["version"] or bool(pruned),
            "pruned_orphan_evidence_rows": pruned, "dry_run": False}


def rollback(engine: Engine, *, confirm_backup: bool, writers_stopped: bool,
             allow_evidence_loss: bool) -> dict:
    """Return the schema to 0.1 by dropping memory_evidence. Older servers ignore the table,
    so rolling back code alone is safe; dropping it is only needed for a clean 0.1 schema.

    Destructive, so it needs both a verified backup and confirmation that service writers
    are stopped. Service writers do not take the schema advisory lock; on PostgreSQL the
    evidence count and DROP therefore run under an ACCESS EXCLUSIVE table lock in the same
    transaction, so a row inserted by a still-running writer either commits before the
    count (and is counted) or waits and is never silently lost. SQLite is for tests only:
    a concurrent writer makes the drop fail rather than lose rows.
    """
    if not confirm_backup:
        raise UpgradeError("refusing to change the schema without --confirm-backup")
    if not writers_stopped:
        raise UpgradeError("refusing a destructive rollback without --writers-stopped; stop all "
                           "DistributedAI API replicas and workers first")
    before = detect(engine)
    if before["version"] == "0.1":
        return {"previous_schema": "0.1", "current_schema": "0.1", "changed": False, "dry_run": False}
    if before["version"] != "0.2":
        raise UpgradeError(f"cannot roll back schema '{before['version']}'")
    table = MemoryEvidence.__table__
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _BOOTSTRAP_LOCK_KEY})
            conn.execute(text("LOCK TABLE memory_evidence IN ACCESS EXCLUSIVE MODE"))
        rows = conn.execute(select(func.count()).select_from(table)).scalar_one()
        if rows and not allow_evidence_loss:
            raise UpgradeError(f"memory_evidence holds {rows} rows; pass --allow-evidence-loss after backup")
        table.drop(conn)
    return {"previous_schema": "0.2", "current_schema": detect(engine)["version"],
            "changed": True, "dropped_evidence_rows": rows, "dry_run": False}
