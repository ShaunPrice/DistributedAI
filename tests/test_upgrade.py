# SPDX-License-Identifier: Apache-2.0
"""Schema 0.1 -> 0.2 upgrade against a synthetic database produced by released commit fec5178.

tests/fixtures/schema-0.1-synthetic.sql was generated with the released code and a test-only
key-encryption key (b"k" * 32). Every name, token and payload in it is fictional.
"""
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select

from distributedai.encryption import CryptoBox, LocalWrapper
from distributedai.persistence import upgrade
from distributedai.storage_encryption import enable_encryption
from distributedai.store import MemoryEvidence, MemoryProposal, MemoryRecord, ServiceError, Store

FIXTURE = Path(__file__).parent / "fixtures" / "schema-0.1-synthetic.sql"
ROOT = Path(__file__).resolve().parents[1]
WRITER = "fixture-writer-token-000000000000000"
REVIEWER = "fixture-reviewer-token-0000000000000"


@pytest.fixture
def old_db(tmp_path):
    path = tmp_path / "old.db"
    connection = sqlite3.connect(path)
    connection.executescript(FIXTURE.read_text())
    connection.close()
    engine = create_engine(f"sqlite:///{path}")
    yield path, engine
    engine.dispose()


def raw_rows(engine):
    with engine.connect() as conn:
        return {table.name: conn.execute(select(table).order_by(*table.primary_key.columns)).all()
                for table in (MemoryRecord.__table__, MemoryProposal.__table__)}


def encrypted_store(path):
    store = Store(f"sqlite:///{path}")
    box = CryptoBox(store._engine, {"local": LocalWrapper(b"k" * 32)})
    enable_encryption(store, box)
    return store


def test_fixture_is_schema_0_1_with_encrypted_payloads(old_db):
    _, engine = old_db
    report = upgrade.plan(engine)
    assert report["current_schema"] == "0.1" and report["dry_run"] is True
    assert report["counts"]["plaintext_fields"] == 0 and report["counts"]["encrypted_fields"] >= 5
    assert report["actions"] and "no existing" in report["actions"][0]
    assert upgrade.detect(engine)["version"] == "0.1"  # dry run changed nothing
    assert "Synthetic" not in json.dumps(report)


def test_apply_requires_backup_confirmation_and_is_idempotent(old_db):
    path, engine = old_db
    before = raw_rows(engine)
    with pytest.raises(upgrade.UpgradeError):
        upgrade.apply(engine, confirm_backup=False)
    first = upgrade.apply(engine, confirm_backup=True)
    assert first == {"previous_schema": "0.1", "current_schema": "0.2", "changed": True,
                     "pruned_orphan_evidence_rows": 0, "dry_run": False}
    second = upgrade.apply(engine, confirm_backup=True)
    assert second["changed"] is False and second["current_schema"] == "0.2"
    assert raw_rows(engine) == before  # ciphertext untouched, nothing re-encrypted


def test_upgraded_legacy_records_keep_unknown_provenance_and_decrypt(old_db):
    path, engine = old_db
    upgrade.apply(engine, confirm_backup=True)
    store = encrypted_store(path)
    writer, reviewer = store.authenticate(WRITER), store.authenticate(REVIEWER)
    scope = store.dispatch(writer, "scope_list", {})["scopes"]
    project = next(s["scope_id"] for s in scope if s["kind"] == "project")
    legacy = store.dispatch(writer, "memory_get", {"scope_id": project, "key": "pump-schedule"})
    assert legacy["content"] == "Synthetic pump runs nightly"
    assert legacy["source"] == "synthetic handbook p.4"
    assert legacy["evidence"] is None and legacy["freshness"]["status"] == "unknown"
    assert legacy["updated_at"] is not None  # present, yet never used as retrieval time
    packet = store.dispatch(writer, "memory_context", {"scope_id": project})
    assert {item["freshness"] for item in packet["items"]} == {"unknown"}
    pid = store.dispatch(writer, "memory_propose", {"scope_id": project, "key": "pump-schedule",
        "content": "Synthetic pump runs at dawn", "expected_version": 1,
        "evidence": {"source_url": "https://handbook.example/pumps", "observed_at": "2026-10-01"}})["proposal_id"]
    store.dispatch(reviewer, "memory_review", {"proposal_id": pid, "accept": True})
    assert store.dispatch(writer, "memory_get", {"scope_id": project, "key": "pump-schedule"})["evidence"]
    with engine.connect() as conn:
        payloads = conn.execute(select(MemoryEvidence.__table__.c.payload)).scalars().all()
    assert payloads and all(value.startswith("enc:v1:") for value in payloads)
    store._engine.dispose()


def test_new_code_needs_the_additive_table_which_server_start_creates(old_db):
    path, _ = old_db
    store = encrypted_store(path)
    writer = store.authenticate(WRITER)
    project = next(s["scope_id"] for s in store.dispatch(writer, "scope_list", {})["scopes"] if s["kind"] == "project")
    with pytest.raises(Exception):
        store.dispatch(writer, "memory_get", {"scope_id": project, "key": "pump-schedule"})
    store.initialize()  # the normal server start path performs the same additive creation
    assert upgrade.detect(store._engine)["version"] == "0.2"
    assert store.dispatch(writer, "memory_get", {"scope_id": project, "key": "pump-schedule"})["evidence"] is None
    store._engine.dispose()


def test_rollback_guards_evidence_and_upgrade_prunes_orphans(old_db):
    path, engine = old_db
    upgrade.apply(engine, confirm_backup=True)
    store = encrypted_store(path)
    writer = store.authenticate(WRITER)
    project = next(s["scope_id"] for s in store.dispatch(writer, "scope_list", {})["scopes"] if s["kind"] == "project")
    store.dispatch(writer, "memory_propose", {"scope_id": project, "key": "draft", "content": "Synthetic draft",
                                              "evidence": {"title": "Synthetic source"}})
    store._engine.dispose()
    with pytest.raises(upgrade.UpgradeError):
        upgrade.rollback(engine, confirm_backup=True, writers_stopped=True, allow_evidence_loss=False)
    with pytest.raises(upgrade.UpgradeError):
        upgrade.rollback(engine, confirm_backup=False, writers_stopped=True, allow_evidence_loss=True)
    with pytest.raises(upgrade.UpgradeError, match="writers-stopped"):
        upgrade.rollback(engine, confirm_backup=True, writers_stopped=False, allow_evidence_loss=True)
    # Simulate an older server deleting the key after a code-only rollback: it never knew
    # about memory_evidence, so the evidence row is orphaned.
    with engine.begin() as conn:
        conn.execute(MemoryProposal.__table__.delete().where(MemoryProposal.__table__.c.key == "draft"))
    assert upgrade.plan(engine)["counts"]["orphan_evidence_rows"] == 1
    assert upgrade.apply(engine, confirm_backup=True)["pruned_orphan_evidence_rows"] == 1
    result = upgrade.rollback(engine, confirm_backup=True, writers_stopped=True, allow_evidence_loss=False)
    assert result["current_schema"] == "0.1" and result["dropped_evidence_rows"] == 0
    assert upgrade.rollback(engine, confirm_backup=True, writers_stopped=True, allow_evidence_loss=False)["changed"] is False
    assert upgrade.apply(engine, confirm_backup=True)["current_schema"] == "0.2"


def test_unrecognised_schemas_are_refused(tmp_path):
    empty = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    assert upgrade.plan(empty)["current_schema"] == "empty"
    with pytest.raises(upgrade.UpgradeError):
        upgrade.apply(empty, confirm_backup=True)
    partial = create_engine(f"sqlite:///{tmp_path / 'partial.db'}")
    with partial.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE orgs (id VARCHAR(32) PRIMARY KEY)")
    assert upgrade.detect(partial)["version"] == "unknown"
    with pytest.raises(upgrade.UpgradeError):
        upgrade.apply(partial, confirm_backup=True)


def test_cli_dry_run_reports_counts_only(old_db, tmp_path):
    path, _ = old_db
    env = {"PATH": os.environ.get("PATH", ""), "DATABASE_URL": f"sqlite:///{path}",
           "PYTHONPATH": str(ROOT)}
    run = subprocess.run([sys.executable, "-m", "distributedai.cli", "upgrade"], cwd=tmp_path,
                         env=env, capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    assert report["current_schema"] == "0.1" and "Synthetic" not in run.stdout
    refused = subprocess.run([sys.executable, "-m", "distributedai.cli", "upgrade", "--apply"], cwd=tmp_path,
                             env=env, capture_output=True, text=True, timeout=60)
    assert refused.returncode == 2 and "confirm-backup" in refused.stdout
    applied = subprocess.run([sys.executable, "-m", "distributedai.cli", "upgrade", "--apply", "--confirm-backup"],
                             cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    assert applied.returncode == 0 and json.loads(applied.stdout)["current_schema"] == "0.2"


def test_context_ops_fail_cleanly_for_unknown_scope(old_db):
    path, engine = old_db
    upgrade.apply(engine, confirm_backup=True)
    store = encrypted_store(path)
    with pytest.raises(ServiceError):
        store.dispatch(store.authenticate(WRITER), "memory_context", {"scope_id": "missing"})
    store._engine.dispose()


MALFORMED = {
    "missing unique proposal link": "CREATE TABLE memory_evidence (id VARCHAR(32) PRIMARY KEY, "
        "org_id VARCHAR(32) NOT NULL REFERENCES orgs(id), scope_id VARCHAR(32) NOT NULL REFERENCES scopes(id), "
        "key VARCHAR(200) NOT NULL, proposal_id VARCHAR(32) NOT NULL, version INTEGER, payload TEXT NOT NULL, "
        "created_at DATETIME NOT NULL)",
    "wrong types": "CREATE TABLE memory_evidence (id VARCHAR(32) PRIMARY KEY, org_id VARCHAR(32) NOT NULL, "
        "scope_id VARCHAR(32) NOT NULL, key VARCHAR(200) NOT NULL, proposal_id VARCHAR(32) NOT NULL UNIQUE, "
        "version TEXT, payload INTEGER NOT NULL, created_at DATETIME NOT NULL)",
    "nullable payload": "CREATE TABLE memory_evidence (id VARCHAR(32) PRIMARY KEY, org_id VARCHAR(32) NOT NULL, "
        "scope_id VARCHAR(32) NOT NULL, key VARCHAR(200) NOT NULL, proposal_id VARCHAR(32) NOT NULL UNIQUE, "
        "version INTEGER, payload TEXT, created_at DATETIME NOT NULL)",
    "short key": "CREATE TABLE memory_evidence (id VARCHAR(32) PRIMARY KEY, org_id VARCHAR(32) NOT NULL, "
        "scope_id VARCHAR(32) NOT NULL, key VARCHAR(10) NOT NULL, proposal_id VARCHAR(32) NOT NULL UNIQUE, "
        "version INTEGER, payload TEXT NOT NULL, created_at DATETIME NOT NULL)",
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_evidence_table_is_unknown_and_recoverable(old_db, name):
    path, engine = old_db
    with engine.begin() as conn:
        conn.exec_driver_sql(MALFORMED[name])
        conn.exec_driver_sql("INSERT INTO memory_evidence (id, org_id, scope_id, key, proposal_id, version, "
                             "payload, created_at) SELECT 'e1', id, id, 'k', 'p1', 1, 9, '2026-01-01' FROM orgs LIMIT 1")
    detected = upgrade.detect(engine)
    assert detected["version"] == "unknown" and detected["problems"]
    for action in (lambda: upgrade.apply(engine, confirm_backup=True),
                   lambda: upgrade.rollback(engine, confirm_backup=True, writers_stopped=True,
                                            allow_evidence_loss=True)):
        with pytest.raises(upgrade.UpgradeError):
            action()
    with engine.connect() as conn:  # refused actions left the unknown table and its row intact
        assert conn.exec_driver_sql("SELECT count(*) FROM memory_evidence").scalar_one() == 1
    # Documented recovery: preserve the unexpected table under another name, then apply.
    with engine.begin() as conn:
        conn.exec_driver_sql("ALTER TABLE memory_evidence RENAME TO memory_evidence_unrecognised")
    assert upgrade.apply(engine, confirm_backup=True)["current_schema"] == "0.2"
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT count(*) FROM memory_evidence_unrecognised").scalar_one() == 1


def test_current_schema_created_by_the_model_is_recognised(old_db):
    _, engine = old_db
    upgrade.apply(engine, confirm_backup=True)
    assert upgrade.evidence_table_problems(engine) == []


# -- the upgrade tool resolves database configuration only ----------------------------------

UNRELATED_SECRETS = ("CONTENT_MASTER_KEY", "MANAGEMENT_KEY", "OIDC_SUBJECTS", "SUPPORT_DEFAULTS",
                     "BILLING_PLAN_LIMITS", "BILLING_PRICES", "PAYMENT_PROVIDERS", "OIDC_CONNECTIONS",
                     "KEY_PROVIDERS", "TENANT_KEY_PROVIDERS", "PLATFORM_ADMIN_TOKEN", "PLATFORM_SUBJECTS",
                     "LOGIN_CLIENT_SECRET", "LOGIN_SUBJECTS")


def run_cli(tmp_path, env, *arguments):
    return subprocess.run([sys.executable, "-m", "distributedai.cli", "upgrade", *arguments], cwd=tmp_path,
                          env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(ROOT), **env},
                          capture_output=True, text=True, timeout=60)


def test_cli_never_touches_unrelated_secret_files(old_db, tmp_path):
    path, _ = old_db
    locked = tmp_path / "unreadable-secret"
    locked.write_text("synthetic-unrelated-secret")
    locked.chmod(0)
    env = {"DATABASE_URL": f"sqlite:///{path}"}
    for index, name in enumerate(UNRELATED_SECRETS):
        # Alternate unreadable and missing files: reading any of them would fail the command.
        env[name + "_FILE"] = str(locked) if index % 2 == 0 else str(tmp_path / f"missing-{name}")
    try:
        if os.access(locked, os.R_OK):  # e.g. running as root: permissions cannot prove it
            pytest.skip("file permissions are not enforced for this user")
        preflight = run_cli(tmp_path, env)
        assert preflight.returncode == 0, preflight.stdout + preflight.stderr
        assert json.loads(preflight.stdout)["current_schema"] == "0.1"
        applied = run_cli(tmp_path, env, "--apply", "--confirm-backup")
        assert applied.returncode == 0 and json.loads(applied.stdout)["current_schema"] == "0.2"
        assert "synthetic-unrelated-secret" not in applied.stdout + applied.stderr
    finally:
        locked.chmod(0o600)


def test_database_url_fallbacks_are_preserved(tmp_path, monkeypatch):
    from distributedai.config import Settings, database_url_from_env
    for name in ("DATABASE_URL", "DATABASE_URL_FILE", "DB_PASSWORD", "DB_PASSWORD_FILE", "DB_HOST"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="DATABASE_URL or DB_PASSWORD_FILE"):
        database_url_from_env()
    password = tmp_path / "db_password"
    password.write_text("synthetic p@ss/word\n")
    monkeypatch.setenv("DB_PASSWORD_FILE", str(password))
    assert database_url_from_env() == "postgresql+psycopg://distributedai:synthetic%20p%40ss%2Fword@db:5432/distributedai"
    monkeypatch.setenv("DB_HOST", "database.internal")
    assert "@database.internal:5432/" in database_url_from_env()
    url_file = tmp_path / "database_url"
    url_file.write_text("sqlite:///synthetic.db\n")
    monkeypatch.setenv("DATABASE_URL_FILE", str(url_file))
    assert database_url_from_env() == "sqlite:///synthetic.db"
    monkeypatch.delenv("DATABASE_URL_FILE")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///direct.db")
    assert database_url_from_env() == "sqlite:///direct.db"
    assert Settings.from_env().database_url == "sqlite:///direct.db"  # serving path unchanged


def test_cli_failures_never_echo_database_credentials(tmp_path):
    secret_password = "Synthetic-Db-Password-91x"
    unreachable = run_cli(tmp_path, {"DATABASE_URL": f"postgresql+psycopg://dbuser:{secret_password}@127.0.0.1:1/db"})
    malformed = run_cli(tmp_path, {"DATABASE_URL": f"nosuchdriver://dbuser:{secret_password}@host/db"})
    password_file = tmp_path / "unreadable-db-password"
    password_file.write_text(secret_password)
    password_file.chmod(0)
    try:
        unreadable = run_cli(tmp_path, {"DB_PASSWORD_FILE": str(password_file)})
    finally:
        password_file.chmod(0o600)
    missing = run_cli(tmp_path, {})
    for run in (unreachable, malformed, unreadable, missing):
        output = run.stdout + run.stderr
        assert run.returncode == 2, output
        assert secret_password not in output and "dbuser" not in output and "Traceback" not in output
        assert json.loads(run.stdout)["error"]
    assert "DATABASE_URL or DB_PASSWORD_FILE" in json.loads(missing.stdout)["error"]
