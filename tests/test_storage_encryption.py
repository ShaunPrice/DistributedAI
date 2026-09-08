# SPDX-License-Identifier: Apache-2.0
import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from distributedai.encryption import CryptoBox, EncryptionError, LocalWrapper
from distributedai.storage_encryption import enable_encryption, migrate_existing
from distributedai.store import Job, MemoryProposal, MemoryRecord, MemoryVersion, Message
from test_store import env as env


@pytest.fixture
def encrypted(env):
    box = CryptoBox(env.store._engine, {"local": LocalWrapper(b"k" * 32)})
    box.initialize()
    enable_encryption(env.store, box)
    env.crypto = box
    return env


def proposal(e, key="secret-key", content="confidential original", version=0):
    return e.store.dispatch(e.alice, "memory_propose", {"scope_id": e.proj_a,
        "key": key, "content": content, "source": "confidential provenance",
        "expected_version": version})["proposal_id"]


def test_all_payloads_encrypted_with_roundtrip_and_history(encrypted):
    e = encrypted
    pid = proposal(e)
    e.store.dispatch(e.carol, "memory_review", {"proposal_id": pid, "accept": True})
    pid2 = proposal(e, content="confidential replacement", version=1)
    e.store.dispatch(e.carol, "memory_review", {"proposal_id": pid2, "accept": True})
    e.store.dispatch(e.alice, "message_send", {"scope_id": e.proj_a,
        "recipient_id": e.bob.id, "body": "confidential communication"})
    created = e.store.dispatch(e.alice, "job_create", {"scope_id": e.proj_a,
        "assignee_id": e.alice.id, "objective": "confidential objective",
        "idempotency_key": "fixture-job"})
    claim = e.store.dispatch(e.alice, "job_claim", {"job_id": created["job_id"]})
    e.store.dispatch(e.alice, "job_submit", {"job_id": created["job_id"],
        "claim_token": claim["claim_token"], "result": {"answer": "confidential result"}})
    with e.store._engine.connect() as conn:
        for model in [MemoryRecord, MemoryVersion, MemoryProposal, Message, Job]:
            rows = conn.execute(select(model.__table__)).mappings().all()
            assert rows
            assert "confidential" not in str(rows)
    with Session(e.store._engine) as sess:
        record = sess.scalar(select(MemoryRecord))
        assert record.content == "confidential replacement"
        sess.expire(record)
        assert record.content == "confidential replacement"
        sess.refresh(record, ["content"])
        assert record.content == "confidential replacement"
        assert len(sess.scalars(select(MemoryVersion)).all()) == 2
        job = sess.get(Job, created["job_id"])
        assert "confidential result" in job.result
        assert job.objective == "confidential objective"


def test_plaintext_and_ciphertext_substitution_fail_closed(encrypted):
    e = encrypted
    pid = proposal(e)
    table = MemoryProposal.__table__
    with e.store._engine.begin() as conn:
        source = conn.execute(select(table.c.source).where(table.c.id == pid)).scalar_one()
        conn.execute(update(table).where(table.c.id == pid).values(content=source))
    with pytest.raises(EncryptionError):
        e.store.dispatch(e.carol, "memory_review", {"proposal_id": pid, "accept": True})
    with e.store._engine.begin() as conn:
        conn.execute(update(table).where(table.c.id == pid).values(content="raw legacy secret"))
    with pytest.raises(EncryptionError):
        e.store.dispatch(e.carol, "memory_review", {"proposal_id": pid, "accept": True})


def test_offline_migration_is_idempotent_and_atomic(env):
    e = env
    pid = proposal(e)
    box = CryptoBox(e.store._engine, {"local": LocalWrapper(b"k" * 32)})
    box.initialize()
    assert migrate_existing(e.store, box)["encrypted_rows"] == 1
    assert migrate_existing(e.store, box)["encrypted_rows"] == 0
    enable_encryption(e.store, box)
    with Session(e.store._engine) as sess:
        assert sess.get(MemoryProposal, pid).content == "confidential original"
    with e.store._engine.begin() as conn:
        conn.execute(update(MemoryProposal.__table__).where(MemoryProposal.id == pid)
            .values(content="plaintext", source="enc:v1:1:forged"))
    with pytest.raises(EncryptionError):
        migrate_existing(e.store, box)
    with e.store._engine.connect() as conn:
        assert conn.execute(select(MemoryProposal.__table__.c.content)).scalar_one() == "plaintext"


def test_failed_encryption_rolls_back_and_other_engines_unaffected(encrypted, monkeypatch, tmp_path):
    from distributedai.store import Store
    e = encrypted
    def fail(*args):
        raise EncryptionError("fixture failure")
    monkeypatch.setattr(e.crypto, "encrypt", fail)
    with pytest.raises(EncryptionError):
        proposal(e)
    with e.store._engine.connect() as conn:
        assert not conn.execute(select(MemoryProposal.__table__)).first()
    other = Store(f"sqlite:///{tmp_path / 'other.db'}")
    other.initialize()
    assert getattr(other._engine, "_distributedai_crypto", None) is None
