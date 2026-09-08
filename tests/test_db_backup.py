# SPDX-License-Identifier: Apache-2.0
"""Backup cryptography and restore gating; PostgreSQL subprocesses are mocked."""
import base64
import io
import os
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from scripts import db_backup as backup


@pytest.fixture
def archive(tmp_path):
    key = os.urandom(32)
    key_file = tmp_path / "recipient.key"
    key_file.write_bytes(base64.b64encode(key))
    path = tmp_path / "database.enc"
    payload = b"PGDMP" + b"private database metadata\x00" * 50000
    with path.open("wb") as output:
        backup.encrypt_stream(io.BytesIO(payload), output, key)
    return path, key_file, key, payload


def test_streaming_archive_is_standard_authenticated_aes256(archive):
    path, _, key, payload = archive
    raw = path.read_bytes()
    header = raw[:len(backup.MAGIC) + backup.NONCE_BYTES]
    assert payload[:128] not in raw
    assert AESGCM(key).decrypt(header[-12:], raw[len(header):], header) == payload
    output = io.BytesIO()
    with path.open("rb") as source:
        assert backup.decrypt_stream(source, output, key) == len(payload)
    assert output.getvalue() == payload
    second = io.BytesIO()
    backup.encrypt_stream(io.BytesIO(payload), second, key)
    assert second.getvalue() != raw


@pytest.mark.parametrize("corruption", ["version", "nonce", "payload", "tag", "truncated", "wrong-key"])
def test_bad_archive_never_invokes_database_and_cleans_plaintext(archive, tmp_path, monkeypatch, corruption):
    path, key_file, _, _ = archive
    if corruption == "wrong-key":
        key_file.write_bytes(base64.b64encode(os.urandom(32)))
    else:
        raw = bytearray(path.read_bytes())
        if corruption == "truncated":
            raw = raw[:-25]
        else:
            index = {"version": 0, "nonce": 12, "payload": 100, "tag": -1}[corruption]
            raw[index] ^= 1
        path.write_bytes(raw)
    monkeypatch.setattr(backup.subprocess, "run", lambda *a, **k: pytest.fail("Invalid archive must not contact database"))
    with pytest.raises(backup.BackupError):
        backup.restore(path, key_file, scratch_dir=tmp_path, confirm=True)
    assert not list(tmp_path.glob(".distributedai-backup-*"))


def test_restore_verifies_before_empty_database_check_and_uses_transaction(archive, tmp_path, monkeypatch):
    path, key_file, _, payload = archive
    monkeypatch.setenv("PGDATABASE", "isolated_restore")
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if args[0] == "psql":
            return SimpleNamespace(returncode=0, stdout=b"0\n")
        assert args[0] == "pg_restore" and "--single-transaction" in args
        assert "--clean" not in args and "--create" not in args
        temporary = Path(args[-1])
        assert temporary.read_bytes() == payload
        assert temporary.stat().st_mode & 0o777 == 0o600
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(backup.subprocess, "run", run)
    assert backup.restore(path, key_file, scratch_dir=tmp_path, confirm=True) == {"restored": True}
    assert len(calls) == 2 and not list(tmp_path.glob(".distributedai-backup-*"))


def test_nonempty_database_and_missing_confirmation_never_restore(archive, tmp_path, monkeypatch):
    path, key_file, _, _ = archive
    monkeypatch.setenv("PGDATABASE", "restore_target")
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=b"5\n")
    monkeypatch.setattr(backup.subprocess, "run", run)
    with pytest.raises(backup.BackupError):
        backup.restore(path, key_file, scratch_dir=tmp_path)
    assert not calls
    with pytest.raises(backup.BackupError):
        backup.restore(path, key_file, scratch_dir=tmp_path, confirm=True)
    assert len(calls) == 1 and calls[0][0] == "psql"


def test_backup_failure_never_publishes_partial_archive(archive, tmp_path, monkeypatch):
    _, key_file, _, _ = archive
    monkeypatch.setenv("PGDATABASE", "source")
    class FailedDump:
        stdout = io.BytesIO(b"partial dump")
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def wait(self): return 1
    monkeypatch.setattr(backup.subprocess, "Popen", lambda *a, **kw: FailedDump())
    output = tmp_path / "failed.enc"
    with pytest.raises(backup.BackupError):
        backup.backup(output, key_file)
    assert not output.exists() and not list(tmp_path.glob(".distributedai-backup-*"))


def test_existing_output_and_size_bound_are_enforced(archive, tmp_path):
    path, key_file, key, payload = archive
    before = path.read_bytes()
    with pytest.raises(backup.BackupError):
        backup.backup(path, key_file)
    assert path.read_bytes() == before
    with pytest.raises(backup.BackupError):
        backup.encrypt_stream(io.BytesIO(payload), io.BytesIO(), key, max_bytes=10)
    with pytest.raises(backup.BackupError):
        backup.decrypt_stream(io.BytesIO(before), io.BytesIO(), key, max_bytes=10)


def test_successful_backup_publishes_only_private_encrypted_archive(archive, tmp_path, monkeypatch):
    _, key_file, key, payload = archive
    monkeypatch.setenv("PGDATABASE", "source")
    monkeypatch.setenv("PGPASSWORD", "synthetic-secret")
    class Dump:
        stdout = io.BytesIO(payload)
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def wait(self): return 0
    def start(args, **kwargs):
        assert "synthetic-secret" not in str(args)
        assert args == ["pg_dump", "--format=custom", "--no-owner", "--no-acl"]
        return Dump()
    monkeypatch.setattr(backup.subprocess, "Popen", start)
    output = tmp_path / "complete.enc"
    assert backup.backup(output, key_file)["payload_bytes"] == len(payload)
    assert output.stat().st_mode & 0o777 == 0o600
    plain = io.BytesIO()
    with output.open("rb") as source:
        backup.decrypt_stream(source, plain, key)
    assert plain.getvalue() == payload
    assert not list(tmp_path.glob(".distributedai-backup-*"))
