# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant field encryption and envelope keys; callers must enforce tenant authorisation.

No ciphertext fallback, plaintext keys in database, key export, or provider-selected URLs.
Provider registrations are trusted deployment configuration, never request parameters.
"""
from __future__ import annotations

import base64
import json
import os
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import Column, ForeignKey, Integer, LargeBinary, MetaData, String, Table, insert, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError


from ..domain import EncryptionError


class KeyWrapper(Protocol):
    def wrap(self, key: bytes, context: bytes) -> bytes: ...
    def unwrap(self, wrapped: bytes, context: bytes) -> bytes: ...


class LocalWrapper:
    """AES-256-GCM KEK supplied from a protected deployment secret file."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise EncryptionError("Master key must contain exactly 32 bytes")
        self._cipher = AESGCM(key)

    def wrap(self, key: bytes, context: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._cipher.encrypt(nonce, key, context)

    def unwrap(self, wrapped: bytes, context: bytes) -> bytes:
        return self._cipher.decrypt(wrapped[:12], wrapped[12:], context)


class AWSKMSWrapper:
    """Fixed AWS KMS symmetric encryption key; client may be supplied for testing."""

    def __init__(self, key_id: str, client=None):
        if client is None:
            import boto3
            client = boto3.client("kms")
        self._client, self._key_id = client, key_id

    def wrap(self, key: bytes, context: bytes) -> bytes:
        return self._client.encrypt(KeyId=self._key_id, Plaintext=key,
            EncryptionContext={"distributedai": context.decode()})["CiphertextBlob"]

    def unwrap(self, wrapped: bytes, context: bytes) -> bytes:
        return self._client.decrypt(KeyId=self._key_id, CiphertextBlob=wrapped,
            EncryptionContext={"distributedai": context.decode()})["Plaintext"]


class AzureKeyVaultWrapper:
    """Versioned Azure Key Vault RSA key, wrapping only the random AES data key."""

    def __init__(self, key_id: str, client=None):
        if client is None:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys.crypto import CryptographyClient
            client = CryptographyClient(key_id, DefaultAzureCredential())
        self._client = client

    def wrap(self, key: bytes, context: bytes) -> bytes:
        # RSA-OAEP-256 has no AAD. Field AEAD independently binds tenant/version/record.
        return self._client.wrap_key("RSA-OAEP-256", key).encrypted_key

    def unwrap(self, wrapped: bytes, context: bytes) -> bytes:
        return self._client.unwrap_key("RSA-OAEP-256", wrapped).key


class GCPKMSWrapper:
    """Fixed Google Cloud KMS CryptoKey (use symmetric ENCRYPT_DECRYPT purpose)."""

    def __init__(self, key_id: str, client=None):
        if client is None:
            from google.cloud import kms
            client = kms.KeyManagementServiceClient()
        self._client, self._key_id = client, key_id

    def wrap(self, key: bytes, context: bytes) -> bytes:
        return self._client.encrypt(request={"name": self._key_id, "plaintext": key,
            "additional_authenticated_data": context}).ciphertext

    def unwrap(self, wrapped: bytes, context: bytes) -> bytes:
        return self._client.decrypt(request={"name": self._key_id, "ciphertext": wrapped,
            "additional_authenticated_data": context}).plaintext


metadata = MetaData()
keyrings = Table("tenant_keyrings", metadata,
    Column("org_id", String(64), primary_key=True),
    Column("active_version", Integer, nullable=False))
key_versions = Table("tenant_key_versions", metadata,
    Column("org_id", String(64), ForeignKey("tenant_keyrings.org_id"), primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("provider", String(128), nullable=False),
    Column("wrapped_key", LargeBinary, nullable=False))


def _context(org_id: str, version: int) -> bytes:
    return json.dumps(["distributedai-key-v1", org_id, version], separators=(",", ":")).encode()


def _aad(org_id: str, record_id: str, field: str, version: int) -> bytes:
    return json.dumps(["distributedai-content-v1", org_id, record_id, field, version],
        separators=(",", ":")).encode()


class CryptoBox:
    """Persistent per-tenant versioned AES-256-GCM encryption.

    Initialize schema during setup, provision keys before content transactions. Rotation
    changes writes only; retain old provider registrations and KEKs for historical reads.
    This low-level class is private to the data plane, never a central-admin API.
    """

    PREFIX = "enc:v1:"

    def __init__(self, engine: Engine, providers: dict[str, KeyWrapper], default_provider="local"):
        if default_provider not in providers:
            raise EncryptionError("Default encryption provider is unavailable")
        self.engine, self._providers, self.default_provider = engine, dict(providers), default_provider
        self._request_keys = ContextVar(f"keys-{id(self)}", default=None)

    @contextmanager
    def operation(self):
        """Bound key reuse to one operation, avoiding a KMS round trip per field."""
        token = self._request_keys.set({})
        try:
            yield
        finally:
            self._request_keys.reset(token)

    def initialize(self):
        metadata.create_all(self.engine)

    def provision(self, org_id: str):
        """Idempotent initial key setup; unique constraint arbitrates concurrent replicas."""
        with self.engine.connect() as conn:
            if conn.execute(select(keyrings.c.org_id).where(keyrings.c.org_id == org_id)).first():
                return
        try:
            with self.engine.begin() as conn:
                conn.execute(insert(keyrings).values(org_id=org_id, active_version=1))
                self._insert_key(conn, org_id, 1, self.default_provider, os.urandom(32))
        except IntegrityError:
            with self.engine.connect() as conn:
                if not conn.execute(select(keyrings.c.org_id).where(keyrings.c.org_id == org_id)).first():
                    raise EncryptionError("Tenant key provisioning failed") from None

    def _insert_key(self, conn, org_id, version, provider, key):
        try:
            if len(key) != 32:
                raise ValueError()
            wrapped = self._providers[provider].wrap(key, _context(org_id, version))
            conn.execute(insert(key_versions).values(org_id=org_id, version=version,
                provider=provider, wrapped_key=wrapped))
        except Exception:
            raise EncryptionError("Tenant key operation failed") from None

    def rotate(self, org_id: str, provider: str, imported_key: bytes | None = None) -> dict:
        """Organisation-admin-only integration point; NEVER expose via central admin.

        Imported AES-256 key is wrapped immediately and never returned. A secure cloud
        registration passes only a configured provider alias and generates a random DEK.
        """
        if provider not in self._providers:
            raise EncryptionError("Encryption provider is unavailable")
        with self.engine.begin() as conn:
            current = conn.execute(select(keyrings.c.active_version).where(
                keyrings.c.org_id == org_id).with_for_update()).scalar_one_or_none()
            if current is None:
                raise EncryptionError("Tenant key is not provisioned")
            version = current + 1
            self._insert_key(conn, org_id, version, provider,
                imported_key if imported_key is not None else os.urandom(32))
            conn.execute(update(keyrings).where(keyrings.c.org_id == org_id).values(active_version=version))
        return {"version": version, "provider": provider, "algorithm": "AES-256-GCM"}

    def status(self, org_id: str) -> dict:
        with self.engine.connect() as conn:
            rows = conn.execute(select(key_versions.c.version, key_versions.c.provider).where(
                key_versions.c.org_id == org_id).order_by(key_versions.c.version)).all()
            active = conn.execute(select(keyrings.c.active_version).where(keyrings.c.org_id == org_id)).scalar_one_or_none()
        return {"algorithm": "AES-256-GCM", "active_version": active,
            "versions": [{"version": r.version, "provider": r.provider} for r in rows]}

    def _key(self, org_id: str, version: int | None = None):
        cache = self._request_keys.get()
        cache_key = (org_id, version)
        if cache is not None and cache_key in cache:
            return cache[cache_key]
        with self.engine.connect() as conn:
            if version is None:
                version = conn.execute(select(keyrings.c.active_version).where(
                    keyrings.c.org_id == org_id)).scalar_one_or_none()
            row = conn.execute(select(key_versions).where(key_versions.c.org_id == org_id,
                key_versions.c.version == version)).mappings().one_or_none()
        if row is None:
            raise EncryptionError("Tenant key is unavailable")
        key = self._providers[row["provider"]].unwrap(row["wrapped_key"], _context(org_id, version))
        if len(key) != 32:
            raise EncryptionError("Tenant key is invalid")
        if cache is not None:
            cache[cache_key] = (key, version)
            cache[(org_id, version)] = (key, version)
        return key, version

    def encrypt(self, org_id: str, record_id: str, field: str, plaintext: str) -> str:
        try:
            key, version = self._key(org_id)
            nonce = os.urandom(12)
            payload = nonce + AESGCM(key).encrypt(nonce, plaintext.encode(), _aad(org_id, record_id, field, version))
            return f"{self.PREFIX}{version}:" + base64.b64encode(payload).decode()
        except Exception:
            raise EncryptionError("Content encryption failed") from None

    def decrypt(self, org_id: str, record_id: str, field: str, ciphertext: str) -> str:
        try:
            if not ciphertext.startswith(self.PREFIX):
                raise ValueError()
            version_string, encoded = ciphertext[len(self.PREFIX):].split(":", 1)
            version = int(version_string)
            payload = base64.b64decode(encoded, validate=True)
            key, _ = self._key(org_id, version)
            return AESGCM(key).decrypt(payload[:12], payload[12:],
                _aad(org_id, record_id, field, version)).decode()
        except Exception:
            raise EncryptionError("Content decryption failed") from None

    @staticmethod
    def new_record_id() -> str:
        return uuid.uuid4().hex
