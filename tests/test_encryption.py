# SPDX-License-Identifier: Apache-2.0
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select

from distributedai.encryption import (
    AWSKMSWrapper, AzureKeyVaultWrapper, CryptoBox, EncryptionError, GCPKMSWrapper,
    LocalWrapper, key_versions,
)


@pytest.fixture
def box(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'keys.db'}")
    box = CryptoBox(engine, {"local": LocalWrapper(b"k" * 32)})
    box.initialize()
    box.provision("a")
    box.provision("b")
    return box


def test_field_ciphertext_is_random_bound_and_persistent(box):
    value = box.encrypt("a", "row", "content", "private memory 🔒")
    assert value != box.encrypt("a", "row", "content", "private memory 🔒")
    assert "private" not in value
    reopened = CryptoBox(box.engine, {"local": LocalWrapper(b"k" * 32)})
    assert reopened.decrypt("a", "row", "content", value) == "private memory 🔒"
    for org, row, field in [("b", "row", "content"), ("a", "other", "content"), ("a", "row", "source")]:
        with pytest.raises(EncryptionError):
            reopened.decrypt(org, row, field, value)


@pytest.mark.parametrize("value", ["plaintext", "enc:v1:1:bad", "enc:v1:-1:AAAA", "", "enc:v1:1:"])
def test_decryption_fails_closed(box, value):
    with pytest.raises(EncryptionError, match="Content decryption failed"):
        box.decrypt("a", "r", "content", value)


def test_rotation_keeps_history_and_wraps_imported_key(box):
    old = box.encrypt("a", "r", "content", "before")
    assert box.rotate("a", "local", b"z" * 32)["version"] == 2
    new = box.encrypt("a", "r", "content", "after")
    assert old.startswith("enc:v1:1:") and new.startswith("enc:v1:2:")
    assert box.decrypt("a", "r", "content", old) == "before"
    assert box.decrypt("a", "r", "content", new) == "after"
    with box.engine.connect() as conn:
        rows = conn.execute(select(key_versions)).mappings().all()
    assert all(b"z" * 32 not in r["wrapped_key"] for r in rows)
    assert "wrapped_key" not in str(box.status("a"))
    assert box.status("b")["active_version"] == 1


def test_key_failure_does_not_write_plaintext_or_change_active_version(box):
    with pytest.raises(EncryptionError):
        box.rotate("a", "local", b"short")
    with pytest.raises(EncryptionError):
        box.rotate("a", "unknown")
    assert box.status("a")["active_version"] == 1
    box.provision("a")
    assert len(box.status("a")["versions"]) == 1
    with pytest.raises(EncryptionError):
        box.encrypt("unprovisioned", "r", "content", "secret")


def test_wrong_master_key_and_modified_ciphertext_fail(box):
    value = box.encrypt("a", "r", "content", "secret")
    wrong = CryptoBox(box.engine, {"local": LocalWrapper(b"x" * 32)})
    with pytest.raises(EncryptionError):
        wrong.decrypt("a", "r", "content", value)
    with pytest.raises(EncryptionError):
        box.decrypt("a", "r", "content", value[:-5] + "AAAA=")


def test_local_wrap_binds_key_context():
    wrapper = LocalWrapper(b"k" * 32)
    wrapped = wrapper.wrap(b"d" * 32, b"tenant-a")
    assert wrapper.unwrap(wrapped, b"tenant-a") == b"d" * 32
    with pytest.raises(Exception):
        wrapper.unwrap(wrapped, b"tenant-b")
    with pytest.raises(EncryptionError):
        LocalWrapper(b"short")


def test_cloud_adapters_forward_fixed_keys_and_aad():
    class AWS:
        def encrypt(self, **kw):
            assert kw["KeyId"] == "aws-fixed"
            self.data, self.context = kw["Plaintext"], kw["EncryptionContext"]
            return {"CiphertextBlob": b"wrapped"}
        def decrypt(self, **kw):
            assert kw["KeyId"] == "aws-fixed" and kw["EncryptionContext"] == self.context
            return {"Plaintext": self.data}
    class GCP:
        def encrypt(self, request):
            assert request["name"] == "gcp-fixed"
            self.data, self.context = request["plaintext"], request["additional_authenticated_data"]
            return SimpleNamespace(ciphertext=b"wrapped")
        def decrypt(self, request):
            assert request["name"] == "gcp-fixed" and request["additional_authenticated_data"] == self.context
            return SimpleNamespace(plaintext=self.data)
    class Azure:
        def wrap_key(self, algorithm, key):
            assert algorithm == "RSA-OAEP-256"
            self.data = key
            return SimpleNamespace(encrypted_key=b"wrapped")
        def unwrap_key(self, algorithm, value):
            assert algorithm == "RSA-OAEP-256" and value == b"wrapped"
            return SimpleNamespace(key=self.data)
    for wrapper in [AWSKMSWrapper("aws-fixed", AWS()), GCPKMSWrapper("gcp-fixed", GCP()),
                    AzureKeyVaultWrapper("azure-fixed", Azure())]:
        assert wrapper.unwrap(wrapper.wrap(b"d" * 32, b"tenant"), b"tenant") == b"d" * 32
