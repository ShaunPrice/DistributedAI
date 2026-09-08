# SPDX-License-Identifier: Apache-2.0
"""Session encryption is AES-256-GCM, bounded, time-limited and purpose-bound."""
import base64

from cryptography.fernet import Fernet, InvalidToken
import pytest

from distributedai.session_crypto import SessionCipher


@pytest.fixture
def cipher():
    return SessionCipher(Fernet.generate_key())


def test_roundtrip_and_unique_nonces(cipher):
    envelopes = [cipher.encrypt(b"private-session") for _ in range(100)]
    assert all(isinstance(envelope, bytes) for envelope in envelopes)
    assert len({base64.urlsafe_b64decode(envelope)[12:24] for envelope in envelopes}) == 100
    assert all(cipher.decrypt(envelope, ttl=300) == b"private-session" for envelope in envelopes)
    assert cipher.decrypt(cipher.encrypt(b"")) == b""


@pytest.mark.parametrize("offset", [0, 4, 11, 12, 23, 24, -1])
def test_version_timestamp_nonce_payload_and_tag_are_authenticated(cipher, offset):
    raw = bytearray(base64.urlsafe_b64decode(cipher.encrypt(b"private-session")))
    raw[offset] ^= 1
    with pytest.raises(InvalidToken):
        cipher.decrypt(base64.urlsafe_b64encode(raw), ttl=300)


def test_ttl_future_and_authenticated_time(cipher, monkeypatch):
    monkeypatch.setattr("distributedai.session_crypto.time.time", lambda: 1000)
    token = cipher.encrypt(b"session")
    monkeypatch.setattr("distributedai.session_crypto.time.time", lambda: 1010)
    assert cipher.decrypt(token, ttl=10) == b"session"
    with pytest.raises(InvalidToken):
        cipher.decrypt(token, ttl=9)
    monkeypatch.setattr("distributedai.session_crypto.time.time", lambda: 999)
    with pytest.raises(InvalidToken):
        cipher.decrypt(token)


def test_purpose_and_key_isolation():
    key = Fernet.generate_key()
    token = SessionCipher(key, purpose=b"tenant").encrypt(b"session")
    for cipher in [SessionCipher(key, purpose=b"platform"), SessionCipher(Fernet.generate_key(), purpose=b"tenant")]:
        with pytest.raises(InvalidToken):
            cipher.decrypt(token)
    with pytest.raises(InvalidToken):
        SessionCipher(key).decrypt(Fernet(key).encrypt(b"legacy"))


@pytest.mark.parametrize("token", [b"", b"%%%%", b"abc", b"x" * 131073, "string", None])
def test_malformed_bounded_inputs(cipher, token):
    with pytest.raises(InvalidToken):
        cipher.decrypt(token)


@pytest.mark.parametrize("key", [b"", b"%%%", base64.urlsafe_b64encode(b"short"), "☃", None])
def test_invalid_keys(key):
    with pytest.raises(ValueError):
        SessionCipher(key)


def test_invalid_ttl_and_payload(cipher):
    token = cipher.encrypt(b"session")
    for ttl in [-1, True, "300", 1.5]:
        with pytest.raises(InvalidToken):
            cipher.decrypt(token, ttl=ttl)
    for payload in [b"x" * 65537, "string"]:
        with pytest.raises(ValueError):
            cipher.encrypt(payload)
