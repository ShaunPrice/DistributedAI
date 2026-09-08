# SPDX-License-Identifier: AGPL-3.0-only
"""AES-256-GCM browser envelopes with authenticated version, time and purpose.

The input key has the same encoding as an existing Fernet key (32 random bytes,
URL-safe base64), but old Fernet cookies are deliberately not accepted. Switching
formats expires existing sessions without changing deployment key files.
"""
import base64
import binascii
import secrets
import struct
import time

from cryptography.exceptions import InvalidTag
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = b"DAS1"
HEADER_LENGTH = 24  # 4-byte version + 8-byte UTC timestamp + 12-byte GCM nonce
MAX_TOKEN_LENGTH = 131072


class SessionCipher:
    def __init__(self, key: bytes | str, *, purpose: bytes = b"distributedai/management-session/v1"):
        try:
            encoded = key.encode("ascii") if isinstance(key, str) else key
            raw = base64.b64decode(encoded, altchars=b"-_", validate=True)
        except (ValueError, TypeError, binascii.Error, UnicodeError) as exc:
            raise ValueError("Session key must encode exactly 32 random bytes") from exc
        if len(raw) != 32:
            raise ValueError("Session key must encode exactly 32 random bytes")
        if not isinstance(purpose, bytes) or not purpose or len(purpose) > 256:
            raise ValueError("Session purpose must be 1 to 256 bytes")
        self._cipher = AESGCM(raw)
        self._purpose = purpose

    def encrypt(self, data: bytes) -> bytes:
        if not isinstance(data, bytes) or len(data) > 65536:
            raise ValueError("Session payload must be bounded bytes")
        header = VERSION + struct.pack(">Q", int(time.time())) + secrets.token_bytes(12)
        return base64.urlsafe_b64encode(header + self._cipher.encrypt(header[12:], data, header + self._purpose))

    def decrypt(self, token: bytes, ttl: int | None = None) -> bytes:
        try:
            if not isinstance(token, bytes) or len(token) > MAX_TOKEN_LENGTH:
                raise InvalidToken
            if ttl is not None and (type(ttl) is not int or ttl < 0):
                raise InvalidToken
            raw = base64.b64decode(token, altchars=b"-_", validate=True)
            if len(raw) < HEADER_LENGTH + 16 or raw[:4] != VERSION:
                raise InvalidToken
            header = raw[:HEADER_LENGTH]
            data = self._cipher.decrypt(header[12:], raw[HEADER_LENGTH:], header + self._purpose)
            issued = struct.unpack(">Q", header[4:12])[0]
            now = int(time.time())
            if issued > now or (ttl is not None and now - issued > ttl):
                raise InvalidToken
            return data
        except (InvalidTag, ValueError, TypeError, binascii.Error, struct.error) as exc:
            raise InvalidToken from exc
