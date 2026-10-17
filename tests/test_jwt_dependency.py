# SPDX-License-Identifier: Apache-2.0
"""Guard the options-reuse claim-verification regression in our JWT dependency."""
import secrets

import jwt
import pytest


@pytest.mark.parametrize("decode", [jwt.decode, jwt.decode_complete])
def test_unverified_decode_does_not_disable_later_claim_verification(decode):
    key = secrets.token_bytes(32)
    token = jwt.encode({"sub": "synthetic-test-subject", "exp": 1}, key, algorithm="HS256")
    options = {"verify_signature": False}

    decode(token, options=options)
    assert options == {"verify_signature": False}

    options["verify_signature"] = True
    with pytest.raises(jwt.ExpiredSignatureError):
        decode(token, key, algorithms=["HS256"], options=options)
