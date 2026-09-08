# SPDX-License-Identifier: AGPL-3.0-only
"""Provider-hosted browser login. ID tokens never authorise MCP requests."""
import asyncio
import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode, urlparse

import httpx
import jwt
from cryptography.fernet import InvalidToken
from starlette.responses import JSONResponse, RedirectResponse

FLOW_COOKIE = "da_oidc_flow"


class CloudLogin:
    def __init__(self, settings, cipher, store, *, base_path="/manage", session_cookie="da_management"):
        self.base_path, self.session_cookie = base_path, session_cookie
        self.settings, self.cipher, self.store = settings, cipher, store
        url = urlparse(settings.public_url)
        self.origin = f"{url.scheme}://{url.netloc}"
        self.callback = self.origin + self.base_path + "/oidc/callback"
        self.secure = url.scheme == "https"
        self.metadata = None
        self.jwks = None
        self.lock = asyncio.Lock()

    async def discover(self):
        async with self.lock:
            if self.metadata is not None:
                return self.metadata
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                response = await client.get(self.settings.login_issuer.rstrip("/") + "/.well-known/openid-configuration")
                response.raise_for_status()
                if len(response.content) > 131072:
                    raise ValueError("Oversized discovery")
                metadata = response.json()
            if metadata.get("issuer") != self.settings.login_issuer:
                raise ValueError("Discovery issuer mismatch")
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                endpoint = urlparse(metadata[key])
                if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.fragment:
                    raise ValueError("Provider endpoint requires HTTPS")
            self.jwks = jwt.PyJWKClient(metadata["jwks_uri"], timeout=10)
            self.metadata = metadata
            return metadata

    async def start(self, request):
        if self.settings.login_mode == "token":
            return JSONResponse({"error": "Cloud sign-in is disabled"}, 404)
        try:
            metadata = await self.discover()
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return JSONResponse({"error": "Identity provider unavailable"}, 503)
        flow = {"state": secrets.token_urlsafe(32), "nonce": secrets.token_urlsafe(32),
                "verifier": secrets.token_urlsafe(48)}
        challenge = base64.urlsafe_b64encode(hashlib.sha256(flow["verifier"].encode()).digest()).rstrip(b"=").decode()
        params = {"client_id": self.settings.login_client_id, "redirect_uri": self.callback,
                  "response_type": "code", "scope": "openid", "state": flow["state"],
                  "nonce": flow["nonce"], "code_challenge": challenge,
                  "code_challenge_method": "S256", "response_mode": "query"}
        response = RedirectResponse(metadata["authorization_endpoint"] + "?" + urlencode(params), 302)
        response.set_cookie(FLOW_COOKIE, self.cipher.encrypt(json.dumps(flow).encode()).decode(),
                            max_age=300, httponly=True, secure=self.secure, samesite="lax", path=self.base_path + "/oidc")
        return response

    def verify_id_token(self, token, nonce):
        if not isinstance(token, str) or len(token) > 32768:
            raise ValueError("Invalid ID token")
        key = self.jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256", "ES256"],
                            audience=self.settings.login_client_id,
                            issuer=self.settings.login_issuer,
                            options={"require": ["exp", "iat", "sub", "nonce"]})
        if not secrets.compare_digest(str(claims["nonce"]), nonce):
            raise ValueError("Nonce mismatch")
        if "azp" in claims and claims["azp"] != self.settings.login_client_id:
            raise ValueError("Authorised party mismatch")
        if isinstance(claims["aud"], list) and len(claims["aud"]) > 1 and claims.get("azp") != self.settings.login_client_id:
            raise ValueError("Multiple audiences require authorised party")
        if claims.get("token_use", "id") != "id":
            raise ValueError("Expected ID token")
        return claims

    async def finish(self, request):
        response = JSONResponse({"error": "Cloud sign-in failed. Restart sign-in or contact your administrator."}, 401)
        try:
            if self.settings.login_mode == "token":
                raise ValueError("Disabled")
            cookie = request.cookies.get(FLOW_COOKIE, "")
            if len(cookie) > 8192:
                raise ValueError("Oversized cookie")
            flow = json.loads(self.cipher.decrypt(cookie.encode(), ttl=300))
            params = request.query_params
            if any(len(params.getlist(key)) != 1 for key in ("state", "code")) or "error" in params:
                raise ValueError("Invalid response")
            if not secrets.compare_digest(params["state"], flow["state"]) or len(params["code"]) > 8192:
                raise ValueError("State mismatch")
            metadata = await self.discover()
            data = {"grant_type": "authorization_code", "code": params["code"],
                    "redirect_uri": self.callback, "client_id": self.settings.login_client_id,
                    "code_verifier": flow["verifier"]}
            # All three documented providers support client_secret_post for web clients.
            if self.settings.login_client_secret:
                data["client_secret"] = self.settings.login_client_secret
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                result = await client.post(metadata["token_endpoint"], data=data)
                result.raise_for_status()
                if len(result.content) > 131072:
                    raise ValueError("Oversized token response")
                claims = await asyncio.to_thread(self.verify_id_token, result.json()["id_token"], flow["nonce"])
            principal_id = self.settings.login_subjects.get(claims["sub"])
            principal = await asyncio.to_thread(self.store.resolve_principal, principal_id) if principal_id else None
            if principal is None:
                raise ValueError("Unassigned identity")
            session = {"kind": "oidc", "principal_id": principal.id, "sub": claims["sub"],
                       "issuer": self.settings.login_issuer, "expires": min(claims["exp"], int(time.time()) + 1800)}
            response = RedirectResponse(self.base_path + "/", 303)
            response.set_cookie(self.session_cookie, self.cipher.encrypt(json.dumps(session).encode()).decode(),
                                max_age=max(1, int(session["expires"] - time.time())), httponly=True,
                                secure=self.secure, samesite="strict", path=self.base_path)
        except (InvalidToken, jwt.PyJWTError, httpx.HTTPError, ValueError, TypeError, KeyError, UnicodeError):
            pass  # Never return provider response bodies or authorization codes to the browser/log.
        response.delete_cookie(FLOW_COOKIE, path=self.base_path + "/oidc", secure=self.secure, httponly=True, samesite="lax")
        return response
