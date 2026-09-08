# SPDX-License-Identifier: AGPL-3.0-only
"""Content-blind platform operations; deliberately separate from tenant authorisation."""
import asyncio
import base64
import copy
import hashlib
import hmac
import json
import time
from types import SimpleNamespace
from pathlib import Path
from urllib.parse import urlparse

from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.applications import Starlette
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from .management import BrowserHeaders
from .oidc import CloudLogin
from ..session_crypto import SessionCipher
from ..domain import ServiceError

COOKIE = "da_platform"
TTL = 900
STATIC = Path(__file__).resolve().parents[1] / "static"


def platform_app(service, settings):
    token = getattr(settings, "platform_admin_token", "")
    mode = getattr(settings, "login_mode", "token")
    subjects = getattr(settings, "platform_subjects", [])
    if not isinstance(token, str) or (mode != "oidc" and len(token) < 48) or not settings.management_key:
        raise ValueError("Platform console requires a separate credential of at least 48 characters and MANAGEMENT_KEY")
    # Domain separation prevents even a valid management cookie from being used here.
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"distributedai/platform-session/v1").derive(base64.urlsafe_b64decode(settings.management_key))
    cipher = SessionCipher(base64.urlsafe_b64encode(derived), purpose=b"distributedai/platform-session/v1")
    credential_digest = hashlib.sha256(token.encode()).hexdigest()
    cloud_settings = copy.copy(settings)
    cloud_settings.login_mode = mode
    cloud_settings.login_subjects = {subject: "platform-administrator" for subject in subjects}
    class PlatformIdentity:
        def resolve_principal(self, principal_id):
            return SimpleNamespace(id="platform-administrator") if principal_id == "platform-administrator" else None
    cloud = CloudLogin(cloud_settings, cipher, PlatformIdentity(), base_path="/platform", session_cookie=COOKIE)
    url = urlparse(settings.public_url)
    origin = f"{url.scheme}://{url.netloc}"

    def csrf(request):
        return request.headers.get("origin") == origin and request.headers.get("content-type", "").split(";")[0] == "application/json"

    async def identity(request):
        try:
            cookie = request.cookies.get(COOKIE, "")
            if len(cookie) > 4096:
                return False
            if await asyncio.to_thread(service.sessions.is_revoked, cookie):
                return False
            session = json.loads(cipher.decrypt(cookie.encode(), ttl=TTL))
            if session.get("kind") == "oidc":
                valid = (mode != "token" and session.get("sub") in getattr(settings, "platform_subjects", [])
                        and session.get("issuer") == settings.login_issuer
                        and session.get("principal_id") == "platform-administrator"
                        and session.get("expires", 0) > time.time())
                if valid:
                    request.scope["security_actor"] = "platform-oidc:" + session["sub"]
                return valid
            valid = mode != "oidc" and session == {"purpose": "platform", "credential": credential_digest}
            if valid:
                request.scope["security_actor"] = "platform-token-administrator"
            return valid
        except (InvalidToken, ValueError, UnicodeError, TypeError):
            return False

    async def page(request):
        return FileResponse(STATIC / "platform.html")

    async def asset(request):
        name = request.path_params["name"]
        if name not in {"platform.js", "style.css", "favicon.svg", "icon-projects.svg", "icon-people.svg", "icon-reviews.svg", "icon-billing.svg", "icon-keys.svg", "icon-audit.svg"}:
            return JSONResponse({"error": "Not found"}, 404)
        return FileResponse(STATIC / name)

    async def login_options(request):
        return JSONResponse({"token": mode in {"token", "both"}, "oidc": mode in {"oidc", "both"},
                             "provider": getattr(settings, "login_provider", "Organisation")})

    async def login(request):
        if mode == "oidc":
            return JSONResponse({"error": "Use platform identity sign-in"}, 403)
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        try:
            data = await request.json()
            supplied = data.get("token", "")
            valid = isinstance(supplied, str) and len(supplied) <= 2048 and hmac.compare_digest(
                hashlib.sha256(supplied.encode()).hexdigest(), credential_digest)
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            return JSONResponse({"error": "Invalid platform credential"}, 401)
        request.scope["security_actor"] = "platform-token-administrator"
        response = JSONResponse({"authenticated": True})
        response.set_cookie(COOKIE, cipher.encrypt(json.dumps({"purpose": "platform", "credential": credential_digest}).encode()).decode(),
                            max_age=TTL, httponly=True, secure=url.scheme == "https", samesite="strict", path="/platform")
        return response

    async def logout(request):
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        await asyncio.to_thread(service.sessions.revoke, request.cookies.get(COOKIE, ""), TTL)
        response = JSONResponse({"authenticated": False})
        response.delete_cookie(COOKIE, path="/platform", secure=url.scheme == "https", httponly=True, samesite="strict")
        return response

    async def state(request):
        if not await identity(request):
            return JSONResponse({"error": "Platform sign-in required"}, 401)
        result = await asyncio.to_thread(service.list_accounts)
        return JSONResponse({"status": "available", **result})

    async def update(request):
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        if not await identity(request):
            return JSONResponse({"error": "Platform sign-in required"}, 401)
        try:
            data = await request.json()
            if not isinstance(data, dict) or set(data) != {"account_id", "suspended"}:
                raise ValueError("Only account_id and suspended are accepted")
            return JSONResponse(await asyncio.to_thread(service.set_suspended, data["account_id"], data["suspended"]))
        except (ValueError, TypeError):
            return JSONResponse({"error": "Invalid account operation"}, 400)
        except LookupError:
            return JSONResponse({"error": "Account not found"}, 404)

    async def assign_plan(request):
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        if not await identity(request):
            return JSONResponse({"error": "Platform sign-in required"}, 401)
        try:
            body = await request.body()
            if len(body) > 4096:
                raise ValueError()
            data = json.loads(body)
            if not isinstance(data, dict) or set(data) != {"account_id", "plan"}:
                raise ValueError()
            return JSONResponse(await asyncio.to_thread(service.set_plan, data["account_id"], data["plan"]))
        except (ValueError, TypeError, ServiceError):
            return JSONResponse({"error": "Invalid account plan"}, 400)
        except LookupError:
            return JSONResponse({"error": "Account not found"}, 404)

    return BrowserHeaders(Starlette(routes=[*([Route("/", page), Route("/assets/{name}", asset)] if getattr(settings, "serve_assets", True) else []),
        Route("/login", login, methods=["POST"]), Route("/logout", logout, methods=["POST"]),
        Route("/login-options", login_options), Route("/oidc/start", cloud.start), Route("/oidc/callback", cloud.finish),
        Route("/state", state), Route("/accounts", update, methods=["POST"]),
        Route("/accounts/plan", assign_plan, methods=["POST"])]))
