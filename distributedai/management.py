# SPDX-License-Identifier: AGPL-3.0-only
"""Same-origin management console with encrypted, short-lived HttpOnly sessions.

Session encryption keys are deployment secrets shared across API replicas. The original
credential is checked on every call, so revoking it terminates existing browser sessions.
No token is stored in browser localStorage or supplied to scripts after login.
"""
import asyncio
import json
from pathlib import Path
import secrets
import time
from urllib.parse import urlparse

from cryptography.fernet import InvalidToken
from starlette.applications import Starlette
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from .auth import Verifier
from .oidc import CloudLogin
from .session_crypto import SessionCipher
from .store import ServiceError

TTL = 1800
COOKIE = "da_management"
STATIC = Path(__file__).parent / "static"
OPERATIONS = {
    "instance_create", "instance_list", "connection_issue", "connection_list", "connection_revoke", "billing_status",
    "scope_create", "scope_list", "principal_create", "principal_list", "principal_revoke",
    "grant", "grant_list", "grant_revoke", "project_resolve", "memory_search", "memory_history",
    "memory_review", "proposal_list", "audit_list", "job_list", "job_review", "job_cancel",
}


class BrowserHeaders:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def secure_send(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend([
                    (b"cache-control", b"no-store"),
                    (b"content-security-policy", b"default-src 'none'; script-src 'self'; style-src 'self'; "
                     b"connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-frame-options", b"DENY"),
                ])
            await send(message)
        await self.app(scope, receive, secure_send)


def management_app(store, settings):
    cipher = SessionCipher(settings.management_key.encode())
    verifier = Verifier(store, settings, purpose="management")
    cloud = CloudLogin(settings, cipher, store)
    url = urlparse(settings.public_url)
    origin = f"{url.scheme}://{url.netloc}"

    async def identity(request):
        try:
            encrypted = request.cookies.get(COOKIE, "")
            if len(encrypted) > 16384:
                return None
            session = json.loads(cipher.decrypt(encrypted.encode(), ttl=TTL))
            if session["kind"] == "oidc":
                if settings.login_mode == "token" or session["expires"] <= time.time() or session["issuer"] != settings.login_issuer:
                    return None
                if settings.login_subjects.get(session["sub"]) != session["principal_id"]:
                    return None
                return await asyncio.to_thread(store.resolve_principal, session["principal_id"])
            if settings.login_mode == "oidc" or session["kind"] != "token":
                return None
            token = session["token"]
        except (InvalidToken, ValueError, UnicodeError, KeyError, TypeError):
            return None
        access = await verifier.verify_token(token)
        return await asyncio.to_thread(store.resolve_principal, access.client_id) if access else None

    def csrf(request):
        return request.headers.get("origin") == origin and request.headers.get("content-type", "").split(";")[0] == "application/json"

    async def page(request):
        return FileResponse(STATIC / "index.html")

    async def asset(request):
        name = request.path_params["name"]
        if name not in {"app.js", "style.css", "favicon.svg", "icon-projects.svg", "icon-people.svg", "icon-reviews.svg", "icon-billing.svg", "icon-keys.svg", "icon-audit.svg"}:
            return JSONResponse({"error": "Not found"}, 404)
        return FileResponse(STATIC / name)

    async def login_options(request):
        return JSONResponse({"token": settings.login_mode in {"token", "both"},
                             "oidc": settings.login_mode in {"oidc", "both"},
                             "provider": settings.login_provider})

    async def login(request):
        if settings.login_mode == "oidc":
            return JSONResponse({"error": "Use organisation sign-in"}, 403)
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        try:
            data = await request.json()
            token = data.get("token", "")
            if not isinstance(token, str) or len(token) > 2048:
                return JSONResponse({"error": "Invalid credential"}, 401)
            access = await verifier.verify_token(token)
        except (ValueError, TypeError, AttributeError):
            access = None
        if not access:
            return JSONResponse({"error": "Invalid or revoked access token"}, 401)
        response = JSONResponse({"authenticated": True})
        response.set_cookie(COOKIE, cipher.encrypt(json.dumps({"kind": "token", "token": token}).encode()).decode(), max_age=TTL,
                            httponly=True, secure=url.scheme == "https", samesite="strict",
                            path="/manage")
        return response

    async def logout(request):
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        response = JSONResponse({"authenticated": False})
        response.delete_cookie(COOKIE, path="/manage", secure=url.scheme == "https",
                               httponly=True, samesite="strict")
        return response

    async def state(request):
        principal = await identity(request)
        if principal is None:
            return JSONResponse({"error": "Sign in to continue"}, 401)
        scopes = await asyncio.to_thread(store.dispatch, principal, "scope_list", {})
        return JSONResponse({"principal": {"id": principal.id, "name": principal.name,
                                           "org_id": principal.org_id,
                                           "is_org_admin": principal.is_org_admin}, **scopes})

    async def action(request):
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        principal = await identity(request)
        if principal is None:
            return JSONResponse({"error": "Session expired or credential revoked"}, 401)
        op = request.path_params["operation"]
        if op not in OPERATIONS:
            return JSONResponse({"error": "Operation not available"}, 404)
        try:
            arguments = await request.json()
            if not isinstance(arguments, dict):
                return JSONResponse({"error": "Expected an object"}, 400)
            issued = None
            if op == "principal_create":
                # User-supplied token fields cannot select weak credentials.
                if set(arguments) != {"name"}:
                    return JSONResponse({"error": "Only name is accepted"}, 400)
                issued = secrets.token_urlsafe(48)
                arguments["token"] = issued
            result = await asyncio.to_thread(store.dispatch, principal, op, arguments)
            if issued:
                result = {**result, "issued_token": issued}
            return JSONResponse(result)
        except ServiceError as exc:
            status = {
                "quota_exceeded": 429,
                "invalid_argument": 400, "weak_token": 400, "unknown_operation": 400,
                "conflict": 409, "invalid_state": 409, "already_bootstrapped": 409,
                # Use the same outward status for inaccessible project codes as unknown codes.
                "not_found": 403,
            }.get(exc.code, 403)
            return JSONResponse({"error": exc.message, "code": exc.code}, status)
        except (json.JSONDecodeError, TypeError, ValueError):
            return JSONResponse({"error": "Invalid request"}, 400)

    from .billing_http import billing_routes
    billing_admin = billing_routes(store, settings, identity, csrf)
    from .key_management import key_routes
    key_admin = key_routes(store, settings, identity, csrf) if getattr(store, "crypto", None) else []
    return BrowserHeaders(Starlette(routes=[
        Route("/", page), Route("/assets/{name}", asset),
        Route("/login", login, methods=["POST"]), Route("/logout", logout, methods=["POST"]),
        Route("/login-options", login_options),
        Route("/oidc/start", cloud.start), Route("/oidc/callback", cloud.finish),
        Route("/state", state), Route("/api/{operation}", action, methods=["POST"]),
    ] + key_admin + billing_admin))
