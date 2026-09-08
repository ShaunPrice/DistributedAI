# SPDX-License-Identifier: AGPL-3.0-only
"""Security headers and metadata-only request audit. Never log request bodies or URLs."""
import hashlib
import json
import logging
import uuid

log = logging.getLogger("distributedai.security")


class SecurityBoundary:
    def __init__(self, app, *, https=False):
        self.app, self.https = app, https

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = uuid.uuid4().hex
        response_started = False
        path = scope.get("path", "")
        category = "authentication" if path.rstrip("/").endswith(("/login", "/logout", "/oidc/callback")) else "application"
        async def secure_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                headers = message.setdefault("headers", [])
                names = {key.lower() for key, _ in headers}
                additions = {
                    b"x-request-id": request_id.encode(),
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=(), payment=()",
                    b"cache-control": b"no-store",
                    b"content-security-policy": b"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
                }
                if self.https:
                    additions[b"strict-transport-security"] = b"max-age=31536000"
                headers.extend((key, value) for key, value in additions.items() if key not in names)
                status = message["status"]
                if status >= 400 or category == "authentication" or scope.get("method") not in {"GET", "HEAD", "OPTIONS"}:
                    actor = scope.get("security_actor")
                    log.info(json.dumps({"event": "http_security", "request_id": request_id,
                        "category": category, "status": status,
                        "actor": hashlib.sha256(str(actor).encode()).hexdigest() if actor else None}))
            await send(message)
        try:
            await self.app(scope, receive, secure_send)
        except Exception as exc:
            # No exception messages/tracebacks: database/provider errors can contain data.
            log.error(json.dumps({"event": "application_error", "request_id": request_id,
                                  "error_type": type(exc).__name__}))
            if not response_started:
                from starlette.responses import JSONResponse
                await JSONResponse({"error": "Request could not be completed", "request_id": request_id}, 500)(scope, receive, secure_send)
