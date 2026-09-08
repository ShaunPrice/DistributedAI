# SPDX-License-Identifier: AGPL-3.0-only
"""Billing HTTP/JSON adapter. Provider workflows and database transactions are injected."""
import asyncio
import json

from starlette.responses import JSONResponse
from starlette.routing import Route

from ..application.billing import MAX_BODY
from ..domain import ServiceError


def _error(exc):
    code = getattr(exc, "code", "provider_error")
    if code == "retry_event":
        return JSONResponse({"error": "Retry billing event"}, 503)
    status = {"unknown_provider": 404, "not_supported": 501, "conflict": 409,
              "invalid_argument": 400, "webhook_verification_failed": 400,
              "invalid_webhook": 400, "unsupported_event": 400}.get(code, 503)
    return JSONResponse({"error": "Billing request could not be completed", "code": code}, status)


def webhook_routes(store):
    service = store.billing_application

    async def webhook(request):
        if not service.enabled:
            return JSONResponse({"error": "Billing disabled"}, 404)
        try:
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > MAX_BODY:
                    return JSONResponse({"error": "Request too large"}, 413)
            result = await asyncio.to_thread(service.webhook, request.path_params["provider"],
                dict(request.headers), bytes(body))
            return JSONResponse(result)
        except ServiceError as exc:
            return _error(exc)
        except (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError):
            return JSONResponse({"error": "Invalid billing event"}, 400)
    return [Route("/billing/webhooks/{provider}", webhook, methods=["POST"])]


def billing_routes(store, settings, identity, csrf):
    service = store.billing_application

    async def actor(request):
        return await asyncio.to_thread(service.resolve_owner, await identity(request))

    async def options(request):
        owner = await actor(request)
        if owner is None:
            return JSONResponse({"error": "Organisation administrator required"}, 403)
        try:
            return JSONResponse(await asyncio.to_thread(service.options, owner))
        except ServiceError as exc:
            return _error(exc)

    async def action(request):
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        owner = await actor(request)
        if owner is None:
            return JSONResponse({"error": "Organisation administrator required"}, 403)
        if not service.enabled:
            return JSONResponse({"error": "Billing disabled"}, 404)
        try:
            body = await request.body()
            if len(body) > 4096:
                raise ValueError()
            result = await asyncio.to_thread(service.action, owner, json.loads(body),
                checkout=request.url.path.endswith("/checkout"))
            return JSONResponse(result)
        except ServiceError as exc:
            return _error(exc)
        except (ValueError, TypeError, KeyError, AttributeError):
            return JSONResponse({"error": "Invalid billing request"}, 400)
    return [Route("/billing/options", options), Route("/billing/checkout", action, methods=["POST"]),
            Route("/billing/portal", action, methods=["POST"])]
