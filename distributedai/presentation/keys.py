# SPDX-License-Identifier: AGPL-3.0-only
"""HTTP adapter for organisation key use cases; no persistence or raw crypto access."""
import asyncio
import binascii
from starlette.responses import JSONResponse
from starlette.routing import Route
from ..domain import ServiceError, EncryptionError


def key_routes(application, settings, identity, csrf):
    service = application.keys

    async def status(request):
        actor = await identity(request)
        if actor is None:
            return JSONResponse({"error": "Organisation administrator access required"}, 403)
        try:
            return JSONResponse(await asyncio.to_thread(service.status, actor))
        except ServiceError:
            return JSONResponse({"error": "Organisation administrator access required"}, 403)
        except EncryptionError:
            return JSONResponse({"error": "Key status is unavailable"}, 503)

    async def rotate(request):
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        actor = await identity(request)
        if actor is None:
            return JSONResponse({"error": "Organisation administrator access required"}, 403)
        try:
            if len(await request.body()) > 4096:
                raise ValueError()
            return JSONResponse(await asyncio.to_thread(service.rotate, actor, await request.json()))
        except ServiceError:
            return JSONResponse({"error": "Organisation administrator access required"}, 403)
        except (ValueError, TypeError, binascii.Error, EncryptionError):
            return JSONResponse({"error": "Key configuration rejected"}, 400)

    return [Route("/keys", status), Route("/keys/rotate", rotate, methods=["POST"])]
