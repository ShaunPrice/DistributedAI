# SPDX-License-Identifier: AGPL-3.0-only
"""Organisation-only key administration. No key export or central-admin delegation."""
import asyncio
import base64
import binascii

from starlette.responses import JSONResponse
from starlette.routing import Route

from .encryption import EncryptionError
from .store import Principal


def key_routes(store, settings, identity, csrf):
    async def authorised(request):
        actor = await identity(request)
        if not isinstance(actor, Principal):
            return None
        # Re-derive organisation and role; never trust claims supplied by the browser.
        actor = await asyncio.to_thread(store.resolve_principal, actor.id)
        return actor if actor and actor.is_org_admin else None

    def allowed(org_id):
        aliases = settings.tenant_key_providers.get(org_id, [])
        if not isinstance(aliases, list) or any(not isinstance(v, str) for v in aliases):
            return {"local"}
        return {"local", *aliases}

    async def status(request):
        actor = await authorised(request)
        if actor is None:
            return JSONResponse({"error": "Organisation administrator access required"}, 403)
        crypto = getattr(store, "crypto", None)
        if crypto is None:
            return JSONResponse({"error": "Encryption is not configured"}, 503)
        try:
            await asyncio.to_thread(crypto.provision, actor.org_id)
            result = await asyncio.to_thread(crypto.status, actor.org_id)
            return JSONResponse({**result, "providers": sorted(allowed(actor.org_id))})
        except EncryptionError:
            return JSONResponse({"error": "Key status is unavailable"}, 503)

    async def rotate(request):
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        actor = await authorised(request)
        if actor is None:
            return JSONResponse({"error": "Organisation administrator access required"}, 403)
        crypto = getattr(store, "crypto", None)
        if crypto is None:
            return JSONResponse({"error": "Encryption is not configured"}, 503)
        try:
            body = await request.body()
            if len(body) > 4096:
                raise ValueError()
            data = await request.json()
            if not isinstance(data, dict) or set(data) - {"provider", "manual_key"}:
                raise ValueError()
            provider = data.get("provider")
            if not isinstance(provider, str) or provider not in allowed(actor.org_id):
                raise ValueError()
            key = None
            if "manual_key" in data:
                encoded = data["manual_key"]
                if not isinstance(encoded, str) or len(encoded) != 44:
                    raise ValueError()
                key = base64.b64decode(encoded, validate=True)
                if len(key) != 32:
                    raise ValueError()
            await asyncio.to_thread(crypto.provision, actor.org_id)
            result = await asyncio.to_thread(crypto.rotate, actor.org_id, provider, key)
            return JSONResponse(result)
        except (ValueError, TypeError, binascii.Error, EncryptionError):
            return JSONResponse({"error": "Key configuration rejected"}, 400)

    return [Route("/keys", status), Route("/keys/rotate", rotate, methods=["POST"])]
