# SPDX-License-Identifier: Apache-2.0
import asyncio
import json
import logging
import httpx
import pytest
from starlette.responses import JSONResponse
from distributedai.presentation.mcp import Limits
from distributedai.presentation.security import SecurityBoundary
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware


async def ok(scope, receive, send):
    await JSONResponse({"ok": True})(scope, receive, send)


async def test_anonymous_clients_do_not_share_credential_bucket():
    app = Limits(ok, rpm=1)
    for ip in ["192.0.2.1", "192.0.2.2"]:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(ip,123)),base_url="https://example.test") as client:
            assert (await client.get("/manage/state")).status_code == 200
            assert (await client.get("/manage/state")).status_code == 429


async def test_login_budget_is_tighter_than_normal_requests():
    app = Limits(ok)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="https://example.test") as client:
        for _ in range(10):
            assert (await client.post("/manage/login", json={})).status_code == 200
        assert (await client.post("/manage/login",json={})).status_code == 429
        assert (await client.get("/manage/")).status_code == 200


async def test_slow_request_body_has_total_deadline():
    async def slow():
        await asyncio.sleep(.05)
        return {"type":"http.request","body":b"x","more_body":True}
    messages=[]
    async def send(message): messages.append(message)
    await Limits(ok, body_timeout=.01)({"type":"http","method":"POST","path":"/mcp","headers":[],"client":("192.0.2.1",123)},slow,send)
    assert messages[0]["status"] == 408


async def test_security_headers_and_logs_exclude_secrets(caplog):
    caplog.set_level(logging.INFO, logger="distributedai.security")
    app = SecurityBoundary(Limits(ok,rpm=1),https=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="https://example.test") as client:
        response=await client.post('/manage/login?code=private-code',json={"token":"secret-content"})
        blocked=await client.get('/')
        assert blocked.status_code==429
        for result in [response,blocked]:
            assert result.headers['strict-transport-security']=='max-age=31536000'
            assert result.headers['x-frame-options']=='DENY'
            assert 'camera=()' in result.headers['permissions-policy']
            assert len(result.headers['x-request-id'])==32
    assert 'private-code' not in caplog.text and 'secret-content' not in caplog.text
    assert any(json.loads(r.message).get('category')=='authentication' for r in caplog.records)


@pytest.mark.parametrize('peer,expected', [('192.0.2.10','198.51.100.12'),('192.0.2.11','192.0.2.11')])
async def test_forwarded_identity_only_from_explicit_proxy(peer,expected):
    async def address(scope,receive,send):
        await JSONResponse({'ip':scope['client'][0]})(scope,receive,send)
    app=ProxyHeadersMiddleware(address,trusted_hosts=['192.0.2.10'])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=(peer,123)),base_url='http://example.test') as client:
        response=await client.get('/',headers={'X-Forwarded-For':'198.51.100.12'})
        assert response.json()['ip']==expected

async def test_immediate_chunks_cannot_extend_total_deadline(monkeypatch):
    from types import SimpleNamespace
    from distributedai.presentation import mcp
    moments=iter([0.0,0.0,0.001,0.02])
    monkeypatch.setattr(mcp,'time',SimpleNamespace(monotonic=lambda:next(moments)))
    async def receive(): return {'type':'http.request','body':b'x','more_body':True}
    messages=[]
    async def send(message): messages.append(message)
    await Limits(ok,body_timeout=.01)({'type':'http','method':'POST','path':'/mcp','headers':[],'client':('192.0.2.1',1)},receive,send)
    assert messages[0]['status']==408
