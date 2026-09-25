"""Deterministic adapter transfer linearization; no Chrome or network."""
import asyncio
import json
import sys
from pathlib import Path

import pytest
from aiohttp import web

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'))
from browser_control import PipeBrowser


class Request:
    def __init__(self, **data):
        self.data = data
        self.match_info = {'token': 'generation', 'suffix': 'devtools/browser'}

    async def json(self):
        return self.data


def adapter():
    b = PipeBrowser.__new__(PipeBrowser)
    b.token = 'generation'
    b.port = 9222
    b.rotating = b.frozen = False
    b.transfer = None
    b.inflight = 0
    b.clients, b.roots, b.pending = {}, {}, {}
    b.serial = 0
    b.loop = asyncio.get_running_loop()
    b.write_lock = asyncio.Lock()
    b.transfer_lock = asyncio.Lock()
    b.mark_activity = lambda: None
    return b


def test_public_write_waiting_on_lock_cannot_cross_begin():
    async def scenario():
        b = adapter()
        writes = []
        b._write = lambda data: writes.append(json.loads(data[:-1]))
        async with b.write_lock:
            public = asyncio.create_task(b.call('Runtime.evaluate', generation=b.token))
            await asyncio.sleep(0)
            async def private(method, *args, **kwargs):
                if method == 'Browser.getVersion':
                    return {'result': {}}
                return await PipeBrowser.call(b, method, *args, **kwargs)
            b.call = private
            begin = asyncio.create_task(b.transfer_begin(Request()))
            await asyncio.sleep(0)
            assert b.transfer and not writes
        assert json.loads((await begin).text)['ticket'] == b.transfer
        with pytest.raises(ConnectionError):
            await public
        assert not writes
    asyncio.run(scenario())


def test_private_call_and_end_are_serialized_at_command_barrier():
    async def scenario():
        b = adapter()
        b.transfer = 'ticket'
        entering, proceed = asyncio.Event(), asyncio.Event()
        methods = []
        async def call(method, *args, **kwargs):
            methods.append(method)
            if method == 'Target.getTargets':
                entering.set()
                await proceed.wait()
                return {'result': {'targetInfos': [{'type': 'page', 'targetId': 'page'}]}}
            if method == 'Target.attachToTarget':
                return {'result': {'sessionId': 'session'}}
            return {'result': {}}
        b.call = call
        invoke = asyncio.create_task(b.transfer_call(Request(ticket='ticket', method='Network.getAllCookies')))
        await entering.wait()
        end = asyncio.create_task(b.transfer_end(Request(ticket='ticket')))
        await asyncio.sleep(0)
        assert b.transfer == 'ticket' and methods == ['Target.getTargets']
        proceed.set()
        await invoke
        await end
        assert b.transfer is None
        assert methods == ['Target.getTargets', 'Target.attachToTarget', 'Network.getAllCookies',
                           'Target.detachFromTarget']
        with pytest.raises(web.HTTPForbidden):
            await b.transfer_call(Request(ticket='ticket', method='Network.getAllCookies'))
    asyncio.run(scenario())


def test_public_attachment_completed_after_begin_is_not_registered(monkeypatch):
    async def scenario():
        b = adapter()
        attached, proceed = asyncio.Event(), asyncio.Event()
        detached = []
        async def call(method, *args, **kwargs):
            if method == 'Target.attachToBrowserTarget':
                attached.set()
                await proceed.wait()
                return {'result': {'sessionId': 'root'}}
            if method == 'Target.detachFromTarget':
                detached.append(args[0]['sessionId'])
            return {'result': {}}
        b.call = call
        route = asyncio.create_task(b.route(Request()))
        await attached.wait()
        await b.transfer_begin(Request())
        proceed.set()
        with pytest.raises(web.HTTPGone):
            await route
        assert detached == ['root'] and not b.clients
    asyncio.run(scenario())


def test_public_prepare_yield_does_not_register_after_begin(monkeypatch):
    async def scenario():
        b = adapter()
        preparing, proceed = asyncio.Event(), asyncio.Event()
        detached = []
        class WS:
            closed = False
            def __init__(self, **kwargs): pass
            async def prepare(self, request):
                preparing.set()
                await proceed.wait()
            async def close(self): self.closed = True
        monkeypatch.setattr('browser_control.web.WebSocketResponse', WS)
        async def call(method, *args, **kwargs):
            if method == 'Target.attachToBrowserTarget':
                return {'result': {'sessionId': 'root'}}
            if method == 'Target.detachFromTarget':
                detached.append(args[0]['sessionId'])
            return {'result': {}}
        b.call = call
        route = asyncio.create_task(b.route(Request()))
        await preparing.wait()
        await b.transfer_begin(Request())
        proceed.set()
        ws = await route
        assert ws.closed and detached == ['root'] and not b.clients
    asyncio.run(scenario())
