"""Deterministic full-window transfer admission and quarantine regressions."""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pytest
from aiohttp import web

from test_browser_transfer_races import Request, adapter


def test_paused_prepare_cannot_register_across_begin_end_commit(monkeypatch):
    async def scenario():
        b = adapter()
        b.quarantined = False
        b.epoch = 0
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
        ticket = json.loads((await b.transfer_begin(Request(destination=True))).text)['ticket']
        await b.transfer_end(Request(ticket=ticket))
        assert b.quarantined
        with pytest.raises(web.HTTPGone):
            await b.route(Request())
        committed = json.loads((await b.transfer_commit(Request(ticket=ticket))).text)
        assert committed['cdp_url'].endswith('/' + b.token)
        assert b.quarantined
        await b.transfer_activate(Request(ticket=ticket))
        proceed.set()
        ws = await route
        assert ws.closed and detached == ['root'] and not b.clients
        with pytest.raises(web.HTTPGone):
            await b.route(Request())
    asyncio.run(scenario())
