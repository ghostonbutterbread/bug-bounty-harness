"""Exact activation recovery must revoke both URLs and admitted clients."""
import asyncio
import json
import sys
from pathlib import Path

import pytest
from aiohttp import web

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_browser_transfer_races import Request, adapter


def test_applied_activation_fence_is_exact_idempotent_and_closes_clients():
    async def scenario():
        b = adapter()
        b.transfer = 'ticket'
        b.transfer_destination = True
        b.quarantined = True
        b.call = lambda *args, **kwargs: asyncio.sleep(0, result={'result': {}})
        await b.transfer_commit(Request(ticket='ticket'))
        published = b.token
        await b.transfer_activate(Request(ticket='ticket'))
        assert b.transfer == 'ticket' and not b.quarantined
        for field in ('transaction', 'owner', 'generation', 'ticket'):
            with pytest.raises(web.HTTPForbidden):
                await b.transfer_fence(Request(**{'ticket': 'ticket', field: 'wrong'}))
        class WS:
            closed = False
            async def close(self): self.closed = True
        ws = WS()
        b.clients[ws] = {'root'}
        b.roots[ws] = 'root'
        detached = []
        async def detach(session): detached.append(session)
        b.detach = detach
        fenced = json.loads((await b.transfer_fence(Request(ticket='ticket'))).text)
        assert fenced['fenced'] is True and fenced['quarantined'] is True
        assert b.token != published and b.epoch >= 2
        assert ws.closed and detached == ['root']
        assert b.quarantined and b.transfer == 'ticket'
        assert json.loads((await b.transfer_fence(Request(ticket='ticket'))).text)['fenced'] is True
        assert detached == ['root']
        with pytest.raises(web.HTTPForbidden):
            await b.transfer_finalize(Request(ticket='ticket'))
        for token in ('generation', published, b.token):
            request = Request(ticket='ticket')
            request.match_info['token'] = token
            with pytest.raises(web.HTTPGone):
                await b.route(request)
    asyncio.run(scenario())


def test_late_finalize_cannot_undo_fence_and_failed_barrier_stays_private():
    async def scenario():
        b = adapter()
        b.transfer, b.transfer_destination, b.quarantined = 'ticket', True, True
        b.call = lambda *args, **kwargs: asyncio.sleep(0, result={'result': {}})
        await b.transfer_commit(Request(ticket='ticket'))
        await b.transfer_activate(Request(ticket='ticket'))
        class WS:
            closed = False
            async def close(self): self.closed = True
        ws = WS()
        b.clients[ws] = {'root'}
        b.roots[ws] = 'root'
        calls = []
        async def detach(session):
            calls.append(session)
            if len(calls) == 1: raise RuntimeError('detach failed')
        b.detach = detach
        with pytest.raises(RuntimeError):
            await b.transfer_fence(Request(ticket='ticket'))
        assert b.quarantined and not b.transfer_fenced
        with pytest.raises(web.HTTPForbidden):
            await b.transfer_finalize(Request(ticket='ticket'))
        assert json.loads((await b.transfer_fence(Request(ticket='ticket'))).text)['fenced']
        assert ws.closed and calls == ['root', 'root']
    asyncio.run(scenario())
