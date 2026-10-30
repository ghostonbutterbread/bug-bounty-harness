"""Synthetic cancellation and accounting regressions; use offline guard."""
import asyncio
import json

import httpx
import pytest

from agents import bypass_harness as harness
from agents.bypass_types.ssti import SSTIBypass


def test_ssti_individual_cancellation_is_no_response(monkeypatch):
    async def cancelled(*args):
        raise asyncio.CancelledError('synthetic-secret-marker')
    monkeypatch.setattr(SSTIBypass, '_probe', cancelled)
    async def run():
        return await SSTIBypass().scan('https://app.example.test/p?q=1', None, asyncio.Semaphore(2), None)
    results = asyncio.run(run())
    assert results and all(r.status_code == 0 and 'cancel' in r.note.lower() for r in results)
    assert 'synthetic-secret-marker' not in repr(results)


@pytest.mark.parametrize('kind', ['403', 'lfi', 'rfi', 'ssrf', 'redirect'])
def test_legacy_gather_probe_cancellation_is_no_response(kind, monkeypatch):
    scan = harness.BypassOrchestrator()
    async def cancelled(*args, **kwargs):
        raise asyncio.CancelledError('synthetic-secret-marker')
    monkeypatch.setattr(scan, '_get_payload', cancelled)
    # 403 has its own helper; intercept all its request helpers.
    if kind == '403':
        first = True
        async def baseline_then_cancel(*args, **kwargs):
            nonlocal first
            if first:
                first = False
                return None
            raise asyncio.CancelledError('synthetic-secret-marker')
        monkeypatch.setattr(scan, '_get', baseline_then_cancel)
    async def run():
        if kind == '403':
            return [r async for r in scan._run_403('https://app.example.test/p', None, asyncio.Semaphore(2))]
        return [r async for r in getattr(scan, '_run_' + kind)(
            'https://app.example.test/p', 'q', None, asyncio.Semaphore(2))]
    results = asyncio.run(run())
    assert results and all(r.status_code == 0 and 'cancel' in r.note.lower() for r in results)


def test_waf_summary_tracks_clean_failure_and_cancellation(tmp_path, monkeypatch):
    from agents.waf_interceptor import WAFInterceptor
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    waf = WAFInterceptor('https://app.example.test', program='fixture', verbose=False)
    summary = waf._out_dir / 'summary.json'
    assert json.loads(summary.read_text())['total_requests'] == 0
    class Client:
        outcome = 'response'
        async def request(self, method, url, **kwargs):
            if self.outcome == 'cancel':
                raise asyncio.CancelledError('synthetic-secret-marker')
            if self.outcome == 'fail':
                raise ValueError('synthetic-secret-marker')
            return httpx.Response(200, request=httpx.Request(method, url))
    client = Client()
    asyncio.run(waf.aget('/p', client=client))
    client.outcome = 'fail'
    with pytest.raises(ValueError):
        asyncio.run(waf.aget('/p', client=client))
    client.outcome = 'cancel'
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(waf.aget('/p', client=client))
    data = json.loads(summary.read_text())
    assert data['total_requests'] == 3
    assert data['observed_responses'] == 1
    assert data['client_call_failures'] == 1
    assert data['client_call_cancellations'] == 1
    assert 'synthetic-secret-marker' not in summary.read_text()


def test_direct_dispatched_alias_unknown():
    counts = harness.BypassOrchestrator().request_counts
    assert counts['dispatched'] is None
    assert counts.get('dispatched') is None
    assert counts['client_call_attempts'] == 0
    assert dict(counts)['dispatched'] is None
    with pytest.raises(KeyError):
        _ = counts['not_a_dimension']


@pytest.mark.parametrize('kind', ['cors', 'traversal', 'xxe', 'idor', 'race'])
def test_each_registered_family_represents_probe_cancellation(kind, monkeypatch):
    module = __import__('agents.bypass_types.' + kind, fromlist=['dummy'])
    cls = getattr(module, {'cors': 'CORSBypass', 'traversal': 'TraversalBypass',
                           'xxe': 'XXEBypass', 'idor': 'IDORBypass', 'race': 'RaceBypass'}[kind])
    name = {'idor': '_get', 'race': '_single'}.get(kind, '_probe')
    calls = 0
    async def probe(*args, **kwargs):
        nonlocal calls
        calls += 1
        if kind in ('idor', 'race') and calls == 1:
            return {'status': 200, 'len': 0, 'hash': 'fixture', 'text': ''}
        raise asyncio.CancelledError('synthetic-secret-marker')
    monkeypatch.setattr(cls, name, probe)
    async def run():
        return await cls().scan('https://app.example.test/1?id=1', None, asyncio.Semaphore(2), None, param='id')
    results = asyncio.run(run())
    assert results and all(r.status_code == 0 and 'cancel' in r.note.lower() for r in results)
    assert 'synthetic-secret-marker' not in repr(results)


@pytest.mark.parametrize('kind', ['cors', 'traversal', 'xxe', 'ssti', 'idor', 'race', '403', 'lfi', 'rfi', 'ssrf', 'redirect'])
def test_parent_cancellation_closes_client_and_pending_probes(kind, monkeypatch):
    from contextlib import asynccontextmanager
    class Limiter:
        @asynccontextmanager
        async def http(self):
            yield
        def adapt_to_response(self, response):
            pass
    async def run():
        entered, exited = asyncio.Event(), []
        class Client:
            calls = 0
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                exited.append('client')
            async def request(self, method, url, **kwargs):
                self.calls += 1
                if kind in ('idor', 'race', '403') and self.calls == 1:
                    return httpx.Response(200, text='ok', request=httpx.Request(method, url))
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    exited.append('probe')
        monkeypatch.setattr(harness.httpx, 'AsyncClient', lambda **kwargs: Client())
        scan = harness.BypassOrchestrator()
        scan._limiter = Limiter()
        async def consume():
            return [r async for r in scan.run_bypass('https://app.example.test/1?id=1', kind, param='id')]
        task = asyncio.create_task(consume())
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert 'client' in exited and 'probe' in exited
        assert exited[-1] == 'client'
        assert scan.request_counts['observed_responses'] == (1 if kind in ('idor', 'race', '403') else 0)
    asyncio.run(run())


@pytest.mark.parametrize('stage', ['detect', 'scan'])
def test_sweep_individual_cancelled_module_is_reported(stage, monkeypatch):
    class FakeModule:
        name = 'Fake'
        async def detect(self, *args):
            if stage == 'detect':
                raise asyncio.CancelledError('synthetic-secret-marker')
            return True
        async def scan(self, *args, **kwargs):
            if stage == 'scan':
                raise asyncio.CancelledError('synthetic-secret-marker')
            return []
    async def no_ssrf(*args):
        if False:
            yield
    monkeypatch.setattr(harness, 'ALL_MODULES', [FakeModule])
    monkeypatch.setattr(harness.BypassOrchestrator, '_run_ssrf', no_ssrf)
    scan = harness.BypassOrchestrator()
    async def run():
        return [r async for r in scan.run_sweep('https://app.example.test/p')]
    results = asyncio.run(run())
    assert len(results) == 1 and results[0].status_code == 0
    assert 'CancelledError' in results[0].note and 'synthetic-secret-marker' not in repr(results)
    assert scan.request_counts['observed_responses'] == 0


@pytest.mark.parametrize('stage', ['detect', 'scan'])
def test_sweep_parent_cancel_cleans_module_and_client(stage, monkeypatch):
    async def run():
        entered, closed = asyncio.Event(), []
        class Module:
            name = 'Fake'
            async def wait(self):
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    closed.append('module')
            async def detect(self, *args):
                return await self.wait() if stage == 'detect' else True
            async def scan(self, *args, **kwargs):
                return await self.wait()
        class Client:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                closed.append('client')
        monkeypatch.setattr(harness, 'ALL_MODULES', [Module])
        monkeypatch.setattr(harness.httpx, 'AsyncClient', lambda **kwargs: Client())
        async def consume():
            return [r async for r in harness.BypassOrchestrator().run_sweep('https://app.example.test/p')]
        task = asyncio.create_task(consume())
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert closed == ['module', 'client']
    asyncio.run(run())


def test_waf_retry_cancellation_flushes_and_closes_owned_client(tmp_path, monkeypatch):
    from agents import waf_interceptor as module
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    monkeypatch.setitem(module.WAF_BYPASSES, 'Akamai', [{'headers': {'X-Test': '1'}}])
    monkeypatch.setitem(module.WAF_BYPASSES, 'generic', [])
    closed = []
    class Client:
        calls = 0
        def __init__(self, **kwargs):
            pass
        async def request(self, method, url, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return httpx.Response(403, text='Access Denied', request=httpx.Request(method, url))
            raise asyncio.CancelledError('synthetic-secret-marker')
        async def aclose(self):
            closed.append(True)
    monkeypatch.setattr(module.httpx, 'AsyncClient', Client)
    waf = module.WAFInterceptor('https://app.example.test', program='fixture', verbose=False)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(waf.aget('/p?token=synthetic-secret-marker'))
    data = json.loads((waf._out_dir / 'summary.json').read_text())
    assert closed == [True]
    assert (data['total_requests'], data['observed_responses'], data['client_call_cancellations'], data['waf_blocks']) == (2, 1, 1, 1)
    assert 'synthetic-secret-marker' not in ''.join(p.read_text() for p in waf._out_dir.iterdir())


def test_sync_waf_clean_and_failure_persist(tmp_path, monkeypatch):
    from agents.waf_interceptor import WAFInterceptor
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    waf = WAFInterceptor('https://app.example.test', program='fixture', verbose=False)
    class Session:
        calls = 0
        def request(self, method, url, **kwargs):
            self.calls += 1
            if self.calls == 2:
                raise ValueError('synthetic-secret-marker')
            return httpx.Response(200, request=httpx.Request(method, url))
    waf._session = Session()
    waf.get('/p')
    with pytest.raises(ValueError):
        waf.get('/p')
    data = json.loads((waf._out_dir / 'summary.json').read_text())
    assert (data['total_requests'], data['observed_responses'], data['client_call_failures']) == (2, 1, 1)
    assert 'synthetic-secret-marker' not in (waf._out_dir / 'summary.json').read_text()
