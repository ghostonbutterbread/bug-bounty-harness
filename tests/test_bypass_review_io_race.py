"""Offline regressions for WAF persistence and incomplete race observations."""
import asyncio
import errno
import json
from contextlib import asynccontextmanager

import httpx
import pytest

from agents import bypass_harness
from agents.bypass_types.race import RaceBypass, RACE_COUNT
from agents.waf_interceptor import WAFInterceptor


@pytest.mark.parametrize('outcome', ['response', 'failure', 'cancel'])
def test_async_summary_failure_preserves_primary_outcome(tmp_path, monkeypatch, caplog, outcome):
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    waf = WAFInterceptor('https://app.example.test', program='fixture', verbose=False)
    real_open = open
    def broken_open(path, *args, **kwargs):
        if str(path).endswith('summary.json'):
            raise OSError(errno.ENOSPC, 'synthetic-secret-marker')
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr('builtins.open', broken_open)
    response = httpx.Response(200, request=httpx.Request('GET', 'https://app.example.test/p'))
    failure = ValueError('primary')
    cancellation = asyncio.CancelledError('primary')
    class Client:
        async def request(self, *args, **kwargs):
            if outcome == 'failure':
                raise failure
            if outcome == 'cancel':
                raise cancellation
            return response
    if outcome == 'response':
        assert asyncio.run(waf.aget('/p', client=Client())) is response
    else:
        with pytest.raises(type(failure if outcome == 'failure' else cancellation)) as exc:
            asyncio.run(waf.aget('/p', client=Client()))
        assert exc.value is (failure if outcome == 'failure' else cancellation)
    assert waf.summary_write_failures >= 1
    assert 'summary.json' in caplog.text and 'synthetic-secret-marker' not in caplog.text


def test_partial_race_is_unknown_and_json_reports_observations(tmp_path):
    baseline = {'status': 200, 'hash': 'a', 'text': 'synthetic-secret-marker'}
    responses = [baseline] + [asyncio.CancelledError('synthetic-secret-marker') for _ in range(RACE_COUNT - 1)]
    result = RaceBypass()._analyse('https://app.example.test/p', baseline, responses, 'GET')[0]
    assert not result.success and result.incomplete
    assert '[unknown]' in result.to_line() and 'HTTP 200' in result.to_line()
    assert 'HTTP 200: 1' in result.evidence and str(RACE_COUNT - 1) in result.note
    path = tmp_path / 'report.json'
    bypass_harness._write_json(path, [result], 'https://app.example.test/p', 'race')
    data = json.loads(path.read_text())
    assert data['hits'] == [] and data['incomplete_results'][0]['incomplete'] is True
    assert 'synthetic-secret-marker' not in path.read_text()


@pytest.mark.parametrize('mode', ['sync', 'async'])
@pytest.mark.parametrize('outcome', ['response', 'failure', 'cancel'])
@pytest.mark.parametrize('failed_flush', [1, 2])
def test_single_flush_failure_before_or_after_client_call(tmp_path, monkeypatch, caplog, mode, outcome, failed_flush):
    if mode == 'sync' and outcome == 'cancel':
        pytest.skip('sync interface has no asyncio cancellation outcome')
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    waf = WAFInterceptor('https://app.example.test', program='fixture', verbose=False)
    original = open
    writes = 0
    def failing_open(path, *args, **kwargs):
        nonlocal writes
        if str(path).endswith('summary.json'):
            writes += 1
            if writes == failed_flush:
                raise OSError(errno.EACCES, 'synthetic-secret-marker')
        return original(path, *args, **kwargs)
    monkeypatch.setattr('builtins.open', failing_open)
    response = httpx.Response(200, request=httpx.Request('GET', 'https://app.example.test/p'))
    error = asyncio.CancelledError('primary') if outcome == 'cancel' else ValueError('primary')
    class Client:
        def request(self, *args, **kwargs):
            if outcome != 'response':
                raise error
            return response
    class AsyncClient:
        async def request(self, *args, **kwargs):
            return Client().request(*args, **kwargs)
    waf._session = Client()
    def call():
        return waf.get('/p') if mode == 'sync' else asyncio.run(waf.aget('/p', client=AsyncClient()))
    if outcome == 'response':
        assert call() is response
    else:
        with pytest.raises(type(error)) as exc:
            call()
        assert exc.value is error
    assert writes == 2 and waf.summary_write_failures == 1
    assert waf.summary_last_errno == errno.EACCES
    assert waf.stats['total_requests'] == 1
    assert waf.stats['observed_responses'] == (outcome == 'response')
    assert waf.stats['client_call_failures'] == (outcome == 'failure')
    assert waf.stats['client_call_cancellations'] == (outcome == 'cancel')
    assert 'synthetic-secret-marker' not in caplog.text and str(tmp_path) not in caplog.text


def test_initial_and_partial_write_failure_are_visible(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    original = open
    class BrokenFile:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def write(self, text): raise OSError(errno.ENOSPC, 'synthetic-secret-marker')
    def failing_open(path, *args, **kwargs):
        if str(path).endswith('summary.json'):
            return BrokenFile()
        return original(path, *args, **kwargs)
    monkeypatch.setattr('builtins.open', failing_open)
    waf = WAFInterceptor('https://app.example.test', program='fixture', verbose=False)
    assert waf.summary_write_failures == 1 and waf.summary_last_errno == errno.ENOSPC
    assert 'partial' in caplog.text and 'check storage and permissions' in caplog.text
    assert 'synthetic-secret-marker' not in caplog.text and str(tmp_path) not in caplog.text


def test_summary_close_failure_keeps_sync_response(tmp_path, monkeypatch):
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    waf = WAFInterceptor('https://app.example.test', program='fixture', verbose=False)
    original = open
    class BrokenClose:
        def __init__(self, file): self.file = file
        def __enter__(self): return self.file
        def __exit__(self, *args):
            self.file.close()
            raise OSError(errno.EIO, 'synthetic-secret-marker')
    def failing_open(path, *args, **kwargs):
        f = original(path, *args, **kwargs)
        return BrokenClose(f) if str(path).endswith('summary.json') else f
    monkeypatch.setattr('builtins.open', failing_open)
    response = httpx.Response(200, request=httpx.Request('GET', 'https://app.example.test/p'))
    class Session:
        def request(self, *args, **kwargs): return response
    waf._session = Session()
    assert waf.get('/p') is response
    assert waf.summary_write_failures == 2 and waf.summary_last_errno == errno.EIO


@pytest.mark.parametrize('missing,baseline', [(False, True), (True, True), (False, False)])
def test_race_complete_and_missing_observations(missing, baseline):
    response = {'status': 200, 'hash': 'a', 'text': 'secret'}
    burst = [response] * (RACE_COUNT - int(missing))
    result = RaceBypass()._analyse('https://app.example.test/p', response if baseline else None, burst, 'GET')[0]
    assert result.incomplete == (missing or not baseline)
    assert ('[unknown]' if result.incomplete else '[miss]') in result.to_line()
    assert 'HTTP 200:' in result.evidence
    if not baseline:
        assert 'Baseline: unknown' in result.evidence


@pytest.mark.parametrize('bad', [None, ValueError('synthetic-secret-marker'), asyncio.CancelledError('synthetic-secret-marker')])
def test_race_failed_or_cancelled_probe_never_becomes_negative(bad):
    response = {'status': 200, 'hash': 'a', 'text': 'secret'}
    result = RaceBypass()._analyse('https://app.example.test/p', response, [response] * (RACE_COUNT - 1) + [bad], 'GET')[0]
    assert not result.success and result.incomplete and '[unknown]' in result.to_line()
    assert 'no response=1' in result.note and 'HTTP 200: 14' in result.evidence
    assert 'synthetic-secret-marker' not in repr(result)


def test_parent_cancel_after_some_race_responses_propagates():
    async def run():
        entered, closed = asyncio.Event(), []
        calls = 0
        class Limiter:
            @asynccontextmanager
            async def http(self): yield
            def adapt_to_response(self, response): pass
        class Client:
            async def request(self, method, url, **kwargs):
                nonlocal calls
                calls += 1
                if calls <= 2:
                    return httpx.Response(200, request=httpx.Request(method, url))
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    closed.append(True)
        task = asyncio.create_task(RaceBypass().scan('https://app.example.test/p', Client(), asyncio.Semaphore(3), Limiter()))
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert calls > 2 and closed
    asyncio.run(run())


def test_race_mixed_child_outcomes_respect_concurrency_and_keep_hit():
    async def run():
        active = peak = calls = 0
        class Limiter:
            @asynccontextmanager
            async def http(self): yield
            def adapt_to_response(self, response): pass
        class Client:
            async def request(self, method, url, **kwargs):
                nonlocal active, peak, calls
                index = calls
                calls += 1
                active += 1
                peak = max(peak, active)
                try:
                    await asyncio.sleep(0)
                    if index == 3:
                        raise asyncio.CancelledError('synthetic-secret-marker')
                    if index == 4:
                        raise httpx.ConnectError('synthetic-secret-marker')
                    if index == 5:
                        raise ValueError('synthetic-secret-marker')
                    return httpx.Response(403 if index == 2 else 200, text='private-body', request=httpx.Request(method, url))
                finally:
                    active -= 1
        results = await RaceBypass().scan('https://app.example.test/p', Client(), asyncio.Semaphore(3), Limiter())
        assert calls == RACE_COUNT + 1 and peak <= 3 and active == 0
        result = results[0]
        assert result.success and result.incomplete and '[HIT]' in result.to_line()
        assert '[incomplete]' in result.to_line()
        assert 'observed=12/15' in result.note and 'cancelled=1' in result.note
        assert 'HTTP 200:' in result.evidence and 'HTTP 403:' in result.evidence
        assert 'synthetic-secret-marker' not in repr(results) and 'private-body' not in repr(results)
    asyncio.run(run())


@pytest.mark.parametrize('mode', ['normal', 'payload', 'wrap'])
@pytest.mark.parametrize('outcome', ['response', 'cancel'])
def test_waf_retry_summary_failure_and_owned_cleanup(tmp_path, monkeypatch, caplog, mode, outcome):
    from agents import waf_interceptor as module
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    monkeypatch.setitem(module.WAF_BYPASSES, 'Akamai', [{'headers': {'X-Fixture': '1'}}])
    monkeypatch.setitem(module.WAF_BYPASSES, 'generic', [])
    waf = WAFInterceptor('https://app.example.test', program='fixture', verbose=False)
    original = open
    def failing_open(path, *args, **kwargs):
        if str(path).endswith('summary.json'):
            raise OSError(errno.ENOSPC, 'synthetic-secret-marker')
        return original(path, *args, **kwargs)
    monkeypatch.setattr('builtins.open', failing_open)
    blocked = httpx.Response(403, text='Access Denied', request=httpx.Request('GET', 'https://app.example.test/p'))
    allowed = httpx.Response(200, request=httpx.Request('GET', 'https://app.example.test/p'))
    closed = []
    cancel = asyncio.CancelledError('primary')
    class Client:
        calls = 0
        def __init__(self, **kwargs): pass
        async def request(self, *args, **kwargs):
            self.calls += 1
            if mode != 'wrap' and self.calls == 1:
                return blocked
            if outcome == 'cancel': raise cancel
            return allowed
        async def aclose(self): closed.append(True)
    monkeypatch.setattr(module.httpx, 'AsyncClient', Client)
    client = Client()
    async def call():
        if mode == 'wrap':
            return await waf.wrap_async(client, 'GET', 'https://app.example.test/p', blocked)
        return await (waf.aget('/p') if mode == 'normal' else waf.aget_payload('/p'))
    if outcome == 'cancel':
        with pytest.raises(asyncio.CancelledError) as exc:
            asyncio.run(call())
        assert exc.value is cancel
    else:
        assert asyncio.run(call()) is allowed
    assert closed == ([] if mode == 'wrap' else [True])
    assert waf.summary_write_failures >= 3 and waf.stats['waf_blocks'] == 1
    assert 'synthetic-secret-marker' not in caplog.text and str(tmp_path) not in caplog.text
