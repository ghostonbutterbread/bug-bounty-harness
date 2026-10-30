"""Synthetic privacy and accounting regressions; run with offline guard."""
import asyncio
from contextlib import asynccontextmanager

import httpx
import json

from agents import bypass_harness as harness


def test_ssti_original_query_is_not_copied_to_result_or_reports(monkeypatch, tmp_path, capsys):
    marker = 'synthetic-old-query-marker-91'
    body = 'synthetic-response-marker-92'
    target = f'https://app.example.test/p?q={marker}&q=other'
    sent = []

    class Limiter:
        @asynccontextmanager
        async def http(self):
            yield
        def adapt_to_response(self, response):
            pass

    scan = harness.BypassOrchestrator()
    scan._limiter = Limiter()
    monkeypatch.setattr(harness, 'BypassOrchestrator', lambda **kw: scan)
    async def request(self, method, url, **kwargs):
        sent.append(url)
        return httpx.Response(200, text='49 ' + body, request=httpx.Request(method, url))
    monkeypatch.setattr(httpx.AsyncClient, 'request', request)
    hits, misses = asyncio.run(harness.run_and_report(target, 'ssti', output_dir=str(tmp_path)))
    captured = capsys.readouterr()
    output = captured.out + captured.err + repr(hits + misses)
    output += ''.join(p.read_text() for p in tmp_path.iterdir())
    assert marker not in output
    assert body not in output
    assert sent and all(marker in url for url in sent)
    assert any(r.payload == 'q={{7*7}}' for r in hits)


def test_dispatched_compatibility_field_is_null_when_transport_unknown(tmp_path):
    counts = harness.Counter(client_call_attempts=1, unknown_failures=1)
    path = tmp_path / 'summary.json'
    harness._write_json(path, [], 'https://app.example.test/p', 'ssti', counts=counts)
    report = json.loads(path.read_text())
    assert report['request_counts']['dispatched'] is None
    assert report['request_counts']['client_call_attempts'] == 1
    assert report['request_counts']['observed_responses'] == 0


def test_waf_wrap_counts_actual_client_calls_not_supplied_response(monkeypatch, tmp_path):
    from agents import waf_interceptor as module
    waf = module.WAFInterceptor('https://app.example.test', verbose=True)
    waf._out_dir = tmp_path
    monkeypatch.setitem(module.WAF_BYPASSES, 'Akamai', [{'headers': {'X-Test': '1'}}, {'headers': {'X-Test': '2'}}])
    monkeypatch.setitem(module.WAF_BYPASSES, 'generic', [])
    calls = []
    class Client:
        async def request(self, method, url, **kwargs):
            calls.append(url)
            if len(calls) == 1:
                raise ValueError('synthetic-secret')
            return httpx.Response(200, request=httpx.Request(method, url))
    url = 'https://app.example.test/p?token=synthetic-query-marker'
    original = httpx.Response(403, text='Access Denied', request=httpx.Request('GET', url))
    result = asyncio.run(waf.wrap_async(Client(), 'GET', url, original))
    assert result.status_code == 200
    assert len(calls) == waf.stats['total_requests'] == 2
    assert json.loads((tmp_path / 'summary.json').read_text())['total_requests'] == 2


def test_cors_and_race_retain_only_derived_observations(tmp_path):
    from agents.bypass_types.cors import CORSBypass
    from agents.bypass_types.race import RaceBypass
    from agents.bypass_types import BypassResult
    marker = 'synthetic-untrusted-response-marker'
    class Limiter:
        @asynccontextmanager
        async def http(self):
            yield
        def adapt_to_response(self, response):
            pass
    class Client:
        async def get(self, url, headers):
            return httpx.Response(200, headers={'Access-Control-Allow-Origin': headers['Origin'],
                'Access-Control-Allow-Credentials': 'true', 'X-Secret': marker}, text=marker)
    async def go():
        return await CORSBypass()._probe('https://app.example.test/p', 'evil_absolute',
            'https://evil-cors-test.com', Client(), asyncio.Semaphore(1), Limiter())
    cors = asyncio.run(go())
    race = RaceBypass()._analyse('https://app.example.test/p', {'status': 200, 'hash': 'a'},
        [{'status': 200, 'hash': 'a', 'text': marker}, {'status': 403, 'hash': 'b', 'text': marker}], 'GET')
    assert 'reflected' in cors.evidence and 'credentials' in cors.evidence
    assert '200' in race[0].evidence and '403' in race[0].evidence
    assert marker not in repr([cors, *race])
    assert BypassResult(True, 'cors', 'origin_header', 'x', '', 'https://app.example.test', 200, marker).evidence == '[response evidence withheld]'
    harness._write_report(tmp_path / 'report.txt', [cors, *race], 'https://app.example.test/p', 'sweep')
    harness._write_json(tmp_path / 'report.json', [cors, *race], 'https://app.example.test/p', 'sweep')
    rendered = (tmp_path / 'report.txt').read_text() + (tmp_path / 'report.json').read_text()
    assert 'reflected' in rendered and 'HTTP 403' in rendered
    assert marker not in rendered


def test_waf_direct_payload_counts_initial_and_tier_retries(monkeypatch, tmp_path, capsys):
    from agents import waf_interceptor as module
    waf = module.WAFInterceptor('https://app.example.test', verbose=True)
    waf._out_dir = tmp_path
    monkeypatch.setitem(module.WAF_BYPASSES, 'Akamai', [{'headers': {'X-Test': 'yes'}}])
    monkeypatch.setitem(module.WAF_BYPASSES, 'generic', [])
    monkeypatch.setattr(waf, '_obfuscate_url_params', lambda url: [('fixture', url)])
    calls = []
    class Client:
        async def request(self, method, url, **kwargs):
            calls.append(url)
            if len(calls) == 2:
                raise ValueError('synthetic-exception-marker')
            return httpx.Response(403 if len(calls) == 1 else 200,
                text='Access Denied' if len(calls) == 1 else 'synthetic-body-marker',
                request=httpx.Request(method, url))
    result = asyncio.run(waf.aget_payload('/p?token=synthetic-query-marker', client=Client()))
    assert result.status_code == 200
    assert waf.stats['total_requests'] == len(calls) == 3
    output = capsys.readouterr().out + ''.join(p.read_text() for p in tmp_path.iterdir())
    for marker in ('synthetic-query-marker', 'synthetic-exception-marker', 'synthetic-body-marker'):
        assert marker not in output


def test_waf_retry_failure_returns_original_and_counts_attempt(monkeypatch, tmp_path):
    from agents import waf_interceptor as module
    waf = module.WAFInterceptor('https://app.example.test')
    waf._out_dir = tmp_path
    monkeypatch.setitem(module.WAF_BYPASSES, 'Akamai', [{'headers': {'X-Test': 'yes'}}])
    monkeypatch.setitem(module.WAF_BYPASSES, 'generic', [])
    class Client:
        async def request(self, method, url, **kwargs):
            raise ValueError('synthetic-exception-marker')
    url = 'https://app.example.test/p'
    original = httpx.Response(403, text='Access Denied', request=httpx.Request('GET', url))
    assert asyncio.run(waf.wrap_async(Client(), 'GET', url, original)) is original
    assert waf.stats['total_requests'] == 1
    assert waf.stats['bypass_fail'] == 1
    assert json.loads((tmp_path / 'summary.json').read_text())['total_requests'] == 1
