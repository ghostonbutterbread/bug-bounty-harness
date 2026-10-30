import asyncio
from contextlib import asynccontextmanager

import httpx
import pytest

from agents.bypass_types.cors import CORSBypass, _build_origins
from agents import bypass_harness as h, waf_interceptor as w
from agents.bypass_types.race import RaceBypass


class Limiter:
    @asynccontextmanager
    async def http(self):
        yield

    def adapt_to_response(self, response):
        pass


@pytest.mark.parametrize('target,origin', [
    ('http://app.example.test/p', 'http://app.example.test'),
    ('http://APP.example.test:80/p', 'http://app.example.test'),
    ('https://bücher.example.test/p', 'https://xn--bcher-kva.example.test'),
])
def test_cors_same_origin_is_not_cross_origin_hit(target, origin):
    class Client:
        async def get(self, url, headers):
            return httpx.Response(200, headers={'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true'})
    result = asyncio.run(CORSBypass()._probe(target, 'http_downgrade', origin, Client(), asyncio.Semaphore(1), Limiter()))
    assert not result.success
    assert 'same-origin' in result.note


@pytest.mark.parametrize('category,origin', [
    ('http_downgrade', 'http://app.example.test'),
    ('evil_subdomain', 'https://evil.app.example.test'),
    ('pre_domain', 'https://evil-cors-test.com.app.example.test'),
])
def test_cors_conditional_origin_control_not_asserted(category, origin):
    class Client:
        async def get(self, url, headers):
            return httpx.Response(403, headers={'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true'})
    result = asyncio.run(CORSBypass()._probe('https://app.example.test:8443/p', category, origin, Client(), asyncio.Semaphore(1), Limiter()))
    assert not result.success and result.incomplete
    assert 'control' in result.note and 'validate' in result.note


def test_waf_header_retry_not_attributed_to_original_403_payload(monkeypatch):
    scan = h.BypassOrchestrator()
    scan._limiter = Limiter()
    monkeypatch.setattr(h, '_403_HEADER_PAYLOADS', [{'Referer': 'https://example.test/'}])
    monkeypatch.setattr(h, '_403_PATH_SUFFIXES', [])
    monkeypatch.setattr(h, '_403_PATH_PREFIXES', [])
    monkeypatch.setattr(h, '_403_METHODS', [])
    monkeypatch.setitem(w.WAF_BYPASSES, 'Akamai', [{'headers': {'X-Fixture-Bypass': 'yes'}}])
    monkeypatch.setitem(w.WAF_BYPASSES, 'generic', [])
    waf = w.WAFInterceptor('https://app.example.test', verbose=False)
    monkeypatch.setattr(scan, '_get_waf', lambda url: waf)
    calls = []
    class Client:
        async def request(self, method, url, **kwargs):
            headers = kwargs.get('headers', {})
            calls.append(headers)
            status, text = (403, 'ordinary forbidden') if len(calls) == 1 else ((200, 'ok') if 'X-Fixture-Bypass' in headers else (403, 'Access Denied'))
            return httpx.Response(status, text=text, request=httpx.Request(method, url))
    async def run():
        return [r async for r in scan._run_403('https://app.example.test/p', Client(), asyncio.Semaphore(1))]
    result = asyncio.run(run())[0]
    assert len(calls) > 2 and calls[2]['X-Fixture-Bypass'] == 'yes'
    assert not result.success and result.incomplete
    assert 'retry' in result.note and 'unknown' in result.note
    assert 'Referer' not in result.payload and 'unknown' in result.payload


def test_race_rate_limit_is_not_a_race_win():
    observed = [{'status': 200, 'hash': 'same', 'text': ''}] * 14 + [{'status': 429, 'hash': 'same', 'text': ''}]
    result = RaceBypass()._analyse('https://app.example.test/p', {'status': 200, 'hash': 'same'}, observed, 'GET')[0]
    assert not result.success
    assert 'rate' in result.note.lower()
    assert 'HTTP 429: 1' in result.evidence


def test_payload_retry_is_not_attributed_to_original(monkeypatch):
    scan = h.BypassOrchestrator()
    scan._limiter = Limiter()
    monkeypatch.setattr(h, '_LFI_PAYLOADS', {'synthetic': ['original']})
    monkeypatch.setitem(w.WAF_BYPASSES, 'Akamai', [])
    monkeypatch.setitem(w.WAF_BYPASSES, 'generic', [])
    waf = w.WAFInterceptor('https://app.example.test', verbose=False)
    monkeypatch.setattr(waf, '_obfuscate_url_params', lambda url: [('synthetic', url.replace('original', 'variant'))])
    monkeypatch.setattr(scan, '_get_waf', lambda url: waf)
    class Client:
        async def request(self, method, url, **kwargs):
            return httpx.Response(200 if 'variant' in url else 403, text='root:x:0:0:' if 'variant' in url else 'Access Denied', request=httpx.Request(method, url))
    async def run():
        return [r async for r in scan._run_lfi('https://app.example.test/p', 'file', Client(), asyncio.Semaphore(1))]
    result = asyncio.run(run())[0]
    assert not result.success and result.incomplete
    assert 'retry' in result.note and 'unknown' in result.note
    assert waf.stats['total_requests'] == 2
    assert result.payload != 'original' and 'unknown' in result.payload


@pytest.mark.parametrize('kind', ['lfi', 'rfi', 'ssrf', 'redirect'])
def test_all_payload_families_disclose_retry_unknown(monkeypatch, kind):
    scan = h.BypassOrchestrator()
    monkeypatch.setattr(h, f'_{kind.upper()}_PAYLOADS', {'synthetic': ['value']})
    async def retry(*args, **kwargs):
        response = httpx.Response(200, text='root:x:0:0:')
        response.extensions['bbh_waf_retry'] = True
        return response
    monkeypatch.setattr(scan, '_get_payload', retry)
    async def run():
        return [r async for r in getattr(scan, f'_run_{kind}')('https://app.example.test/p', 'q', None, asyncio.Semaphore(1))]
    result = asyncio.run(run())[0]
    assert not result.success and result.incomplete and 'unknown' in result.note


def test_403_retried_baseline_is_not_comparison_evidence(monkeypatch):
    scan = h.BypassOrchestrator()
    monkeypatch.setattr(h, '_403_HEADER_PAYLOADS', [{}])
    monkeypatch.setattr(h, '_403_PATH_SUFFIXES', [])
    monkeypatch.setattr(h, '_403_PATH_PREFIXES', [])
    monkeypatch.setattr(h, '_403_METHODS', [])
    calls = 0
    async def get(*args, **kwargs):
        nonlocal calls
        calls += 1
        response = httpx.Response(403 if calls == 1 else 200)
        if calls == 1:
            response.extensions['bbh_waf_retry'] = True
        return response
    monkeypatch.setattr(scan, '_get', get)
    async def run():
        return [r async for r in scan._run_403('https://app.example.test/p', None, asyncio.Semaphore(1))]
    result = asyncio.run(run())[0]
    assert not result.success and result.incomplete and 'baseline' in result.note


def test_race_distinct_success_bodies_remain_investigation_signal():
    responses = [{'status': 200, 'hash': 'a', 'text': 'private-a'}] * 13
    responses += [{'status': 200, 'hash': 'b', 'text': 'private-b'}, {'status': 429, 'hash': 'c', 'text': 'private-c'}]
    results = RaceBypass()._analyse('https://app.example.test/p', responses[0], responses, 'GET')
    assert results[0].success and 'possible race' in results[0].note
    assert len(results) == 3 and all(r.status_code == 200 for r in results[1:])
    assert 'private-' not in repr(results)


def test_sync_payload_retry_exposes_unknown_provenance(monkeypatch):
    import requests
    waf = w.WAFInterceptor('https://app.example.test', verbose=False)
    monkeypatch.setitem(w.WAF_BYPASSES, 'Akamai', [])
    monkeypatch.setitem(w.WAF_BYPASSES, 'generic', [])
    monkeypatch.setattr(waf, '_obfuscate_url_params', lambda url: [('synthetic', url.replace('original', 'variant'))])
    class Session:
        def request(self, method, url, **kwargs):
            response = requests.Response()
            response.status_code = 200 if 'variant' in url else 403
            response._content = b'ok' if 'variant' in url else b'Access Denied'
            return response
    monkeypatch.setattr(waf, '_get_session', lambda: Session())
    result = waf.get_payload('/p?q=original')
    assert result.status_code == 200 and result._bbh_waf_retry is True
    assert waf.stats['total_requests'] == 2
