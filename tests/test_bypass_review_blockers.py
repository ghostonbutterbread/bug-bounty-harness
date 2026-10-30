"""Synthetic review regressions; use the offline guard."""
import asyncio
import sys

import httpx
import pytest

from agents import bypass_harness as harness


@pytest.mark.parametrize('target', [
    'https://user:synthetic-secret%40app.example.test/p',
    'https://user%3Asynthetic-secret%40app.example.test/p',
    'https://@app.example.test/p',
    'https://user:synthetic-secret@app.example.test/p',
    'https://user%253Asynthetic-secret%2540app.example.test/p',
    'https://app.example.test%3Asynthetic-secret:443/p',
    'https://app.example.test:65536/p',
])
def test_reject_bad_authority_before_banner(target, monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['bypass', '--target', target])
    def fail_if_run(coro):
        coro.close()
        raise AssertionError('validation did not stop before scan')
    monkeypatch.setattr(harness.asyncio, 'run', fail_if_run)
    with pytest.raises(SystemExit):
        harness.main()
    captured = capsys.readouterr()
    assert not captured.out
    assert 'synthetic-secret' not in captured.err


def test_httpx_parser_is_used_for_credential_authorities(monkeypatch):
    original = httpx.URL
    calls = []
    def track(value):
        calls.append(value)
        return original(value)
    monkeypatch.setattr(harness.httpx, 'URL', track)
    with pytest.raises(ValueError):
        harness._reject_url_userinfo('https://user:synthetic-secret@app.example.test/p')
    assert calls


def test_invalid_url_exception_does_not_retain_httpx_secret():
    with pytest.raises(ValueError) as exc:
        harness._reject_url_userinfo('https://user:synthetic-secret%40app.example.test/p')
    assert exc.value.__context__ is None


def test_request_construction_failure_is_not_reported_as_dispatch():
    seen = []
    async def handle(request):
        seen.append(request)
        return httpx.Response(200)
    counts = harness.Counter()
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as raw:
            client = harness._ScopedClient(raw, lambda url: True, enforce_headers=False, counts=counts)
            with pytest.raises(Exception):
                await client.get('https://app.example.test/p', headers={'X-Bad': 'bad\u2603value'})
    asyncio.run(go())
    assert not seen
    assert counts['client_call_attempts'] == 1
    assert counts['observed_responses'] == 0
    assert counts['unknown_failures'] == 1
    assert 'dispatched' not in counts


def test_http_client_exception_message_is_not_exposed():
    class Broken:
        async def request(self, *args, **kwargs):
            raise ValueError('synthetic-embedded-exception-secret')
    async def go():
        client = harness._ScopedClient(Broken(), lambda url: True)
        with pytest.raises(Exception) as exc:
            await client.get('https://app.example.test/p')
        assert 'synthetic-embedded-exception-secret' not in str(exc.value)
        assert exc.value.__context__ is None
    asyncio.run(go())


def test_header_validation_exception_does_not_reveal_value():
    async def go():
        client = harness._ScopedClient(object(), lambda url: True)
        with pytest.raises(Exception) as exc:
            await client.get('https://app.example.test/p', headers={'X-Synthetic': 'synthetic-secret-☃'})
        assert 'synthetic-secret' not in str(exc.value)
        assert 'synthetic-secret' not in str(getattr(exc.value, 'object', ''))
        assert exc.value.__context__ is None
    asyncio.run(go())


def test_httpx_valid_url_with_query_space_is_accepted():
    harness._reject_url_userinfo('https://app.example.test/p?q=ordinary value')


def test_valid_url_is_sent_without_rewriting_query_bytes():
    seen = []
    target = 'https://app.example.test:8443/a%2Fb?x=1&x=2'
    async def handle(request):
        seen.append(request)
        return httpx.Response(200)
    counts = harness.Counter()
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as raw:
            client = harness._ScopedClient(raw, lambda url: True, counts=counts)
            await client.get(target)
    asyncio.run(go())
    assert seen[0].url.raw_path == b'/a%2Fb?x=1&x=2'
    assert seen[0].url.port == 8443
    assert counts['client_call_attempts'] == counts['observed_responses'] == 1


def test_redacted_results_and_reports_with_nested_secrets(monkeypatch, tmp_path, capsys):
    from dataclasses import asdict
    secret = 'synthetic-query-secret'
    response_secret = 'synthetic-response-secret'
    target = f'https://app.example.test/p?token={secret}&page=ordinary'
    class Scan:
        deferred = harness.Counter()
        request_counts = harness.Counter()
        execution_errors = 0
        async def run_bypass(self, target, kind, param=None):
            yield harness.BypassResult(True, '403', 'header_injection', '403_bypass',
                "{'Authorization': 'Bearer synthetic-auth-secret', 'Cookie': 'sid=synthetic-cookie-secret'}",
                target, 200, '{"nested":{"token":"' + response_secret + '"}}')
    monkeypatch.setattr(harness, 'BypassOrchestrator', lambda **kw: Scan())
    successes, _ = asyncio.run(harness.run_and_report(target, '403', output_dir=str(tmp_path)))
    output = capsys.readouterr().out + repr([asdict(r) for r in successes])
    output += ''.join(p.read_text() for p in tmp_path.iterdir())
    for value in [secret, response_secret, 'synthetic-auth-secret', 'synthetic-cookie-secret']:
        assert value not in output
    assert '403_bypass' in output and '200' in output


def test_real_403_sweep_masks_query_and_response_without_changing_requests(monkeypatch, tmp_path, capsys):
    from contextlib import asynccontextmanager
    target = 'https://app.example.test/p?token=synthetic-query-value&x=ordinary'
    sent = []
    class Limiter:
        @asynccontextmanager
        async def http(self):
            yield
        def adapt_to_response(self, response):
            pass
    class Waf:
        async def wrap_async(self, client, method, url, response, **kwargs):
            return response
    scan = harness.BypassOrchestrator(verbose=True)
    scan._limiter = Limiter()
    monkeypatch.setattr(scan, '_get_waf', lambda url: Waf())
    monkeypatch.setattr(harness, 'BypassOrchestrator', lambda **kwargs: scan)
    async def request(self, method, url, **kwargs):
        sent.append(url)
        return httpx.Response(200, text='synthetic-response-value',
                              request=httpx.Request(method, url))
    monkeypatch.setattr(httpx.AsyncClient, 'request', request)
    hits, misses = asyncio.run(harness.run_and_report(target, '403', output_dir=str(tmp_path)))
    stdout = capsys.readouterr().out
    output = stdout + repr(hits + misses) + ''.join(p.read_text() for p in tmp_path.iterdir())
    assert 'synthetic-query-value' not in output
    assert 'synthetic-response-value' not in output
    assert sent and all('token=synthetic-query-value' in url for url in sent)
    assert '403_bypass' in output and 'HTTP 200' in stdout
    assert {p.suffix for p in tmp_path.iterdir()} == {'.txt', '.json'}
    assert (tmp_path / 'summary.json').is_file()


def test_waf_logs_do_not_expose_query_token(tmp_path, capsys):
    from agents.waf_interceptor import WAFInterceptor
    waf = WAFInterceptor(target='https://app.example.test', verbose=True)
    waf._out_dir = tmp_path
    url = 'https://app.example.test/p?token=synthetic-waf-secret&x=1'
    class Client:
        async def request(self, method, url, **kwargs):
            return httpx.Response(200, request=httpx.Request(method, url))
    async def go():
        response = httpx.Response(403, text='Access Denied', request=httpx.Request('GET', url))
        await waf.wrap_async(Client(), 'GET', url, response)
    asyncio.run(go())
    output = capsys.readouterr().out + ''.join(p.read_text() for p in tmp_path.iterdir())
    assert 'synthetic-waf-secret' not in output
    assert 'status=403' in (tmp_path / 'blocks_log.txt').read_text()
    assert 'status=200' in (tmp_path / 'bypasses_log.txt').read_text()


def test_waf_nested_retry_headers_do_not_leak(monkeypatch, tmp_path, capsys):
    from agents import waf_interceptor as module
    waf = module.WAFInterceptor(target='https://app.example.test', verbose=True)
    waf._out_dir = tmp_path
    monkeypatch.setitem(module.WAF_BYPASSES, 'Akamai', [{'headers': {
        'Authorization': 'Basic synthetic-waf-auth', 'Cookie': 'sid=synthetic-waf-cookie'}}])
    monkeypatch.setitem(module.WAF_BYPASSES, 'generic', [])
    class Client:
        async def request(self, method, url, **kwargs):
            return httpx.Response(200, request=httpx.Request(method, url))
    url = 'https://app.example.test/p'
    async def go():
        response = httpx.Response(403, text='Access Denied', request=httpx.Request('GET', url))
        await waf.wrap_async(Client(), 'GET', url, response)
    asyncio.run(go())
    output = capsys.readouterr().out + ''.join(p.read_text() for p in tmp_path.iterdir())
    assert 'synthetic-waf-auth' not in output
    assert 'synthetic-waf-cookie' not in output
    assert 'status=200' in output


def test_no_response_is_reported_unknown_not_miss():
    result = harness.BypassResult(False, '403', 'header', '403_bypass', '',
                                  'https://app.example.test/p', 0, '', 'request_error')
    assert '[unknown]' in result.to_line()
    assert '[miss]' not in result.to_line()


def test_sensitive_payload_and_nested_sessions_are_suppressed():
    result = harness.BypassResult(True, 'cors', 'origin_header', 'test',
        "{'headers': {'Authorization': 'Basic synthetic-auth-value', 'Cookie': 'sid=synthetic-cookie-value'}, 'nested': {'session_id': 'synthetic-session-value'}}",
        'https://app.example.test/p', 200, '')
    for secret in ('synthetic-auth-value', 'synthetic-cookie-value', 'synthetic-session-value'):
        assert secret not in result.payload


def test_query_value_with_space_is_fully_withheld():
    from agents.bypass_redaction import safe_text
    output = safe_text('https://app.example.test/p?token=synthetic first secret&x=ordinary')
    assert 'synthetic' not in output and 'first secret' not in output
    assert 'app.example.test/p' in output


def test_token_like_jwt_and_basic_header_are_not_output():
    from agents.bypass_redaction import safe_text
    jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c3ludGhldGljX3NpZ25hdHVyZQ'
    for value in [jwt, 'Authorization: Basic synthetic-basic-value']:
        output = safe_text(value)
        assert value not in output
    assert 'synthetic-basic-value' not in safe_text('Authorization: Basic synthetic-basic-value')
