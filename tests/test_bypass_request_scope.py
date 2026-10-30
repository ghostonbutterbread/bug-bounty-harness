"""Synthetic request-boundary tests; no target traffic."""
import asyncio
from contextlib import asynccontextmanager

import httpx
import pytest

from agents import bypass_harness as harness


class Limiter:
    @asynccontextmanager
    async def http(self):
        yield

    def adapt_to_response(self, response):
        pass


@pytest.fixture
def scanner(tmp_path, monkeypatch):
    monkeypatch.setattr(harness.ScopeValidator, 'SCOPES_BASE', tmp_path / 'scopes')
    monkeypatch.setattr(harness.ScopeValidator, 'LEGACY_RECON_BASE', tmp_path / 'legacy')
    folder = tmp_path / 'scopes' / 'synthetic'
    folder.mkdir(parents=True)
    (folder / 'in-scope.txt').write_text('app.example.test\n')
    (folder / 'out-of-scope.txt').write_text('https://app.example.test/user/1\n')
    calls = []

    class Client:
        def __init__(self, **kwargs):
            assert kwargs['follow_redirects'] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def request(self, method, url, **kwargs):
            calls.append((method, str(url), kwargs))
            return httpx.Response(200, text='ok', request=httpx.Request(method, url))

        async def get(self, url, **kwargs):
            return await self.request('GET', url, **kwargs)

        async def post(self, url, **kwargs):
            return await self.request('POST', url, **kwargs)

        async def options(self, url, **kwargs):
            return await self.request('OPTIONS', url, **kwargs)

    monkeypatch.setattr(harness.httpx, 'AsyncClient', Client)
    scan = harness.BypassOrchestrator(program='synthetic')
    scan._limiter = Limiter()
    return scan, calls


def test_idor_generated_denied_path_never_reaches_client(scanner):
    scan, calls = scanner
    async def run():
        return [r async for r in scan.run_bypass('https://app.example.test/user/2', 'idor')]
    asyncio.run(run())
    urls = [url for _, url, _ in calls]
    assert 'https://app.example.test/user/2' in urls
    assert 'https://app.example.test/user/1' not in urls


def test_explicit_non_program_mode_keeps_generated_requests(scanner):
    _, calls = scanner
    scan = harness.BypassOrchestrator(program=None)
    scan._limiter = Limiter()
    async def run():
        return [r async for r in scan.run_bypass('https://app.example.test/user/2', 'idor')]
    asyncio.run(run())
    assert 'https://app.example.test/user/1' in [url for _, url, _ in calls]


def test_cooperating_subclass_uses_guard(scanner, monkeypatch):
    scan, calls = scanner
    class CustomIDOR(harness.IDORBypass):
        async def scan(self, target, client, sem, limiter, param=None):
            with pytest.raises(httpx.RequestError):
                await client.get('https://app.example.test/user/1')
            await client.get(target)
            return []
    monkeypatch.setitem(scan._MODULE_TYPES, 'idor', CustomIDOR)
    async def run():
        return [r async for r in scan.run_bypass('https://app.example.test/user/2', 'idor')]
    asyncio.run(run())
    assert [url for _, url, _ in calls] == ['https://app.example.test/user/2']


def test_403_with_query_runs_and_preserves_baseline_query(scanner, monkeypatch):
    scan, calls = scanner
    monkeypatch.setattr(scan, '_get_waf', lambda url: type('Waf', (), {
        'wrap_async': lambda self, client, method, url, response, **kw: async_identity(response)
    })())
    async def run():
        return [r async for r in scan.run_bypass('https://app.example.test/user/2?x=1&x=2', '403')]
    results = asyncio.run(run())
    assert results
    assert any(url == 'https://app.example.test/user/2?x=1&x=2' for _, url, _ in calls)
    assert any(url == 'https://app.example.test/user/2/?x=1&x=2' for _, url, _ in calls)


async def async_identity(value):
    return value


@pytest.mark.parametrize('program', [None, 'synthetic'])
@pytest.mark.parametrize('kind', ['403', 'sweep'])
def test_userinfo_rejected_before_output_generation_or_transport(scanner, program, kind, capsys):
    scan, calls = scanner
    scan.program = program
    scan.verbose = True
    secret = 'synthetic-password-314'
    target = f'https://user:{secret}@app.example.test/user/2'
    async def run():
        return [r async for r in scan.run_bypass(target, kind)]
    with pytest.raises(ValueError) as exc:
        asyncio.run(run())
    assert secret not in str(exc.value)
    assert secret not in capsys.readouterr().out
    assert not calls


@pytest.mark.parametrize('kind', ['cors', 'xxe', 'traversal', 'ssti', 'race', 'idor', '403', 'lfi', 'rfi', 'ssrf', 'redirect', 'auto', 'sweep'])
def test_other_scanner_families_use_scoped_client(scanner, monkeypatch, kind):
    scan, calls = scanner
    guarded_calls = []
    original_request = harness._ScopedClient.request
    async def instrumented(self, method, url, **kwargs):
        guarded_calls.append((method, str(url)))
        return await original_request(self, method, url, **kwargs)
    monkeypatch.setattr(harness._ScopedClient, 'request', instrumented)
    # Avoid WAF logging and retries; retry behavior is tested separately.
    class Waf:
        async def wrap_async(self, client, method, url, response, **kwargs):
            return response
        async def aget_payload(self, url, client):
            return await client.request('GET', url)
    monkeypatch.setattr(scan, '_get_waf', lambda url: Waf())
    async def run():
        return [r async for r in scan.run_bypass('https://app.example.test/user/2?id=2', kind)]
    asyncio.run(run())
    assert calls
    assert all((method, url) in guarded_calls for method, url, _ in calls)
    assert all(scan._check_scope(url) for _, url, _ in calls)
    assert all(kwargs['follow_redirects'] is False for _, _, kwargs in calls)


def test_waf_retry_mutations_are_guarded(scanner, monkeypatch):
    scan, calls = scanner
    class Waf:
        async def aget_payload(self, url, client):
            for candidate in ['https://app.example.test/user/1',
                              'https://app.example.test/user/%31',
                              'https://app.example.test/user/2']:
                try:
                    response = await client.request('GET', candidate, follow_redirects=True)
                except httpx.RequestError:
                    continue
            return response
    monkeypatch.setattr(scan, '_get_waf', lambda url: Waf())
    monkeypatch.setattr(harness, '_LFI_PAYLOADS', {'fixture': ['x']})
    async def run():
        return [r async for r in scan.run_bypass('https://app.example.test/user/2', 'lfi')]
    asyncio.run(run())
    assert [url for _, url, _ in calls] == ['https://app.example.test/user/2']
    assert calls[0][2]['follow_redirects'] is False


def test_scope_errors_fail_before_request_and_do_not_authorize(scanner, monkeypatch):
    scan, calls = scanner
    class Broken:
        def is_in_scope(self, url):
            raise OSError('scope failure')
    scan._scope = Broken()
    async def run():
        return [r async for r in scan.run_bypass('https://app.example.test/user/2', 'idor')]
    with pytest.raises(OSError, match='scope validation failed'):
        asyncio.run(run())
    assert not calls


def test_generated_url_validation_exception_prevents_client_call(scanner):
    scan, calls = scanner
    original = scan._scope.is_in_scope
    def check(url):
        if url.endswith('/user/1'):
            raise OSError('synthetic validator error')
        return original(url)
    scan._scope.is_in_scope = check
    async def run():
        return [r async for r in scan.run_bypass('https://app.example.test/user/2', 'idor')]
    asyncio.run(run())
    assert calls
    assert all(url != 'https://app.example.test/user/1' for _, url, _ in calls)


def test_real_httpx_transport_does_not_follow_redirect(scanner):
    scan, _ = scanner
    # The fixture patches the constructor; recover the real class from a subclass.
    from httpx._client import AsyncClient
    seen = []
    async def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={'location': '/user/1'})
    async def run():
        async with AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as underlying:
            guarded = harness._ScopedClient(underlying, scan._check_scope)
            response = await guarded.get('https://app.example.test/user/2', follow_redirects=True)
            assert response.status_code == 302
    asyncio.run(run())
    assert seen == ['https://app.example.test/user/2']


def test_scoped_client_rejects_dot_segment_normalized_destination(scanner):
    scan, calls = scanner
    class Underlying:
        async def request(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
    async def run():
        guarded = harness._ScopedClient(Underlying(), scan._check_scope)
        with pytest.raises(httpx.RequestError):
            await guarded.request('GET', 'https://app.example.test/user/2/../1')
    asyncio.run(run())
    assert not calls


def test_real_waf_retry_generated_path_passes_guard(scanner, monkeypatch):
    from agents import waf_interceptor
    scan, calls = scanner
    waf = waf_interceptor.WAFInterceptor(target='https://app.example.test', program=None)
    monkeypatch.setattr(waf, '_write_log', lambda *a: None)
    monkeypatch.setattr(waf, '_flush_summary', lambda: None)
    monkeypatch.setattr(waf, '_build_bypass_kwargs',
                        lambda kwargs, bypass, path: (kwargs, '/user/1'))
    monkeypatch.setitem(waf_interceptor.WAF_BYPASSES, 'generic', [{}])
    class Underlying:
        async def request(self, method, url, **kwargs):
            calls.append((method, str(url), kwargs))
            return httpx.Response(200, request=httpx.Request(method, url))
    async def run():
        client = harness._ScopedClient(Underlying(), scan._check_scope)
        original = httpx.Response(403, text='blocked', request=httpx.Request('GET', 'https://app.example.test/user/2'))
        result = await waf.wrap_async(client, 'GET', 'https://app.example.test/user/2', original)
        assert result is original
    asyncio.run(run())
    assert calls == []


def test_routing_headers_are_checked_before_transport(scanner):
    scan, calls = scanner
    (scan._scope.SCOPES_BASE / 'synthetic' / 'out-of-scope.txt').write_text(
        'https://app.example.test/user/1\nhttps://app.example.test/admin\nlocalhost\n')
    scan = harness.BypassOrchestrator(program='synthetic')
    target = 'https://app.example.test/user/2?x=1&x=2'
    async def run():
        guarded = harness._ScopedClient(harness.httpx.AsyncClient(follow_redirects=False), scan._check_scope)
        for headers in [
            {'X-Original-URL': '/admin'}, {'X-Rewrite-URL': '/admin'},
            {'Host': 'localhost'}, {'X-Forwarded-Host': 'localhost'},
            {'Forwarded': 'for=127.0.0.1;host=localhost'},
            {'X-Rewrite-URL': '/user/other'},
            {'X-Forwarded-Proto': 'http'}, {'X-Forwarded-Port': '80'},
            {'X-Original-URL': '/user/%32'},
        ]:
            with pytest.raises(httpx.RequestError):
                await guarded.get(target, headers=headers)
        await guarded.get(target, headers={'X-Original-URL': '/user/2'})
        await guarded.get(target, headers={'X-Forwarded-Host': 'app.example.test'})
    asyncio.run(run())
    assert len(calls) == 2


def test_403_path_variants_preserve_encoded_path_and_query(scanner, monkeypatch):
    scan, calls = scanner
    monkeypatch.setattr(scan, '_get_waf', lambda url: type('Waf', (), {
        'wrap_async': lambda self, client, method, url, response, **kw: async_identity(response)
    })())
    # Isolate path generation from ScopeValidator's deliberate refusal of
    # ambiguous encodings under a path exclusion.
    scan._scope = None
    target = 'https://app.example.test/user/a%3Fb%2Fc?x=1&x=2'
    async def run():
        return [r async for r in scan.run_bypass(target, '403')]
    asyncio.run(run())
    urls = [url for _, url, _ in calls]
    assert 'https://app.example.test/user/a%3Fb%2Fc/?x=1&x=2' in urls
    assert not any('/user/a?b/c' in url for url in urls)


def test_waf_case_path_preserves_encoded_bytes_and_query():
    from agents.waf_interceptor import _apply_path_case
    assert _apply_path_case('/user/a%3Fb%2Fc?x=Ab&x=Cd', 'upper') == \
        '/USER/A%3FB%2FC?x=Ab&x=Cd'
    assert _apply_path_case('/User?next=https://x.test/Ab&x=1', 'lower') == \
        '/user?next=https://x.test/Ab&x=1'
    assert _apply_path_case('https://app.example.test/User%2fA?x=Ab&x=Cd', 'lower') == \
        'https://app.example.test/user%2fa?x=Ab&x=Cd'


def test_waf_origin_preserves_port(scanner):
    scan, _ = scanner
    # No output files or network: the WAF interceptor is unprogrammed here.
    scan.program = None
    assert scan._get_waf('https://app.example.test:8443/user/2').target == \
        'https://app.example.test:8443'


def test_403_emits_only_allowed_routing_headers_and_counts_deferrals(scanner, monkeypatch):
    scan, calls = scanner
    (scan._scope.SCOPES_BASE / 'synthetic' / 'out-of-scope.txt').write_text(
        'https://app.example.test/admin\nlocalhost\n')
    scan = harness.BypassOrchestrator(program='synthetic')
    scan._limiter = Limiter()
    monkeypatch.setattr(scan, '_get_waf', lambda url: type('Waf', (), {
        'wrap_async': lambda self, client, method, url, response, **kw: async_identity(response)
    })())
    async def run():
        return [r async for r in scan.run_bypass('https://app.example.test/user/2', '403')]
    asyncio.run(run())
    headers = [kw.get('headers', {}) for _, _, kw in calls]
    assert {'X-Original-URL': '/user/2'} in headers
    assert {'X-Rewrite-URL': '/user/2'} in headers
    assert {'X-Forwarded-Host': 'app.example.test'} in headers
    assert not any(h.get('X-Original-URL') == '/admin' or h.get('X-Rewrite-URL') == '/admin'
                   or h.get('X-Forwarded-Host') == 'localhost' or h.get('Host') == 'localhost'
                   for h in headers)
    assert scan.deferred['rewrite resource outside saved scope'] == 2
    assert scan.deferred['host override is not the request authority'] >= 2
    assert scan.deferred['path delimiter mutation changes query semantics'] == 1


def test_real_waf_host_retry_is_guarded_but_same_origin_retry_runs(scanner, monkeypatch):
    from agents import waf_interceptor
    scan, calls = scanner
    waf = waf_interceptor.WAFInterceptor(target='https://app.example.test', program=None, verbose=False)
    monkeypatch.setitem(waf_interceptor.WAF_BYPASSES, 'AWS WAF', [
        {'headers': {'Host': 'localhost'}},
        {'headers': {'X-Forwarded-Host': 'app.example.test'}},
    ])
    monkeypatch.setitem(waf_interceptor.WAF_BYPASSES, 'generic', [])
    async def run():
        client = harness._ScopedClient(harness.httpx.AsyncClient(follow_redirects=False),
                                       scan._check_scope, deferred=scan.deferred)
        original = httpx.Response(403, text='403 Forbidden',
                                  request=httpx.Request('GET', 'https://app.example.test/user/2'))
        return await waf.wrap_async(client, 'GET', 'https://app.example.test/user/2', original)
    assert asyncio.run(run()).status_code == 200
    assert len(calls) == 1
    assert calls[0][2]['headers'] == {'X-Forwarded-Host': 'app.example.test'}
    assert scan.deferred['host override is not the request authority'] == 1


def test_named_program_encoded_variants_use_raw_path_when_granted(scanner, monkeypatch):
    scan, calls = scanner
    (scan._scope.SCOPES_BASE / 'synthetic' / 'out-of-scope.txt').write_text('localhost\n')
    scan = harness.BypassOrchestrator(program='synthetic')
    scan._limiter = Limiter()
    monkeypatch.setattr(scan, '_get_waf', lambda url: type('Waf', (), {
        'wrap_async': lambda self, client, method, url, response, **kw: async_identity(response)
    })())
    target = 'https://app.example.test/user/a%3Fb%2Fc?x=A&x=B'
    async def run():
        return [r async for r in scan.run_bypass(target, '403')]
    asyncio.run(run())
    assert any(url == 'https://app.example.test/user/a%3Fb%2Fc/?x=A&x=B'
               for _, url, _ in calls)
    assert all('/user/a?b/c' not in url for _, url, _ in calls)


def test_registered_modules_have_no_obvious_raw_client_calls():
    import ast
    import inspect
    assert set(harness.ALL_MODULES) == set(harness.BypassOrchestrator._MODULE_TYPES.values())
    for module in harness.ALL_MODULES:
        tree = ast.parse(inspect.getsource(inspect.getmodule(module)))
        attributes = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)]
        assert '_client' not in attributes
        assert 'AsyncClient' not in [n.func.attr for n in ast.walk(tree)
                                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]


def test_report_counts_transport_not_result_entries(scanner, monkeypatch, tmp_path, capsys):
    import json
    scan, calls = scanner
    scan._limiter = Limiter()
    monkeypatch.setattr(harness, 'BypassOrchestrator', lambda **kwargs: scan)
    monkeypatch.setattr(scan, '_get_waf', lambda url: type('Waf', (), {
        'wrap_async': lambda self, client, method, url, response, **kw: async_identity(response)
    })())
    asyncio.run(harness.run_and_report('https://app.example.test/user/2', '403',
                                       output_dir=str(tmp_path), quiet=True))
    summary = json.loads((tmp_path / 'summary.json').read_text())
    counts = summary['request_counts']
    assert counts['client_call_attempts'] == len(calls)
    assert counts['completed'] == len(calls)
    assert counts['skipped_scope'] > 0
    assert counts['deferred'] > 0
    assert counts['errors'] == 0
    assert summary['total'] == summary['result_count']
    assert summary['total'] != len(calls)
    assert f"Client-call attempts {len(calls)}" in capsys.readouterr().out


def test_report_counts_failed_dispatch_and_redacts_error(scanner, monkeypatch, tmp_path, capsys):
    import json
    scan, calls = scanner
    scan.verbose = True
    monkeypatch.setattr(harness, 'BypassOrchestrator', lambda **kwargs: scan)
    secret = 'synthetic-error-secret-285'
    async def broken(self, method, url, **kwargs):
        calls.append((method, url, kwargs))
        raise httpx.RequestError(secret)
    monkeypatch.setattr(harness.httpx.AsyncClient, 'request', broken)
    monkeypatch.setattr(harness, '_403_HEADER_PAYLOADS', [])
    monkeypatch.setattr(harness, '_403_PATH_SUFFIXES', [])
    monkeypatch.setattr(harness, '_403_PATH_PREFIXES', [])
    monkeypatch.setattr(harness, '_403_METHODS', [])
    asyncio.run(harness.run_and_report('https://app.example.test/user/2', '403',
                                       output_dir=str(tmp_path), quiet=True))
    counts = json.loads((tmp_path / 'summary.json').read_text())['request_counts']
    assert counts['client_call_attempts'] == len(calls) > 0
    assert counts['completed'] == 0
    assert counts['errors'] == len(calls)
    assert secret not in capsys.readouterr().out
    assert secret not in ''.join(p.read_text() for p in tmp_path.iterdir() if p.is_file())


@pytest.mark.parametrize('program', [None, 'synthetic'])
def test_403_empty_query_delimiter_reaches_mock_transport(scanner, monkeypatch, program):
    from httpx._client import AsyncClient
    scan, _ = scanner
    if program is None:
        scan.program = None
        scan._scope = None
    received = []
    async def handler(request):
        received.append(request.url.raw_path)
        return httpx.Response(403, request=request)
    async def run():
        async with AsyncClient(transport=httpx.MockTransport(handler)) as raw:
            client = harness._ScopedClient(raw, scan._check_scope,
                                            enforce_headers=program is not None,
                                            deferred=scan.deferred, counts=scan.request_counts)
            return [r async for r in scan._run_403('https://app.example.test/user/2',
                                                   client, asyncio.Semaphore(10))]
    monkeypatch.setattr(scan, '_get_waf', lambda url: type('Waf', (), {
        'wrap_async': lambda self, client, method, url, response, **kw: async_identity(response)
    })())
    asyncio.run(run())
    assert b'/user/2?' in received
    assert scan.deferred['path delimiter mutation changes query semantics'] == 1


def test_sweep_surfaces_module_errors_without_exception_secrets(scanner, monkeypatch):
    scan, _ = scanner
    secret = 'synthetic-module-error-secret'
    class Broken:
        name = 'broken'
        async def detect(self, *args):
            raise RuntimeError(secret)
        async def scan(self, *args, **kwargs):
            raise RuntimeError(secret)
    monkeypatch.setattr(harness, 'ALL_MODULES', [Broken])
    async def empty(*args, **kwargs):
        if False:
            yield
    monkeypatch.setattr(scan, '_run_ssrf', empty)
    async def run():
        return [r async for r in scan.run_sweep('https://app.example.test/user/2')]
    results = asyncio.run(run())
    assert scan.execution_errors == 2
    assert any(r.technique == 'module_error' for r in results)
    assert secret not in repr(results)


def test_scope_denied_target_counts_one_skipped_without_dispatch(scanner, monkeypatch, tmp_path):
    import json
    scan, calls = scanner
    monkeypatch.setattr(harness, 'BypassOrchestrator', lambda **kwargs: scan)
    asyncio.run(harness.run_and_report('https://app.example.test/user/1', '403',
                                       output_dir=str(tmp_path), quiet=True))
    counts = json.loads((tmp_path / 'summary.json').read_text())['request_counts']
    assert counts == dict(generated=1, dispatched=None, completed=0, skipped_scope=1,
                          deferred=0, errors=0, client_call_attempts=0,
                          observed_responses=0, unknown_failures=0)
    assert calls == []


def test_real_waf_retry_error_never_logs_exception_text(scanner, monkeypatch, capsys):
    from agents import waf_interceptor
    scan, _ = scanner
    waf = waf_interceptor.WAFInterceptor(target='https://app.example.test', program=None, verbose=True)
    monkeypatch.setitem(waf_interceptor.WAF_BYPASSES, 'AWS WAF', [{'headers': {'X-Test': 'x'}}])
    monkeypatch.setitem(waf_interceptor.WAF_BYPASSES, 'generic', [])
    secret = 'synthetic-waf-error-secret'
    class Broken:
        async def request(self, *args, **kwargs):
            raise httpx.RequestError(secret)
    async def run():
        client = harness._ScopedClient(Broken(), scan._check_scope, counts=scan.request_counts)
        original = httpx.Response(403, text='403 Forbidden',
                                  request=httpx.Request('GET', 'https://app.example.test/user/2'))
        return await waf.wrap_async(client, 'GET', 'https://app.example.test/user/2', original)
    asyncio.run(run())
    assert scan.request_counts['errors'] == 1
    assert secret not in capsys.readouterr().out


@pytest.mark.parametrize('kind', ['cors', 'xxe', 'traversal', 'ssti'])
def test_registered_module_errors_never_expose_exception_text(scanner, monkeypatch, kind):
    scan, calls = scanner
    secret = 'synthetic-module-request-secret'
    async def broken(self, method, url, **kwargs):
        calls.append((method, url, kwargs))
        raise httpx.RequestError(secret)
    monkeypatch.setattr(harness.httpx.AsyncClient, 'request', broken)
    async def run():
        return [r async for r in scan.run_bypass('https://app.example.test/user/2?file=x', kind, param='file')]
    results = asyncio.run(run())
    assert results
    assert secret not in repr(results)
    assert scan.request_counts['client_call_attempts'] == len(calls) > 0
    assert scan.request_counts['errors'] >= len(calls)


def test_cli_and_guard_reject_userinfo_without_emitting_or_dispatching(scanner, monkeypatch, capsys):
    import sys
    scan, calls = scanner
    secret = 'synthetic-cli-secret-217'
    target = f'https://user:{secret}@app.example.test/user/2'
    monkeypatch.setattr(sys, 'argv', ['bypass', '--target', target])
    with pytest.raises(SystemExit):
        harness.main()
    output = capsys.readouterr()
    assert secret not in output.out + output.err
    async def run():
        client = harness._ScopedClient(harness.httpx.AsyncClient(follow_redirects=False), scan._check_scope)
        with pytest.raises(ValueError) as exc:
            await client.get(target)
        assert secret not in str(exc.value)
    asyncio.run(run())
    assert not calls


def test_403_existing_query_defers_delimiters_and_retains_query(scanner, monkeypatch):
    scan, calls = scanner
    monkeypatch.setattr(scan, '_get_waf', lambda url: type('Waf', (), {
        'wrap_async': lambda self, client, method, url, response, **kw: async_identity(response)
    })())
    async def run():
        return [r async for r in scan.run_bypass('https://app.example.test/user/2?x=1&x=2', '403')]
    asyncio.run(run())
    assert scan.deferred['path delimiter mutation changes query semantics'] == 2
    assert not any('/user/2??x=' in url for _, url, _ in calls)
    assert any(url.endswith('?x=1&x=2') for _, url, _ in calls)


def test_unexpected_legacy_execution_error_is_visible(scanner, monkeypatch, tmp_path):
    import json
    scan, _ = scanner
    monkeypatch.setattr(harness, 'BypassOrchestrator', lambda **kwargs: scan)
    invocations = 0
    async def broken(client, url, **kwargs):
        nonlocal invocations
        invocations += 1
        if invocations == 1:
            return httpx.Response(403, request=httpx.Request('GET', url))
        raise RuntimeError('synthetic-unexpected-secret')
    monkeypatch.setattr(scan, '_get', broken)
    asyncio.run(harness.run_and_report('https://app.example.test/user/2', '403',
                                       output_dir=str(tmp_path), quiet=True))
    summary = json.loads((tmp_path / 'summary.json').read_text())
    assert summary['execution_errors'] == invocations - 1
    assert 'synthetic-unexpected-secret' not in (tmp_path / 'summary.json').read_text()


def test_validator_failure_does_not_disclose_exception_text(scanner):
    scan, calls = scanner
    secret = 'synthetic-scope-error-secret'
    class Broken:
        def is_in_scope(self, url):
            raise OSError(secret)
    scan._scope = Broken()
    async def run():
        return [r async for r in scan.run_bypass('https://app.example.test/user/2', '403')]
    with pytest.raises(OSError) as exc:
        asyncio.run(run())
    assert secret not in str(exc.value)
    assert exc.value.__context__ is None
    assert not calls


@pytest.mark.parametrize('waf_name', [
    'Akamai', 'Cloudflare', 'AWS WAF', 'Imperva', 'F5 BIG-IP',
    'Sucuri', 'Wordfence', 'ModSecurity', 'PerimeterX', 'generic',
])
def test_all_registered_waf_retry_families_pass_scope_guard(scanner, monkeypatch, waf_name):
    from agents import waf_interceptor
    scan, calls = scanner
    waf = waf_interceptor.WAFInterceptor(target='https://app.example.test', program=None)
    monkeypatch.setattr(waf, '_write_log', lambda *args: None)
    monkeypatch.setattr(waf, '_flush_summary', lambda: None)
    monkeypatch.setattr(waf, 'detect_waf', lambda response: {'name': waf_name, 'confidence': 'test', 'evidence': ''})
    async def no_delay(*args):
        return None
    monkeypatch.setattr(waf_interceptor.asyncio, 'sleep', no_delay)
    class Underlying:
        async def request(self, method, url, **kwargs):
            calls.append((method, str(url), kwargs))
            return httpx.Response(403, request=httpx.Request(method, url))
    target = 'https://app.example.test/user/2?file=abc'
    async def run():
        client = harness._ScopedClient(Underlying(), scan._check_scope,
                                        deferred=scan.deferred, counts=scan.request_counts)
        original = httpx.Response(403, request=httpx.Request('GET', target))
        await waf.wrap_async(client, 'GET', target, original)
        await waf.aget_payload(target, client=client)
    asyncio.run(run())
    assert calls
    assert scan.request_counts['client_call_attempts'] == len(calls)
    assert all(scan._check_scope(url) and scan._check_scope(str(httpx.URL(url)))
               and kwargs['follow_redirects'] is False for _, url, kwargs in calls)
    assert all(url != 'https://app.example.test/user/1' for _, url, _ in calls)


def test_module_gathered_execution_errors_are_reported_even_without_dispatch(scanner, monkeypatch, tmp_path):
    import json
    scan, calls = scanner
    monkeypatch.setattr(harness, 'BypassOrchestrator', lambda **kwargs: scan)
    async def broken(*args, **kwargs):
        raise RuntimeError('synthetic-task-error-secret')
    monkeypatch.setattr(harness.CORSBypass, '_probe', broken)
    asyncio.run(harness.run_and_report('https://app.example.test/user/2', 'cors',
                                       output_dir=str(tmp_path), quiet=True))
    summary = json.loads((tmp_path / 'summary.json').read_text())
    assert summary['result_error_count'] > 0
    assert not calls
    assert 'synthetic-task-error-secret' not in (tmp_path / 'summary.json').read_text()


def test_malformed_target_with_credentials_is_rejected_without_echo(scanner, capsys):
    scan, calls = scanner
    scan._scope = None
    scan.verbose = True
    secret = 'synthetic-malformed-password'
    target = f'https:///user:{secret}@app.example.test/user/2'
    async def run():
        return [r async for r in scan.run_bypass(target, '403')]
    with pytest.raises(ValueError) as exc:
        asyncio.run(run())
    assert secret not in str(exc.value) + capsys.readouterr().out
    assert not calls


def test_deferred_counts_are_written_to_json(scanner, tmp_path):
    import json
    scan, _ = scanner
    scan.deferred['forwarding semantics not proven safe'] = 3
    output = tmp_path / 'report.json'
    harness._write_json(output, [], 'https://app.example.test/user/2', '403', scan.deferred)
    assert json.loads(output.read_text())['deferred_requests_by_reason'] == {
        'forwarding semantics not proven safe': 3}


def test_real_mock_transport_never_receives_denied_routing_headers(scanner):
    scan, _ = scanner
    from httpx._client import AsyncClient
    received = []
    async def handler(request):
        received.append(request)
        return httpx.Response(200)
    async def run():
        async with AsyncClient(transport=httpx.MockTransport(handler)) as raw:
            client = harness._ScopedClient(raw, scan._check_scope)
            with pytest.raises(httpx.RequestError):
                await client.get('https://app.example.test/user/2', headers={'Host': 'localhost'})
            with pytest.raises(httpx.RequestError):
                await client.get('https://app.example.test/user/2', headers={'X-Rewrite-URL': '/user/1'})
            await client.get('https://app.example.test/user/2', headers={'X-Rewrite-URL': '/user/2'})
    asyncio.run(run())
    assert len(received) == 1
    assert received[0].headers['host'] == 'app.example.test'
    assert received[0].headers['x-rewrite-url'] == '/user/2'
