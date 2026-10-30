"""Synthetic provider-boundary regressions; no live network."""
import asyncio
import contextlib
import io
import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from agents import subdomain_agent as agent


def test_urlscan_task_url_accepts_idna_and_case_insensitive_scheme():
    collector = agent.SubdomainCollector('target.invalid', '', [], None)
    collector.limiter = None
    class Response:
        status_code = 200
        def json(self):
            return {'results': [{'task': {'url': url}} for url in (
                'https://bücher.target.invalid/path',
                'HTTPS://UPPER.target.invalid:443/path?q=1',
                'https://faß.target.invalid/',
            )]}
    with patch.object(collector.session, 'get', return_value=Response()):
        assert collector.from_urlscan() == {
            'xn--bcher-kva.target.invalid', 'upper.target.invalid',
            'xn--fa-hia.target.invalid',
        }


@pytest.mark.parametrize('url', [
    'https://user@x.target.invalid/',
    'https://x.target.invalid@oob.invalid/',
    'https://oob.invalid/path/x.target.invalid',
    'https://oob.invalid/?fake=x.target.invalid',
    'https://oob.invalid/#x.target.invalid',
    'https://x.target.invalid:bad/',
    'https://x.target.invalid:65536/',
    'https://x.target.invalid:/',
    'https://x.target.invalid:１２/',
    'https://x.target.invalid\\@oob.invalid/',
    'https://x.target.invalid%2eoob.invalid/',
    'https://x.target.invalid\t.oob.invalid/',
    'https://x.target.invalid：443/',
    ' https://x.target.invalid/',
    '//x.target.invalid/',
    'https:///x.target.invalid/',
])
def test_urlscan_task_url_rejects_spoofed_or_malformed_authority(url):
    collector = agent.SubdomainCollector('target.invalid', '', [], None)
    collector.limiter = None
    class Response:
        status_code = 200
        def json(self): return {'results': [{'task': {'url': url}}]}
    with patch.object(collector.session, 'get', return_value=Response()):
        assert collector.from_urlscan() == set()


def test_crtsh_rejects_spoof_and_canonicalizes():
    collector = agent.SubdomainCollector('target.invalid', '', [], None)
    collector.limiter = None
    class Response:
        status_code = 200
        def json(self):
            return [{'name_value': 'oob.invalid?fake=.target.invalid\n*.GOOD.target.invalid.\nnot-target.invalid'}]
    with patch.object(collector.session, 'get', return_value=Response()):
        assert collector.from_crtsh() == {'good.target.invalid'}


def test_probe_rejects_url_authority_before_transport():
    requests = []
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: requests.append(r) or httpx.Response(200)), event_hooks={'response': [agent._capture_probe_response]}) as client:
            with pytest.raises(ValueError, match='hostname'):
                await agent.probe_subdomain('oob.invalid?fake=.target.invalid', asyncio.Semaphore(1), client)
    asyncio.run(exercise())
    assert not requests


def test_takeover_progress_classifies_failed_and_successful_rechecks():
    real_client = httpx.AsyncClient
    def handler(request):
        if request.url.host.startswith('fail'):
            raise httpx.ConnectError('FAKE_SECRET', request=request)
        if request.url.host.startswith('redirect'):
            return httpx.Response(302, headers={'Location': 'https://else.invalid/'})
        return httpx.Response(404, text='not a fingerprint')
    def factory(**kwargs):
        return real_client(transport=httpx.MockTransport(handler), **kwargs)
    results = [agent.ProbeResult(f'{name}.target.invalid', f'https://{name}.target.invalid', 404, '', 0, '', '', 'httpx') for name in ('fail', 'redirect', 'ok')]
    output = io.StringIO()
    with patch.object(httpx, 'AsyncClient', side_effect=factory), contextlib.redirect_stdout(output):
        assert asyncio.run(agent._run_takeover_checks(results, 3, set(), set())) == []
    assert '3/3 attempts completed' in output.getvalue()
    assert '1 checked' in output.getvalue()
    assert '1 deferred' in output.getvalue()
    assert '1 failed' in output.getvalue()
    assert 'FAKE_SECRET' not in output.getvalue()


def test_probe_progress_distinguishes_scope_skips():
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        results = asyncio.run(agent.probe_all(['skip.target.invalid'], scope_check=lambda url: False))
    assert results[0].source == 'skipped'
    assert '0 attempted' in output.getvalue()
    assert '1 skipped' in output.getvalue()


def test_summary_counts_only_attempted_probes_including_no_response(tmp_path):
    results = [
        agent.ProbeResult('ok.target.invalid', 'https://ok.target.invalid', 200, '', 0, '', '', 'httpx'),
        agent.ProbeResult('failed.target.invalid', 'https://failed.target.invalid', 0, '', 0, '', '', 'httpx'),
        agent.ProbeResult('skipped.target.invalid', 'https://skipped.target.invalid', 0, '', 0, '', '', 'skipped'),
    ]
    with patch.object(agent, 'RECON_BASE', tmp_path):
        out = agent.write_outputs('test', 'target.invalid', set(), [], results, [])
    summary = json.loads((out / 'summary.json').read_text())
    assert summary['total_probed'] == 2
    assert len(json.loads((out / 'scan_results.json').read_text())) == 3


def test_run_probe_summary_does_not_call_scope_skips_dead(tmp_path, capsys):
    class Collector:
        def __init__(self, *args): pass
        def from_crtsh(self): return {'n.target.invalid'}
        def from_js_files(self): return set()
        def from_local_urls(self): return set()
        def from_mutations(self, names): return set()
    async def skipped(subs, threads):
        return [agent.ProbeResult(s, 'https://' + s, 0, '', 0, '', '', 'skipped') for s in subs]
    with patch.object(agent, 'SubdomainCollector', Collector), patch.object(agent, 'probe_all', skipped), patch.object(agent, 'RECON_BASE', tmp_path), patch.object(agent, '_which', return_value=None), patch.object(agent, 'record_recon_artifacts', None):
        agent.run('target.invalid', 'test', ['crtsh'], None, 2, False, False, True)
    output = capsys.readouterr().out
    assert 'Dead/No-resp  : 0' in output
    assert 'Skipped       : 1' in output


def test_scope_skipped_probe_makes_mixed_coverage_partial(tmp_path, capsys):
    class Collector:
        def __init__(self, *args): self.calls = {}
        def from_crtsh(self): return {'ok.target.invalid', 'skip.target.invalid'}
        def from_js_files(self): return set()
        def from_local_urls(self): return set()
        def from_mutations(self, names): return set()
        def is_in_scope(self, url):
            if 'skip.target.invalid' not in url:
                return True
            self.calls[url] = self.calls.get(url, 0) + 1
            return url.startswith('https:') and self.calls[url] == 1

    calls = []
    real_client = httpx.AsyncClient
    def factory(**kwargs):
        return real_client(transport=httpx.MockTransport(
            lambda request: calls.append(str(request.url)) or httpx.Response(404, text='not a fingerprint')
        ), **kwargs)
    with patch.object(agent, 'SubdomainCollector', Collector), patch.object(agent, 'RECON_BASE', tmp_path), patch.object(agent, '_which', return_value=None), patch.object(agent, 'record_recon_artifacts', None), patch.object(agent.socket, 'getaddrinfo', side_effect=OSError('offline')), patch.object(httpx, 'AsyncClient', side_effect=factory):
        agent.run('target.invalid', 'test', ['crtsh'], None, 2, False, False, False)
    coverage = json.loads((tmp_path / 'test/ghost/subdomain/summary.json').read_text())['takeover_coverage']
    assert calls == ['https://ok.target.invalid', 'https://ok.target.invalid']
    assert coverage['checked_subdomains'] == ['ok.target.invalid']
    assert coverage['skipped_subdomains'] == ['skip.target.invalid']
    assert coverage['status'] == 'partial'
    assert 'Takeover coverage partial: 1 checked, 0 deferred, 1 skipped, 0 failed' in capsys.readouterr().out


def test_run_no_response_is_failed_not_checked(tmp_path):
    class Collector:
        def __init__(self, *a): pass
        def from_crtsh(self): return {'n.target.invalid'}
        def from_js_files(self): return set()
        def from_local_urls(self): return set()
        def from_mutations(self, subs): return set()
    async def failed(subs, threads):
        return [agent.ProbeResult(s, 'https://' + s, 0, '', 0, '', '', 'httpx') for s in subs]
    with patch.object(agent, 'SubdomainCollector', Collector), patch.object(agent, 'probe_all', failed), patch.object(agent, 'RECON_BASE', tmp_path), patch.object(agent, '_which', return_value=None), patch.object(agent, 'record_recon_artifacts', None):
        agent.run('target.invalid', 'test', ['crtsh'], None, 2, False, False, False)
    coverage = json.loads((tmp_path / 'test/ghost/subdomain/summary.json').read_text())['takeover_coverage']
    assert coverage['status'] == 'partial'
    assert coverage['checked_count'] == 0
    assert coverage['failed_subdomains'] == ['n.target.invalid']


@pytest.mark.parametrize('value', [
    'oob.invalid?fake=.target.invalid', 'user@x.target.invalid',
    'x.target.invalid:443', 'x.target.invalid/path', 'x.target.invalid#fragment',
    'x.target.invalid\t', 'x.target.invalid%2e', 'xn--.target.invalid',
    'x\u200b.target.invalid', 'x\u00ad.target.invalid',
    'x..target.invalid', '-x.target.invalid', 'https://x.target.invalid',
])
def test_invalid_hostnames_never_dispatch(value):
    calls = []
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200)), event_hooks={'response': [agent._capture_probe_response]}) as client:
            with pytest.raises(ValueError, match='^invalid hostname$'):
                await agent.probe_subdomain(value, asyncio.Semaphore(1), client)
    asyncio.run(exercise())
    assert not calls


@pytest.mark.parametrize('method,payload', [
    ('from_otx', {'passive_dns': [{'hostname': 'oob.invalid?fake=.target.invalid'}, {'hostname': 'BÜCHER.target.invalid.'}]}),
    ('from_bufferover', {'FDNS_A': ['1.2.3.4,oob.invalid?fake=.target.invalid', '1.2.3.4,BÜCHER.target.invalid.']}),
    ('from_urlscan', {'results': [{'page': {'domain': 'oob.invalid?fake=.target.invalid', 'apex': 'BÜCHER.target.invalid.'}}]}),
    ('from_rdap', {'nameservers': [{'ldhName': 'oob.invalid?fake=.target.invalid'}, {'ldhName': 'BÜCHER.target.invalid.'}]}),
    ('from_whoxy', {'search_result': [{'domain_name': 'oob.invalid?fake=.target.invalid'}, {'domain_name': 'BÜCHER.target.invalid.'}]}),
])
def test_provider_hostname_fields(method, payload, monkeypatch):
    collector = agent.SubdomainCollector('target.invalid', '', [], None)
    collector.limiter = None
    monkeypatch.setenv('WHOXY_API_KEY', 'synthetic')
    class Response:
        status_code = 200
        def json(self): return payload
    with patch.object(collector.session, 'get', return_value=Response()):
        assert getattr(collector, method)() == {'xn--bcher-kva.target.invalid'}


def test_run_filters_spoof_and_exclusion_before_dispatch(tmp_path):
    calls = []
    class Scope:
        def is_out_of_scope(self, value): return 'excluded.target.invalid' in value
        def is_empty(self): return True
    original = agent.SubdomainCollector
    class Collector(original):
        def __init__(self, *a):
            super().__init__('target.invalid', '', [], None)
            self.scope = Scope()
        def from_crtsh(self):
            return {'oob.invalid?fake=.target.invalid', 'excluded.target.invalid', 'GOOD.target.invalid.', 'BÜCHER.target.invalid', 'nottarget.invalid'}
        def from_js_files(self): return set()
        def from_local_urls(self): return set()
        def from_mutations(self, subs): return set()
    real_client = httpx.AsyncClient
    def factory(**kwargs):
        return real_client(transport=httpx.MockTransport(lambda r: calls.append(str(r.url)) or httpx.Response(200)), **kwargs)
    with patch.object(agent, 'SubdomainCollector', Collector), patch.object(agent, 'RECON_BASE', tmp_path), patch.object(agent, '_which', return_value=None), patch.object(agent, 'record_recon_artifacts', None), patch.object(httpx, 'AsyncClient', side_effect=factory), patch.object(agent.socket, 'getaddrinfo', side_effect=OSError('no DNS')):
        agent.run('target.invalid', 'test', ['crtsh'], None, 2, False, False, True)
    assert set(calls) == {'https://good.target.invalid', 'https://xn--bcher-kva.target.invalid'}


def test_scope_error_aborts_probe_before_dispatch():
    calls = []
    def denied(url): raise OSError('scope unavailable')
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200)), event_hooks={'response': [agent._capture_probe_response]}) as client:
            with pytest.raises(OSError, match='scope unavailable'):
                await agent.probe_subdomain('ok.target.invalid', asyncio.Semaphore(1), client, scope_check=denied)
    asyncio.run(exercise())
    assert not calls


@pytest.mark.parametrize('probe_status,skip_probe,skip_takeover,expected', [
    (404, False, False, ('complete', 1, 0, 0, 0)),
    (200, False, False, ('no-eligible', 0, 0, 1, 0)),
    (302, False, False, ('partial', 0, 1, 0, 0)),
    (0, False, False, ('partial', 0, 0, 0, 1)),
    (404, True, False, ('partial', 0, 0, 1, 0)),
    (404, False, True, ('skipped', 0, 0, 1, 0)),
])
def test_run_coverage_categories(tmp_path, probe_status, skip_probe, skip_takeover, expected):
    class Collector:
        def __init__(self, *a): pass
        def from_crtsh(self): return {'n.target.invalid'}
        def from_js_files(self): return set()
        def from_local_urls(self): return set()
        def from_mutations(self, subs): return set()
    async def probe(subs, threads):
        return [agent.ProbeResult(s, 'https://' + s, probe_status, '', 0, '', '', 'httpx') for s in subs]
    real_client = httpx.AsyncClient
    def factory(**kwargs):
        return real_client(transport=httpx.MockTransport(lambda r: httpx.Response(404, text='not a fingerprint')), **kwargs)
    with patch.object(agent, 'SubdomainCollector', Collector), patch.object(agent, 'probe_all', probe), patch.object(agent, 'RECON_BASE', tmp_path), patch.object(agent, '_which', return_value=None), patch.object(agent, 'record_recon_artifacts', None), patch.object(httpx, 'AsyncClient', side_effect=factory):
        agent.run('target.invalid', 'test', ['crtsh'], None, 2, False, skip_probe, skip_takeover)
    c = json.loads((tmp_path / 'test/ghost/subdomain/summary.json').read_text())['takeover_coverage']
    assert tuple(c[k] for k in ('status', 'checked_count', 'deferred_count', 'skipped_count', 'failed_count')) == expected


def test_cli_preserves_invalid_input_for_validation(tmp_path):
    import os
    import subprocess
    import sys
    result = subprocess.run([sys.executable, '-m', 'agents.subdomain_agent', '--target', ' target.invalid\t', '--program', 'test', '--use-apis', '', '--skip-probe', '--skip-takeover'], env=dict(os.environ, HOME=str(tmp_path)), capture_output=True, text=True)
    assert result.returncode != 0
    assert 'invalid hostname' in result.stderr


def test_empty_run_has_no_eligible_coverage(tmp_path):
    class Collector:
        def __init__(self, *a): pass
        def from_js_files(self): return set()
        def from_local_urls(self): return set()
        def from_mutations(self, subs): return set()
    with patch.object(agent, 'SubdomainCollector', Collector), patch.object(agent, 'RECON_BASE', tmp_path), patch.object(agent, '_which', return_value=None), patch.object(agent, 'record_recon_artifacts', None):
        agent.run('target.invalid', 'test', [], None, 2, False, False, False)
    coverage = json.loads((tmp_path / 'test/ghost/subdomain/summary.json').read_text())['takeover_coverage']
    assert coverage['status'] == 'no-eligible'
    assert all(coverage[key] == 0 for key in ('checked_count', 'deferred_count', 'skipped_count', 'failed_count'))


def test_scope_exclusion_blocks_http_fallback():
    calls = []
    async def exercise():
        def transport(request):
            calls.append(str(request.url))
            raise httpx.ConnectError('synthetic', request=request)
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport), event_hooks={'response': [agent._capture_probe_response]}) as client:
            result = await agent.probe_subdomain('ok.target.invalid', asyncio.Semaphore(1), client, scope_check=lambda url: url.startswith('https:'))
            assert result.status == 0
    asyncio.run(exercise())
    assert calls == ['https://ok.target.invalid']


def test_real_scope_exclusion_without_allow_entries(tmp_path):
    scope_dir = tmp_path / 'test'
    scope_dir.mkdir()
    (scope_dir / 'excluded.txt').write_text('*.blocked.target.invalid\n')
    collector = agent.SubdomainCollector('target.invalid', '', [], None)
    collector.scope = agent.ScopeValidator('test', scopes_base=tmp_path)
    assert not collector.is_in_scope('https://one.blocked.target.invalid')
    assert collector.is_in_scope('https://good.target.invalid')


def test_wayback_uses_actual_url_host_not_regex_prefix():
    collector = agent.SubdomainCollector('target.invalid', '', [], None)
    collector.limiter = None
    class Response:
        status_code = 200
        def json(self):
            return [['original'], ['https://good.target.invalid.oob.invalid/path'], ['https://ok.target.invalid/path'], ['https://oob.invalid/?x=.target.invalid']]
    with patch.object(collector.session, 'get', return_value=Response()):
        assert collector.from_wayback() == {'ok.target.invalid'}


def test_takeover_rejects_mismatched_url_without_dispatch():
    calls, failed = [], set()
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200))) as client:
            result = agent.ProbeResult('n.target.invalid', 'https://oob.invalid/?fake=.target.invalid', 404, '', 0, '', '', 'httpx')
            assert await agent.check_takeover_async(result, asyncio.Semaphore(1), client, set(), failed) is None
    asyncio.run(exercise())
    assert not calls
    assert failed == {'n.target.invalid'}


def test_recheck_unexpected_server_error_is_failure():
    failed = set()
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500))) as client:
            result = agent.ProbeResult('n.target.invalid', 'https://n.target.invalid', 404, '', 0, '', '', 'httpx')
            assert await agent.check_takeover_async(result, asyncio.Semaphore(1), client, set(), failed) is None
    asyncio.run(exercise())
    assert failed == {'n.target.invalid'}
