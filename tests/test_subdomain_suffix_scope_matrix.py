"""PC-20261030-002207-67d5e107: suffix-spoofed values never reach transport.

Synthetic and offline. A value is accepted only when its parsed destination
host is the scope root or a proper subdomain; query, fragment, path,
userinfo, port, backslash and look-alike suffixes are rejected before any
request. Fixed by e603ed17 (merged to beta in cdc6d82e); these cases pin it.
"""
import asyncio
from unittest.mock import patch

import httpx
import pytest
from agents import subdomain_agent as agent

ROOT = 'target.invalid'
SPOOFS = [
    'https://evil.invalid/?x=.target.invalid',
    'evil.invalid?x=.target.invalid',
    'evil.invalid#.target.invalid',
    'https://evil.invalid/#.target.invalid',
    'evil.invalid/.target.invalid',
    'x.target.invalid@evil.invalid',
    'https://x.target.invalid@evil.invalid/',
    'evil.invalid:443#.target.invalid',
    'x.target.invalid:8443',
    'eviltarget.invalid',
    'EVILTARGET.INVALID.',
    'x.target.invalid.evil.invalid',
    '*.evil.invalid',
    '*.eviltarget.invalid',
    'evil.invalid\\.target.invalid',
    'evil.invalid%2f.target.invalid',
    'evil.invalid .target.invalid',
]
# Valid hostnames that are simply unrelated: rejected by the target check,
# not by hostname syntax.
UNRELATED_HOSTNAMES = {'eviltarget.invalid', 'EVILTARGET.INVALID.', 'x.target.invalid.evil.invalid'}
GOOD = ['A.Target.INVALID.', '*.api.target.invalid', 'bücher.target.invalid']
OUT_HOSTS = ('evil.invalid', 'eviltarget.invalid')


def _payloads(values):
    return {
        'from_crtsh': [{'name_value': '\n'.join(values)}],
        'from_otx': {'passive_dns': [{'hostname': v} for v in values]},
        'from_bufferover': {'FDNS_A': ['192.0.2.1,' + v for v in values]},
        'from_urlscan': {'results': [{'page': {'domain': v}, 'task': {'url': v}} for v in values]},
        'from_rdap': {'nameservers': [{'ldhName': v} for v in values]},
        'from_whoxy': {'search_result': [{'domain_name': v} for v in values]},
        'from_wayback': [['original']] + [[v] for v in values],
    }


def _in_root(host):
    return host == ROOT or host.endswith('.' + ROOT)


@pytest.mark.parametrize('method', sorted(_payloads([])))
def test_provider_keeps_only_parsed_hosts_under_root(method, monkeypatch):
    monkeypatch.setenv('WHOXY_API_KEY', 'synthetic')
    collector = agent.SubdomainCollector(ROOT, '', [], None)
    collector.limiter = None
    payload = _payloads(SPOOFS + GOOD)[method]

    class Response:
        status_code = 200
        def json(self):
            return payload
    with patch.object(collector.session, 'get', return_value=Response()):
        got = getattr(collector, method)()
    assert all(_in_root(h) for h in got), got
    assert not any(h == o or h.endswith('.' + o) for h in got for o in OUT_HOSTS), got
    if method in ('from_crtsh', 'from_otx'):
        assert got == {'a.target.invalid', 'api.target.invalid', 'xn--bcher-kva.target.invalid'}


@pytest.mark.parametrize('value', SPOOFS)
def test_target_check_rejects_spoof(value):
    assert not agent.is_target_host(value, ROOT)


@pytest.mark.parametrize('value', [v for v in SPOOFS if v not in UNRELATED_HOSTNAMES])
def test_probe_rejects_non_hostname_before_transport(value):
    calls = []

    async def exercise():
        async with httpx.AsyncClient(
                transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200)),
                event_hooks={'response': [agent._capture_probe_response]}) as client:
            with pytest.raises(ValueError):
                await agent.probe_subdomain(value, asyncio.Semaphore(1), client)
    asyncio.run(exercise())
    assert not calls


def test_js_fetch_requests_only_parsed_in_root_urls(tmp_path):
    js_list = tmp_path / 'test' / 'ghost' / 'recon' / 'js_files.txt'
    js_list.parent.mkdir(parents=True)
    js_list.write_text('\n'.join([
        'https://evil.invalid\\.target.invalid/app.js',
        'https://evil.invalid/?x=.target.invalid',
        'https://x.target.invalid@evil.invalid/app.js',
        'https://eviltarget.invalid/app.js',
        'https://cdn.target.invalid/app.js',
    ]) + '\n')
    collector = agent.SubdomainCollector(ROOT, '', [], None)
    collector.program = 'test'

    class Response:
        text = 'see api.target.invalid'
    with patch.object(agent, 'RECON_BASE', tmp_path), \
            patch.object(collector.session, 'get', return_value=Response()) as get:
        assert collector.from_js_files() == {'api.target.invalid'}
    assert [c.args[0] for c in get.call_args_list] == ['https://cdn.target.invalid/app.js']


@pytest.mark.parametrize('use_scope', [True, False], ids=['wildcard-scope', 'no-scope'])
def test_run_never_requests_out_of_scope_authority(tmp_path, use_scope):
    scopes = tmp_path / 'scopes' / 'test'
    scopes.mkdir(parents=True)
    (scopes / 'in-scope.txt').write_text('*.target.invalid\n')
    (scopes / 'out-of-scope.txt').write_text('# none\n')
    with patch.object(agent.ScopeValidator, 'LEGACY_RECON_BASE', tmp_path / 'legacy'):
        scope = agent.ScopeValidator('test', scopes_base=tmp_path / 'scopes')
    assert scope.is_in_scope('https://a.target.invalid')
    assert not scope.is_in_scope('https://eviltarget.invalid')

    class Collector(agent.SubdomainCollector):
        def __init__(self, *a):
            super().__init__(ROOT, '', [], None)
            self.scope = scope if use_scope else None
        def from_crtsh(self):
            return set(SPOOFS) | set(GOOD)
        def from_js_files(self): return set()
        def from_local_urls(self): return set()
        def from_mutations(self, subs): return set()

    hosts = []
    real_client = httpx.AsyncClient

    def factory(**kwargs):
        return real_client(transport=httpx.MockTransport(
            lambda r: hosts.append(r.url.raw_host.decode('ascii')) or httpx.Response(200)), **kwargs)
    with patch.object(agent, 'SubdomainCollector', Collector), \
            patch.object(agent, 'RECON_BASE', tmp_path), \
            patch.object(agent, '_which', return_value=None), \
            patch.object(agent, 'record_recon_artifacts', None), \
            patch.object(httpx, 'AsyncClient', side_effect=factory), \
            patch.object(agent.socket, 'getaddrinfo', side_effect=OSError('no DNS')):
        agent.run(ROOT, 'test', ['crtsh'], None, 2, False, False, True)
    expected = {'a.target.invalid', 'xn--bcher-kva.target.invalid'}
    assert set(hosts) == expected
    assert set((tmp_path / 'test/ghost/subdomain/all_subs.txt').read_text().split()) == expected
