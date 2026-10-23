"""Offline regression and bounded historical source-map recovery contracts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch
from email.message import Message
import io
import ssl
import urllib.error
import urllib.parse


import pytest

from agents import js_analyzer as J

BUNDLE = 'https://app.example.com/static/app.js'
STAMP = '20240102030405'
MAP = json.dumps({'version': 3, 'sources': ['src/main.ts'], 'sourcesContent': ['export const x = 1;']}).encode()


class Response:
    def __init__(self, body, status=200, headers=None):
        self.body = io.BytesIO(body)
        self.status = status
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def read(self, size=-1):
        return self.body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def inventory(tmp_path, *extra, run='out', urls=None):
    source = tmp_path / 'urls.txt'
    source.write_text('\n'.join(urls or [BUNDLE]) + '\n')
    assert J.main(['inventory', 'demo', '--input', str(source), '--target-host', 'example.com',
                   '--output-root', str(tmp_path / run), '--run-id', run,
                   '--library-root', str(tmp_path / 'lib'),
                   '--integration-index-root', str(tmp_path / 'integrations'), *extra]) == 0
    return (J.read_jsonl(tmp_path / run / 'metadata.jsonl'),
            json.loads((tmp_path / run / 'manifest.json').read_text()))


@pytest.mark.parametrize(('headers', 'expected', 'origin'), [
    ({'SourceMap': '../maps/header.map', 'X-SourceMap': 'legacy.map'}, 'https://app.example.com/maps/header.map', 'SourceMap'),
    ({'x-sourcemap': 'legacy.map'}, BUNDLE.rsplit('/', 1)[0] + '/legacy.map', 'X-SourceMap'),
])
def test_response_header_precedes_comment_and_survives_cache(tmp_path, headers, expected, origin):
    def open_response(request, timeout):
        assert request.full_url == BUNDLE
        return Response(b'//# sourceMappingURL=comment.map\n', headers=headers)

    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response), \
         patch.object(J, 'http_get_limited', return_value=(MAP, 200, 'application/json', False)) as fetch:
        first, _ = inventory(tmp_path)
        second, _ = inventory(tmp_path, run='again')
    assert first[0]['source_map'] == expected
    assert second[0]['source_map'] == expected
    assert second[0]['source_map_discovery'] == origin
    assert second[0]['source_map_status'] == 'cached'
    assert fetch.call_count == 1
    assert fetch.call_args.args[0] == expected


@pytest.mark.parametrize('header', ['https://outside.invalid/map', 'data:application/json,{}'])
def test_header_cannot_fall_back_to_comment_when_not_fetchable(tmp_path, header):
    with patch.object(J.urllib.request.OpenerDirector, 'open', return_value=Response(
            b'//# sourceMappingURL=comment.map', headers={'SourceMap': header})), \
         patch.object(J, 'http_get_limited') as fetch:
        rows, _ = inventory(tmp_path)
    fetch.assert_not_called()
    assert rows[0]['source_map_discovery'] == 'SourceMap'


@pytest.mark.parametrize(('failure', 'reason', 'status'), [
    (404, 'http_404', 404), (429, 'http_429', 429), (302, 'http_302', 302),
    (ssl.SSLCertVerificationError('secret'), 'tls', None),
    (TimeoutError('secret'), 'timeout', None),
    (urllib.error.URLError('secret'), 'transport', None),
    (b'not json', 'invalid', 200), (b'x' * 101, 'oversize', 200),
])
def test_map_fetch_diagnostics_are_actionable_and_redacted(tmp_path, capsys, failure, reason, status):
    def open_response(request, timeout):
        if request.full_url == BUNDLE:
            return Response(b'//# sourceMappingURL=app.js.map')
        if isinstance(failure, int):
            raise urllib.error.HTTPError(request.full_url, failure, 'secret', Message(), io.BytesIO(b'secret'))
        if isinstance(failure, Exception):
            raise failure
        return Response(failure)

    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, _ = inventory(tmp_path, '--source-map-max-bytes', '100')
    assert rows[0]['source_map_reason'] == reason
    assert rows[0]['source_map_http_status'] == status
    assert 'secret' not in capsys.readouterr().err


@pytest.mark.parametrize('transport', [ssl.SSLError('secret'), TimeoutError('secret')])
def test_wrapped_transport_failure_category(transport):
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=urllib.error.URLError(transport)):
        result = J.http_get_limited(BUNDLE + '.map', timeout=1, max_bytes=100)
    assert result[:2] == (b'', None)
    assert result.reason == ('tls' if isinstance(transport, ssl.SSLError) else 'timeout')


def cdx(original, *stamps):
    return json.dumps([['timestamp', 'original', 'statuscode', 'digest'],
                       *[[stamp, original, '200', 'A' * 32] for stamp in stamps]]).encode()


def replay(original, stamp=STAMP):
    return f'https://web.archive.org/web/{stamp}id_/{original}'


def test_archived_bundle_declaration_resolves_original_relative_and_renders_history(tmp_path):
    old = b'const old = true;\n//# sourceMappingURL=../maps/old.map\n'
    map_url = 'https://app.example.com/maps/old.map'
    calls = []

    def open_response(request, timeout):
        url = request.full_url
        calls.append(url)
        if url == BUNDLE:
            return Response(b'const current = true;')
        if url.startswith('https://web.archive.org/cdx/search/cdx?'):
            original = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['url'][0]
            return Response(cdx(original, STAMP))
        if url == replay(BUNDLE):
            return Response(old)
        if url == replay(map_url):
            return Response(MAP)
        raise AssertionError(f'unexpected request: {url}')

    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, manifest = inventory(tmp_path, '--source-map-wayback', 'auto')
    history = rows[0]['source_map_history']
    assert rows[0]['source_map_status'] == 'not_detected'
    assert history['status'] == 'recovered'
    assert history['original_map_url'] == map_url
    assert history['map_archive_timestamp'] == STAMP
    assert history['map_retrieval_url'] == replay(map_url)
    assert history['map_sha256'] == hashlib.sha256(MAP).hexdigest()
    assert history['archived_bundle_sha256'] == hashlib.sha256(old).hexdigest()
    assert history['current_bundle_sha256'] == rows[0]['sha256']
    assert history['current_bundle_match_verified'] is False
    modules = J.read_jsonl(tmp_path / 'out' / 'source_map_modules.jsonl')
    assert modules[0]['historical'] is True
    assert modules[0]['source_map_history']['map_retrieval_url'] == replay(map_url)
    packet = Path(modules[0]['packet_paths'][0]).read_text()
    assert 'HISTORICAL' in packet and 'not verified' in packet
    assert replay(map_url) in packet
    ledger = json.loads((tmp_path / 'lib' / 'ledger.json').read_text())
    assert not ledger.get('source_maps')
    assert manifest['historical_source_maps_recovered'] == 1
    assert manifest['source_maps_downloaded'] == 0
    assert len(calls) == 5


@pytest.mark.parametrize('with_content', [True, False])
def test_exact_missing_map_recovery_is_unverified_historical_and_cached(tmp_path, with_content):
    map_url = BUNDLE + '.map'
    document = {'version': 3, 'sources': ['src/main.ts']}
    if with_content:
        document['sourcesContent'] = ['export const historical = true;']
    map_body = json.dumps(document).encode()
    archive_calls = []

    def open_response(request, timeout):
        url = request.full_url
        if url == BUNDLE:
            return Response(b'//# sourceMappingURL=app.js.map')
        if url == map_url:
            raise urllib.error.HTTPError(url, 404, '', Message(), io.BytesIO())
        archive_calls.append(url)
        headers = {k.lower(): v for k, v in request.header_items()}
        assert set(headers) <= {'user-agent', 'accept'}
        if url.startswith('https://web.archive.org/cdx/search/cdx?'):
            params = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            assert params == {'url': [map_url], 'matchType': ['exact'], 'output': ['json'],
                              'fl': ['timestamp,original,statuscode,digest'], 'filter': ['statuscode:200'], 'limit': ['2']}
            return Response(cdx(map_url, STAMP))
        assert url == replay(map_url)
        return Response(map_body)

    options = ['--source-map-wayback', 'auto', '--header', 'Cookie: session=private',
               '--header', 'Authorization: Bearer private', '--header', 'Host: app.example.com',
               '--header', 'X-Researcher: private']
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        first, _ = inventory(tmp_path, *options)
        rows, manifest = inventory(tmp_path, *options, run='again')
    assert len(archive_calls) == 2
    assert first[0]['source_map_status'] == 'fetch_failed'
    history = rows[0]['source_map_history']
    assert history['status'] == 'cached'
    assert history['archived_bundle_sha256'] == ''
    assert history['current_bundle_match_verified'] is False
    assert history['embedded_source_recovered'] is with_content
    assert manifest['source_map_wayback']['requests'] == 0
    assert manifest['historical_source_maps_reused'] == 1
    modules = J.read_jsonl(tmp_path / 'again' / 'source_map_modules.jsonl')
    assert modules[0]['source'] == 'src/main.ts'
    assert bool(modules[0]['packet_paths']) is with_content
    assert not json.loads((tmp_path / 'lib' / 'ledger.json').read_text()).get('source_maps')


def test_exact_archived_bundle_hash_verifies_only_bundle_bytes(tmp_path):
    body = b'const x=1;\n//# sourceMappingURL=app.js.map'
    map_url = BUNDLE + '.map'

    def open_response(request, timeout):
        url = request.full_url
        if url == BUNDLE:
            # Invalid authoritative header suppresses the live comment declaration.
            return Response(body, headers={'SourceMap': 'data:invalid'})
        if '/cdx/' in url:
            original = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['url'][0]
            return Response(cdx(original, STAMP))
        return Response(body if url == replay(BUNDLE) else MAP)

    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, _ = inventory(tmp_path, '--source-map-wayback', 'auto')
    history = rows[0]['source_map_history']
    assert history['original_map_url'] == map_url
    assert history['current_bundle_match_verified'] is True
    assert history['archived_bundle_sha256'] == rows[0]['sha256']
    assert Path(history['bundle_artifact_path']).read_bytes() == body
    module = J.read_jsonl(tmp_path / 'out' / 'source_map_modules.jsonl')[0]
    packet = Path(module['packet_paths'][0]).read_text()
    assert 'SHA256 verified' in packet
    assert 'not a verified build binding' in packet


@pytest.mark.parametrize('body', [
    'const t=`outer ${`inner\n//# sourceMappingURL=fake.map\n`} tail`;',
    'const t=`outer ${ {key: `inner /*# sourceMappingURL=fake.map */`} } tail`;',
])
def test_nested_template_decoys_do_not_become_comments(body):
    assert J.last_source_map_directive('//# sourceMappingURL=real.map\n' + body) == 'real.map'


def test_unavailable_live_bundle_can_recover_historical_declaration(tmp_path):
    old = b'//# sourceMappingURL=app.js.map'
    def open_response(request, timeout):
        url = request.full_url
        if url == BUNDLE:
            raise urllib.error.URLError(TimeoutError('private'))
        if '/cdx/' in url:
            original = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['url'][0]
            return Response(cdx(original, STAMP))
        return Response(old if url == replay(BUNDLE) else MAP)

    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, _ = inventory(tmp_path, '--source-map-wayback', 'auto')
    assert len(rows) == 1
    assert rows[0]['source_map_history']['status'] == 'recovered'
    assert rows[0]['source_map_history']['current_bundle_match_verified'] is False
    assert rows[0]['source_map_history']['current_bundle_sha256'] == ''
    assert not json.loads((tmp_path / 'lib' / 'ledger.json').read_text()).get('urls', {}).get(BUNDLE)


@pytest.mark.parametrize('extra', [[], ['--source-map-wayback', 'off'],
                                  ['--source-map-wayback', 'auto', '--source-maps', 'off']])
def test_archive_is_never_contacted_without_both_opt_ins(tmp_path, extra):
    calls = []
    def open_response(request, timeout):
        calls.append(request.full_url)
        assert request.full_url == BUNDLE
        return Response(b'const x = true;')
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, manifest = inventory(tmp_path, *extra)
    assert calls == [BUNDLE]
    assert rows[0]['source_map_history']['status'] == 'disabled'
    assert manifest['source_map_wayback']['requests'] == 0


@pytest.mark.parametrize(('index', 'reason'), [
    (404, 'http_404'), (429, 'http_429'), (503, 'http_503'), (302, 'http_302'),
    (ssl.SSLError('private'), 'tls'), (TimeoutError('private'), 'timeout'),
    (urllib.error.URLError('private'), 'transport'), (b'bad json', 'invalid_index'),
    (b'x' * 2048, 'oversize'), (cdx(BUNDLE), 'empty_index'), (b'[]', 'empty_index'),
])
def test_archive_index_failures_remain_distinct(tmp_path, index, reason):
    archive_calls = []
    def open_response(request, timeout):
        if request.full_url == BUNDLE:
            return Response(b'const x=true;')
        archive_calls.append(request.full_url)
        assert '/cdx/search/cdx?' in request.full_url
        if isinstance(index, int):
            raise urllib.error.HTTPError(request.full_url, index, 'private', Message(), io.BytesIO(b'private'))
        if isinstance(index, Exception):
            raise index
        return Response(index)
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, manifest = inventory(tmp_path, '--source-map-wayback', 'auto', '--source-map-wayback-max-bytes', '1024')
    assert len(archive_calls) == 1
    assert rows[0]['source_map_history']['reason'] == reason
    assert rows[0]['source_map_history']['status'] == 'not_recovered'
    assert manifest['historical_source_maps_recovered'] == 0


@pytest.mark.parametrize('row', [
    [STAMP, 'https://outside.invalid/steal', '200', 'A' * 32],
    [STAMP, BUNDLE + '?other=1', '200', 'A' * 32],
    ['20249999000000', BUNDLE, '200', 'A' * 32],
    ['2024/../../host', BUNDLE, '200', 'A' * 32],
    [STAMP, BUNDLE, '302', 'A' * 32],
    [STAMP, BUNDLE, '200', 'not-a-digest'],
])
def test_hostile_cdx_rows_cannot_supply_a_fetch_url(tmp_path, row):
    payload = json.dumps([['timestamp', 'original', 'statuscode', 'digest'], row]).encode()
    calls = []
    def open_response(request, timeout):
        calls.append(request.full_url)
        if request.full_url == BUNDLE:
            return Response(b'const x=1;')
        assert '/cdx/' in request.full_url
        return Response(payload)
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, _ = inventory(tmp_path, '--source-map-wayback', 'auto')
    assert len(calls) == 2
    assert rows[0]['source_map_history']['reason'] == 'invalid_index'


def test_archive_429_halts_all_later_assets(tmp_path):
    urls = [BUNDLE, 'https://app.example.com/static/next.js']
    calls = []
    def open_response(request, timeout):
        if request.full_url in urls:
            return Response(b'const x=1;')
        calls.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 429, '', Message(), io.BytesIO())
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, manifest = inventory(tmp_path, '--source-map-wayback', 'auto', urls=urls)
    assert len(calls) == 1
    assert [r['source_map_history']['reason'] for r in rows] == ['http_429', 'http_429']
    assert manifest['source_map_wayback']['stopped_reason'] == 'http_429'


@pytest.mark.parametrize('options', [
    ['--source-map-wayback-max-requests', '1'],
    ['--source-map-wayback-max-total-bytes', '16'],
    ['--source-map-wayback-max-captures', '1'],
])
def test_archive_run_budgets_are_enforced(tmp_path, options):
    calls = []
    def open_response(request, timeout):
        if request.full_url == BUNDLE:
            return Response(b'const x=1;')
        calls.append(request.full_url)
        assert '/cdx/' in request.full_url or len(calls) > 1
        return Response(cdx(BUNDLE, STAMP, '20230102030405'))
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, manifest = inventory(tmp_path, '--source-map-wayback', 'auto', *options)
    assert manifest['historical_source_maps_recovered'] == 0
    summary = manifest['source_map_wayback']
    assert summary['requests'] <= summary['max_requests']
    assert summary['bytes_read'] <= summary['max_total_bytes']
    if options[0] == '--source-map-wayback-max-captures':
        assert len(calls) == 1  # Server ignored limit: reject entire response.
        assert rows[0]['source_map_history']['reason'] == 'invalid_index'


@pytest.mark.parametrize('original', ['https://outside.invalid/a.js', BUNDLE + '#inline-script-1',
                                     'https://user:private@app.example.com/app.js',
                                     'https://:private@app.example.com/app.js',
                                     'https://@app.example.com/app.js', BUNDLE + '?q=*'])
def test_archive_original_scope_is_checked_before_query(tmp_path, original):
    args = J.build_parser().parse_args(['inventory', 'demo', '--source-map-wayback', 'auto'])
    recovery = J.WaybackRecovery(args, ['example.com'], {}, tmp_path)
    with patch.object(J, 'http_get_limited', return_value=(b'[]', 200, 'application/json', False)) as fetch:
        assert recovery.captures(original, []) == []
    fetch.assert_not_called()


@pytest.mark.parametrize(('failure', 'reason'), [
    (404, 'http_404'), (429, 'http_429'), (302, 'http_302'),
    (ssl.SSLError('private'), 'tls'), (TimeoutError('private'), 'timeout'),
    (b'bad map', 'invalid'), (b'x' * 2048, 'oversize'),
])
def test_archived_map_failure_is_not_silently_an_empty_index(tmp_path, failure, reason):
    map_url = BUNDLE + '.map'
    def open_response(request, timeout):
        url = request.full_url
        if url == BUNDLE:
            return Response(b'//# sourceMappingURL=app.js.map')
        if url == map_url:
            raise urllib.error.HTTPError(url, 404, '', Message(), io.BytesIO())
        if '/cdx/' in url:
            original = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['url'][0]
            return Response(cdx(original, STAMP) if original == map_url else cdx(original))
        assert url == replay(map_url)
        if isinstance(failure, int):
            raise urllib.error.HTTPError(url, failure, '', Message(), io.BytesIO())
        if isinstance(failure, Exception):
            raise failure
        return Response(failure)
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, _ = inventory(tmp_path, '--source-map-wayback', 'auto', '--source-map-wayback-max-bytes', '1024')
    history = rows[0]['source_map_history']
    assert any(a['operation'] == 'map' and a['reason'] == reason for a in history['attempts'])
    assert history['status'] == 'not_recovered'
    assert not json.loads((tmp_path / 'lib' / 'ledger.json').read_text()).get('source_maps')


def test_historical_packet_and_expansion_budgets_and_lowered_cache_cap(tmp_path):
    map_url = BUNDLE + '.map'
    def open_response(request, timeout):
        url = request.full_url
        if url == BUNDLE:
            return Response(b'//# sourceMappingURL=app.js.map')
        if url == map_url:
            raise urllib.error.HTTPError(url, 404, '', Message(), io.BytesIO())
        if '/cdx/' in url:
            return Response(cdx(map_url, STAMP))
        return Response(MAP)
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        _, first = inventory(tmp_path, '--source-map-wayback', 'auto', '--source-map-max-packets', '0')
        modules = J.read_jsonl(tmp_path / 'out' / 'source_map_modules.jsonl')
        assert modules[0]['packet_status'] == 'truncated_by_budget'
        assert first['historical_source_map_packets'] == 0
        _, second = inventory(tmp_path, '--source-map-wayback', 'auto', run='second')
        assert second['historical_source_map_packets'] == 1
        rows, third = inventory(tmp_path, '--source-map-wayback', 'auto', '--source-map-max-bytes', '10', run='third')
    assert third['historical_source_map_packets'] == 0
    assert rows[0]['source_map_history']['reason'] == 'oversize'
    assert rows[0]['source_map_history']['embedded_source_recovered'] is False
    assert J.read_jsonl(tmp_path / 'third' / 'source_map_modules.jsonl') == []


def test_archive_transport_keeps_environment_proxy_tls_and_no_redirects(tmp_path):
    real_build = J.urllib.request.build_opener
    openers = []
    def build(*handlers):
        opener = real_build(*handlers)
        openers.append(opener)
        return opener
    proxy = 'http://proxy.invalid:8888'
    with patch.object(J.urllib.request, 'getproxies', return_value={'http': proxy, 'https': proxy}), \
         patch.object(J.urllib.request, 'build_opener', side_effect=build), \
         patch.object(J.urllib.request.OpenerDirector, 'open', return_value=Response(b'{}')):
        J.http_get_limited(replay(BUNDLE), timeout=7, max_bytes=100, include_program_headers=False)
    handlers = openers[0].handlers
    assert any(isinstance(h, J.urllib.request.ProxyHandler) and h.proxies['https'] == proxy for h in handlers)
    assert any(isinstance(h, J.NoRedirectHandler) for h in handlers)
    tls = next(h for h in handlers if isinstance(h, J.urllib.request.HTTPSHandler))
    assert tls._context is None  # urllib's verified default, not a custom insecure SSL context.


def test_failed_archived_map_transport_is_not_retried_for_another_bundle_capture(tmp_path):
    map_url = BUNDLE + '.map'
    map_calls = []
    def open_response(request, timeout):
        url = request.full_url
        if url == BUNDLE:
            return Response(b'const current=true;')
        if '/cdx/' in url:
            original = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['url'][0]
            return Response(cdx(original, STAMP, '20230102030405') if original == BUNDLE else cdx(original, STAMP))
        if url.startswith('https://web.archive.org/web/') and url.endswith(BUNDLE):
            return Response(b'//# sourceMappingURL=app.js.map')
        assert url == replay(map_url)
        map_calls.append(url)
        raise ssl.SSLError('private')
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, _ = inventory(tmp_path, '--source-map-wayback', 'auto')
    assert len(map_calls) == 1
    assert rows[0]['source_map_history']['reason'] == 'tls'


def test_incomplete_map_response_is_safe_transport_diagnostic(tmp_path):
    import http.client
    def open_response(request, timeout):
        if request.full_url == BUNDLE:
            return Response(b'//# sourceMappingURL=app.js.map')
        raise http.client.IncompleteRead(b'private', 100)
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        rows, _ = inventory(tmp_path)
    assert rows[0]['source_map_reason'] == 'transport'
    assert rows[0]['source_map_status'] == 'fetch_failed'


def test_archive_honors_timeout_delay_and_expanded_source_cap(tmp_path):
    map_url = BUNDLE + '.map'
    calls = []
    def open_response(request, timeout):
        assert timeout == 7
        calls.append(request.full_url)
        if request.full_url == BUNDLE:
            return Response(b'//# sourceMappingURL=app.js.map')
        if request.full_url == map_url:
            raise urllib.error.HTTPError(map_url, 404, '', Message(), io.BytesIO())
        if '/cdx/' in request.full_url:
            return Response(cdx(map_url, STAMP))
        return Response(MAP)
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response), \
         patch.object(J.time, 'sleep') as sleep:
        rows, manifest = inventory(tmp_path, '--source-map-wayback', 'auto', '--timeout', '7', '--delay', '0.25',
                                   '--source-map-max-expanded-bytes', '1')
    assert sleep.call_count == len(calls) == 4
    assert all(call.args == (0.25,) for call in sleep.call_args_list)
    assert rows[0]['source_map_history']['status'] == 'recovered'
    assert manifest['historical_source_map_packets'] == 0
    modules = J.read_jsonl(tmp_path / 'out' / 'source_map_modules.jsonl')
    assert modules[0]['packet_status'] == 'truncated_by_budget'


@pytest.mark.parametrize('mode', ['off', 'live_success'])
def test_historical_cache_never_enables_traffic_or_overrides_live_map(tmp_path, mode):
    map_url = BUNDLE + '.map'
    live_map = json.dumps({'version': 3, 'sources': ['live.ts']}).encode()
    archive_calls = []
    def open_response(request, timeout):
        url = request.full_url
        if url == BUNDLE:
            return Response(b'//# sourceMappingURL=app.js.map')
        if url == map_url:
            if mode == 'live_success' and (tmp_path / 'out' / 'manifest.json').exists():
                return Response(live_map)
            raise urllib.error.HTTPError(url, 404, '', Message(), io.BytesIO())
        archive_calls.append(url)
        return Response(cdx(map_url, STAMP) if '/cdx/' in url else MAP)
    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=open_response):
        inventory(tmp_path, '--source-map-wayback', 'auto')
        rows, manifest = inventory(tmp_path, *(['--source-map-wayback', 'auto'] if mode == 'live_success' else []), run='again')
    assert len(archive_calls) == 2
    assert manifest['source_map_wayback']['requests'] == 0
    assert rows[0]['source_map_history']['status'] == ('not_needed' if mode == 'live_success' else 'disabled')
    if mode == 'live_success':
        assert rows[0]['source_map_sha256'] == hashlib.sha256(live_map).hexdigest()
        assert not J.read_jsonl(tmp_path / 'again' / 'source_map_modules.jsonl')[0]['historical']


@pytest.mark.parametrize('budget', ['packets', 'bytes', 'modules'])
def test_source_module_budget_is_checked_before_chunk_allocation(tmp_path, budget):
    record = J.JsRecord(BUNDLE, 200, 'application/javascript', 1, 'a' * 64, '')
    modules = [{'source_index': 0, 'source': 'large.ts', 'source_root': '', 'source_label': 'large.ts',
                'has_content': True, 'content': 'x' * 10000}]
    with patch.object(J, 'chunk_text', side_effect=AssertionError('over-budget chunks must not be allocated')):
        rows, packets, summary = J.write_source_map_modules(
            root=tmp_path, source_maps_dir=tmp_path / 'maps', record=record,
            source_map_sha256='b' * 64, modules=modules, chunk_size=1, chunk_overlap=0,
            module_limit=0 if budget == 'modules' else 1,
            max_packets=0 if budget == 'packets' else 20000,
            max_expanded_bytes=0 if budget == 'bytes' else 20000)
    assert rows[0]['source'] == 'large.ts'
    assert rows[0]['packet_status'] == 'truncated_by_budget'
    assert not packets and summary['expanded_bytes'] == 0


@pytest.mark.parametrize("prefix", [
    'const s="' + 'a' * 3500 + '";\n',
    "const s='" + 'a' * 3500 + "';\n",
    'const s=`' + 'a\n' * 3500 + '`;\n',
    '/* ' + 'a' * 3500 + ' */\n',
    'const r=/[' + 'a' * 3500 + '//]/;\n',
], ids=['double', 'single', 'template', 'comment', 'regex'])
def test_directive_after_arbitrary_old_tail_boundary(prefix):
    assert J.last_source_map_directive(prefix + '//# sourceMappingURL=real.js.map\n') == 'real.js.map'


@pytest.mark.parametrize("decoy", [
    'const s="' + 'a' * 3500 + '//# sourceMappingURL=fake.map";',
    'const s=`' + 'a\n' * 3500 + '/*# sourceMappingURL=fake.map */`;',
    'const r=/[' + 'a' * 3500 + '//# sourceMappingURL=fake.map]/;',
], ids=['string', 'template', 'regex'])
def test_long_lexical_decoys_do_not_override_comment(decoy):
    assert J.last_source_map_directive('//@ sourceMappingURL=real.map\n' + decoy) == 'real.map'


@pytest.mark.parametrize('failure', ['timeout', 'http_error', 'empty_success'])
def test_unavailable_bundle_has_no_live_artifact_packet_or_success_count(tmp_path, failure):
    import sqlite3

    def response(request, timeout):
        url = request.full_url
        if url == BUNDLE:
            if failure == 'timeout':
                raise urllib.error.URLError(TimeoutError())
            if failure == 'http_error':
                raise urllib.error.HTTPError(url, 403, '', Message(), io.BytesIO(b'not JavaScript'))
            return Response(b'')
        if '/cdx/' in url:
            original = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['url'][0]
            return Response(cdx(original, STAMP))
        return Response(b'//# sourceMappingURL=app.js.map' if url == replay(BUNDLE) else MAP)

    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=response):
        rows, manifest = inventory(tmp_path, '--source-map-wayback', 'auto')
    assert manifest['js_downloaded'] == 0
    assert manifest['js_unavailable'] == 1
    assert manifest['downloads_reused'] == 0
    assert rows[0]['artifact_path'] == rows[0]['sha256'] == ''
    assert rows[0]['byte_count'] == rows[0]['chunk_count'] == 0
    assert not list((tmp_path / 'lib' / 'downloads').glob('*.js'))
    packets = J.read_jsonl(tmp_path / 'out' / 'packets.jsonl')
    assert packets and all(p.get('historical') for p in packets)
    assert rows[0]['source_map_history']['current_bundle_sha256'] == ''
    assert not rows[0]['source_map_history']['current_bundle_match_verified']
    assert all(p['sha256'] == rows[0]['source_map_history']['archived_bundle_sha256'] for p in packets)
    with sqlite3.connect(tmp_path / 'lib' / 'js_info.sqlite') as db:
        assert db.execute('SELECT count(*) FROM js_files').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM js_url_aliases').fetchone()[0] == 0


def test_history_cache_rechecks_current_binding_after_failed_bundle_fetch(tmp_path):
    body = b'const current = true;'

    def response(request, timeout):
        url = request.full_url
        if url == BUNDLE:
            if (tmp_path / 'out' / 'manifest.json').exists():
                raise urllib.error.HTTPError(url, 403, '', Message(), io.BytesIO(body))
            return Response(body)
        if '/cdx/' in url:
            original = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['url'][0]
            return Response(cdx(original, STAMP))
        if url == replay(BUNDLE):
            return Response(body, headers={'SourceMap': 'app.js.map'})
        return Response(MAP)

    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=response):
        first, _ = inventory(tmp_path, '--source-map-wayback', 'auto')
        assert first[0]['source_map_history']['current_bundle_match_verified']
        Path(first[0]['artifact_path']).unlink()
        second, _ = inventory(tmp_path, '--source-map-wayback', 'auto', run='again')
    history = second[0]['source_map_history']
    assert history['current_bundle_sha256'] == ''
    assert history['current_bundle_match_verified'] is False
    packet = Path(J.read_jsonl(tmp_path / 'again' / 'source_map_modules.jsonl')[0]['packet_paths'][0]).read_text()
    assert 'Archived bundle matches current bytes (SHA256 verified).' not in packet
    assert 'not verified' in packet


def test_cached_history_never_trusts_old_current_binding_fields(tmp_path):
    args = J.build_parser().parse_args(['inventory', 'demo', '--source-map-wayback', 'auto'])
    record = J.JsRecord(BUNDLE, 403, 'application/javascript', 5, 'a' * 64, '')
    map_sha = hashlib.sha256(MAP).hexdigest()
    (tmp_path / f'{map_sha}.map').write_bytes(MAP)
    previous = {'original_map_url': BUNDLE + '.map', 'map_sha256': map_sha,
                'current_bundle_sha256': record.sha256, 'archived_bundle_sha256': record.sha256,
                'current_bundle_match_verified': True}
    ledger = {'historical_source_maps': {J.WaybackRecovery.cache_key(record): previous}}
    recovery = J.WaybackRecovery(args, ['example.com'], ledger, tmp_path)
    with patch.object(J, 'http_get_limited') as fetch:
        history, body = recovery.recover(record)
    fetch.assert_not_called()
    assert body == MAP and history['status'] == 'cached'
    assert history['current_bundle_sha256'] == ''
    assert history['current_bundle_match_verified'] is False


@pytest.mark.parametrize('expression', [
    'x++ / y;', 'x-- / y;', '++x / y;', '--x / y;',
    '({x: 1}).x++ / y;', 'x++ /* separator */ / y;',
    'x++ + /[/]/.test("/");',
])
def test_postfix_division_keeps_trailing_map_declaration(expression):
    body = 'let x=4, y=2; ' + expression + '\n' + 'var a=1;\n' * 500
    assert J.last_source_map_directive(body + '//# sourceMappingURL=real.map\n') == 'real.map'


@pytest.mark.parametrize('keyword', [
    'return', 'throw', 'case', 'else', 'delete', 'void', 'typeof', 'yield', 'await',
    'if', 'while', 'for', 'with', 'switch', 'catch', 'do', 'try', 'finally', 'function', 'class',
])
@pytest.mark.parametrize('member', ['.', ' . /* separator */ ', '?.', '?. /* separator */ '])
@pytest.mark.parametrize('call', ['', '()'])
def test_keyword_member_division_keeps_trailing_map_declaration(keyword, member, call):
    prefix = f'let obj={{{keyword}:()=>4}}, y=2; obj{member}{keyword}{call} / y;\n'
    body = prefix + 'var a=1;\n' * 500 + '//# sourceMappingURL=real.map\n'
    assert J.last_source_map_directive(body) == 'real.map'


@pytest.mark.parametrize('keyword', ['return', 'delete', 'if'])
def test_private_keyword_member_division_keeps_trailing_map_declaration(keyword):
    prefix = f'class C {{ #{keyword}=4; f(){{ const y=2; this.#{keyword} / y; }} }}\n'
    body = prefix + 'var a=1;\n' * 500 + '//# sourceMappingURL=real.map\n'
    assert J.last_source_map_directive(body) == 'real.map'


@pytest.mark.parametrize('expression', [
    'const values=[...typeof /[//# sourceMappingURL=fake.map]/];',
    'const values={...void /[//# sourceMappingURL=fake.map]/};',
])
def test_spread_keyword_regex_does_not_create_map_comment(expression):
    assert J.last_source_map_directive('//# sourceMappingURL=real.map\n' + expression) == 'real.map'


@pytest.mark.parametrize('prefix', [
    'if (true) {} /`/.test("x");',
    'while (false) {} /`/.test("x");',
    'function f() {} /`/.test("x");',
    'async function f() {} /`/.test("x");',
    'class C {} /`/.test("x");',
    '{ let n=1; } /`/.test("x");',
    'const n={} / 2;',
    'const n=(function(){}) / 2;',
    'const n=function(){} / 2;',
    'const n=class {} / 2;',
    'const n=(()=>{}) / 2;',
    'function f(x=function(){}) {} /`/.test("x");',
    'async function f(){ for await (const x of []) {} /`/.test("x"); }',
    'class C { f(){ function g(){} /`/.test("x"); } }',
    'const f=()=>{ function g(){} /`/.test("x"); };',
    'const obj={if(){ function g(){} /`/.test("x"); }};',
    'class C { function={} / 2; }',
    'class C { class={} / 2; }',
    'try {} catch {} /`/.test("x");',
    'label: {} /`/.test("x");',
    'export function f() {} /`/.test("x");',
    'export class C {} /`/.test("x");',
    'export default function f() {} /`/.test("x");',
    'try {} catch (e) {} /`/.test("x");',
    'export default class {} /`/.test("x");',
    'function outer(){ const n=1\nfunction f(){} /`/.test("x"); }',
])
def test_block_regex_and_expression_brace_division_keep_tail_declaration(prefix):
    body = prefix + '\n' + 'var a=1;\n' * 500 + '//# sourceMappingURL=real.map\n'
    assert J.last_source_map_directive(body) == 'real.map'


def test_comment_parse_limit_is_explicit_in_inventory(tmp_path):
    with patch.object(J.urllib.request.OpenerDirector, 'open', return_value=Response(b'//# sourceMappingURL=real.map')), \
         patch.object(J, 'http_get_limited') as fetch:
        rows, manifest = inventory(tmp_path, '--source-map-parse-max-bytes', '1')
    fetch.assert_not_called()
    assert rows[0]['source_map_status'] == 'scan_failed'
    assert rows[0]['source_map_reason'] == 'parse_limit'
    assert manifest['source_map_scans_failed'] == 1


def test_header_precedence_bypasses_comment_parser_budget(tmp_path):
    with patch.object(J.urllib.request.OpenerDirector, 'open', return_value=Response(
            b'//# sourceMappingURL=decoy.map', headers={'SourceMap': 'header.map'})), \
         patch.object(J, 'last_source_map_directive', side_effect=AssertionError('header needs no parser')), \
         patch.object(J, 'http_get_limited', return_value=(MAP, 200, 'application/json', False)):
        rows, manifest = inventory(tmp_path, '--source-map-parse-max-bytes', '1')
    assert rows[0]['source_map'] == BUNDLE.rsplit('/', 1)[0] + '/header.map'
    assert rows[0]['source_map_status'] == 'downloaded'
    assert manifest['source_map_scans_failed'] == 0


@pytest.mark.parametrize('dependency', ['tree_sitter', 'tree_sitter_javascript'])
def test_missing_parser_does_not_fall_back_to_lexical_guesses(tmp_path, dependency):
    with patch.dict('sys.modules', {dependency: None}), \
         patch.object(J.urllib.request.OpenerDirector, 'open', return_value=Response(b'//# sourceMappingURL=real.map')):
        rows, manifest = inventory(tmp_path)
    assert rows[0]['source_map_status'] == 'scan_failed'
    assert rows[0]['source_map_reason'] == 'parser_unavailable'
    assert manifest['source_map_scans_failed'] == 1


@pytest.mark.parametrize('limit', ['0', '-1'])
def test_parser_budget_must_be_positive_before_any_paths_or_io(limit):
    with patch.object(J, 'resolve_inventory_paths', side_effect=AssertionError('validation must precede I/O')) as paths, \
         pytest.raises(SystemExit, match='positive'):
        J.main(['inventory', 'demo', '--input', 'unused', '--source-map-parse-max-bytes', limit])
    paths.assert_not_called()


def test_parser_limit_uses_utf8_bytes_and_accepts_exact_boundary():
    text = 'const x="é";\n//# sourceMappingURL=real.map'
    with pytest.raises(J.SourceMapScanError, match='parse_limit'):
        J.last_source_map_directive(text, max_bytes=len(text))
    assert J.last_source_map_directive(text, max_bytes=len(text.encode())) == 'real.map'


def test_absent_marker_needs_no_ast_or_parser_dependency():
    with patch.dict('sys.modules', {'tree_sitter': None}):
        assert J.last_source_map_directive('const value=1;' * 100, max_bytes=1) == ''


def test_parser_memory_failure_is_explicit_not_no_declaration():
    with patch('tree_sitter.Parser', side_effect=MemoryError()):
        signals = J.extract_signals('//# sourceMappingURL=real.map', BUNDLE)
    assert signals['source_map'] == ''
    assert signals['source_map_scan_reason'] == 'parser_memory'


def test_archived_bundle_parser_budget_is_reported(tmp_path):
    def response(request, timeout):
        if request.full_url == BUNDLE:
            return Response(b'const current=1;')
        if '/cdx/' in request.full_url:
            original = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)['url'][0]
            return Response(cdx(original, STAMP))
        assert request.full_url == replay(BUNDLE)
        return Response(b'//# sourceMappingURL=real.map')

    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=response):
        rows, _ = inventory(tmp_path, '--source-map-wayback', 'auto', '--source-map-parse-max-bytes', '1')
    assert rows[0]['source_map_history']['status'] == 'not_recovered'
    assert rows[0]['source_map_history']['reason'] == 'parse_limit'
    assert any(a['reason'] == 'parse_limit' for a in rows[0]['source_map_history']['attempts'])


class WireSocket:
    """Feed the real stdlib HTTP decoder, without sockets or a live server."""

    def __init__(self, body, missing=0, *, chunked=False):
        headers = ((b'' if missing is None else f'Content-Length: {len(body) + missing}\r\n'.encode())
                   + (b'Transfer-Encoding: chunked\r\n' if chunked else b''))
        payload = (f'{len(body):x}\r\n'.encode() + body + b'\r\n0\r\n\r\n') if chunked else body
        self.wire = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n' + headers + b'\r\n' + payload

    def makefile(self, *args):
        return io.BytesIO(self.wire)


def wire_response(body, missing=0, *, chunked=False):
    import http.client
    response = http.client.HTTPResponse(WireSocket(body, missing, chunked=chunked))  # type: ignore[arg-type]
    response.begin()
    return response


@pytest.mark.parametrize('missing', [None, 0, 1, 100])
def test_bounded_fetch_checks_content_length_completion(missing):
    with patch.object(J.urllib.request.OpenerDirector, 'open', return_value=wire_response(MAP, missing)):
        result = J.http_get_limited(replay(BUNDLE + '.map'), timeout=1, max_bytes=4096,
                                    include_program_headers=False)
    assert result.bytes_read == len(MAP)
    if missing:
        assert result[0] == b'' and J.fetch_reason(result) == 'transport'
    else:
        assert result[0] == MAP and J.fetch_reason(result) == 'ok'


@pytest.mark.parametrize('declared', [False, True])
def test_bounded_fetch_collects_short_reads_until_complete(declared):
    class ShortReads(Response):
        def read(self, size=-1):
            return super().read(min(size, 3))

    headers = {'Content-Length': str(len(MAP))} if declared else {}
    with patch.object(J.urllib.request.OpenerDirector, 'open', return_value=ShortReads(MAP, headers=headers)):
        result = J.http_get_limited(replay(BUNDLE + '.map'), timeout=1, max_bytes=len(MAP))
    assert result[0] == MAP and J.fetch_reason(result) == 'ok'
    assert result.bytes_read == len(MAP)


def test_chunked_framing_not_conflicting_content_length_controls_completion():
    with patch.object(J.urllib.request.OpenerDirector, 'open', return_value=wire_response(MAP, 10000, chunked=True)):
        result = J.http_get_limited(replay(BUNDLE + '.map'), timeout=1, max_bytes=len(MAP))
    assert result[0] == MAP and J.fetch_reason(result) == 'ok'
    assert result.bytes_read == len(MAP)


@pytest.mark.parametrize('partial_kind', ['map', 'bundle', 'index'])
def test_incomplete_archive_payload_is_never_published(tmp_path, partial_kind):
    archived_js = b'const old=true;\n//# sourceMappingURL=app.js.map\n'
    map_url = BUNDLE + '.map'

    def response(request, timeout):
        url = request.full_url
        if url == BUNDLE:
            return Response(b'const current=true;' if partial_kind == 'bundle' else b'//# sourceMappingURL=app.js.map')
        if url == map_url:
            raise urllib.error.HTTPError(url, 404, '', Message(), io.BytesIO())
        if '/cdx/' in url:
            original = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['url'][0]
            stamps = [STAMP] if partial_kind in {'bundle', 'index'} or original == map_url else []
            body = cdx(original, *stamps)
            return wire_response(body, 100) if partial_kind == 'index' else Response(body)
        if url == replay(BUNDLE):
            return wire_response(archived_js, 100)
        assert url == replay(map_url)
        return wire_response(MAP, 100 if partial_kind == 'map' else 0)

    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=response):
        rows, manifest = inventory(tmp_path, '--source-map-wayback', 'auto')
    history = rows[0]['source_map_history']
    assert history['status'] == 'not_recovered'
    assert manifest['historical_source_maps_recovered'] == 0
    assert not list(tmp_path.rglob('*.map'))
    assert not list((tmp_path / 'lib' / 'sourcemaps' / 'historical_bundles').glob('*.js'))
    assert all(not p.get('historical') for p in J.read_jsonl(tmp_path / 'out' / 'packets.jsonl'))
    ledger = json.loads((tmp_path / 'lib' / 'ledger.json').read_text())
    assert not ledger.get('historical_source_maps')
    assert any(a['reason'] == 'transport' for a in history['attempts'])


def test_partial_archive_reads_are_charged_to_total_budget(tmp_path):
    import http.client
    args = J.build_parser().parse_args(['inventory', 'demo', '--source-map-wayback', 'auto',
                                      '--source-map-wayback-max-total-bytes', '10'])
    recovery = J.WaybackRecovery(args, ['example.com'], {}, tmp_path)
    read_sizes = []

    class FakeSocket:
        def makefile(self, *args):
            return io.BytesIO(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nxxxxxxxx\r\n')

    class PartialResponse(http.client.HTTPResponse):
        def __init__(self):
            super().__init__(FakeSocket())
            self.begin()

        def read(self, amt=None):
            read_sizes.append(amt)
            return super().read(amt)

    with patch.object(J.urllib.request.OpenerDirector, 'open', side_effect=lambda *a, **k: PartialResponse()):
        attempts = []
        assert recovery.fetch(replay(BUNDLE), 'map', attempts, 100) is None
        assert attempts[0]['reason'] == 'transport'
        assert recovery.fetch(replay(BUNDLE + '.map'), 'map', attempts, 100) is None
    assert recovery.bytes_read >= 8
    assert sum(min(8, size) for size in read_sizes) <= 10
    assert recovery.bytes_read <= args.source_map_wayback_max_total_bytes


@pytest.mark.parametrize('initial_progress', [False, True])
def test_uncertain_failed_archive_read_reserves_its_read_budget(tmp_path, initial_progress):
    args = J.build_parser().parse_args(['inventory', 'demo', '--source-map-wayback', 'auto',
                                      '--source-map-wayback-max-total-bytes', '10'])
    recovery = J.WaybackRecovery(args, ['example.com'], {}, tmp_path)

    class ReadTimeout(Response):
        def read(self, size=-1):
            if initial_progress and self.body.tell() == 0:
                return super().read(min(size, 3))
            raise TimeoutError('private')

    with patch.object(J.urllib.request.OpenerDirector, 'open', return_value=ReadTimeout(b'abc')) as opened:
        attempts = []
        assert recovery.fetch(replay(BUNDLE), 'map', attempts, 100) is None
        assert recovery.fetch(replay(BUNDLE + '.map'), 'map', attempts, 100) is None
    assert opened.call_count == 1
    assert attempts[0]['reason'] == 'timeout'
    assert recovery.bytes_read == 10
