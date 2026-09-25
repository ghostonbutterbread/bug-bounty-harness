"""Opt-in, local-only two-Chrome auth transfer experiment; no production route."""
import contextlib
import http.server
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_browser_lifecycle_systemd import disposable_fixture_root, PROVISIONER
import browser_provisioner as manager


def call_page(url, method, params=None):
    import websocket
    pages = json.load(urllib.request.urlopen(url + '/json/list', timeout=5))
    page = next(p for p in pages if p['type'] == 'page')
    with contextlib.closing(websocket.create_connection(page['webSocketDebuggerUrl'], timeout=10)) as ws:
        ws.send(json.dumps({'id': 1, 'method': method, 'params': params or {}}))
        while True:
            response = json.loads(ws.recv())
            if response.get('id') == 1:
                assert 'error' not in response, (method, response.get('error'))
                return response['result']


def evaluate(url, expression):
    result = call_page(url, 'Runtime.evaluate', {'expression': expression, 'returnByValue': True,
                                                  'awaitPromise': True})
    assert 'exceptionDetails' not in result, result.get('exceptionDetails')
    return result['result'].get('value')


def navigate(url, target, expected=None):
    call_page(url, 'Page.navigate', {'url': target})
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if evaluate(url, 'location.href') == (expected or target):
            return
        time.sleep(.1)
    raise AssertionError('navigation did not settle')


@pytest.mark.skipif(os.environ.get('BBH_AUTH_CANARY') != '1', reason='explicit local canary opt-in')
@pytest.mark.parametrize('lost_reply,bad_check', [
    (None, None), ('end', None), ('commit', None),
    (None, 'principal'), (None, 'redirect'), (None, 'domain-cookie')])
def test_two_chrome_native_cookie_and_selected_origin_storage_transfer(lost_reply, bad_check, monkeypatch, capsys):
    import websocket  # noqa: F401 - establish dependency before any browser allocation
    with disposable_fixture_root() as (root, _evidence):
        # The fixture issues an opaque test session; neither it nor browser state
        # is printed or written into a capture file. Only a local origin is used.
        secret = os.urandom(24).hex()
        checks = {'count': 0, 'reject_at': None, 'bad': None}
        class App(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/login':
                    self.send_response(302)
                    self.send_header('Set-Cookie', f'__Host-session={secret}; Secure; HttpOnly; SameSite=Lax; Path=/')
                    self.send_header('Location', '/app')
                    self.end_headers()
                elif self.path == '/app':
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'<!doctype html><title>fixture</title>')
                elif self.path == '/me':
                    checks['count'] += 1
                    authorized = (any(c in self.headers.get('Cookie', '').split('; ') for c in
                                      (f'__Host-session={secret}', f'session={secret}'))
                                  and checks['count'] != checks['reject_at'])
                    if checks['bad'] == 'redirect' and authorized:
                        self.send_response(302)
                        self.send_header('Location', '/app')
                        self.end_headers()
                        return
                    self.send_response(200 if authorized else 401)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    principal = 'other' if checks['bad'] == 'principal' else 'anon'
                    self.wfile.write(f'<span data-testid="account-name">{principal if authorized else "guest"}</span>'.encode())
                else:
                    self.send_error(404)
            def log_message(self, *args):
                pass
        app = http.server.ThreadingHTTPServer(('127.0.0.1', 0), App)
        thread = threading.Thread(target=app.serve_forever, daemon=True)
        thread.start()
        origin = f'http://localhost:{app.server_port}'
        # Explicit external proxy mode owns this disposable browser fixture. Chrome
        # bypasses loopback for the app; nonlocal traffic is rejected by proxy.
        class Reject(http.server.BaseHTTPRequestHandler):
            def do_CONNECT(self): self.send_error(502)
            def do_GET(self): self.send_error(502)
            def log_message(self, *args): pass
        proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Reject)
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        proxy_thread.start()
        env = {**os.environ, 'BROWSER_STARTUP_DIAGNOSTICS': '1',
               'BROWSER_PROVISIONER_STATE': str(root / 'state/manager.sqlite'),
               'HARNESS_BOUNTY_ARTIFACT_ROOT': str(root / 'artifacts'),
               'HARNESS_SHARED_BASE': str(root / 'shared')}
        contract = {'program': 'fixture', 'auth_domain': 'fixture.invalid', 'account_alias': 'anon',
                    'disposable_fixture': True, 'allowed_origins': [origin],
                    'check': {'url': origin + '/me', 'method': 'GET',
                              'principal_selector': '[data-testid="account-name"]', 'expected_principal': 'anon'},
                    'local_storage_keys': ['fixture-credential'],
                    'cookie_selector': {'name': '__Host-session', 'domain': 'localhost', 'path': '/'}}
        state_dir = root / 'state'
        state_dir.mkdir(mode=0o700, exist_ok=True)
        contract_path = state_dir / 'fixture-site-contract.json'
        contract_path.write_text(json.dumps(contract))
        contract_path.chmod(0o600)
        owners = [subprocess.Popen(['sleep', 'infinity']) for _ in range(2)]
        leases = []
        def command(*args):
            result = subprocess.run([sys.executable, str(PROVISIONER), *map(str, args)],
                                    env=env, text=True, capture_output=True, timeout=90)
            assert result.returncode == 0, (args[0], result.returncode)
            return json.loads(result.stdout)
        try:
            for index in range(2):
                result = command('request', 'fixture', 'anon', '--auth-domain', 'fixture.invalid',
                                 '--instance-key', f'canary-{index}', '--agent-id', 'fixture-agent',
                                 '--run-id', f'canary-{index}', '--owner-pid', owners[index].pid,
                                 '--purpose', 'local auth canary', '--ttl-seconds', '120',
                                 '--min-ram-available-mib', '1', '--min-swap-free-mib', '0',
                                 '--headless', '--proxy', 'external', '--proxy-server',
                                 f'http://127.0.0.1:{proxy.server_port}', '--proxy-cert-mode', 'none',
                                 '--proxy-ownership', 'browser', '--wait-seconds', '0')
                assert result['status'] == 'started', result['status']
                leases.append(result['lease_id'])
            with sqlite3.connect(env['BROWSER_PROVISIONER_STATE']) as db:
                rows = [db.execute('SELECT profile_dir,launch_file FROM browsers WHERE lease_id=?',
                                   (lid,)).fetchone() for lid in leases]
            assert rows[0][0] != rows[1][0]
            urls = [json.loads(Path(row[1]).read_text())['cdp_url'] for row in rows]
            for url in urls:
                assert json.load(urllib.request.urlopen(url + '/json/version', timeout=5))['Browser']
            source, destination = urls
            navigate(source, origin + '/login', origin + '/app')
            assert evaluate(source, 'location.origin') == origin
            evaluate(source, "localStorage.setItem('fixture-credential', 'approved')")
            check = "fetch('/me', {redirect:'manual'}).then(async r => r.status === 200 && (await r.text()).includes('>anon<') && localStorage.getItem('fixture-credential') === 'approved')"
            assert evaluate(source, check) is True
            source_url = evaluate(source, 'location.href')
            navigate(destination, origin + '/app')
            assert evaluate(destination, "fetch('/me').then(r => r.ok)") is False
            assert evaluate(destination, check) is False
            # The adapter fences rotation and public CDP while an exclusive
            # manager transaction is in progress; no payload is printed.
            import httpx
            with sqlite3.connect(env['BROWSER_PROVISIONER_STATE']) as db:
                launch = db.execute('SELECT launch_file FROM browsers WHERE lease_id=?', (leases[0],)).fetchone()[0]
            socket_path = json.loads(Path(launch).read_text())['control_socket']
            with httpx.Client(transport=httpx.HTTPTransport(uds=socket_path), timeout=15) as control:
                import websocket
                page = next(p for p in json.load(urllib.request.urlopen(source + '/json/list', timeout=5))
                            if p['type'] == 'page')
                begin = {'transaction': 'direct-canary', 'owner': leases[0],
                         'generation': source, 'destination': False}
                with contextlib.closing(websocket.create_connection(page['webSocketDebuggerUrl'], timeout=5)):
                    assert control.post('http://localhost/transfer/begin', json=begin).status_code == 409
                ticket = control.post('http://localhost/transfer/begin', json=begin).json()['ticket']
                try:
                    assert control.post('http://localhost/rotate').status_code == 409
                    assert control.post('http://localhost/transfer/begin',
                                        json={**begin, 'transaction': 'other'}).status_code == 409
                finally:
                    assert control.post('http://localhost/transfer/end',
                                        json={**begin, 'ticket': ticket}).status_code == 200
            assert evaluate(source, check) is True
            manager.STATE = Path(env['BROWSER_PROVISIONER_STATE'])
            # Inject an app-native rejection after the import. The manager must
            # remove both cookie and storage before releasing destination CDP.
            checks['reject_at'] = checks['count'] + 3
            assert manager.manager_fixture_auth_transfer(leases[0], leases[1], origin=origin) == {
                'status': 'auth-clone-unavailable', 'reason': 'destination-app-check-failed'}
            checks['reject_at'] = None
            assert evaluate(destination, check) is False
            assert evaluate(destination, "localStorage.getItem('fixture-credential')") is None
            assert not any(c['name'] == '__Host-session' and c['domain'] == 'localhost'
                           for c in call_page(destination, 'Network.getAllCookies')['cookies'])
            assert evaluate(source, check) is True
            if bad_check:
                checks['bad'] = bad_check
                if bad_check == 'domain-cookie':
                    call_page(source, 'Network.deleteCookies', {'name': '__Host-session', 'url': origin + '/'})
                    call_page(source, 'Network.setCookie', {'name': 'session', 'value': secret,
                        'domain': 'localhost', 'path': '/', 'httpOnly': True})
                assert manager.manager_fixture_auth_transfer(leases[0], leases[1], origin=origin) == {
                    'status': 'auth-clone-unavailable', 'reason':
                    'source-cookie-unverified' if bad_check == 'domain-cookie' else 'source-app-check-failed'}
                assert evaluate(destination, "localStorage.getItem('fixture-credential')") is None
                assert not call_page(destination, 'Network.getAllCookies')['cookies']
                assert evaluate(source, 'location.href') == source_url
                return
            if lost_reply:
                with sqlite3.connect(env['BROWSER_PROVISIONER_STATE']) as db:
                    dest_launch = db.execute('SELECT launch_file FROM browsers WHERE lease_id=?',
                                             (leases[1],)).fetchone()[0]
                dest_socket = json.loads(Path(dest_launch).read_text())['control_socket']
                original_client = httpx.Client
                original_transport = httpx.HTTPTransport
                sockets = {}
                applied = []
                def tracked_transport(*, uds):
                    transport = original_transport(uds=uds)
                    sockets[id(transport)] = uds
                    return transport
                class LostEndClient:
                    def __init__(self, *, transport, timeout):
                        self.client = original_client(transport=transport, timeout=timeout)
                        self.is_destination = sockets[id(transport)] == dest_socket
                    def post(self, url, **kwargs):
                        response = self.client.post(url, **kwargs)
                        if self.is_destination and url.endswith('/transfer/' + lost_reply):
                            applied.append(response.status_code)
                            raise httpx.ReadError('control reply lost after application')
                        return response
                    def get(self, url, **kwargs): return self.client.get(url, **kwargs)
                    def __enter__(self): return self
                    def __exit__(self, *args): self.close()
                    def close(self): self.client.close()
                with monkeypatch.context() as patch:
                    patch.setattr(httpx, 'HTTPTransport', tracked_transport)
                    patch.setattr(httpx, 'Client', LostEndClient)
                    disposition = manager.manager_fixture_auth_transfer(leases[0], leases[1], origin=origin)
                assert applied == [200]
                assert disposition == {'status': 'auth-clone-unavailable',
                                       'reason': 'destination-disposed-after-end-uncertainty'}
                with pytest.raises(Exception):
                    urllib.request.urlopen(destination + '/json/version', timeout=2)
                assert evaluate(source, check) is True
                return
            assert manager.manager_fixture_auth_transfer(leases[0], leases[1], origin=origin) == {
                'status': 'fixture-auth-transferred'}
            destination = json.loads(Path(rows[1][1]).read_text())['cdp_url']
            assert destination != urls[1]
            with pytest.raises(Exception):
                urllib.request.urlopen(urls[1] + '/json/version', timeout=2)
            assert evaluate(destination, check) is True
            assert evaluate(source, check) is True
            assert evaluate(source, 'location.href') == source_url
            assert evaluate(source, 'document.cookie') == ''
            print('manager native canary: two isolated Chromes; app checks passed; source unchanged')
        finally:
            for lid in reversed(leases):
                command('release', '--lease-id', lid, '--agent-id', 'fixture-agent',
                        '--disposition', 'completed', '--profile-health', 'healthy')
            for owner in owners:
                owner.terminate()
                owner.wait(timeout=5)
            proxy.shutdown()
            proxy.server_close()
            app.shutdown()
            app.server_close()
            thread.join(timeout=5)
            proxy_thread.join(timeout=5)
            output = capsys.readouterr()
            assert secret not in output.out and secret not in output.err
            for pattern in ('*.json', '*.log', '*.txt'):
                for file in root.rglob(pattern):
                    assert secret not in file.read_text(errors='replace')
