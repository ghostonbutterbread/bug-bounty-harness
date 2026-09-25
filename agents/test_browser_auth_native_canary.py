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
def test_two_chrome_native_cookie_and_selected_origin_storage_transfer():
    import websocket  # noqa: F401 - establish dependency before any browser allocation
    with disposable_fixture_root() as (root, _evidence):
        # The fixture issues an opaque test session; neither it nor browser state
        # is printed or written into a capture file. Only a local origin is used.
        secret = os.urandom(24).hex()
        class App(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/login':
                    self.send_response(302)
                    self.send_header('Set-Cookie', f'session={secret}; HttpOnly; SameSite=Lax; Path=/')
                    self.send_header('Location', '/app')
                    self.end_headers()
                elif self.path == '/app':
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'<!doctype html><title>fixture</title>')
                elif self.path == '/whoami':
                    self.send_response(200 if f'session={secret}' in self.headers.get('Cookie', '').split('; ') else 401)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"authenticated":true}' if f'session={secret}' in self.headers.get('Cookie', '').split('; ') else b'{"authenticated":false}')
                else:
                    self.send_error(404)
            def log_message(self, *args):
                pass
        app = http.server.ThreadingHTTPServer(('127.0.0.1', 0), App)
        thread = threading.Thread(target=app.serve_forever, daemon=True)
        thread.start()
        origin = f'http://127.0.0.1:{app.server_port}'
        # Explicit external proxy mode owns this disposable browser fixture. Chrome
        # bypasses loopback for the app; nonlocal traffic is rejected by proxy.
        class Reject(http.server.BaseHTTPRequestHandler):
            def do_CONNECT(self): self.send_error(502)
            def do_GET(self): self.send_error(502)
            def log_message(self, *args): pass
        proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Reject)
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        proxy_thread.start()
        env = {**os.environ, 'BROWSER_PROVISIONER_STATE': str(root / 'state/manager.sqlite'),
               'HARNESS_BOUNTY_ARTIFACT_ROOT': str(root / 'artifacts'),
               'HARNESS_SHARED_BASE': str(root / 'shared')}
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
            check = "fetch('/whoami').then(r => r.ok && localStorage.getItem('fixture-credential') === 'approved')"
            assert evaluate(source, check) is True
            source_url = evaluate(source, 'location.href')
            # Browser-native CDP cookie export retains HttpOnly (document.cookie
            # cannot). Selected-origin storage is read in the source page context.
            cookies = call_page(source, 'Network.getAllCookies')['cookies']
            selected = [c for c in cookies if c['name'] == 'session' and c['domain'] == '127.0.0.1']
            assert len(selected) == 1 and selected[0]['httpOnly'] is True
            storage = evaluate(source, "localStorage.getItem('fixture-credential')")
            assert storage == 'approved'
            navigate(destination, origin + '/app')
            assert evaluate(destination, "fetch('/whoami').then(r => r.ok)") is False
            assert evaluate(destination, check) is False
            # Transfer exists only in Python memory and CDP's private loopback
            # websocket; no endpoint, profile copy or persisted payload.
            call_page(destination, 'Network.setCookies', {'cookies': selected})
            assert evaluate(destination, check) is False  # cookie alone is insufficient
            evaluate(destination, 'localStorage.setItem(' + json.dumps('fixture-credential') + ',' + json.dumps(storage) + ')')
            assert evaluate(destination, check) is True
            assert evaluate(source, check) is True
            assert evaluate(source, 'location.href') == source_url
            assert evaluate(source, 'document.cookie') == ''
            print('native canary: two isolated Chromes; HttpOnly cookie and selected-origin localStorage transferred; app checks passed; source unchanged')
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
