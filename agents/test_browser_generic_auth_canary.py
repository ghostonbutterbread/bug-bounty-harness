"""Opt-in, private two-Chrome HTTPS .test transport canary; no external site traffic."""
import http.server
import json
import os
from pathlib import Path
import select
import shutil
import socket
import ssl
import subprocess
import threading
import urllib.request

import pytest

from agents.test_browser_lifecycle_systemd import disposable_fixture_root, PROVISIONER
from agents.test_browser_auth_native_canary import evaluate, navigate
from agents.test_browser_auth_native_canary import call_page
from agents.test_browser_generic_auth_transfer import contract_file, POOL
import browser_provisioner as manager


@pytest.mark.skipif(os.environ.get('BBH_GENERIC_AUTH_CANARY') != '1',
                    reason='explicit disposable HTTPS two-Chrome opt-in')
@pytest.mark.parametrize('with_storage', [False, True])
def test_two_chrome_approved_https_nonlocalhost_origin(monkeypatch, with_storage):
    import websocket  # noqa: F401
    with disposable_fixture_root() as (root, _evidence):
        secret = os.urandom(24).hex()
        class App(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                authorized = False
                if self.path == '/login':
                    self.send_response(302)
                    self.send_header('Set-Cookie', f'__Host-token={secret}; Secure; HttpOnly; SameSite=Lax; Path=/')
                    self.send_header('Set-Cookie', f'session={secret}; Secure; HttpOnly; SameSite=Lax; Path=/')
                    self.send_header('Set-Cookie', f'exact-domain-auth={secret}; Domain=auth.example.test; Secure; HttpOnly; SameSite=Strict; Max-Age=3600; Path=/')
                    self.send_header('Set-Cookie', f'parent-auth={secret}; Domain=example.test; Secure; HttpOnly; SameSite=Strict; Max-Age=3600; Path=/')
                    self.send_header('Location', '/app')
                elif self.path == '/app':
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                elif self.path == '/me':
                    observed = self.headers.get('Cookie', '').split('; ')
                    authorized = all(f'{name}={secret}' in observed for name in
                                     ('__Host-token', 'session', 'exact-domain-auth', 'parent-auth'))
                    self.send_response(200 if authorized else 401)
                    self.send_header('Content-Type', 'text/html')
                else:
                    self.send_error(404)
                    return
                self.end_headers()
                if self.path == '/me':
                    self.wfile.write(b'<span data-testid="identity">' +
                                     (b'blue' if authorized else b'guest') + b'</span>')
            def log_message(self, format, *args): pass
        app = http.server.ThreadingHTTPServer(('127.0.0.1', 0), App)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=auth.example.test', '-addext', 'subjectAltName=DNS:auth.example.test'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        app.socket = tls.wrap_socket(app.socket, server_side=True)
        app_thread = threading.Thread(target=app.serve_forever, daemon=True)
        app_thread.start()
        origin = f'https://auth.example.test:{app.server_port}'
        class LocalOnlyProxy(http.server.BaseHTTPRequestHandler):
            def do_CONNECT(self):
                if self.path != f'auth.example.test:{app.server_port}':
                    self.send_error(502)
                    return
                try:
                    with socket.create_connection(('127.0.0.1', app.server_port), timeout=5) as upstream:
                        self.send_response(200, 'Connection Established')
                        self.end_headers()
                        self.connection.settimeout(10)
                        upstream.settimeout(10)
                        sockets = (self.connection, upstream)
                        while True:
                            readable, _, _ = select.select(sockets, (), (), 10)
                            if not readable: return
                            for source in readable:
                                payload = source.recv(65536)
                                if not payload: return
                                (upstream if source is self.connection else self.connection).sendall(payload)
                except (OSError, ValueError):
                    return
            def do_GET(self): self.send_error(502)
            def log_message(self, format, *args): pass
        proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), LocalOnlyProxy)
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        proxy_thread.start()
        env = {**os.environ, 'BROWSER_STARTUP_DIAGNOSTICS': '1',
               'BROWSER_PROVISIONER_STATE': str(root / 'state/manager.sqlite'),
               'HARNESS_BOUNTY_ARTIFACT_ROOT': str(root / 'artifacts'),
               'HARNESS_SHARED_BASE': str(root / 'shared')}
        state_dir = root / 'state'
        state_dir.mkdir(mode=0o700, exist_ok=True)
        pool = (POOL[0], POOL[1], 'anon')  # disposable anonymous lease, mock login is blue
        contract = contract_file(state_dir, origin=origin, pool=pool)
        reviewed = json.loads(contract.read_text())
        del reviewed['local_storage_keys']
        del reviewed['cookie_selector']
        reviewed['state_mode'] = 'exact-origin'
        contract.write_text(json.dumps(reviewed))
        owners = [subprocess.Popen(['sleep', 'infinity']) for _ in range(2)]
        leases = []
        try:
            for index in range(2):
                command = [shutil.which('python3'), str(PROVISIONER), 'request', pool[0], pool[2],
                           '--auth-domain', pool[1], '--instance-key', f'generic-canary-{index}',
                           '--agent-id', f'generic-owner-{index}', '--run-id', f'generic-run-{index}',
                           '--owner-pid', str(owners[index].pid), '--purpose', 'private HTTPS auth canary',
                           '--ttl-seconds', '120', '--min-ram-available-mib', '1',
                           '--min-swap-free-mib', '0', '--headless', '--proxy', 'external',
                           '--proxy-server', f'http://127.0.0.1:{proxy.server_port}',
                           '--proxy-cert-mode', 'ignore', '--proxy-ownership', 'browser', '--wait-seconds', '0']
                result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=90)
                assert secret not in result.stdout and secret not in result.stderr
                assert result.returncode == 0, result.returncode
                started = json.loads(result.stdout)
                assert started['status'] == 'started', started['status']
                leases.append(started['lease_id'])
            import sqlite3
            with sqlite3.connect(env['BROWSER_PROVISIONER_STATE']) as db:
                rows = [db.execute('SELECT profile_dir,launch_file FROM browsers WHERE lease_id=?',
                                   (lid,)).fetchone() for lid in leases]
            assert rows[0][0] != rows[1][0]
            urls = [json.loads(Path(row[1]).read_text())['cdp_url'] for row in rows]
            for url in urls:
                assert json.load(urllib.request.urlopen(url + '/json/version', timeout=5))['Browser']
            navigate(urls[0], origin + '/login', origin + '/app')
            if with_storage:
                evaluate(urls[0], "localStorage.setItem('program-auth', 'alpha')")
                evaluate(urls[0], "localStorage.setItem('other-auth', 'beta')")
            navigate(urls[1], origin + '/app')
            assert evaluate(urls[0], "fetch('/me', {redirect:'manual'}).then(r => r.status)") == 200
            assert evaluate(urls[1], "fetch('/me', {redirect:'manual'}).then(r => r.status)") == 401
            before = call_page(urls[0], 'Network.getAllCookies')['cookies']
            source_cookies = [c for c in before if c['name'] in
                              ('__Host-token', 'session', 'exact-domain-auth', 'parent-auth')]
            assert len(source_cookies) == 4
            assert next(c for c in source_cookies if c['name'] == 'session')['domain'] == 'auth.example.test'
            assert next(c for c in source_cookies if c['name'] == 'exact-domain-auth')['domain'] == '.auth.example.test'
            assert any(c['name'] == 'parent-auth' and c['domain'].lstrip('.') == 'example.test'
                       for c in source_cookies)
            monkeypatch.setattr(manager, 'STATE', Path(env['BROWSER_PROVISIONER_STATE']))
            if with_storage:
                original_check = manager._fixture_verified_observation
                observations = []
                def reject_import(contract, observation):
                    observations.append(observation)
                    return len(observations) != 3 and original_check(contract, observation)
                monkeypatch.setattr(manager, '_fixture_verified_observation', reject_import)
                rejected = manager.manager_approved_auth_transfer(leases[0], leases[1], origin=origin,
                    source_owner_agent_id='generic-owner-0', source_owner_run_id='generic-run-0',
                    destination_owner_agent_id='generic-owner-1', destination_owner_run_id='generic-run-1')
                monkeypatch.setattr(manager, '_fixture_verified_observation', original_check)
                assert rejected == {'status': 'auth-clone-unavailable', 'reason': 'destination-app-check-failed'}
                assert not call_page(urls[1], 'Network.getAllCookies')['cookies']
                assert evaluate(urls[1], 'localStorage.length') == 0
                assert call_page(urls[0], 'Network.getAllCookies')['cookies'] == before
            disposition = manager.manager_approved_auth_transfer(leases[0], leases[1], origin=origin,
                source_owner_agent_id='generic-owner-0', source_owner_run_id='generic-run-0',
                destination_owner_agent_id='generic-owner-1', destination_owner_run_id='generic-run-1')
            assert disposition == {'status': 'auth-transferred'}, disposition
            published = json.loads(Path(rows[1][1]).read_text())['cdp_url']
            assert published != urls[1]
            assert evaluate(published, "fetch('/me', {redirect:'manual'}).then(r => r.status)") == 200
            assert evaluate(urls[0], "fetch('/me', {redirect:'manual'}).then(r => r.status)") == 200
            after = call_page(published, 'Network.getAllCookies')['cookies']
            assert {c['name'] for c in after if c['name'] in
                    ('__Host-token', 'session', 'exact-domain-auth', 'parent-auth')} == {
                '__Host-token', 'session', 'exact-domain-auth', 'parent-auth'}
            assert all(next(c for c in after if c['name'] == name)['domain'] == 'auth.example.test'
                       for name in ('__Host-token', 'session', 'exact-domain-auth'))
            child = call_page(published, 'Network.getCookies',
                              {'urls': [f'https://probe.auth.example.test:{app.server_port}/']})['cookies']
            assert not {c['name'] for c in child} & {'__Host-token', 'session', 'exact-domain-auth'}
            assert 'parent-auth' in {c['name'] for c in child}
            assert call_page(urls[0], 'Network.getAllCookies')['cookies'] == before
            assert 'blue' in evaluate(urls[0], "fetch('/me', {redirect:'manual'}).then(r => r.text())")
            assert 'blue' in evaluate(published, "fetch('/me', {redirect:'manual'}).then(r => r.text())")
            assert evaluate(published, 'localStorage.length') == (2 if with_storage else 0)
            if with_storage:
                assert evaluate(published, "localStorage.getItem('program-auth')") == 'alpha'
                assert evaluate(published, "localStorage.getItem('other-auth')") == 'beta'
            assert evaluate(urls[0], 'location.href') == origin + '/app'
        finally:
            for owner in owners:
                owner.terminate()
                owner.wait(timeout=5)
            proxy.shutdown(); proxy.server_close(); proxy_thread.join(timeout=5)
            app.shutdown(); app.server_close(); app_thread.join(timeout=5)
