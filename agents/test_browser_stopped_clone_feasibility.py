"""Opt-in disposable local stopped-profile experiment; never a production clone path."""
import contextlib
from dataclasses import replace
import http.server
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import threading
import urllib.request

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_browser_lifecycle_systemd import disposable_fixture_root, PROVISIONER
from test_browser_auth_native_canary import call_page, evaluate, navigate
from agents.browser_offline_snapshot import TerminalProof, SnapshotRefused, snapshot_stopped_profile


@pytest.mark.skipif(os.environ.get('BBH_STOPPED_CLONE_CANARY') != '1', reason='explicit disposable opt-in')
def test_stopped_profile_raw_vs_filtered_clone(capsys):
    import websocket  # dependency preflight
    from browser_lifecycle import owner_state
    secret = os.urandom(24).hex()
    class App(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/login':
                self.send_response(302)
                self.send_header('Set-Cookie', f'session={secret}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600')
                self.send_header('Location', '/app')
                self.end_headers()
                return
            if self.path not in ('/app', '/me'):
                self.send_error(404)
                return
            authorized = f'session={secret}' in self.headers.get('Cookie', '').split('; ')
            body = (b'<!doctype html><title>fixture</title>' if self.path == '/app' else
                    (b'<span data-testid="principal">owned-fixture</span>' if authorized else
                     b'<span data-testid="principal">guest</span>'))
            self.send_response(200 if self.path == '/app' or authorized else 401)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args): pass
    class Reject(http.server.BaseHTTPRequestHandler):
        def do_CONNECT(self): self.send_error(502)
        def do_GET(self): self.send_error(502)
        def log_message(self, *args): pass
    with disposable_fixture_root() as (root, evidence):
        app = http.server.ThreadingHTTPServer(('127.0.0.1', 0), App)
        proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Reject)
        threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (app, proxy)]
        for thread in threads: thread.start()
        origin = f'http://127.0.0.1:{app.server_port}'
        state = root / 'state'
        state.mkdir(mode=0o700, exist_ok=True)
        env = {**os.environ, 'BROWSER_PROVISIONER_STATE': str(state / 'manager.sqlite'),
               'HARNESS_BOUNTY_ARTIFACT_ROOT': str(root / 'artifacts'),
               'HARNESS_SHARED_BASE': str(root / 'shared')}
        owners = [subprocess.Popen(['sleep', 'infinity']) for _ in range(3)]
        active = {}
        def command(*parts):
            result = subprocess.run([sys.executable, str(PROVISIONER), *map(str, parts)],
                                    env=env, capture_output=True, text=True, timeout=100)
            assert secret not in result.stdout + result.stderr
            assert result.returncode == 0, (parts[0], result.returncode, result.stderr[-500:])
            return json.loads(result.stdout)
        def launch(index, phase):
            name = ('source', 'raw', 'filtered')[index]
            result = command('request', 'fixture', 'anon', '--auth-domain', 'fixture.invalid',
                             '--instance-key', 'stopped-' + name, '--agent-id', 'stopped-fixture',
                             '--run-id', f'{name}-{phase}', '--owner-pid', owners[index].pid,
                             '--purpose', 'disposable stopped profile feasibility', '--ttl-seconds', '120',
                             '--min-ram-available-mib', '1', '--min-swap-free-mib', '0',
                             '--headless', '--proxy', 'external', '--proxy-server',
                             f'http://127.0.0.1:{proxy.server_port}', '--proxy-cert-mode', 'none',
                             '--proxy-ownership', 'browser', '--wait-seconds', '0')
            assert result['status'] == 'started', result['status']
            lease = result['lease_id']
            with sqlite3.connect(state / 'manager.sqlite') as db:
                profile, launch_file, unit = db.execute(
                    'SELECT profile_dir,launch_file,unit FROM browsers WHERE lease_id=?', (lease,)).fetchone()
            info = json.loads(Path(launch_file).read_text())
            url = info['cdp_url']
            assert json.load(urllib.request.urlopen(url + '/json/version', timeout=5))['Browser']
            active[index] = (lease, Path(profile), url, unit, info['process_identity'])
            return active[index]
        def stop(index, graceful=False):
            lease, profile, url, unit, identity = active[index]
            if graceful:
                import websocket
                import time
                browser_ws = json.load(urllib.request.urlopen(url + '/json/version', timeout=5))['webSocketDebuggerUrl']
                with contextlib.closing(websocket.create_connection(browser_ws, timeout=5)) as ws:
                    ws.send(json.dumps({'id': 1, 'method': 'Browser.close'}))
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        urllib.request.urlopen(url + '/json/version', timeout=.5)
                    except Exception:
                        break
                    time.sleep(.1)
            command('release', '--lease-id', lease, '--agent-id', 'stopped-fixture',
                    '--disposition', 'completed', '--profile-health', 'healthy')
            assert owner_state(identity) == 'terminal'
            with pytest.raises(Exception):
                urllib.request.urlopen(url + '/json/version', timeout=2)
            show = subprocess.run(['systemctl', '--user', 'show', unit,
                                   '--property=ActiveState', '--value'], text=True, capture_output=True, timeout=10)
            assert show.returncode == 0 and show.stdout.strip() in ('inactive', 'failed')
            assert not (profile / 'SingletonLock').exists()
            active.pop(index)
            return profile
        def proof(source):
            st = source.stat()
            return TerminalProof('fixture', 'fixture.invalid', 'anon', 'stopped', 'fixture-lease',
                                 str(source), st.st_dev, st.st_ino, 'verified-terminal-unit',
                                 'verified-terminal-root', 'verified-terminal-cdp', True, True, True, True)
        check = "fetch('/me').then(async r => r.status === 200 && (await r.text()).includes('>owned-fixture<') && localStorage.getItem('fixture-required') === 'approved')"
        private = root / 'private'
        private.mkdir(mode=0o700)
        try:
            source = launch(0, 'seed')[1]
            source_url = active[0][2]
            navigate(source_url, origin + '/login', origin + '/app')
            evaluate(source_url, "localStorage.setItem('fixture-required', 'approved')")
            assert evaluate(source_url, check) is True
            cookies = call_page(source_url, 'Network.getAllCookies')['cookies']
            assert any(c['name'] == 'session' and c['expires'] > 0 for c in cookies), 'persistent cookie not set'
            assert evaluate(source_url, 'document.cookie') == ''  # HttpOnly
            # A live source cannot be copied even when a caller fabricates terminal flags.
            with pytest.raises(SnapshotRefused, match='lock|proof'):
                snapshot_stopped_profile(source, private, lambda: replace(proof(source), root_terminal=False))
            assert not list(private.iterdir())
            import time
            time.sleep(2)  # allow browser storage writes to settle before manager stop
            source = stop(0, graceful=True)  # exact unit/root/CDP closure precedes both copies
            assert source.exists() and list(source.rglob('Local Storage/leveldb/*')), 'profile not persisted after release'
            cookie_dbs = [p for p in source.rglob('Cookies') if p.is_file()]
            assert cookie_dbs, 'cookie DB not persisted'
            counts = []
            for cookie_db in cookie_dbs:
                with sqlite3.connect(f'file:{cookie_db}?mode=ro', uri=True) as db:
                    counts.append(db.execute('SELECT count(*) FROM cookies').fetchone()[0])
            assert any(count >= 1 for count in counts), ('cookie rows after stop', counts)
            _, reused, check_url, _, _ = launch(0, 'persistence-check')
            assert reused == source, 'provisioner selected different source profile'
            navigate(check_url, origin + '/app')
            assert evaluate(check_url, check) is True, ('source-restart',
                evaluate(check_url, 'location.origin') == origin,
                evaluate(check_url, "fetch('/me').then(r => r.status)"),
                evaluate(check_url, "localStorage.getItem('fixture-required') === 'approved'"))
            source = stop(0)  # reacquire terminal fence for copy
            storage_files = list(source.rglob('Local Storage/leveldb/*'))
            assert storage_files, 'source origin storage was not persisted at browser stop'
            # Chrome leaves stale Singleton artifacts even after verified stop.
            # Unlink only this fixture's exact profile artifacts under its
            # no-restart boundary, not an unverified live/other profile.
            for name in ('SingletonLock', 'SingletonCookie', 'SingletonSocket'):
                artifact = source / name
                if os.path.lexists(artifact): artifact.unlink()
            assert not os.path.lexists(source / 'SingletonLock')
            # A restart/lock appearing at the copy boundary must refuse even
            # if the caller supplies a stale all-terminal proof.
            (source / 'SingletonLock').write_text('fixture-restart-fence')
            with pytest.raises(SnapshotRefused, match='lock'):
                snapshot_stopped_profile(source, private, lambda: proof(source))
            (source / 'SingletonLock').unlink()
            assert not list(private.iterdir())
            # Fixture-only NSS marker represents nonportable task CA material; no real CA is imported.
            marker = source / 'cert9.db'
            assert not marker.exists()
            marker.write_bytes(b'fixture-nss-marker')
            (source / 'key4.db').write_bytes(b'fixture-client-key-marker')
            (source / 'task-proxy-ca.pem').write_bytes(b'fixture-proxy-marker')
            for index in (1, 2):
                _, profile, url, _, _ = launch(index, 'empty')
                navigate(url, origin + '/app')
                assert evaluate(url, check) is False
                assert evaluate(url, "localStorage.getItem('fixture-required')") is None
                assert stop(index) == profile
            # Holding this fixture's no-restart boundary: no source launch until copies finish.
            assert 0 not in active
            raw = private / 'raw'
            # Chrome leaves dangling Singleton symlinks/socket after stop; raw
            # byte copy of those runtime artifacts fails or points back to source.
            # Compare unfiltered *portable files*, omitting only runtime locks.
            shutil.copytree(source, raw, ignore=shutil.ignore_patterns(
                'SingletonLock', 'SingletonCookie', 'SingletonSocket', 'DevToolsActivePort'))
            filtered = snapshot_stopped_profile(source, private, lambda: proof(source))
            assert (raw / 'cert9.db').read_bytes() == b'fixture-nss-marker'
            assert (raw / 'key4.db').exists()
            assert (raw / 'task-proxy-ca.pem').exists()
            assert not (filtered / 'cert9.db').exists()
            assert not (filtered / 'key4.db').exists()
            assert not (filtered / 'task-proxy-ca.pem').exists()
            for index, donor in ((1, raw), (2, filtered)):
                # Recipients were provisioned, stopped, and checked empty before replacement.
                # Actual recipient path comes from the fixture manager history.
                with sqlite3.connect(state / 'manager.sqlite') as db:
                    row = db.execute('SELECT profile_dir FROM browsers WHERE run_id=?',
                                     (('raw', 'filtered')[index - 1] + '-empty',)).fetchone()
                assert row is not None
                target = Path(row[0])
                assert target != source and not target.is_symlink()
                shutil.rmtree(target)
                shutil.copytree(donor, target, ignore=shutil.ignore_patterns('snapshot-manifest.json'))
                assert sorted(str(p.relative_to(donor)) for p in donor.rglob('*')
                              if p.is_file() and p.name != 'snapshot-manifest.json') == sorted(
                    str(p.relative_to(target)) for p in target.rglob('*') if p.is_file())
                _, profile, url, _, _ = launch(index, 'verify')
                assert profile == target
                navigate(url, origin + '/app')
                observed = evaluate(url, "fetch('/me').then(r => r.status)")
                storage = evaluate(url, "localStorage.getItem('fixture-required') === 'approved'")
                assert evaluate(url, check) is True, (index, observed, storage)
                assert evaluate(url, 'document.cookie') == ''
                assert stop(index) == target
            # Reopen the source only after both copy operations; verify it retains its principal.
            _, reopened, url, _, _ = launch(0, 'verify')
            assert reopened == source
            navigate(url, origin + '/app')
            assert evaluate(url, check) is True
            assert stop(0) == source
            print('stopped clone: raw=principal; filtered=principal; source=principal; CA trust=untested')
        finally:
            for index in list(active): stop(index)
            for owner in owners:
                owner.terminate()
                owner.wait(timeout=5)
            for server, thread in zip((app, proxy), threads):
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            captured = capsys.readouterr()
            assert secret not in captured.out + captured.err
            assert not active
