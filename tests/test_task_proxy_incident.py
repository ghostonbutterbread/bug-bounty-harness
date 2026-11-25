"""Offline entrypoint fixtures; run only inside a network-none container."""
import importlib.util
import ctypes
import fcntl
import json
import os
from pathlib import Path
import socket
import select
import ssl
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/task_proxy_incident.py'

class EntryPoint(unittest.TestCase):
    def setUp(self):
        # Let the fixture child inspect the listener-owning parent under Yama.
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(0x59616d61, ctypes.c_ulong(-1).value, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'fixture PR_SET_PTRACER failed')
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        # Exec workers cannot inherit monkeypatches. Build a fixture-only copy
        # with the two explicit pre-existing admission substitutions.
        import shutil
        import shlex
        self.fixture_script = self.root / 'incident-fixture.py'
        source = SCRIPT.read_text()
        fixture_overrides = "live_gate = lambda: None\ncapture_snapshot = lambda args, snapshot: {'fixture': True}\n\n"
        self.fixture_script.write_text(source.replace("if __name__ == '__main__':", fixture_overrides + "if __name__ == '__main__':"))
        shutil.copyfile(SCRIPT.parent / 'browser_lifecycle.py', self.root / 'browser_lifecycle.py')
        fake = self.root / 'systemctl'
        fake.write_text('#!/bin/sh\ncat ' + shlex.quote(str(self.root / 'systemd-output')) + '\n')
        fake.chmod(0o700)
        self.state = self.root / 'state'
        self.identity = self.root / 'identity.json'
        self.identity.write_text(json.dumps({'host': 'fixture-host', 'agent': 'a', 'run': 'r', 'lane': 'task-123', 'invocation': 'abc', 'pid': 1, 'start': '9', 'port': 0, 'ca': str(self.root / 'cert.pem')}))
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(self.root/'key.pem'), '-out', str(self.root/'cert.pem'), '-days', '1', '-subj', '/CN=api.ipify.org', '-addext', 'subjectAltName=DNS:api.ipify.org'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        (self.root/'mitmproxy').mkdir()
        (self.root/'mitmproxy/mitmproxy-ca-cert.pem').write_bytes((self.root/'cert.pem').read_bytes())
        self.db = self.root / 'manager.sqlite'
        with sqlite3.connect(self.db) as c:
            c.execute('CREATE TABLE task_proxies(agent_id TEXT, run_id TEXT, lane TEXT, state TEXT, admitted INT, invocation TEXT, unit TEXT, port INT, run_dir TEXT)')
            c.execute('INSERT INTO task_proxies VALUES (?,?,?,?,?,?,?,?,?)', ('a','r','task-123','running',1,'inv-1','task-mitm-task-123',0,str(self.root)))
            c.execute('CREATE TABLE proxy_attempts(agent_id TEXT, run_id TEXT, lane TEXT, outcome TEXT)')
            c.execute('INSERT INTO proxy_attempts VALUES (?,?,?,?)', ('a','r','task-123','running'))
        self.systemd = self.root / 'systemd-output'
        self.systemd.write_text(f'ActiveState=active\nInvocationID=inv-1\nMainPID={os.getpid()}\n')


    def tearDown(self):
        if hasattr(self, 'listener'):
            self.listener.close()
        self.temp.cleanup()

    def sample(self, action, ip='8.8.8.8', mutate=False, bad_cert=False, mutate_ca=False, expect_connection=True, mutate_listener=False, bad_hostname=False, race_record=False, assert_lock=False):
        if bad_hostname:
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(self.root/'key.pem'), '-out', str(self.root/'cert.pem'),
                '-days', '1', '-subj', '/CN=wrong.example', '-addext',
                'subjectAltName=DNS:wrong.example'], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=True)
            (self.root/'mitmproxy/mitmproxy-ca-cert.pem').write_bytes((self.root/'cert.pem').read_bytes())
        identity = json.loads(self.identity.read_text())
        if not hasattr(self, 'listener'):
            self.listener = socket.socket()
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind(('127.0.0.1', identity['port']))
            self.listener.listen(1)
        listener = self.listener
        listener.settimeout(2 if expect_connection else 1)
        identity['port'] = listener.getsockname()[1]
        self.identity.write_text(json.dumps(identity))
        with sqlite3.connect(self.db) as c:
            c.execute('UPDATE task_proxies SET port=?', (identity['port'],))
        errors = []
        replacement = []
        def serve():
            try:
                conn, _ = listener.accept()
                if not expect_connection:
                    errors.append('unexpected proxy connection')
                with conn:
                    if assert_lock:
                        with open(self.db.with_suffix('.lock'), 'a') as lock:
                            try:
                                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            except BlockingIOError:
                                pass
                            else:
                                errors.append('sample was not lifecycle fenced')
                    request = b''
                    while b'\r\n\r\n' not in request: request += conn.recv(4096)
                    assert request.startswith(b'CONNECT api.ipify.org:443 HTTP/1.')
                    conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(self.root/'cert.pem', self.root/'key.pem')
                    try:
                        with ctx.wrap_socket(conn, server_side=True) as tls:
                            data = b''
                            while b'\r\n\r\n' not in data: data += tls.recv(4096)
                            assert data.startswith(b'GET / HTTP/1.')
                            if mutate:
                                self.systemd.write_text(f'ActiveState=active\nInvocationID=replaced\nMainPID={os.getpid()}\n')
                            if race_record:
                                target = self.state/'inc-1.json'
                                target.write_bytes(b'concurrent record')
                                target.chmod(0o600)
                            if mutate_listener:
                                listener.close()
                                new_listener = socket.socket()
                                new_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                new_listener.bind(('127.0.0.1', identity['port']))
                                new_listener.listen(1)
                                replacement.append(new_listener)
                            if mutate_ca:
                                ca = self.root/'mitmproxy/mitmproxy-ca-cert.pem'
                                ca.write_bytes(ca.read_bytes() + (self.root/'cert.pem').read_bytes())
                            body = ip.encode(); tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
                    except ssl.SSLError:
                        if not (bad_cert or bad_hostname): raise
            except socket.timeout:
                if expect_connection: errors.append('expected proxy connection missing')
            except Exception as exc: errors.append(repr(exc))
        thread = threading.Thread(target=serve); thread.start()
        env = dict(os.environ, BROWSER_PROVISIONER_STATE=str(self.db), PATH=str(self.root) + ':' + os.environ['PATH'])
        if bad_cert:
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(self.root/'other-key.pem'), '-out', str(self.root/'other-cert.pem'), '-days', '1', '-subj', '/CN=Other'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            (self.root/'mitmproxy/mitmproxy-ca-cert.pem').write_bytes((self.root/'other-cert.pem').read_bytes())
        cmd = [sys.executable, str(self.fixture_script), action, '--agent-id', 'a', '--run-id', 'r', '--expected-lane', 'task-123', '--incident-id', 'inc-1', '--state-dir', str(self.state)]
        result = subprocess.run(cmd, env=env, text=True, capture_output=True, timeout=10)
        thread.join(6)
        if not expect_connection and select.select([listener], [], [], 0)[0]:
            errors.append('unexpected queued proxy connection')
        for sock in replacement: sock.close()
        self.assertFalse(thread.is_alive()); self.assertEqual(errors, [], result.stdout + result.stderr)
        return result

    def test_fixture_entrypoint_holds_manager_lock_during_sample(self):
        result = self.sample('record', assert_lock=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_compare_does_not_sample(self):
        result = self.sample('compare', expect_connection=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['status'], 'blocked')
        self.assertNotIn('8.8.8.8', result.stdout + result.stderr)

    def test_existing_or_invalid_record_rejected_without_sample(self):
        first = self.sample('record')
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        path = self.state/'inc-1.json'
        baseline = path.read_bytes()
        result = self.sample('record', expect_connection=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(path.read_bytes(), baseline)
        valid = json.loads(baseline)
        for modified in (b'{', b'[' * 2000 + b'0' + b']' * 2000,
                         json.dumps({**valid, 'salt': 'xyz'}).encode(),
                         json.dumps({**valid, 'digest': 'xyz'}).encode(),
                         json.dumps({**valid, 'identity': {**valid['identity'], 'invocation': 'wrong'}}).encode()):
            with self.subTest(record=modified[:20]):
                path.write_bytes(modified)
                result = self.sample('compare', expect_connection=False)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(path.read_bytes(), modified)
                self.assertNotIn('8.8.8.8', result.stdout + result.stderr)
        path.write_bytes(baseline)
        path.chmod(0o644)
        result = self.sample('compare', expect_connection=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(path.read_bytes(), baseline)

    def test_real_entrypoint_private_baseline_and_changed_comparison(self):
        first = self.sample('record')
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        self.assertEqual(json.loads(first.stdout)['status'], 'recorded')
        same = self.sample('compare')
        self.assertEqual(same.returncode, 0, same.stderr + same.stdout)
        self.assertEqual(json.loads(same.stdout)['status'], 'unchanged')
        second = self.sample('compare', '1.1.1.1')
        self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
        self.assertEqual(json.loads(second.stdout)['status'], 'changed')
        self.assertNotIn('8.8.8.8', first.stdout + first.stderr + second.stdout + second.stderr)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.state/'inc-1.json').stat().st_mode & 0o777, 0o600)

    def test_concurrent_record_is_not_replaced_after_sample(self):
        result = self.sample('record', race_record=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual((self.state/'inc-1.json').read_bytes(), b'concurrent record')
        self.assertEqual([p.name for p in self.state.iterdir()], ['inc-1.json'])

    def test_wrong_ca_is_refused_without_publication(self):
        result = self.sample('record', bad_cert=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['status'], 'blocked')
        self.assertFalse((self.state/'inc-1.json').exists())

    def test_trusted_certificate_for_wrong_hostname_is_refused(self):
        result = self.sample('record', bad_hostname=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['status'], 'blocked')
        self.assertFalse((self.state/'inc-1.json').exists())
        self.assertNotIn('8.8.8.8', result.stdout + result.stderr)

    def test_process_change_during_sample_is_not_published(self):
        result = self.sample('record', mutate=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.state/'inc-1.json').exists())

    def test_listener_replaced_by_same_process_during_sample_is_not_published(self):
        result = self.sample('record', mutate_listener=True)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse((self.state/'inc-1.json').exists())

    def test_ca_replacement_during_sample_is_not_published(self):
        result = self.sample('record', mutate_ca=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.state/'inc-1.json').exists())

    def test_real_lane_snapshot_binds_process_listener_and_generation(self):
        spec = importlib.util.spec_from_file_location('adapter_test', SCRIPT)
        adapter = importlib.util.module_from_spec(spec); spec.loader.exec_module(adapter)
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1)
        self.addCleanup(listener.close)
        db = self.root / 'other-manager.sqlite'
        with sqlite3.connect(db) as c:
            c.execute('CREATE TABLE task_proxies(agent_id TEXT, run_id TEXT, lane TEXT, state TEXT, admitted INT, invocation TEXT, unit TEXT, port INT, run_dir TEXT)')
            c.execute('INSERT INTO task_proxies VALUES (?,?,?,?,?,?,?,?,?)', ('a','r','task-123','running',1,'inv-1','task-mitm-task-123',listener.getsockname()[1],str(self.root)))
            c.execute('CREATE TABLE proxy_attempts(agent_id TEXT, run_id TEXT, lane TEXT, outcome TEXT)')
            c.execute('INSERT INTO proxy_attempts VALUES (?,?,?,?)', ('a','r','task-123','running'))
        certdir = self.root / 'mitmproxy'; certdir.mkdir(exist_ok=True)
        (certdir / 'mitmproxy-ca-cert.pem').write_bytes((self.root / 'cert.pem').read_bytes())
        adapter.systemd_identity = lambda unit: ('inv-1', os.getpid())
        os.environ['BROWSER_PROVISIONER_STATE'] = str(db)
        self.addCleanup(os.environ.pop, 'BROWSER_PROVISIONER_STATE', None)
        args = type('Args', (), {'agent_id':'a','run_id':'r','expected_lane':'task-123'})()
        identity = adapter.lane_snapshot(args)
        self.assertEqual(identity['lane'], 'task-123')
        self.assertEqual(identity['pid'], os.getpid())
        self.assertEqual(identity['port'], listener.getsockname()[1])
        adapter.systemd_identity = lambda unit: ('wrong-invocation', os.getpid())
        with self.assertRaises(adapter.Blocked): adapter.lane_snapshot(args)
        adapter.systemd_identity = lambda unit: ('inv-1', os.getpid())
        with sqlite3.connect(db) as c:
            c.execute("UPDATE proxy_attempts SET outcome='capture-uncertain'")
        with self.assertRaises(adapter.Blocked): adapter.lane_snapshot(args)

    def test_invalid_cli_arguments_do_not_echo_sensitive_values(self):
        marker = '8.8.8.8'
        result = subprocess.run([sys.executable, str(SCRIPT), marker], text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(marker, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'blocked')

    def test_production_gate_refuses_before_network_or_incident_publication(self):
        result = subprocess.run([sys.executable, str(SCRIPT), 'record', '--agent-id', 'a', '--run-id', 'r', '--expected-lane', 'task-123', '--incident-id', 'inc-1', '--state-dir', str(self.state)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['status'], 'blocked')
        self.assertFalse(self.state.exists())

    def test_snapshot_reads_both_rows_in_one_transaction(self):
        from unittest import mock
        spec = importlib.util.spec_from_file_location('snapshot_tx', SCRIPT)
        adapter = importlib.util.module_from_spec(spec); spec.loader.exec_module(adapter)
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1)
        self.addCleanup(listener.close)
        with sqlite3.connect(self.db) as c:
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('UPDATE task_proxies SET port=?', (listener.getsockname()[1],))
        real_connect = sqlite3.connect
        db_path = self.db
        class Connection:
            def __init__(self, *args, **kwargs): self.c = real_connect(*args, **kwargs)
            def __enter__(self): return self
            def __exit__(self, *args): return self.c.__exit__(*args)
            @property
            def row_factory(self): return self.c.row_factory
            @row_factory.setter
            def row_factory(self, value): self.c.row_factory = value
            def execute(self, sql, *args):
                cursor = self.c.execute(sql, *args)
                if sql.startswith('SELECT * FROM task_proxies'):
                    class Cursor:
                        def fetchone(inner):
                            result = cursor.fetchone()
                            with real_connect(db_path) as writer:
                                writer.execute("UPDATE proxy_attempts SET outcome='capture-uncertain'")
                            return result
                    return Cursor()
                return cursor
        with mock.patch.object(adapter.sqlite3, 'connect', side_effect=Connection), \
             mock.patch.object(adapter, 'systemd_identity', return_value=('inv-1', os.getpid())), \
             mock.patch.dict(os.environ, BROWSER_PROVISIONER_STATE=str(self.db)):
            args = type('Args', (), {'agent_id':'a','run_id':'r','expected_lane':'task-123'})()
            self.assertEqual(adapter.lane_snapshot(args)['lane'], 'task-123')
        with real_connect(self.db) as c:
            self.assertEqual(c.execute('SELECT outcome FROM proxy_attempts').fetchone()[0], 'capture-uncertain')

    def test_bbh_dispatcher_reaches_closed_source_gate(self):
        # A private checkout-shaped launcher tree; no installed environment.
        import shutil
        root = self.root / 'checkout'
        (root/'scripts').mkdir(parents=True)
        (root/'skills/chromium-test/scripts').mkdir(parents=True)
        source = SCRIPT.parents[3]
        for name in ('bbh', 'bbh.py'):
            shutil.copyfile(source/'scripts'/name, root/'scripts'/name)
        shutil.copyfile(SCRIPT, root/'skills/chromium-test/scripts/task_proxy_incident.py')
        shutil.copyfile(SCRIPT.parent/'browser_lifecycle.py', root/'skills/chromium-test/scripts/browser_lifecycle.py')
        (root/'.venv/bin').mkdir(parents=True)
        (root/'.venv/bin/python').symlink_to(sys.executable)
        result = subprocess.run([sys.executable, str(root/'scripts/bbh'),
            'skills/chromium-test/scripts/task_proxy_incident.py', 'record',
            '--agent-id', 'a', '--run-id', 'r', '--expected-lane', 'task-123',
            '--incident-id', 'inc-1', '--state-dir', str(self.state)],
            text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'blocked')
        self.assertFalse(self.state.exists())

if __name__ == '__main__': unittest.main()
