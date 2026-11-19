"""Offline lifecycle fence tests, using exec workers in network-none containers."""
from argparse import Namespace
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'


def fixture_adapter(root):
    """A private code copy substitutes only the observation, not its fence."""
    root = Path(root)
    script = root / 'incident-fixture.py'
    source = (SCRIPTS / 'task_proxy_incident.py').read_text()
    fixture = '''\ndef observe(args):
    import fcntl
    root = Path(args.state_dir)
    if args.operation == 'lock':
        with open(root / 'manager.lock', 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return 'recorded'
            return 'unfenced'
    (root / 'inside').touch()
    if args.operation == 'sleep':
        time.sleep(60)
    if args.operation == 'wait':
        while not (root / 'release').exists():
            time.sleep(.01)
    return 'recorded'
\n'''
    script.write_text(source.replace("if __name__ == '__main__':", fixture + "if __name__ == '__main__':"))
    shutil.copyfile(SCRIPTS / 'browser_lifecycle.py', root / 'browser_lifecycle.py')
    spec = importlib.util.spec_from_file_location('fixture_incident', script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return script, module


class LifecycleFence(unittest.TestCase):
    def test_observation_holds_provisioner_lock(self):
        with tempfile.TemporaryDirectory() as root:
            _, incident = fixture_adapter(root)
            result = incident.bounded_observation(Path(root) / 'manager.sqlite',
                Namespace(state_dir=root, operation='lock'), 2)
            self.assertEqual(result, 'recorded')

    def test_deadline_includes_waiting_for_lifecycle_lock(self):
        with tempfile.TemporaryDirectory() as root:
            _, incident = fixture_adapter(root)
            state = Path(root) / 'manager.sqlite'
            with open(state.with_suffix('.lock'), 'a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                started = time.monotonic()
                with self.assertRaises(incident.Blocked):
                    incident.bounded_observation(state, Namespace(state_dir=root, operation='sleep'), .3)
                self.assertLess(time.monotonic() - started, 2)
                self.assertFalse((Path(root) / 'inside').exists())

    def test_entire_observation_deadline_releases_lock(self):
        with tempfile.TemporaryDirectory() as root:
            _, incident = fixture_adapter(root)
            state = Path(root) / 'manager.sqlite'
            started = time.monotonic()
            with self.assertRaises(incident.Blocked):
                incident.bounded_observation(state, Namespace(state_dir=root, operation='sleep'), .7)
            self.assertTrue((Path(root) / 'inside').exists(), 'worker did not reach observation')
            self.assertLess(time.monotonic() - started, 3)
            with open(state.with_suffix('.lock'), 'a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_active_generation_finish_waits_for_observation(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            script, _ = fixture_adapter(root)
            state = root / 'manager.sqlite'
            env = dict(os.environ, HOME=str(root), TMPDIR=str(root),
                XDG_CONFIG_HOME=str(root / 'config'), XDG_CACHE_HOME=str(root / 'cache'),
                XDG_DATA_HOME=str(root / 'data'), XDG_STATE_HOME=str(root / 'state'),
                BROWSER_PROVISIONER_STATE=str(state))
            setup = '''import sys; sys.path.insert(0,sys.argv[1]); import browser_provisioner as p
c=p.db(); c.execute("INSERT INTO task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state,invocation,admitted) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",('a','r','p','x','test','task-123',8888,'task-mitm-task-123',sys.argv[2],'running','inv-1',1)); c.execute("INSERT INTO proxy_attempts VALUES(?,?,?,?)",('a','r','task-123','running')); c.commit()
'''
            subprocess.run([sys.executable, '-c', setup, str(SCRIPTS), str(root)], env=env, check=True)
            observer_code = '''import importlib.util,sys
from pathlib import Path
from argparse import Namespace
s=importlib.util.spec_from_file_location('fixture_incident',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
assert m.bounded_observation(Path(sys.argv[2])/'manager.sqlite',Namespace(state_dir=sys.argv[2],operation='wait'),5)=='recorded'
'''
            finish_code = '''import sys; from pathlib import Path; from argparse import Namespace; sys.path.insert(0,sys.argv[1]); import browser_provisioner as p
root=Path(sys.argv[2]); active=[True]
p.unit_active=lambda unit: active[0]
p.unit_identity=lambda unit: 'inv-1'
def stop(unit):
 (root/'stopped').write_text(unit); active[0]=False
p.stop_unit=stop
p.port_open=lambda port: False
p.finish_capture_index=lambda row: (Path('/fixture/capture'),True)
p.task_proxy_finish(Namespace(agent_id='a',run_id='r',expected_lane='task-123'))
'''
            observer = subprocess.Popen([sys.executable, '-c', observer_code, str(script), str(root)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            finish = None
            try:
                until = time.monotonic() + 3
                while not (root / 'inside').exists() and time.monotonic() < until and observer.poll() is None:
                    time.sleep(.01)
                self.assertTrue((root / 'inside').exists(), observer.communicate(timeout=1) if observer.poll() is not None else '')
                finish = subprocess.Popen([sys.executable, '-c', finish_code, str(SCRIPTS), str(root)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(.3)
                self.assertIsNone(finish.poll(), 'finish escaped lifecycle lock')
                self.assertFalse((root / 'stopped').exists())
                with sqlite3.connect(state) as db:
                    self.assertEqual(db.execute('SELECT state FROM task_proxies').fetchone()[0], 'running')
                (root / 'release').touch()
                out, err = observer.communicate(timeout=5)
                self.assertEqual(observer.returncode, 0, (out, err))
                out, err = finish.communicate(timeout=5)
                self.assertEqual(finish.returncode, 0, (out, err))
                self.assertEqual(json.loads(out)['status'], 'finished')
                self.assertEqual((root / 'stopped').read_text(), 'task-mitm-task-123')
                with sqlite3.connect(state) as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM task_proxies').fetchone()[0], 0)
                    self.assertEqual(db.execute('SELECT outcome FROM proxy_attempts').fetchone()[0], 'finished')
            finally:
                for process in (observer, finish):
                    if process is not None:
                        if process.poll() is None:
                            process.kill()
                        process.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()
