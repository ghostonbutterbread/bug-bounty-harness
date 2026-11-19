"""Real process-boundary regressions; run only in a network-none container."""
import fcntl
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'


class ProcessBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'manager.sqlite'
        with sqlite3.connect(self.state) as db:
            db.execute('CREATE TABLE task_proxies(agent_id TEXT,run_id TEXT,lane TEXT,state TEXT,admitted INT,invocation TEXT,unit TEXT,port INT,run_dir TEXT)')
            db.execute('CREATE TABLE proxy_attempts(agent_id TEXT,run_id TEXT,lane TEXT,outcome TEXT)')
            db.execute('INSERT INTO task_proxies VALUES (?,?,?,?,?,?,?,?,?)', ('a','r','task-123','running',1,'inv-1','task-mitm-task-123',8888,str(self.root)))
            db.execute('INSERT INTO proxy_attempts VALUES (?,?,?,?)', ('a','r','task-123','running'))
        fake = self.root / 'systemctl'
        fake.write_text('#!' + sys.executable + '\nimport os,time\nfrom pathlib import Path\nPath(' + repr(str(self.root / 'pids')) + ').write_text(str(os.getppid())+" "+str(os.getpid()))\ntime.sleep(60)\n')
        fake.chmod(0o700)
        env = dict(os.environ, HOME=str(self.root), TMPDIR=str(self.root),
                   BROWSER_PROVISIONER_STATE=str(self.state), PATH=str(self.root) + ':/usr/bin:/bin',
                   PRIVATE_ENV_CANARY='private-fixture-canary')
        code = '''import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1]); import task_proxy_incident as i
f=os.open(sys.argv[2]+'/private-secret',os.O_CREAT|os.O_RDWR,0o600)
os.write(f,b'secret'); os.set_inheritable(f,False)
g=os.open(sys.argv[2]+'/inheritable-secret',os.O_CREAT|os.O_RDWR,0o600)
os.set_inheritable(g,True)
Path(sys.argv[2]+'/parent-ready').write_text(str(f))
if sys.argv[3] == 'forkhold':
 root=sys.argv[2]
 real_popen=i.subprocess.Popen
 def forkhold(*a,**kw):
  proc=real_popen(*a,**kw)
  child=os.fork()
  if child==0:
   import time
   Path(root+'/holder').write_text(str(os.getpid()))
   os.close(0); os.close(1); os.close(2)
   time.sleep(60); os._exit(0)
  return proc
 i.subprocess.Popen=forkhold
if sys.argv[3] == 'watchdog':
 from argparse import Namespace
 args=Namespace(action='record',agent_id='a',run_id='r',expected_lane='task-123',incident_id='inc',state_dir=sys.argv[2]+'/out')
 try: i.bounded_observation(Path(sys.argv[2])/'manager.sqlite',args,1.5)
 except i.Blocked: print('blocked')
 else: raise SystemExit(3)
else:
 sys.argv=['incident','record','--agent-id','a','--run-id','r','--expected-lane','task-123','--incident-id','inc','--state-dir',sys.argv[2]+'/out']
 i.main()
'''
        if self._testMethodName == 'test_parent_death_is_detected_when_another_child_holds_the_pipe':
            mode = 'forkhold'
        elif self._testMethodName == 'test_watchdog_stops_hanging_systemctl_and_releases_lock':
            mode = 'watchdog'
        else:
            mode = 'main'
        self.parent = subprocess.Popen([sys.executable, '-c', code, str(SCRIPTS), str(self.root), mode], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.pids = ()
        self.pidfds = []
        self.holder_fd = None
        self.addCleanup(self.cleanup_processes)
        deadline = time.monotonic() + 5
        while not (self.root / 'pids').exists() and time.monotonic() < deadline and self.parent.poll() is None:
            time.sleep(.01)
        self.assertTrue((self.root / 'pids').exists(), self.parent.communicate(timeout=1) if self.parent.poll() is not None else 'fake systemctl did not start')
        self.pids = tuple(map(int, (self.root / 'pids').read_text().split()))
        self.pidfds = [os.pidfd_open(pid) for pid in self.pids]
        if mode == 'forkhold':
            self.assertTrue((self.root / 'holder').exists())
            self.holder_fd = os.pidfd_open(int((self.root / 'holder').read_text()))

    def cleanup_processes(self):
        if self.parent.poll() is None:
            self.parent.kill()
        self.parent.communicate(timeout=3)
        for fd in self.pidfds + ([self.holder_fd] if self.holder_fd is not None else []):
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(fd)

    def test_worker_does_not_inherit_private_descriptor(self):
        worker, _ = self.pids
        links = []
        for fd in (Path('/proc') / str(worker) / 'fd').iterdir():
            try:
                links.append(os.readlink(fd))
            except FileNotFoundError:
                pass
        self.assertNotIn(str(self.root / 'private-secret'), links)
        self.assertNotIn(str(self.root / 'inheritable-secret'), links)
        environment = (Path('/proc') / str(worker) / 'environ').read_bytes()
        self.assertNotIn(b'PRIVATE_ENV_CANARY=', environment)
        self.assertNotIn(b'private-fixture-canary', environment)

    def test_supervisor_death_does_not_guarantee_descendant_cleanup(self):
        # This is an explicit limitation, not a live-admission guarantee.
        import select
        worker = self.pids[0]
        fields = (Path('/proc') / str(worker) / 'stat').read_text().rsplit(')', 1)[1].split()
        supervisor_fd = os.pidfd_open(int(fields[1]))
        try:
            signal.pidfd_send_signal(supervisor_fd, signal.SIGKILL)
            self.assertTrue(select.select([supervisor_fd], [], [], 3)[0])
            for fd in self.pidfds:
                self.assertFalse(select.select([fd], [], [], .1)[0], 'expected surviving owned fixture')
        finally:
            os.close(supervisor_fd)

    def test_watchdog_stops_hanging_systemctl_and_releases_lock(self):
        out, err = self.parent.communicate(timeout=5)
        self.assertEqual(self.parent.returncode, 0, err)
        self.assertEqual(out, b'blocked\n')
        for fd in self.pidfds:
            # pidfd becomes readable at process exit, including zombies.
            import select
            self.assertTrue(select.select([fd], [], [], 3)[0])
        with open(self.state.with_suffix('.lock'), 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_parent_death_is_detected_when_another_child_holds_the_pipe(self):
        import select
        self.parent.kill()
        self.parent.wait(timeout=3)
        for fd in self.pidfds:
            self.assertTrue(select.select([fd], [], [], 3)[0], 'owned worker survived caller death')
        self.assertFalse(select.select([self.holder_fd], [], [], 0)[0], 'fixture holder should remain alive')
        with open(self.state.with_suffix('.lock'), 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_parent_sigkill_stops_worker_and_hanging_systemctl_and_releases_lock(self):
        import select
        self.parent.kill()
        self.parent.wait(timeout=3)
        for fd in self.pidfds:
            self.assertTrue(select.select([fd], [], [], 4)[0], 'owned process survived caller death')
        with open(self.state.with_suffix('.lock'), 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)


class SupervisorDeadline(unittest.TestCase):
    def test_direct_worker_closes_inherited_fd_above_lowered_soft_limit(self):
        import shutil
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            script = root / 'incident.py'
            source = (SCRIPTS / 'task_proxy_incident.py').read_text()
            override = '''\ndef observe(args):
    try:
        target = os.readlink('/proc/self/fd/300')
    except FileNotFoundError:
        return 'recorded'
    return 'unsafe' if target == args.secret else 'recorded'
\n'''
            script.write_text(source.replace("if __name__ == '__main__':", override + "if __name__ == '__main__':"))
            shutil.copyfile(SCRIPTS / 'browser_lifecycle.py', root / 'browser_lifecycle.py')
            secret = root / 'secret'
            launcher = '''import os, resource, sys
fd = int(sys.argv[1])
os.dup2(fd, 300, inheritable=True)
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
assert hard == resource.RLIM_INFINITY or hard >= 301
resource.setrlimit(resource.RLIMIT_NOFILE, (64, hard))
assert os.sysconf('SC_OPEN_MAX') == 64 and os.fstat(300)
os.execve(sys.executable, [sys.executable, '-I', sys.argv[2], '--_worker'],
          {'HOME': sys.argv[3], 'PATH': '/usr/bin:/bin'})
'''
            with secret.open('w') as fd:
                payload = json.dumps({'state': str(root / 'state'), 'args': {'secret': str(secret)}}).encode() + b'\n'
                result = subprocess.run([sys.executable, '-I', '-c', launcher, str(fd.fileno()), str(script), str(root)],
                    input=payload, capture_output=True, pass_fds=(fd.fileno(),), timeout=5)
                os.fstat(fd.fileno())  # The test parent retains its own descriptor.
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'recorded')

    def test_direct_supervisor_preserves_pidfd_above_lowered_soft_limit(self):
        import shutil
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            script = root / 'incident.py'
            source = (SCRIPTS / 'task_proxy_incident.py').read_text()
            override = "\ndef observe(args):\n    return 'recorded'\n\n"
            script.write_text(source.replace("if __name__ == '__main__':", override + "if __name__ == '__main__':"))
            shutil.copyfile(SCRIPTS / 'browser_lifecycle.py', root / 'browser_lifecycle.py')
            launcher = '''import os, resource, sys
fd = os.pidfd_open(os.getpid())
os.dup2(fd, 300, inheritable=True)
_, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (64, hard))
assert os.readlink('/proc/self/fd/300') == 'anon_inode:[pidfd]'
os.execve(sys.executable, [sys.executable, '-I', sys.argv[1], '--_supervise', '300'],
          {'HOME': sys.argv[2], 'PATH': '/usr/bin:/bin'})
'''
            payload = json.dumps({'state': str(root / 'state'), 'args': {}, 'deadline': time.monotonic() + 10}).encode() + b'\n'
            proc = subprocess.Popen([sys.executable, '-I', '-c', launcher, str(script), str(root)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert proc.stdin is not None and proc.stdout is not None
            try:
                proc.stdin.write(payload)
                proc.stdin.flush()  # Keep the control pipe open while the worker runs.
                import select
                self.assertTrue(select.select([proc.stdout], [], [], 5)[0])
                self.assertEqual(os.read(proc.stdout.fileno(), 32), b'recorded')
                self.assertEqual(proc.wait(timeout=5), 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.communicate(timeout=5)

    def test_direct_supervisor_completes_with_pidfd_above_select_limit(self):
        import shutil
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            script = root / 'incident.py'
            source = (SCRIPTS / 'task_proxy_incident.py').read_text()
            override = "\ndef observe(args):\n    return 'recorded'\n\n"
            script.write_text(source.replace("if __name__ == '__main__':", override + "if __name__ == '__main__':"))
            shutil.copyfile(SCRIPTS / 'browser_lifecycle.py', root / 'browser_lifecycle.py')
            launcher = '''import os, resource, sys
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
assert hard == resource.RLIM_INFINITY or hard >= 1200
resource.setrlimit(resource.RLIMIT_NOFILE, (1200, hard))
fd = os.pidfd_open(os.getpid())
os.dup2(fd, 1100, inheritable=True)
assert os.readlink('/proc/self/fd/1100') == 'anon_inode:[pidfd]'
os.execve(sys.executable, [sys.executable, '-I', sys.argv[1], '--_supervise', '1100'],
          {'HOME': sys.argv[2], 'PATH': '/usr/bin:/bin'})
'''
            payload = json.dumps({'state': str(root / 'state'), 'args': {}, 'deadline': time.monotonic() + 10}).encode() + b'\n'
            proc = subprocess.Popen([sys.executable, '-I', '-c', launcher, str(script), str(root)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert proc.stdin is not None and proc.stdout is not None
            try:
                proc.stdin.write(payload)
                proc.stdin.flush()  # Keep the control pipe open until the complete response.
                import select
                self.assertTrue(select.select([proc.stdout], [], [], 5)[0])
                self.assertEqual(os.read(proc.stdout.fileno(), 32), b'recorded')
                self.assertEqual(proc.wait(timeout=5), 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.communicate(timeout=5)

    def test_bounded_observation_completes_with_high_stdout_fd(self):
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / 'incident.py'
            source = (SCRIPTS / 'task_proxy_incident.py').read_text()
            override = "def _worker():\n    os.write(1, b'recorded')\n\n"
            script.write_text(source.replace("if __name__ == '__main__':", override + "if __name__ == '__main__':"))
            code = '''import importlib.util, os, resource, sys
from argparse import Namespace
from pathlib import Path
_, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
assert hard == resource.RLIM_INFINITY or hard >= 1200
resource.setrlimit(resource.RLIMIT_NOFILE, (1200, hard))
spec=importlib.util.spec_from_file_location('isolated',sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fds=[]
while not fds or fds[-1] < 1100:
 fds.append(os.open('/dev/null', os.O_RDONLY))
real_popen=m.subprocess.Popen
def checked_popen(*args, **kwargs):
 p=real_popen(*args, **kwargs)
 assert p.stdout.fileno() >= 1100, p.stdout.fileno()
 return p
m.subprocess.Popen=checked_popen
assert m.bounded_observation(Path(sys.argv[2])/'state',Namespace(),3)=='recorded'
'''
            result = subprocess.run([sys.executable, '-I', '-c', code, str(script), root], capture_output=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_empty_worker_output_hangup_is_not_success(self):
        import importlib.util
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / 'incident.py'
            source = (SCRIPTS / 'task_proxy_incident.py').read_text()
            override = 'def _worker():\n    pass\n\n'
            script.write_text(source.replace("if __name__ == '__main__':", override + "if __name__ == '__main__':"))
            spec = importlib.util.spec_from_file_location('isolated_incident', script)
            assert spec is not None and spec.loader is not None
            incident = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(incident)
            with self.assertRaises(incident.Blocked):
                incident.bounded_observation(Path(root) / 'state', Namespace(), 3)

    def test_output_poll_errors_do_not_accept_valid_worker_response(self):
        import importlib.util
        import select
        from argparse import Namespace
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / 'incident.py'
            source = (SCRIPTS / 'task_proxy_incident.py').read_text()
            override = "def _worker():\n    os.write(1, b'recorded')\n\n"
            script.write_text(source.replace("if __name__ == '__main__':", override + "if __name__ == '__main__':"))
            spec = importlib.util.spec_from_file_location('isolated_incident', script)
            assert spec is not None and spec.loader is not None
            incident = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(incident)
            real_poll = select.poll
            for error in (select.POLLERR, select.POLLNVAL):
                observed = []
                class ErrorPoll:
                    def __init__(self):
                        self.poller = real_poll()
                    def register(self, fd, flags):
                        self.poller.register(fd, flags)
                    def poll(self, timeout):
                        events = self.poller.poll(timeout)
                        observed.extend(events)
                        return [(fd, flags | error) for fd, flags in events]
                with self.subTest(error=error), patch.object(incident.select, 'poll', ErrorPoll):
                    with self.assertRaises(incident.Blocked):
                        incident.bounded_observation(Path(root) / 'state', Namespace(), 3)
                self.assertTrue(observed and observed[0][1] & select.POLLIN, observed)

    def test_output_hangup_with_buffered_success_is_accepted(self):
        import importlib.util
        import select
        from argparse import Namespace
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / 'incident.py'
            source = (SCRIPTS / 'task_proxy_incident.py').read_text()
            override = "def _worker():\n    os.write(1, b'recorded')\n\n"
            script.write_text(source.replace("if __name__ == '__main__':", override + "if __name__ == '__main__':"))
            spec = importlib.util.spec_from_file_location('isolated_incident', script)
            assert spec is not None and spec.loader is not None
            incident = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(incident)
            real_poll = select.poll
            observed = []
            class HangupPoll:
                def __init__(self):
                    self.poller = real_poll()
                def register(self, fd, flags):
                    self.poller.register(fd, flags)
                def poll(self, timeout):
                    events = self.poller.poll(timeout)
                    observed.extend(events)
                    return [(fd, flags | select.POLLHUP) for fd, flags in events]
            with patch.object(incident.select, 'poll', HangupPoll):
                result = incident.bounded_observation(Path(root) / 'state', Namespace(), 3)
            self.assertEqual(result, 'recorded')
            self.assertTrue(observed and observed[0][1] & select.POLLIN, observed)

    def test_high_pidfd_supervisor_stops_worker_when_control_pipe_hangs_up(self):
        import resource
        import select
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            script = root / 'incident.py'
            source = (SCRIPTS / 'task_proxy_incident.py').read_text()
            marker = root / 'worker-pid'
            override = "def _worker():\n    marker = Path(%r)\n    marker.with_suffix('.tmp').write_text(str(os.getpid()))\n    os.replace(marker.with_suffix('.tmp'), marker)\n    time.sleep(60)\n    os.write(1, b'recorded')\n\n" % str(marker)
            script.write_text(source.replace("if __name__ == '__main__':", override + "if __name__ == '__main__':"))
            low_fd = os.pidfd_open(os.getpid())
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, 1200), hard))
                high_fd = fcntl.fcntl(low_fd, fcntl.F_DUPFD_CLOEXEC, 1100)
            finally:
                resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
                os.close(low_fd)
            worker_fd = None
            proc = None
            try:
                proc = subprocess.Popen([sys.executable, '-I', str(script), '--_supervise', str(high_fd)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    pass_fds=(high_fd,), env={'HOME': str(root), 'PATH': '/usr/bin:/bin'})
                assert proc.stdin is not None and proc.stdout is not None
                payload = json.dumps({'state': str(root / 'state'), 'args': {}, 'deadline': time.monotonic() + 10}).encode() + b'\n'
                proc.stdin.write(payload)
                proc.stdin.flush()
                end = time.monotonic() + 5
                while not marker.exists() and proc.poll() is None and time.monotonic() < end:
                    time.sleep(.01)
                self.assertTrue(marker.exists(), 'worker never started')
                worker_fd = os.pidfd_open(int(marker.read_text()))
                proc.stdin.close()
                self.assertEqual(proc.wait(timeout=5), 0)
                self.assertEqual(proc.stdout.read(), b'')
                poller = select.poll()
                poller.register(worker_fd, select.POLLIN)
                self.assertTrue(poller.poll(3000), 'worker survived control-pipe hangup')
            finally:
                if worker_fd is not None:
                    try:
                        signal.pidfd_send_signal(worker_fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.close(worker_fd)
                if proc is not None:
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait(timeout=5)
                    if proc.stdin and not proc.stdin.closed:
                        proc.stdin.close()
                    if proc.stdout:
                        proc.stdout.close()
                    if proc.stderr:
                        proc.stderr.close()
                os.close(high_fd)

    def test_direct_worker_refuses_when_fd_enumeration_unavailable(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            script = root / 'incident.py'
            source = (SCRIPTS / 'task_proxy_incident.py').read_text()
            override = '''\ndef observe(args):
    return 'recorded'
_real_listdir = os.listdir
def _denied_listdir(path):
    if path == '/proc/self/fd':
        raise PermissionError('fixture: proc fd unavailable')
    return _real_listdir(path)
os.listdir = _denied_listdir
\n'''
            script.write_text(source.replace("if __name__ == '__main__':", override + "if __name__ == '__main__':"))
            payload = json.dumps({'state': str(root / 'state'), 'args': {}}).encode() + b'\n'
            # The test-only module copy is available only if execution reaches the worker.
            import shutil
            shutil.copyfile(SCRIPTS / 'browser_lifecycle.py', root / 'browser_lifecycle.py')
            result = subprocess.run([sys.executable, '-I', str(script), '--_worker'],
                input=payload, capture_output=True, env={'HOME': str(root), 'PATH': '/usr/bin:/bin'}, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, b'')

    def test_direct_worker_entry_drops_extra_descriptors_and_environment(self):
        import shutil
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            script = root / 'incident.py'
            source = (SCRIPTS / 'task_proxy_incident.py').read_text()
            override = '''\ndef observe(args):
    if 'PRIVATE_ENV_CANARY' in os.environ or b'private-fixture-canary' in Path('/proc/self/environ').read_bytes():
        return 'unsafe'
    for entry in Path('/proc/self/fd').iterdir():
        try:
            if os.readlink(entry) == args.secret:
                return 'unsafe'
        except FileNotFoundError:
            pass
    return 'recorded'
\n'''
            script.write_text(source.replace("if __name__ == '__main__':", override + "if __name__ == '__main__':"))
            shutil.copyfile(SCRIPTS / 'browser_lifecycle.py', root / 'browser_lifecycle.py')
            secret = root / 'secret'
            with secret.open('w') as fd:
                payload = json.dumps({'state': str(root / 'state'), 'args': {'secret': str(secret)}}).encode() + b'\n'
                env = dict(os.environ, PRIVATE_ENV_CANARY='private-fixture-canary')
                result = subprocess.run([sys.executable, '-I', str(script), '--_worker'],
                    input=payload, capture_output=True, env=env, pass_fds=(fd.fileno(),), timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'recorded')

    def test_supervisor_restores_sigchld_when_caller_ignores_it(self):
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / 'incident.py'
            source = (SCRIPTS / 'task_proxy_incident.py').read_text()
            override = "def _worker():\n    os.write(1, b'recorded')\n\n"
            script.write_text(source.replace("if __name__ == '__main__':", override + "if __name__ == '__main__':"))
            code = '''import importlib.util,signal,sys
from argparse import Namespace
from pathlib import Path
signal.signal(signal.SIGCHLD,signal.SIG_IGN)
s=importlib.util.spec_from_file_location('isolated',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
assert m.bounded_observation(Path(sys.argv[2])/'state',Namespace(),2)=='recorded'
'''
            result = subprocess.run([sys.executable, '-c', code, str(script), root], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_result_is_not_accepted_until_worker_exits(self):
        import importlib.util
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / 'incident.py'
            source = (SCRIPTS / 'task_proxy_incident.py').read_text()
            override = "def _worker():\n    os.write(1, b'recorded')\n    os.kill(os.getpid(), signal.SIGSTOP)\n\n"
            script.write_text(source.replace("if __name__ == '__main__':", override + "if __name__ == '__main__':"))
            spec = importlib.util.spec_from_file_location('isolated_incident', script)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            with self.assertRaises(module.Blocked):
                module.bounded_observation(Path(root) / 'state', Namespace(), .5)


if __name__ == '__main__':
    unittest.main()
