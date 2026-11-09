"""Offline executable-selection regression; no service or socket is touched."""
import hashlib
import io

import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/chromium-test/scripts'
sys.path.insert(0, str(SCRIPTS))
import mitm_lane as lane
import browser_provisioner as provisioner
import hoster_mitm_lane as wrapper


@pytest.fixture
def task_venv(tmp_path):
    """A separate synthetic task runtime, independent of the checkout venv."""
    bindir = tmp_path / 'task-venv' / 'bin'
    bindir.mkdir(parents=True)
    executable = bindir / 'mitmdump'
    executable.write_text(f'#!{sys.executable}\n')
    executable.chmod(0o700)
    return executable


def mock_shared_preflight(monkeypatch, selected):
    """Provide only the executables and shebang needed by synthetic dispatch."""
    available = {'mitmdump': str(ROOT / '.venv/bin/mitmdump'),
                 'systemd-run': '/synthetic/systemd-run', 'openssl': '/synthetic/openssl',
                 '/usr/bin/mitmdump': '/usr/bin/mitmdump', selected: selected}
    monkeypatch.setattr(lane.shutil, 'which', lambda name: available.get(name))
    original_open = Path.open
    def open_with_system_shebang(path, *args, **kwargs):
        if path == Path('/usr/bin/mitmdump'):
            return io.BytesIO(b'#!/usr/bin/python3\n')
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', open_with_system_shebang)


def test_public_wrapper_selects_system_with_activated_venv(monkeypatch, tmp_path, capsys):
    mock_shared_preflight(monkeypatch, '/usr/bin/mitmdump')
    assert lane.shutil.which('mitmdump') == str(ROOT / '.venv/bin/mitmdump')
    monkeypatch.setattr(lane, 'classify_default_absence', lambda _: {'status': 'not-found'})
    monkeypatch.setattr(lane, 'wait_for_port', lambda *_: True)
    monkeypatch.setattr(lane, 'wait_for_ca', lambda *_: True)
    monkeypatch.setattr(lane, 'signer_fingerprint', lambda *_: 'a' * 64)
    monkeypatch.setattr(lane, 'default_generation_observation', lambda root, state: {
        'status': 'observed-fresh', 'unit': state['unit'], 'pid': state['pid']})
    commands = []
    def unit_command(cmd, env):
        commands.append(cmd)
        if cmd[0] == 'loginctl':
            return subprocess.CompletedProcess(cmd, 0, 'yes\n', '')
        if cmd[0] == 'systemctl':
            return subprocess.CompletedProcess(cmd, 0, 'ActiveState=active\nMainPID=1234\nControlGroup=/user.slice/fake\n', '')
        assert cmd[0] == 'systemd-run'
        return subprocess.CompletedProcess(cmd, 0, '', '')
    monkeypatch.setattr(lane, 'unit_command', unit_command)
    monkeypatch.setattr(wrapper, 'running_on_requested_hoster', lambda _: True)
    state = {}
    def remote(args, argv):
        op = next(x for x in ('observe-default', 'classify-default-absence', 'start') if x in argv)
        if op == 'observe-default':
            if not state:
                return {'status': 'local-failed', 'local_returncode': 2, 'remote_status': 'unknown-state'}
            return {'status': 'observed-fresh', 'lane': state['lane'], 'unit': state['unit'],
                    'pid': state['pid'], 'port': 8080, 'listen_host': state['listen_host'],
                    'signer': 'unverified', 'generation_sha256': 'b' * 64,
                    'flow_path_sha256': hashlib.sha256(state['flow_file'].encode()).hexdigest()}
        if op == 'classify-default-absence':
            return {'status': 'not-found', 'lane': lane.DEFAULT_SHARED_LANE, 'local_returncode': 0}
        monkeypatch.setattr(sys, 'argv', ['mitm_lane.py', '--root', str(tmp_path / 'lanes'), *argv[2:]])
        result = lane.start_lane(lane.parse_args())
        state.update(result)
        return {**result, 'local_returncode': 0 if result['status'] == 'running' else 2}
    monkeypatch.setattr(wrapper, 'run_remote', remote)
    monkeypatch.setattr(wrapper, 'sync_attested_default_ca', lambda *a, **kw: {'status': 'already-local', 'local_path': str(tmp_path / 'ca')})
    monkeypatch.setattr(sys, 'argv', ['hoster_mitm_lane.py', '--json', 'ensure-default'])
    wrapper.main()
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'running', result
    submitted = [c for c in commands if c[0] == 'systemd-run']
    assert len(submitted) == 1
    assert submitted[0][submitted[0].index('--') + 1] == '/usr/bin/mitmdump'


def test_explicit_selection_and_task_implicit_selection(monkeypatch, task_venv):
    monkeypatch.setenv('PATH', str(task_venv.parent))
    monkeypatch.setattr(sys, 'argv', ['mitm_lane.py', '--lane', lane.DEFAULT_SHARED_LANE,
                                      '--mitmdump', str(ROOT / '.venv/bin/mitmdump'), 'start', '--port', '8080'])
    args = lane.parse_args()
    assert args.mitmdump == str(ROOT / '.venv/bin/mitmdump')
    monkeypatch.setattr(lane, 'classify_default_absence', lambda _: {'status': 'not-found'})
    # Refuse before dispatch; leave all state under a private pytest directory.
    # The public wrapper test above covers actual synthetic dispatch.
    monkeypatch.setattr(sys, 'argv', ['mitm_lane.py', '--lane', 'task', 'start'])
    assert lane.parse_args().mitmdump == 'mitmdump'
    executable, interpreter = provisioner.mitm_runtime()
    assert executable == str(task_venv.resolve())
    assert interpreter == sys.executable
    monkeypatch.setattr(sys, 'argv', ['mitm_lane.py', '--lane', 'task', '--mitmdump', '/custom/mitmdump', 'start'])
    assert lane.parse_args().mitmdump == '/custom/mitmdump'


@pytest.mark.parametrize('executable', [str(ROOT / '.venv/bin/mitmdump'), '/custom/mitmdump'])
def test_explicit_unsupported_refused(monkeypatch, tmp_path, executable):
    monkeypatch.setattr(sys, 'argv', ['mitm_lane.py', '--root', str(tmp_path), '--lane', lane.DEFAULT_SHARED_LANE,
                                      '--mitmdump', executable, 'start', '--port', '8080'])
    monkeypatch.setattr(lane, 'classify_default_absence', lambda _: {'status': 'not-found'})
    mock_shared_preflight(monkeypatch, executable)
    monkeypatch.setattr(lane, 'unit_command', lambda *_: (_ for _ in ()).throw(AssertionError('unexpected dispatch')))
    assert lane.start_lane(lane.parse_args())['status'] == 'unsupported-runtime'
    assert not list(tmp_path.rglob('flows-*.mitm'))


@pytest.mark.parametrize('options,expected', [([], 'mitmdump'),
                                               (['--mitmdump', '/custom/mitmdump'], '/custom/mitmdump')])
def test_task_public_start_selection(monkeypatch, tmp_path, capsys, options, expected):
    monkeypatch.setattr(sys, 'argv', ['mitm_lane.py', '--json', '--root', str(tmp_path),
                                      '--lane', 'task', *options, 'start'])
    monkeypatch.setattr(lane, '_outside_shared', lambda _: True)
    monkeypatch.setattr(lane, '_local_filesystem', lambda _: True)
    monkeypatch.setattr(lane, '_safe_existing_directories', lambda _: True)
    monkeypatch.setattr(lane, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(lane, 'wait_for_port', lambda _: True)
    monkeypatch.setattr(lane, 'verify_recorded_capture', lambda _: None)
    monkeypatch.setattr(lane, 'capture_destination', lambda root, name, program: (root / name / 'flow', None))
    commands = []
    def popen(command, **kwargs):
        commands.append(command)
        return type('FakeProcess', (), {'pid': 12345})()
    monkeypatch.setattr(lane.subprocess, 'Popen', popen)
    assert lane.main() == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'running'
    assert len(commands) == 1 and commands[0][0] == expected


def test_custom_path_selection_remains_unchanged(monkeypatch, tmp_path):
    custom = tmp_path / 'mitmdump'
    custom.write_text(f'#!{sys.executable}\n')
    custom.chmod(0o700)
    monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + str(ROOT / '.venv/bin'))
    monkeypatch.setattr(sys, 'argv', ['mitm_lane.py', '--lane', lane.DEFAULT_SHARED_LANE, 'start', '--port', '8080'])
    assert lane.parse_args().mitmdump == 'mitmdump'
    assert provisioner.mitm_runtime() == (str(custom), sys.executable)


def test_task_reader_selection_without_system_path(monkeypatch, task_venv):
    monkeypatch.setenv('PATH', str(task_venv.parent))
    executable, interpreter = provisioner.mitm_runtime()
    assert executable == str(task_venv.resolve())
    assert interpreter == sys.executable
    for command in ('start', 'index-store', 'replay-flows'):
        monkeypatch.setattr(sys, 'argv', ['mitm_lane.py', '--lane', 'task', command])
        assert lane.parse_args().mitmdump == 'mitmdump'


def test_shared_default_fails_if_system_executable_missing(monkeypatch, tmp_path):
    available = {'mitmdump': str(ROOT / '.venv/bin/mitmdump'),
                 'systemd-run': '/synthetic/systemd-run', 'openssl': '/synthetic/openssl'}
    monkeypatch.setattr(lane.shutil, 'which', lambda executable: available.get(executable))
    monkeypatch.setattr(sys, 'argv', ['mitm_lane.py', '--root', str(tmp_path),
                                      '--lane', lane.DEFAULT_SHARED_LANE, 'start', '--port', '8080'])
    args = lane.parse_args()
    assert args.mitmdump == '/usr/bin/mitmdump'
    monkeypatch.setattr(lane, 'classify_default_absence', lambda _: {'status': 'not-found'})
    monkeypatch.setattr(lane, 'legacy_start_lane', lambda _: pytest.fail('unexpected dispatch'))
    result = lane.start_lane(args)
    assert result['status'] == 'start-failed'
    assert 'executable unavailable' in result['detail']
