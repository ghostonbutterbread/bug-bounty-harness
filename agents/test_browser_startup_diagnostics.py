"""Local-only deterministic startup failures and sanitized fixture retention."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "skills/chromium-test/scripts"))
from browser_lifecycle import StartupDiagnostics
from agents.test_browser_provisioner import load, start_args
from agents import test_browser_lifecycle_systemd as fixture

SECRET = 'https://user:password@example.invalid/?token=control-secret Cookie: sid=secret'


def test_bounded_private_metadata_and_stderr(tmp_path):
    diag = StartupDiagnostics("launcher", tmp_path / "private")
    with pytest.raises(TimeoutError):
        with diag.phase("pipe-ready"):
            raise TimeoutError(SECRET)
    read, write = os.pipe()
    thread = diag.drain_stderr(os.fdopen(read, "rb"))
    for _ in range(2000):
        os.write(write, SECRET.encode())
    os.close(write)
    thread.join(5)
    assert not thread.is_alive()
    for _ in range(100):
        diag.mark("spawn")
    text = diag.path.read_text()
    data = json.loads(text)
    assert len(data["events"]) == 32
    assert data["events"][1]["error_category"] == "timeout"
    assert data["stderr_bytes_observed"] == 65536
    assert data["stderr_limit_reached"]
    assert len(text) < 8192 and SECRET not in text and 'control-secret' not in text
    assert diag.path.stat().st_mode & 0o777 == 0o600
    assert diag.path.parent.stat().st_mode & 0o777 == 0o700
    assert not list(diag.path.parent.glob('.receipt-*'))


def test_disabled_and_unwritable_diagnostics_do_not_change_errors(monkeypatch, tmp_path):
    monkeypatch.delenv("BROWSER_STARTUP_RECEIPT_DIR", raising=False)
    disabled = StartupDiagnostics("launcher")
    disabled.mark("spawn")
    assert disabled.path is None and not disabled.events
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("unchanged")
    diag = StartupDiagnostics("launcher", blocker / "child")
    original = FileNotFoundError(SECRET)
    with pytest.raises(FileNotFoundError) as caught:
        with diag.phase("spawn"):
            raise original
    assert caught.value is original
    assert blocker.read_text() == "unchanged"


@pytest.mark.parametrize('failure,phase,category', [
    ('timeout', 'publication', 'timeout'),
    ('malformed', 'publication', 'unexpected'),
    ('unreadable', 'publication', 'os-error'),
    ('dispatch', 'dispatch', 'unexpected'),
    ('registration', 'registration', 'unexpected'),
])
def test_manager_failure_receipts(monkeypatch, tmp_path, capsys, failure, phase, category):
    m = load(monkeypatch, tmp_path)
    monkeypatch.setenv('BROWSER_STARTUP_DIAGNOSTICS', '1')
    monkeypatch.setattr(m, 'sweep_rows', lambda *a: ([], []))
    monkeypatch.setattr(m, 'admission', lambda *a: {'status': 'admitted'})
    monkeypatch.setattr(m.uuid, 'uuid4', lambda: '00000000-0000-0000-0000-000000000001')
    monkeypatch.setattr(m, 'LAUNCH_WAIT_SECONDS', 0)  # deterministic timeout, no production deadline change
    monkeypatch.setattr(m, 'unit_active', lambda unit: True)
    calls, stopped, released = [], [], []
    if failure == 'unreadable':
        original_read, original_stat = Path.read_text, Path.stat
        def unreadable(path, *args, **kwargs):
            if path.name.endswith('.launch.json'):
                raise PermissionError(SECRET)
            return original_read(path, *args, **kwargs)
        def no_diagnostic_restat(path, *args, **kwargs):
            if path.name.endswith('.launch.json'):
                raise PermissionError('diagnostics must not restat failed publication')
            return original_stat(path, *args, **kwargs)
        monkeypatch.setattr(Path, 'read_text', unreadable)
        monkeypatch.setattr(Path, 'stat', no_diagnostic_restat)
    def run(command, **kwargs):
        calls.append(command)
        launch = tmp_path / 'state/00000000-0000-0000-0000-000000000001.launch.json'
        if failure == 'malformed':
            launch.write_text(SECRET)
        elif failure == 'registration':
            launch.write_text(json.dumps({'cdp_url': SECRET}))
        return SimpleNamespace(returncode=int(failure == 'dispatch'), stdout='', stderr=SECRET)
    monkeypatch.setattr(m.subprocess, 'run', run)
    monkeypatch.setattr(m, 'stop_unit', lambda unit: stopped.append(unit))
    monkeypatch.setattr(m, 'release_lease', lambda *a: released.append(a))
    monkeypatch.setattr(m, 'lease', lambda args, action, *rest:
                        {'status': 'leased', 'lease': {'lease_id': 'lease', 'account_alias': 'fixture',
                         'auth_domain': 'default', 'profile_dir': str(tmp_path / 'profile')}}
                        if action == 'acquire' else {'status': 'failed'})
    with pytest.raises(SystemExit) as caught:
        m.start(start_args())
    assert caught.value.code == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'launch-failed'
    data = json.loads(next((tmp_path / 'state/startup').glob('*/manager.json')).read_text())
    assert data['events'][-1]['phase'] == phase
    assert data['events'][-1]['error_category'] == category
    assert data['events'][-1]['outcome'] == 'failed'
    assert SECRET not in json.dumps(data)
    assert released and (stopped or failure == 'dispatch')
    assert any(part.startswith('--setenv=BROWSER_STARTUP_RECEIPT_DIR=') for part in calls[0])


def test_adapter_pipe_timeout_records_own_boundary(tmp_path):
    from browser_control import PipeBrowser
    bridge = object.__new__(PipeBrowser)
    bridge.diagnostics = StartupDiagnostics('launcher', tmp_path / 'private')
    bridge.token = 'control-secret'
    async def timeout(*a):
        raise TimeoutError(SECRET)
    bridge.call = timeout
    async def exercise():
        try:
            with pytest.raises(TimeoutError):
                await bridge._serve(0, tmp_path / 'control.sock')
        finally:
            await bridge.runner.cleanup()
            await bridge.control_runner.cleanup()
    asyncio.run(exercise())
    data = json.loads(bridge.diagnostics.path.read_text())
    assert data['events'][-1]['phase'] == 'pipe-ready'
    assert data['events'][-1]['error_category'] == 'timeout'
    assert 'control-secret' not in json.dumps(data)


def test_real_exec_failure_is_private_and_process_is_reaped(monkeypatch, tmp_path):
    from browser_control import PipeBrowser
    directory = tmp_path / 'private'
    monkeypatch.setenv('BROWSER_STARTUP_RECEIPT_DIR', str(directory))
    diag = StartupDiagnostics('launcher', directory)
    diag.mark('spawn')
    bridge = PipeBrowser([str(tmp_path / 'missing-control-secret')], diagnostics=diag,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert bridge.process.wait(timeout=10) != 0
        diag.failed(ConnectionError(SECRET), bridge.process.returncode)
    finally:
        bridge.close()
    assert not bridge.thread.is_alive() and not bridge.stderr_thread.is_alive()
    data = json.loads((directory / 'exec.json').read_text())
    assert data['events'][-1]['error_category'] == 'os-error'
    assert data['events'][-1]['phase'] == 'exec'
    assert json.loads(diag.path.read_text())['stderr_bytes_observed'] > 0
    assert all('control-secret' not in path.read_text() for path in directory.glob('*.json'))


def test_failure_evidence_survives_deleted_profile(monkeypatch):
    monkeypatch.setattr(fixture, 'stop_fixture_units', lambda root: None)
    with pytest.raises(RuntimeError):
        with fixture.disposable_fixture_root() as (root, evidence):
            diag = StartupDiagnostics('launcher', root / 'state/startup/attempt')
            diag.mark('pipe-ready', 'failed', TimeoutError(SECRET))
            (root / 'profile').mkdir()
            (root / 'profile/cookies').write_text(SECRET)
            raise RuntimeError(SECRET)
    assert not root.exists()
    text = (evidence / 'startup.json').read_text()
    data = json.loads(text)
    assert data['fixture_failed'] and data['cleanup_verified']
    assert data['snapshots'][0]['events'][0]['phase'] == 'pipe-ready'
    assert SECRET not in text
    assert (evidence / 'startup.json').stat().st_mode & 0o777 == 0o600
    shutil.rmtree(evidence)


def test_failed_stop_retains_profile_and_evidence(monkeypatch):
    def fail(root):
        raise RuntimeError('unverified stop')
    monkeypatch.setattr(fixture, 'stop_fixture_units', fail)
    with pytest.raises(RuntimeError, match='unverified stop'):
        with fixture.disposable_fixture_root() as (root, evidence):
            (root / 'profile').mkdir()
    assert (root / 'profile').is_dir()
    assert not json.loads((evidence / 'startup.json').read_text())['cleanup_verified']
    shutil.rmtree(root)
    shutil.rmtree(evidence)


def test_cleanup_includes_unregistered_launch_only_exact_units(monkeypatch, tmp_path):
    bid = '00000000-0000-0000-0000-000000000001'
    (tmp_path / 'state/startup' / bid).mkdir(parents=True)
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout='inactive\n')
    monkeypatch.setattr(fixture.subprocess, 'run', run)
    fixture.stop_fixture_units(tmp_path)
    assert [call[-1] for call in calls if 'stop' in call] == ['browser-' + bid, 'browser-owner-' + bid]
    assert len(calls) == 4
