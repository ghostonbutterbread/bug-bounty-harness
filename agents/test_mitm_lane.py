from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from agents.test_shared_default_supervision import signer_fixture, install_signer


def load_mitm_lane():
    root = Path(__file__).resolve().parents[1]
    script = root / "skills" / "chromium-test" / "scripts" / "mitm_lane.py"
    spec = importlib.util.spec_from_file_location("mitm_lane", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def shared_start_args(tmp_path, **overrides):
    values = dict(root=str(tmp_path), lane="hoster-default-8080", port=8080,
                  mitmdump="mitmdump", listen_host="0.0.0.0", proxy_host="hoster",
                  program="general", task="default-capture", account_label=None,
                  account=None, profile_dir=None, run_id=None, agent_id=None,
                  runtime_host=None, transport="mixed", browser_profile_id=None,
                  session_source=None)
    values.update(overrides)
    return argparse.Namespace(**values)


def test_task_lane_start_stop_remain_legacy_without_real_services(monkeypatch, tmp_path):
    module = load_mitm_lane()
    commands, signals = [], []
    class FakeProcess:
        pid = 90001
    monkeypatch.setattr(module, 'pid_alive', lambda _pid: False)
    monkeypatch.setattr(module, 'can_bind_localhost', lambda _port: True)
    monkeypatch.setattr(module, 'legacy_wait_for_port', lambda _port: True)
    monkeypatch.setattr(module, 'wait_for_port', lambda _port: True)
    monkeypatch.setattr(module.subprocess, 'Popen', lambda cmd, **kw: commands.append(cmd) or FakeProcess())
    args = shared_start_args(tmp_path, lane='fixture-task', port=8081, program='fixture',
                             agent_id='a', run_id='r', transport='tool', session_source='fixture-session')
    started = module.start_lane(args)
    assert started['status'] == 'running' and started['port'] == 8081
    assert started['agent_id'] == 'a' and started['transport'] == 'tool'
    assert started['session_source'] == 'fixture-session'
    assert commands and '8081' in commands[0]
    monkeypatch.setattr(module, 'pid_alive', lambda pid: bool(pid) and not signals)
    monkeypatch.setattr(module.os, 'killpg', lambda *args: signals.append(args))
    stopped = module.stop_lane(argparse.Namespace(root=str(tmp_path), lane='fixture-task'))
    assert stopped['status'] == 'stopped' and len(signals) == 1
    assert stopped['flow_file'] == started['flow_file']


def test_task_cli_retains_legacy_timeout_exit(monkeypatch, capsys):
    module = load_mitm_lane()
    monkeypatch.setattr(sys, 'argv', ['mitm_lane.py', '--json', '--lane', 'fixture-task', 'start'])
    monkeypatch.setattr(module, 'start_lane', lambda args: {'status': 'start-timeout', 'lane': args.lane})
    assert module.main() == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'start-timeout'


def test_proxy_store_task_parser_and_metadata_defaults(monkeypatch):
    from agents.test_shared_default_supervision import load
    store = load('proxy_store')
    monkeypatch.setattr(sys, 'argv', ['proxy_store.py', 'index-lane', '--lane', 'fixture-task'])
    args = store.parse_args()
    assert args.transport == 'browser'
    assert store.metadata_from_args(args, {'transport': 'tool'})['transport'] == 'browser'
    monkeypatch.setattr(sys, 'argv', ['proxy_store.py', 'index-lane', '--lane', 'fixture-task', '--transport='])
    args = store.parse_args()
    assert args.transport == ''
    assert store.metadata_from_args(args, {'transport': 'tool'})['transport'] == 'tool'
    monkeypatch.setattr(sys, 'argv', ['proxy_store.py', 'index-lane', '--lane', 'hoster-default-8080'])
    args = store.parse_args()
    assert args.transport is None
    assert store.metadata_from_args(args, {'transport': ''})['transport'] == ''


def test_default_start_reuses_live_state_without_modifying_it(monkeypatch, tmp_path, signer_fixture):
    module = load_mitm_lane()
    ca = tmp_path / 'ca.pem'
    install_signer(ca, signer_fixture)
    state = {"status": "running", "pid": 123, "port": 8080, "lane": "hoster-default-8080",
             "listen_host": "0.0.0.0", "flow_file": "old", "ca_cert": str(ca)}
    module.write_state(tmp_path, state["lane"], state)
    original = module.state_path(tmp_path, state["lane"]).read_bytes()
    monkeypatch.setattr(module, "pid_alive", lambda _pid: True)
    monkeypatch.setattr(module, "can_bind_localhost", lambda _port: False)
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **kw: pytest.fail("spawned"))
    result = module.start_lane(shared_start_args(tmp_path))
    assert result["status"] == "unknown-state"
    assert module.read_state(tmp_path, state['lane'])["flow_file"] == "old"
    assert module.state_path(tmp_path, state["lane"]).read_bytes() == original
    from agents.test_shared_default_supervision import load, observed_dispatch
    from agents.test_shared_default_ca_readiness import wrapper_args
    wrapper = load('hoster_mitm_lane')
    monkeypatch.setattr(wrapper, 'running_on_requested_hoster', lambda _: False)
    remote_ca = '/remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    dispatch = observed_dispatch(remote_ca, signer_fixture)
    calls = []
    def remote(args, command):
        calls.append(command[-1])
        return dispatch(args, command)
    monkeypatch.setattr(wrapper, 'run_remote', remote)
    monkeypatch.setattr(wrapper, 'copy_remote_file', lambda _, src, dst: (dst.write_bytes(ca.read_bytes()) and {'status': 'copied'}))
    assert wrapper.ensure_default(wrapper_args(tmp_path))['status'] == 'running'
    assert calls == ['observe-default', 'attest-default', 'attest-default']
    assert module.state_path(tmp_path, state['lane']).read_bytes() == original


def test_default_start_preserves_old_flow_and_ca(monkeypatch, tmp_path, signer_fixture):
    module = load_mitm_lane()
    directory = tmp_path / "hoster-default-8080"
    confdir = directory / "mitmproxy"
    confdir.mkdir(parents=True)
    old_flow = directory / "flows.mitm"
    old_flow.write_bytes(b"old capture")
    ca = confdir / "mitmproxy-ca-cert.pem"
    install_signer(ca, signer_fixture)
    monkeypatch.setattr(module, "pid_alive", lambda _pid: False)
    monkeypatch.setattr(module, "can_bind_localhost", lambda _port: True)
    monkeypatch.setattr(module, "wait_for_port", lambda _port: True)
    def run(command, _env):
        if command[0] == "systemd-run":
            Path(command[command.index("-w") + 1]).write_bytes(b"new capture")
        return subprocess.CompletedProcess(command, 0, "yes\n", "")
    monkeypatch.setattr(module, "unit_command", run)
    monkeypatch.setattr(module, "unit_status", lambda *_: {"ActiveState": "active", "MainPID": "123", "ControlGroup": "/user.slice/test"})
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    preflight = prepare_direct_preflight(module, tmp_path, monkeypatch, assume_observed=True)
    result = module.start_lane(shared_start_args(tmp_path))
    assert result["status"] == "running"
    assert Path(result["flow_file"]).read_bytes() == b"new capture"
    assert old_flow.read_bytes() == b"old capture"
    assert ca.read_bytes() == (signer_fixture / 'a.crt').read_bytes()
    assert result["confdir"] == str(confdir)
    assert module.read_state(tmp_path, "hoster-default-8080")["flow_file"] == result["flow_file"]
    assert len([c for c in preflight if c[0] == 'systemd-run']) == 1


def test_default_start_refuses_occupied_port_without_spawning(monkeypatch, tmp_path):
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    from agents.test_shared_default_absence import TCP_HEADER
    module = load_mitm_lane()
    calls = prepare_direct_preflight(module, tmp_path, monkeypatch)
    (tmp_path / 'proc/net/tcp').write_text(TCP_HEADER + ' 0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 9001 1 0000000000000000 100 0 0 10 0\n')
    monkeypatch.setattr(module, "pid_alive", lambda _pid: False)
    monkeypatch.setattr(module, "can_bind_localhost", lambda _port: False)
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **kw: pytest.fail("spawned"))
    assert module.start_lane(shared_start_args(tmp_path))["status"] == "unknown-state"
    assert not any(c[0] in ('loginctl', 'systemd-run') for c in calls)


def test_concurrent_cooperative_starts_spawn_once(monkeypatch, tmp_path, signer_fixture):
    module = load_mitm_lane()
    ca = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    install_signer(ca, signer_fixture)
    history = ca.parent.parent / 'flows.mitm'
    history.write_bytes(b'prior capture')
    calls = []
    monkeypatch.setattr(module, "pid_alive", lambda pid: bool(pid))
    monkeypatch.setattr(module, "can_bind_localhost", lambda _port: not module.state_path(tmp_path, "hoster-default-8080").exists())
    monkeypatch.setattr(module, "wait_for_port", lambda _port: True)
    def run(command, _env):
        if command[0] == "systemd-run":
            calls.append(command)
            time.sleep(0.05)
        return subprocess.CompletedProcess(command, 0, "yes\n", "")
    monkeypatch.setattr(module, "unit_command", run)
    monkeypatch.setattr(module, "unit_status", lambda *_: {"ActiveState": "active", "MainPID": "123", "ControlGroup": "/user.slice/test"})
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    preflight = prepare_direct_preflight(module, tmp_path, monkeypatch, assume_observed=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: module.start_lane(shared_start_args(tmp_path)), range(2)))
    statuses = [result['status'] for result in results]
    assert statuses.count('running') == 1
    assert next(status for status in statuses if status != 'running') in {'unknown-state', 'start-cleanup-failed'}
    assert len(calls) == 1
    assert len([c for c in preflight if c[0] == 'systemd-run']) == 1
    assert ca.read_bytes() == (signer_fixture / 'a.crt').read_bytes()
    assert history.read_bytes() == b'prior capture'


def test_corrupt_default_state_is_not_overwritten(monkeypatch, tmp_path):
    module = load_mitm_lane()
    directory = tmp_path / "hoster-default-8080"
    directory.mkdir()
    state = directory / "state.json"
    state.write_text("not json")
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **kw: pytest.fail("spawned"))
    assert module.start_lane(shared_start_args(tmp_path))["status"] == "corrupt-state"
    assert state.read_text() == "not json"


@pytest.mark.parametrize("lane,port", [("hoster-default-8080", 8081)])
def test_start_refuses_noncanonical_lane_or_port(monkeypatch, tmp_path, lane, port):
    module = load_mitm_lane()
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **kw: pytest.fail("spawned"))
    assert module.start_lane(shared_start_args(tmp_path, lane=lane, port=port))["status"] == "unmanaged-start-unsupported"


def test_start_does_not_adopt_an_unowned_live_pid(tmp_path):
    script = Path(__file__).resolve().parents[1] / "skills/chromium-test/scripts/mitm_lane.py"
    directory = tmp_path / "hoster-default-8080"
    directory.mkdir()
    state = directory / "state.json"
    original = json.dumps({"pid": os.getpid(), "lane": "hoster-default-8080", "flow_file": "preserve"})
    state.write_text(original)
    result = subprocess.run(
        [sys.executable, str(script), "--json", "--root", str(tmp_path),
         "--lane", "hoster-default-8080", "start", "--port", "8081"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "unmanaged-start-unsupported"
    assert state.read_text() == original


def test_stop_does_not_signal_unowned_pid_or_alter_state(monkeypatch, tmp_path):
    module = load_mitm_lane()
    directory = tmp_path / "hoster-default-8080"
    directory.mkdir()
    state = directory / "state.json"
    original = json.dumps({"pid": os.getpid(), "lane": "hoster-default-8080", "flow_file": "preserve"})
    state.write_text(original)
    signals = []
    monkeypatch.setattr(module.os, "killpg", lambda *args: signals.append(args))
    result = module.stop_lane(argparse.Namespace(root=str(tmp_path), lane="hoster-default-8080"))
    assert result["status"] == "unmanaged-stop-unsupported"
    assert signals == []
    assert state.read_text() == original
    script = Path(__file__).resolve().parents[1] / "skills/chromium-test/scripts/mitm_lane.py"
    cli = subprocess.run([sys.executable, str(script), "--json", "--root", str(tmp_path),
                          "--lane", "hoster-default-8080", "stop"], capture_output=True, text=True, check=False)
    assert cli.returncode == 2
    assert json.loads(cli.stdout)["status"] == "unmanaged-stop-unsupported"
    assert state.read_text() == original


def test_new_capture_does_not_truncate_or_overwrite_index_lane(monkeypatch, tmp_path):
    module = load_mitm_lane()
    monkeypatch.setattr(module, 'pid_alive', lambda _: False)
    monkeypatch.setattr(module, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(module, 'wait_for_port', lambda _: True)
    commands = []
    def launch(command, **kwargs):
        state = module.read_state(tmp_path, 'named')
        assert Path(state['flow_file']).stat().st_ino == Path(command[-1]).stat().st_ino
        assert int(command[-1].rsplit('/', 1)[1]) in kwargs['pass_fds']
        assert state['index_lane'] != 'named'
        commands.append(command)
        Path(command[-1]).write_bytes(b'capture')
        return argparse.Namespace(pid=123)
    monkeypatch.setattr(module.subprocess, 'Popen', launch)
    args = argparse.Namespace(root=str(tmp_path), lane='named', port=8081, mitmdump='fake',
        listen_host='127.0.0.1', proxy_host='127.0.0.1', program='Exact Name', task='test',
        account='fixture', account_label=None, profile_dir=None, run_id='run', agent_id='agent',
        runtime_host='fixture', transport='browser', browser_profile_id=None, session_source=None)
    first = module.start_lane(args)
    first_file = Path(first['flow_file'])
    assert module.start_lane(args)['status'] == 'capture-recovery-required'
    assert module.stop_lane(args)['status'] == 'stopped'
    second = module.start_lane(args)
    assert first_file.read_bytes() == b'capture'
    assert first_file != Path(second['flow_file'])
    assert first['index_lane'] != second['index_lane']


def test_index_store_uses_saved_capture_identity(monkeypatch, tmp_path):
    module = load_mitm_lane()
    state = {'index_lane': 'capture-one', 'flow_file': str(tmp_path / 'capture.mitm'),
             'program': 'Exact Name', 'task': 'test'}
    Path(state['flow_file']).write_bytes(b'fixture')
    module.write_state(tmp_path, 'named', state)
    executable = tmp_path / 'mitmdump'
    executable.write_text(f'#!{sys.executable}\n')
    monkeypatch.setattr(module.shutil, 'which', lambda _: str(executable))
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"status":"indexed"}', '')
    monkeypatch.setattr(module.subprocess, 'run', run)
    args = argparse.Namespace(mitmdump='fake', db=str(tmp_path / 'db'), lane='named',
                              root=str(tmp_path), flow_file=None, store_full_requests=True)
    assert module.index_store(args)['status'] == 'indexed'
    command = commands[0]
    assert command[command.index('--lane') + 1] == 'capture-one'
    assert command[command.index('--flow-file') + 1] == state['flow_file']
    assert command[command.index('--program') + 1] == state['program']


def test_index_store_uses_mitmdump_runtime_when_checkout_lacks_mitmproxy(tmp_path):
    if os.environ.get('SHARED_DEFAULT_KERNEL_FENCE') == '1':
        pytest.skip('real mitmdump execution is outside the fake-subprocess-only fence')
    if shutil.which("mitmdump") is None:
        pytest.skip("offline system mitmdump runtime unavailable")
    script = Path(__file__).resolve().parents[1] / "skills/chromium-test/scripts/mitm_lane.py"
    result = subprocess.run(
        [sys.executable, str(script), "--json", "--root", str(tmp_path),
         "--lane", "absent", "index-store", "--db", str(tmp_path / "index.sqlite"),
         "--flow-file", str(tmp_path / "missing.mitm"), "--no-full-requests"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2, result.stderr
    assert json.loads(result.stdout)["status"] == "missing-flow-file"
    assert not (tmp_path / "index.sqlite").exists()


def test_index_store_passes_full_request_option(monkeypatch, tmp_path):
    module = load_mitm_lane()
    captured = {}
    mitmdump = tmp_path / "mitmdump"
    mitmdump.write_text(f"#!{sys.executable}\n")
    monkeypatch.setattr(module.shutil, "which", lambda _: str(mitmdump))
    flow_file = tmp_path / 'capture.mitm'
    flow_file.write_bytes(b'fixture')
    module.write_state(tmp_path / 'lanes', 'lane-a', {'flow_file': str(flow_file)})

    def run(command, **_kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, '{"status":"indexed"}', "")

    monkeypatch.setattr(module.subprocess, "run", run)

    result = module.index_store(
        argparse.Namespace(
            mitmdump=str(mitmdump), db=str(tmp_path / "proxy.sqlite"),
            lane="lane-a",
            root=str(tmp_path / "lanes"),
            flow_file=None,
            program="demo",
            task="smoke",
            note=None,
            store_full_requests=True,
        )
    )

    assert result["status"] == "indexed"
    assert captured["command"][0] == sys.executable
    assert "--no-full-requests" not in captured["command"]
