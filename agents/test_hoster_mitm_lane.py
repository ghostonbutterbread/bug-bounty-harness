from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import pytest
from agents.test_shared_default_supervision import signer_fixture, signer_status, observed_dispatch


def load_hoster_lane():
    root = Path(__file__).resolve().parents[1]
    script = root / "skills" / "chromium-test" / "scripts" / "hoster_mitm_lane.py"
    spec = importlib.util.spec_from_file_location("hoster_mitm_lane", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def base_args(**overrides):
    values = {
        "ssh_host": "hoster",
        "ssh_user": "fixture-user",
        "ssh_key": "/fixture/ssh-key",
        "local_lane_root": "/fixture/mitm-lanes",
        "connect_timeout": 10,
        "timeout": 30,
        "dry_run": False,
        "lane": None,
        "agent_id": "agent-a",
        "run_id": "run-a",
        "program": "demo",
        "task": "xss",
        "account_label": "qa-user",
        "runtime_host": "openclaw",
        "proxy_host": "hoster",
        "listen_host": "0.0.0.0",
        "port_min": 8081,
        "port_max": 8090,
        "ttl_seconds": 3600,
        "transport": "browser",
        "browser_profile_id": None,
        "session_source": None,
        "profile_dir": None,
        "proxy_port": 8081,
        "note": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_legacy_acquire_start_preserves_dispatch_and_metadata(monkeypatch):
    module = load_hoster_lane()
    calls = []
    def remote(_args, argv):
        calls.append(argv)
        if 'lease-acquire' in argv:
            return {'status': 'leased', 'lease': {'lane': 'task-a', 'proxy_port': 8081}}
        return {'status': 'running'}
    monkeypatch.setattr(module, 'run_remote_legacy', remote)
    result = module.acquire_start(base_args(session_source='fixture-session', browser_profile_id='fixture-profile'))
    assert result['status'] == 'running' and result['lane'] == 'task-a'
    assert 'lease-acquire' in calls[0] and 'start' in calls[1]
    for token in ('--agent-id', '--run-id', '--program', '--task', '--account-label'):
        assert token in calls[0] and token in calls[1]
    assert 'fixture-session' in calls[1] and 'fixture-profile' in calls[1]
    assert '--port-min' in calls[0] and '8081' in calls[0]



def test_legacy_acquire_parser_keeps_defaults(monkeypatch):
    import sys
    module = load_hoster_lane()
    monkeypatch.setattr(sys, 'argv', ['fixture', '--json', 'acquire-start', '--agent-id', 'a', '--run-id', 'r'])
    args = module.parse_args()
    assert args.func is module.acquire_start
    assert (args.port_min, args.port_max, args.transport) == (module.DEFAULT_PORT_MIN, module.DEFAULT_PORT_MAX, 'browser')
    assert (args.agent_id, args.run_id) == ('a', 'r')



def test_legacy_index_stop_release_dispatch_order(monkeypatch):
    module = load_hoster_lane()
    calls = []
    def remote(_args, argv):
        calls.append(argv)
        return {'status': 'released' if 'lease-release' in argv else 'stopped' if 'stop' in argv else 'indexed'}
    monkeypatch.setattr(module, 'run_remote_legacy', remote)
    result = module.index_stop_release(base_args(lane='lane-a', session_source='fixture-session'))
    assert result['status'] == 'released'
    assert 'stop' in calls[0] and 'index-store' in calls[1] and 'lease-release' in calls[2]
    assert 'fixture-session' in calls[1] and 'lane-a' in calls[2]



def test_ensure_default_reuses_running_listener(monkeypatch, tmp_path, signer_fixture):
    module = load_hoster_lane()
    calls = []

    remote_ca = '/remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    dispatch = observed_dispatch(remote_ca, signer_fixture)
    def fake_run_remote(args, argv):
        calls.append(argv[-1])
        return dispatch(args, argv)

    monkeypatch.setattr(module, "run_remote", fake_run_remote)
    def copy_ca(args, remote_path, local_path):
        local_path.write_bytes((signer_fixture / 'a.crt').read_bytes())
        return {"status": "copied", "local_path": str(local_path)}
    monkeypatch.setattr(module, "copy_remote_file", copy_ca)

    result = module.ensure_default(base_args(lane="hoster-default-8080", port=8080, local_lane_root=str(tmp_path)))

    assert result["status"] == "running"
    assert result["proxy_server"] == "http://hoster:8080"
    assert result["ca_sync"]["status"] == "copied"
    assert Path(result['local_ca_cert']).read_bytes() == (signer_fixture / 'a.crt').read_bytes()
    assert calls == ['observe-default', 'attest-default', 'attest-default']


def test_ensure_default_starts_only_canonical_default_with_safe_capability(monkeypatch, tmp_path, signer_fixture):
    from agents.test_shared_default_supervision import fresh_dispatch
    module = load_hoster_lane()
    monkeypatch.setattr(module, 'running_on_requested_hoster', lambda _: False)
    calls = []
    remote_ca = '/remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    dispatch, seen = fresh_dispatch(remote_ca, signer_fixture)
    def fake_run_remote(args, argv):
        calls.append(argv)
        return dispatch(args, argv)
    monkeypatch.setattr(module, "run_remote", fake_run_remote)
    def copy_ca(args, remote_path, local_path):
        local_path.write_bytes((signer_fixture / 'a.crt').read_bytes())
        return {"status": "copied", "local_path": str(local_path)}
    monkeypatch.setattr(module, "copy_remote_file", copy_ca)
    result = module.ensure_default(base_args(lane="hoster-default-8080", port=8080, local_lane_root=str(tmp_path)))
    assert result["status"] == "running"
    assert [call[-1] for call in calls if call[-1] in ('observe-default', 'attest-default')] == [
        'observe-default', 'observe-default', 'attest-default', 'attest-default']
    assert seen == ['observe-default', 'classify-default-absence', 'start', 'observe-default', 'attest-default', 'attest-default']
    start = next(call for call in calls if 'start' in call)
    assert '--preserve-default-flow' in start and '--require-user-systemd' in start


def test_ensure_default_dry_run_shows_safe_start(monkeypatch):
    module = load_hoster_lane()
    monkeypatch.setattr(module, "running_on_requested_hoster", lambda _args: True)
    result = module.ensure_default(base_args(lane="hoster-default-8080", port=8080, dry_run=True))
    assert result["status"] == "dry-run"
    assert "--preserve-default-flow" in result["start"]["local_command"]


def test_ensure_default_refuses_alternate_lanes_and_ports_before_dispatch(monkeypatch):
    module = load_hoster_lane()
    calls = []
    monkeypatch.setattr(module, "run_remote", lambda *a: calls.append(a))
    for lane, port in [("hoster-default-8080", 8081), ("custom", 8080)]:
        assert module.ensure_default(base_args(lane=lane, port=port))["status"] == "start-failed"
    assert not calls


def test_ensure_default_fails_closed_when_older_remote_rejects_capability(monkeypatch):
    module = load_hoster_lane()
    def remote(_args, argv):
        return {"status": "not-found"} if "status" in argv else {"status": "ssh-failed"}
    monkeypatch.setattr(module, "run_remote", remote)
    assert module.ensure_default(base_args(lane="hoster-default-8080", port=8080))["status"] == "start-failed"


def test_ensure_default_surfaces_occupied_port(monkeypatch, tmp_path):
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    from agents.test_shared_default_supervision import args, load
    from agents.test_shared_default_absence import TCP_HEADER
    direct = load('mitm_lane')
    preflight = prepare_direct_preflight(direct, tmp_path, monkeypatch)
    (tmp_path / 'proc/net/tcp').write_text(TCP_HEADER + ' 0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 9001 1 0000000000000000 100 0 0 10 0\n')
    module = load_hoster_lane()
    monkeypatch.setattr(module, 'running_on_requested_hoster', lambda _: False)
    calls = []
    def remote(_args, argv):
        calls.append(argv)
        if 'observe-default' in argv:
            return {'status': 'ssh-failed', 'remote_status': 'unknown-state', 'ssh_returncode': 2}
        assert 'classify-default-absence' in argv
        classified = direct.classify_default_absence(args(tmp_path))
        assert classified['status'] == 'unknown-state'
        return {'status': 'ssh-failed', 'remote_status': classified['status'], 'ssh_returncode': 2}
    monkeypatch.setattr(module, "run_remote", remote)
    monkeypatch.setattr(module, 'copy_remote_file', lambda *_: pytest.fail('unexpected CA copy'))
    result = module.ensure_default(base_args(lane="hoster-default-8080", port=8080))
    assert result["status"] == "start-failed"
    assert result["start"]["status"] == "unknown-state"
    assert 'Absence was not confirmed' in result['detail']
    assert len(calls) == 2 and all('start' not in c and 'stop' not in c for c in calls)
    assert not any(c[0] in ('loginctl', 'systemd-run') for c in preflight)


def test_ensure_default_rejects_running_non_8080_state(monkeypatch):
    module = load_hoster_lane()
    from agents.test_shared_default_wrapper_attestation import observed
    calls = []
    def remote(_args, argv):
        calls.append(argv)
        return {**observed(), 'port': 8081}
    monkeypatch.setattr(module, "run_remote", remote)
    monkeypatch.setattr(module, 'copy_remote_file', lambda *_: pytest.fail('unexpected CA copy'))
    result = module.ensure_default(base_args(lane="hoster-default-8080", port=8080))
    assert result["status"] == "start-failed" and "port 8080" in result["detail"]
    assert len(calls) == 1 and 'observe-default' in calls[0]


def test_local_hoster_dispatch_uses_this_checkout_not_ssh(monkeypatch):
    module = load_hoster_lane()
    calls = []
    monkeypatch.setattr(module, "running_on_requested_hoster", lambda _args: True)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda command, **_kwargs: calls.append(command) or argparse.Namespace(
            returncode=0, stdout='{"status":"running"}', stderr=""
        ),
    )

    result = module.run_remote(base_args(), ["bbh", "skills/chromium-test/scripts/mitm_lane.py", "--json", "status"])

    assert result == {"status": "running", "local_returncode": 0}
    assert calls[0][0] == module.sys.executable
    assert calls[0][1].endswith("scripts/bbh.py")
    assert "ssh" not in calls[0]


def test_local_hoster_dispatch_sanitizes_stderr_on_failure(monkeypatch):
    module = load_hoster_lane()
    monkeypatch.setattr(module, "running_on_requested_hoster", lambda _args: True)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: argparse.Namespace(returncode=1, stdout="", stderr="missing dependency"),
    )

    result = module.run_remote(base_args(), ["bbh", "skills/chromium-test/scripts/mitm_lane.py", "--json", "index-store"])

    assert result == {"status": "local-failed", "local_returncode": 1, "detail": "Dispatch failed; check connectivity and dispatcher status."}
    assert 'missing dependency' not in str(result)


def test_nonlocal_hoster_dispatch_keeps_bounded_ssh(monkeypatch):
    module = load_hoster_lane()
    monkeypatch.setattr(module, "running_on_requested_hoster", lambda _args: False)

    result = module.run_remote(
        base_args(ssh_host="hoster.example.test", dry_run=True),
        ["bbh", "skills/chromium-test/scripts/mitm_lane.py", "--json", "status"],
    )

    assert result["status"] == "dry-run"
    assert result["ssh_command"][0] == "ssh"
    assert result["ssh_command"][-1] == 'PATH="$HOME/.local/bin:/usr/bin:/bin"; export PATH; bbh skills/chromium-test/scripts/mitm_lane.py --json status'


def test_noninteractive_remote_uses_projected_bbh_with_missing_path(tmp_path, monkeypatch):
    import json
    import os
    import shutil
    import subprocess
    import sys
    assert os.environ.get('SHARED_DEFAULT_KERNEL_FENCE') == '1'
    module = load_hoster_lane()
    monkeypatch.setattr(module, 'running_on_requested_hoster', lambda _: False)
    home = tmp_path / 'home'
    bindir = home / '.local/bin'
    bindir.mkdir(parents=True)
    dispatcher = bindir / 'bbh'
    dispatcher.write_text(f'#!{sys.executable}\nimport json,sys\nprint(json.dumps({{"status":"ok","args":sys.argv[1:]}}))\n')
    dispatcher.chmod(0o700)
    shell = tmp_path / 'fixture-sh'
    shutil.copyfile('/bin/sh', shell)
    shell.chmod(0o700)
    original = subprocess.run
    def fake_ssh(command, **kwargs):
        assert command[0] == 'ssh' and '-T' in command
        return original([str(shell), '-c', command[-1]], env={'HOME': str(home), 'PATH': '/usr/bin:/bin'}, **kwargs)
    monkeypatch.setattr(module.subprocess, 'run', fake_ssh)
    result = module.run_remote(base_args(), ['bbh', 'script.py', '--task=hello;not-a-command'])
    assert result['status'] == 'ok' and result['ssh_returncode'] == 0
    assert result['args'] == ['script.py', '--task=hello;not-a-command']


def test_local_dispatch_failure_returns_nonzero_cli_exit(monkeypatch, capsys):
    module = load_hoster_lane()
    monkeypatch.setattr(
        module,
        "parse_args",
        lambda: argparse.Namespace(json=True, func=lambda _args: {"status": "local-failed", "local_stderr": "missing dependency"}),
    )

    assert module.main() == 2
    assert '"status": "local-failed"' in capsys.readouterr().out


def test_acquire_start_runs_lease_then_remote_start(monkeypatch):
    module = load_hoster_lane()
    calls = []

    def fake_run_remote(args, argv):
        calls.append(argv)
        if "lease-acquire" in argv:
            return {
                "status": "leased",
                "lease": {
                    "lane": "agent-a-1-8081",
                    "proxy_port": 8081,
                    "proxy_server": "http://hoster:8081",
                },
            }
        return {"status": "running", "proxy_server": "http://hoster:8081"}

    monkeypatch.setattr(module, "run_remote_legacy", fake_run_remote)

    result = module.acquire_start(base_args())

    assert result["status"] == "running"
    assert result["proxy_server"] == "http://hoster:8081"
    assert "lease-acquire" in calls[0]
    assert "start" in calls[1]
    assert "--listen-host" in calls[1]
    assert "0.0.0.0" in calls[1]


def test_acquire_start_releases_lease_when_remote_start_fails(monkeypatch):
    module = load_hoster_lane()
    calls = []

    def fake_run_remote(args, argv):
        calls.append(argv)
        if "lease-acquire" in argv:
            return {"status": "leased", "lease": {"lane": "lane-a", "proxy_port": 8081}}
        if "start" in argv:
            return {"status": "port-unavailable"}
        return {"status": "released", "count": 1}

    monkeypatch.setattr(module, "run_remote_legacy", fake_run_remote)

    result = module.acquire_start(base_args())

    assert result["status"] == "start-failed"
    release = next(call for call in calls if "lease-release" in call)
    assert release[:2] == ["bbh", "skills/chromium-test/scripts/proxy_store.py"]


def test_index_stop_release_orders_remote_cleanup(monkeypatch):
    module = load_hoster_lane()
    calls = []

    def fake_run_remote(args, argv):
        calls.append(argv)
        if "index-store" in argv:
            return {"status": "indexed"}
        if "stop" in argv:
            return {"status": "stopped"}
        return {"status": "released", "count": 1}

    monkeypatch.setattr(module, "run_remote_legacy", fake_run_remote)

    result = module.index_stop_release(base_args(lane="lane-a"))

    assert result["status"] == "released"
    assert "stop" in calls[0]
    assert "index-store" in calls[1]
    assert "lease-release" in calls[2]
