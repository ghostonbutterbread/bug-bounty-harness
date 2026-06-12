from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path


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
        "ssh_user": "ryushe",
        "ssh_key": "/home/ryushe/.ssh/hoster",
        "remote_root": "/home/ryushe/projects/bug_bounty_harness",
        "local_lane_root": "/tmp/mitm-lanes",
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

    monkeypatch.setattr(module, "run_remote", fake_run_remote)

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

    monkeypatch.setattr(module, "run_remote", fake_run_remote)

    result = module.acquire_start(base_args())

    assert result["status"] == "start-failed"
    assert any("lease-release" in call for call in calls)


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

    monkeypatch.setattr(module, "run_remote", fake_run_remote)

    result = module.index_stop_release(base_args(lane="lane-a"))

    assert result["status"] == "released"
    assert "stop" in calls[0]
    assert "index-store" in calls[1]
    assert "lease-release" in calls[2]


def test_ensure_default_reuses_running_listener(monkeypatch):
    module = load_hoster_lane()
    calls = []

    def fake_run_remote(args, argv):
        calls.append(argv)
        return {
            "status": "running",
            "alive": True,
            "proxy_server": "http://hoster:8080",
            "proxy_port": 8080,
            "ca_cert": "/home/ryushe/.local/state/ghost/mitm-lanes/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem",
        }

    monkeypatch.setattr(module, "run_remote", fake_run_remote)
    monkeypatch.setattr(
        module,
        "copy_remote_file",
        lambda args, remote_path, local_path: {"status": "copied", "local_path": str(local_path)},
    )

    result = module.ensure_default(base_args(lane="hoster-default-8080", port=8080))

    assert result["status"] == "running"
    assert result["proxy_server"] == "http://hoster:8080"
    assert result["ca_sync"]["status"] == "copied"
    assert len(calls) == 1
    assert "status" in calls[0]


def test_ensure_default_starts_missing_listener(monkeypatch):
    module = load_hoster_lane()
    calls = []

    def fake_run_remote(args, argv):
        calls.append(argv)
        if "status" in argv:
            return {"status": "not-found"}
        return {
            "status": "running",
            "proxy_server": "http://hoster:8080",
            "ca_cert": "/home/ryushe/.local/state/ghost/mitm-lanes/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem",
        }

    monkeypatch.setattr(module, "run_remote", fake_run_remote)
    monkeypatch.setattr(
        module,
        "copy_remote_file",
        lambda args, remote_path, local_path: {"status": "copied", "local_path": str(local_path)},
    )

    result = module.ensure_default(base_args(lane="hoster-default-8080", port=8080))

    assert result["status"] == "running"
    assert result["proxy_server"] == "http://hoster:8080"
    assert result["ca_sync"]["status"] == "copied"
    assert "status" in calls[0]
    assert "start" in calls[1]
    assert "--port" in calls[1]
    assert "8080" in calls[1]
