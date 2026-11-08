"""Offline regressions guarding capture-generation handoff."""
import argparse
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "skills/chromium-test/scripts/browser_provisioner.py"


def test_exact_program_identity_rejects_slug_collision(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BROWSER_PROVISIONER_STATE", str(tmp_path / "state/manager.sqlite"))
    spec = importlib.util.spec_from_file_location("provisioner", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    conn = module.db()
    monkeypatch.setattr(module, "port_open", lambda _: False)
    monkeypatch.setattr(module, "unit_active", lambda _: False)
    monkeypatch.setattr(module, "proxy_ready", lambda _: True)
    monkeypatch.setattr(module, "unit_identity", lambda _: "fixture")
    monkeypatch.setattr(module, "mitm_runtime", lambda: ("/fake/mitmdump", "/fake/python"))
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: argparse.Namespace(returncode=0))
    args = argparse.Namespace(agent_id="agent", run_id="run", program="Demo Name", account="fixture", purpose="test")
    row, created = module.start_proxy(conn, args)
    assert created
    assert row['exact_program'] == 'Demo Name'
    args.program = 'demo-name'
    with pytest.raises(SystemExit):
        module.start_proxy(conn, args)
    assert 'proxy-conflict' in capsys.readouterr().out
    metadata = module.proxy_metadata(row)
    monkeypatch.setattr(module, 'record_info', lambda _: {
        'proxy_server': metadata['proxy_server'], 'proxy_cert_mode': 'import',
        'proxy_cert_status': {'status': 'trusted', 'ca_cert': metadata['ca_cert'], 'ca_sha256': 'fixture'}})
    monkeypatch.setattr(module, 'ca_fingerprint', lambda _: 'fixture')
    assert not module.matching_proxy(conn, argparse.Namespace(
        agent_id='agent', run_id='run', program='demo-name', proxy='mitm'), {})


def test_failed_new_start_preserves_old_finished_receipt(monkeypatch, tmp_path):
    monkeypatch.setenv("BROWSER_PROVISIONER_STATE", str(tmp_path / "state/manager.sqlite"))
    spec = importlib.util.spec_from_file_location("provisioner", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    conn = module.db()
    conn.execute("insert into finished_proxies values(?,?,?,?)", ("agent", "run", "old-lane", 1))
    conn.commit()
    monkeypatch.setattr(module, "port_open", lambda _: False)
    monkeypatch.setattr(module, "unit_active", lambda _: False)
    monkeypatch.setattr(module, "mitm_runtime", lambda: (_ for _ in ()).throw(RuntimeError("fixture start failure")))
    args = argparse.Namespace(agent_id="agent", run_id="run", program="demo", account="fixture", purpose="test")
    with pytest.raises(RuntimeError, match="fixture start failure"):
        module.start_proxy(conn, args)
    assert conn.execute("select lane from finished_proxies where agent_id=? and run_id=?", ("agent", "run")).fetchone()[0] == "old-lane"
