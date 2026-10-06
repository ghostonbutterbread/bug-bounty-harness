from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


def load_mitm_lane():
    root = Path(__file__).resolve().parents[1]
    script = root / "skills" / "chromium-test" / "scripts" / "mitm_lane.py"
    spec = importlib.util.spec_from_file_location("mitm_lane", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_index_store_uses_mitmdump_runtime_when_checkout_lacks_mitmproxy(tmp_path):
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
