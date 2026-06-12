from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
from pathlib import Path


def load_mitm_lane():
    root = Path(__file__).resolve().parents[1]
    script = root / "skills" / "chromium-test" / "scripts" / "mitm_lane.py"
    spec = importlib.util.spec_from_file_location("mitm_lane", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_index_store_passes_full_request_option(monkeypatch):
    module = load_mitm_lane()
    captured = {}

    class Loader:
        def create_module(self, spec):
            return None

        def exec_module(self, fake_module):
            def index_lane(args):
                captured["store_full_requests"] = args.store_full_requests
                return {"status": "indexed"}

            fake_module.index_lane = index_lane

    monkeypatch.setattr(
        importlib.util,
        "spec_from_file_location",
        lambda name, _path: importlib.machinery.ModuleSpec(name, Loader()),
    )

    result = module.index_store(
        argparse.Namespace(
            db="/tmp/proxy.sqlite",
            lane="lane-a",
            root="/tmp/lanes",
            flow_file=None,
            program="demo",
            task="smoke",
            note=None,
            store_full_requests=True,
        )
    )

    assert result["status"] == "indexed"
    assert captured["store_full_requests"] is True
