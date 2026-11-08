from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path


def load():
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/mitm_lane.py'
    spec = importlib.util.spec_from_file_location('mitm_lane_review', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_start_waits_for_stop_state_update(monkeypatch, tmp_path):
    m = load()
    root, lane = tmp_path / 'state', 'lane'
    m.write_state(root, lane, {'status': 'running', 'index_lane': 'old', 'pid': None})
    import argparse
    args = argparse.Namespace(root=str(root), lane=lane)
    monkeypatch.setattr(m, 'pid_alive', lambda _: False)
    entered, release, started = threading.Event(), threading.Event(), threading.Event()
    original_write = m.write_state
    def stalled_write(root, lane, state):
        if state.get('index_lane') == 'old' and state.get('status') == 'stopped':
            entered.set()
            assert release.wait(3)
        original_write(root, lane, state)
    monkeypatch.setattr(m, 'write_state', stalled_write)
    def new_generation(args, root):
        started.set()
        state = {'status': 'running', 'index_lane': 'new'}
        original_write(root, lane, state)
        return state
    monkeypatch.setattr(m, '_start_lane_locked', new_generation)
    stop = threading.Thread(target=m.stop_lane, args=(args,))
    start = threading.Thread(target=m.start_lane, args=(args,))
    stop.start()
    try:
        assert entered.wait(3)
        start.start()
        assert not started.wait(0.2), 'start entered while stop had not committed state'
    finally:
        release.set()
        stop.join(3)
        if start.ident is not None:
            start.join(3)
    assert not stop.is_alive() and not start.is_alive()
    assert m.read_state(root, lane)['index_lane'] == 'new'


def test_proxy_store_direct_cli_preserves_browser_default(monkeypatch):
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/proxy_store.py'
    spec = importlib.util.spec_from_file_location('proxy_store_review', script)
    assert spec and spec.loader
    store = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(store)
    monkeypatch.setattr(sys, 'argv', ['proxy_store.py', 'index-lane', '--lane', 'test'])
    assert store.parse_args().transport == 'browser'
    monkeypatch.setattr(sys, 'argv', ['proxy_store.py', 'index-lane', '--lane', 'test', '--receipt-metadata'])
    assert store.parse_args().transport is None
