import argparse
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

import pytest

from agents.test_standalone_index_review import flow, ix, load, setup_lane

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / 'skills/chromium-test/scripts/mitm_lane.py'


@pytest.mark.parametrize('explicit', [False, True])
@pytest.mark.parametrize('swap_when', ['before-open', 'after-open'])
def test_legacy_symlink_metadata_names_opened_inode(monkeypatch, tmp_path, explicit, swap_when):
    real_popen = subprocess.Popen
    m, args = setup_lane(monkeypatch, tmp_path)
    monkeypatch.setattr(m.subprocess, 'Popen', real_popen)
    (tmp_path / 'private').mkdir()
    first, second, link = (tmp_path / name for name in ('first.mitm', 'second.mitm', 'link.mitm'))
    flow(first)
    flow(second)
    from mitmproxy.io import FlowReader, FlowWriter
    with second.open('rb') as handle:
        item = next(FlowReader(handle).stream())
    item.request.path = '/second'
    with second.open('wb') as handle:
        FlowWriter(handle).add(item)
    link.symlink_to(first)
    m.write_state(Path(args.root), args.lane, {'flow_file': str(link), 'program': 'Old'})
    real_open = m.open_readback
    def retarget(*a, **kw):
        if swap_when == 'before-open':
            link.unlink()
            link.symlink_to(second)
        result = real_open(*a, **kw)
        if swap_when == 'after-open':
            link.unlink()
            link.symlink_to(second)
        return result
    monkeypatch.setattr(m, 'open_readback', retarget)
    index_args = ix(args, tmp_path, str(link) if explicit else None)
    result = m.index_store(index_args)
    selected, path = (second, '/second') if swap_when == 'before-open' else (first, '/owned-fixture')
    with sqlite3.connect(index_args.db) as db:
        lane = db.execute('select flow_file from lanes').fetchone()[0]
        request = db.execute('select path,raw_flow_file from requests').fetchone()
    assert result['status'] == 'indexed'
    assert (lane, request, result['flow_file']) == (str(selected), (path, str(selected)), str(selected))


def test_unlinked_open_capture_is_rejected_and_closed(monkeypatch, tmp_path):
    m, args = setup_lane(monkeypatch, tmp_path)
    target = tmp_path / 'legacy.mitm'
    flow(target)
    m.write_state(Path(args.root), args.lane, {'flow_file': str(target)})
    real_open = m.open_readback
    opened = []
    def unlink_after_open(*a, **kw):
        result = real_open(*a, **kw)
        opened.append(result[0])
        target.unlink()
        return result
    monkeypatch.setattr(m, 'open_readback', unlink_after_open)
    result = m.index_store(ix(args, tmp_path))
    assert result['status'] == 'capture-unavailable'
    with pytest.raises(OSError):
        os.fstat(opened[0])
    assert not Path(ix(args, tmp_path).db).exists()


@pytest.mark.parametrize('json_output', [False, True])
def test_missing_store_cli_nonzero_preserves_output(tmp_path, json_output):
    script = tmp_path / 'mitm_lane.py'
    shutil.copyfile(SCRIPT, script)
    command = [sys.executable, str(script), '--root', str(tmp_path / 'state')]
    if json_output:
        command.append('--json')
    command.append('index-store')
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 2
    if json_output:
        assert json.loads(result.stdout) == {'status': 'missing-proxy-store', 'script': str(tmp_path / 'proxy_store.py')}
    else:
        assert result.stdout == 'missing-proxy-store: \n'


@pytest.mark.parametrize('status', ['start-timeout', 'start-failed', 'corrupt-state'])
def test_main_failure_status_is_nonzero(monkeypatch, capsys, status):
    m = load('mitm_lane')
    monkeypatch.setattr(m, 'parse_args', lambda: argparse.Namespace(json=True, func=lambda _: {'status': status}))
    assert m.main() == 2
    assert json.loads(capsys.readouterr().out)['status'] == status


def test_active_capture_append_after_open_is_visible(monkeypatch, tmp_path):
    real_popen, real_run = subprocess.Popen, subprocess.run
    m, args = setup_lane(monkeypatch, tmp_path)
    (tmp_path / 'private').mkdir()
    state = m.start_lane(args)
    capture = Path(state['flow_file'])
    flow(capture)
    extra = tmp_path / 'extra.mitm'
    flow(extra)
    from mitmproxy.io import FlowReader, FlowWriter
    with extra.open('rb') as handle:
        item = next(FlowReader(handle).stream())
    item.request.path = '/appended-after-open'
    with extra.open('wb') as handle:
        FlowWriter(handle).add(item)
    monkeypatch.setattr(m.subprocess, 'Popen', real_popen)
    def append_then_index(command, **kwargs):
        assert capture.stat().st_ino == os.fstat(kwargs['pass_fds'][0]).st_ino
        with capture.open('ab') as handle:
            handle.write(extra.read_bytes())
        return real_run(command, **kwargs)
    monkeypatch.setattr(m.subprocess, 'run', append_then_index)
    result = m.index_store(ix(args, tmp_path))
    with sqlite3.connect(ix(args, tmp_path).db) as db:
        paths = [row[0] for row in db.execute('select path from requests order by path')]
    assert result['status'] == 'indexed'
    assert paths == ['/appended-after-open', '/owned-fixture']
