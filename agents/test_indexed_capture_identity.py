"""Offline synthetic end-to-end indexed capture identity regressions."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest
from mitmproxy import connection, http
from mitmproxy.io import FlowWriter
from test_task_proxy_mount_selection import setup, args

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def flow(path, route):
    record = http.HTTPFlow(connection.Client(peername=('127.0.0.1', 1), sockname=('127.0.0.1', 2), timestamp_start=1), connection.Server(address=('example.test', 80)))
    record.request = http.Request.make('GET', 'http://example.test/' + route)
    with path.open('wb') as f:
        FlowWriter(f).add(record)


def test_finish_swap_after_validation_rejected_by_indexed_readers(monkeypatch, tmp_path, capsys):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    real_run = subprocess.run
    with monkeypatch.context() as fake:
        fake.setattr(m.subprocess, 'run', lambda *a, **kw: argparse.Namespace(returncode=0))
        row, _ = m.start_proxy(m.db(), args())
    path = Path(row['flow_path'])
    flow(path, 'original')
    actual = path.stat()
    monkeypatch.setattr(m, 'mitm_runtime', lambda: ('/fixture/mitmdump', sys.executable))
    monkeypatch.setattr(m.subprocess, 'run', lambda cmd, **kw: real_run(cmd, **kw) if 'index-lane' in cmd else argparse.Namespace(returncode=0))
    finish = m.finish_capture_index
    def swap_after_final_validation(row):
        result = finish(row)
        path.rename(path.with_name('original.saved'))
        flow(path, 'replacement')
        return result
    monkeypatch.setattr(m, 'finish_capture_index', swap_after_final_validation)
    with pytest.raises(SystemExit) as ex:
        m.finish_proxy(args())
    assert ex.value.code == 0
    capsys.readouterr()
    db = Path.home() / '.local/share/ghost/proxy-store/proxy_store.sqlite'
    with sqlite3.connect(db) as conn:
        saved = conn.execute('select id, path, capture_dev, capture_ino from requests').fetchone()
    assert saved[1:] == ('/original', actual.st_dev, actual.st_ino)
    store = load('proxy_store')
    query = argparse.Namespace(db=db, program=None, lane=row['lane'], run_id=None, agent_id=None, account_label=None, host=None, method=None, path=None, param=None, no_background=False, limit=25)
    found = store.query_requests(query)
    assert found['rows'][0]['capture_identity'] == 'recorded-not-checked'
    out = tmp_path / 'packet.json'
    export = argparse.Namespace(db=db, id=saved[0], flow_uid=None, output=str(out), allow_sensitive_stdout=False)
    assert store.export_request_packet(export)['status'] == 'capture-unavailable'
    assert not out.exists()
    raw = load('raw_history_search')
    sources, ambiguous = raw.index_sources(db, row['exact_program'] or row['program'], row['lane'])
    assert not ambiguous and len(sources) == 1
    events = []
    assert raw.search(sources[0][0], b'replacement', False, events.append, sources[0][1], True) == (0, 0, ['source-replaced'])
    assert not events
    proc = real_run([sys.executable, str(SCRIPTS / 'raw_history_search.py'), '--db', str(db),
                     '--program', row['exact_program'] or row['program'], '--lane', row['lane'],
                     '--contains', 'replacement'], capture_output=True, text=True)
    assert proc.returncode == 2
    summary = json.loads(proc.stdout.splitlines()[-1])
    assert 'source-replaced' in summary['reasons'] and summary['matches'] == 0
    proc = real_run([sys.executable, str(SCRIPTS / 'proxy_store.py'), '--db', str(db), '--json',
                     'export-request', '--id', str(saved[0]), '--output', str(out)], capture_output=True, text=True)
    assert proc.returncode == 2 and json.loads(proc.stdout)['status'] == 'capture-unavailable'
    path.unlink()
    assert raw.search(sources[0][0], b'original', False, events.append, sources[0][1], True) == (0, 0, ['source-unavailable'])
    assert store.export_request_packet(export)['status'] == 'capture-unavailable'
    path.with_name('original.saved').rename(path)
    assert store.export_request_packet(export)['status'] == 'exported'
    assert '/original' in out.read_text()
    assert raw.search(sources[0][0], b'original', False, events.append, sources[0][1], True)[1] == 1
    proc = real_run([sys.executable, str(SCRIPTS / 'proxy_store.py'), '--db', str(db), '--json',
                     'query', '--lane', row['lane']], capture_output=True, text=True)
    queried = json.loads(proc.stdout)
    assert proc.returncode == 0 and queried['rows'][0]['path_key'] == '/original'
    assert queried['rows'][0]['raw_flow_file'] == str(path)
    assert queried['rows'][0]['capture_identity'] == 'recorded-not-checked'
    proc = real_run([sys.executable, str(SCRIPTS / 'raw_history_search.py'), '--db', str(db),
                     '--program', row['exact_program'] or row['program'], '--lane', row['lane'],
                     '--contains', 'original'], capture_output=True, text=True)
    summary = json.loads(proc.stdout.splitlines()[-1])
    assert summary['matches'] == 1 and 'response-not-retained' in summary['reasons']
    assert proc.returncode == 2  # No synthetic response; completeness is not claimed.
    proc = real_run([sys.executable, str(SCRIPTS / 'proxy_store.py'), '--db', str(db), '--json',
                     'export-request', '--id', str(saved[0]), '--output', str(out)], capture_output=True, text=True)
    assert proc.returncode == 0 and json.loads(proc.stdout)['capture_identity'] == 'verified'
    assert '/original' in out.read_text()
    # Migrated historical rows remain usable but do not claim recorded identity.
    with sqlite3.connect(db) as conn:
        conn.execute('update lanes set capture_dev=null, capture_ino=null')
        conn.execute('update requests set capture_dev=null, capture_ino=null')
    assert store.query_requests(query)['rows'][0]['capture_identity'] == 'unavailable-legacy'
    assert store.export_request_packet(export)['status'] == 'exported'
    assert json.loads(out.read_text())['capture_identity'] == 'unavailable-legacy'
    sources, ambiguous = raw.index_sources(db, row['exact_program'] or row['program'], row['lane'])
    assert not ambiguous and sources[0][1] == (actual.st_dev, actual.st_ino)


def test_old_schema_and_conflicting_identities(tmp_path):
    raw = load('raw_history_search')
    path = tmp_path / 'capture.mitm'
    flow(path, 'legacy')
    db = tmp_path / 'old.sqlite'
    with sqlite3.connect(db) as c:
        c.executescript('create table lanes(lane text, program text, flow_file text); create table requests(lane text, program text, raw_flow_file text);')
        c.execute('insert into lanes values (?,?,?)', ('lane', 'program', str(path)))
        c.execute('insert into requests values (?,?,?)', ('lane', 'program', str(path)))
    sources, ambiguous = raw.index_sources(db, 'program', 'lane')
    assert not ambiguous and len(sources) == 1
    with sqlite3.connect(db) as c:
        for table in ('lanes', 'requests'):
            c.execute(f'alter table {table} add capture_dev integer')
            c.execute(f'alter table {table} add capture_ino integer')
        info = path.stat()
        c.execute('update lanes set capture_dev=?, capture_ino=?', (info.st_dev, info.st_ino))
    sources, ambiguous = raw.index_sources(db, 'program', 'lane')
    assert ambiguous and not sources


def test_indexer_spawn_failure_is_actionable(monkeypatch, tmp_path, capsys):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: argparse.Namespace(returncode=0))
    row, _ = m.start_proxy(m.db(), args())
    Path(row['flow_path']).write_bytes(b'fixture')
    monkeypatch.setattr(m, 'mitm_runtime', lambda: ('fixture', sys.executable))
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: (_ for _ in ()).throw(OSError('fixture spawn error')))
    with pytest.raises(SystemExit) as ex:
        m.finish_capture_index(row)
    assert ex.value.code == 2
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'proxy-index-failed'
    assert result['reservation'] == 'retained'
    assert 'start indexer' in result['detail']
    assert m.proxy_row(m.db(), args()) is not None


def test_reindex_new_inode_without_packets_does_not_attest_old_packet(tmp_path):
    """A reused flow UID must not transfer a saved packet to a new inode."""
    source = tmp_path / 'capture.mitm'
    db = tmp_path / 'index.sqlite'
    output = tmp_path / 'packet.json'
    record = http.HTTPFlow(connection.Client(peername=('127.0.0.1', 1), sockname=('127.0.0.1', 2), timestamp_start=1), connection.Server(address=('example.test', 80)))
    record.request = http.Request.make('POST', 'http://example.test/same', b'original-packet')

    def write():
        with source.open('wb') as handle:
            FlowWriter(handle).add(record)

    def index(full):
        fd = os.open(source, os.O_RDONLY)
        try:
            cmd = [sys.executable, str(SCRIPTS / 'proxy_store.py'), '--db', str(db), '--json',
                   'index-lane', '--lane', 'lane', '--program', 'fixture',
                   '--flow-file', str(source), '--flow-fd', str(fd)]
            if not full:
                cmd.append('--no-full-requests')
            result = subprocess.run(cmd, pass_fds=(fd,), capture_output=True, text=True, timeout=90)
            assert result.returncode == 0, (result.stdout, result.stderr)
        finally:
            os.close(fd)

    def export():
        result = subprocess.run([sys.executable, str(SCRIPTS / 'proxy_store.py'), '--db', str(db),
                                 '--json', 'export-request', '--id', '1', '--output', str(output)],
                                capture_output=True, text=True, timeout=90)
        return json.loads(result.stdout)

    write()
    index(True)
    assert export()['capture_identity'] == 'verified'
    output.unlink()
    index(False)  # Same descriptor identity: keep the existing packet.
    assert export()['status'] == 'exported'
    output.unlink()
    source.rename(tmp_path / 'old.saved')
    record.request.content = b'replacement-packet'
    write()
    index(False)
    assert export()['status'] == 'not-found'
    assert not output.exists()
    index(True)
    assert export()['capture_identity'] == 'verified'
    import base64
    assert base64.b64decode(json.loads(output.read_text())['body_base64']) == b'replacement-packet'


def test_raw_search_replaced_fifo_returns_without_blocking(tmp_path):
    import signal

    raw = load('raw_history_search')
    source = tmp_path / 'capture.mitm'
    flow(source, 'original')
    info = source.stat()
    identity = (info.st_dev, info.st_ino)
    source.rename(tmp_path / 'original.saved')
    os.mkfifo(source)
    events = []

    class Hung(Exception):
        pass

    def timeout(_signum, _frame):
        raise Hung()

    previous = signal.signal(signal.SIGALRM, timeout)
    try:
        signal.alarm(2)
        try:
            result = raw.search(source, b'original', False, events.append, identity, True)
        except Hung:
            pytest.fail('opening replacement FIFO blocked before identity check')
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert result == (0, 0, ['source-replaced'])
    assert not events


@pytest.mark.parametrize('first_pinned', [False, True])
def test_reindex_between_legacy_and_pinned_identity_invalidates_packet(tmp_path, first_pinned):
    source = tmp_path / 'capture.mitm'
    db = tmp_path / 'index.sqlite'
    output = tmp_path / 'packet.json'
    flow(source, 'legacy')

    def index(pinned, full):
        cmd = [sys.executable, str(SCRIPTS / 'proxy_store.py'), '--db', str(db), '--json',
               'index-lane', '--lane', 'lane', '--program', 'fixture', '--flow-file', str(source)]
        if not full:
            cmd.append('--no-full-requests')
        fd = os.open(source, os.O_RDONLY) if pinned else None
        try:
            if fd is not None:
                cmd.extend(['--flow-fd', str(fd)])
            proc = subprocess.run(cmd, pass_fds=(fd,) if fd is not None else (),
                                  capture_output=True, text=True, timeout=90)
            assert proc.returncode == 0, (proc.stdout, proc.stderr)
        finally:
            if fd is not None:
                os.close(fd)

    index(first_pinned, True)
    index(not first_pinned, False)
    proc = subprocess.run([sys.executable, str(SCRIPTS / 'proxy_store.py'), '--db', str(db),
                           '--json', 'export-request', '--id', '1', '--output', str(output)],
                          capture_output=True, text=True, timeout=90)
    assert json.loads(proc.stdout)['status'] == 'not-found'
    assert not output.exists()


def test_indexed_fifo_cli_and_legacy_symlink(tmp_path):
    source = tmp_path / 'capture.mitm'
    alias = tmp_path / 'alias.mitm'
    db = tmp_path / 'index.sqlite'
    flow(source, 'needle')
    alias.symlink_to(source)
    fd = os.open(source, os.O_RDONLY)
    try:
        proc = subprocess.run([sys.executable, str(SCRIPTS / 'proxy_store.py'), '--db', str(db),
                               '--json', 'index-lane', '--lane', 'lane', '--program', 'fixture',
                               '--flow-file', str(alias), '--flow-fd', str(fd)],
                              pass_fds=(fd,), capture_output=True, text=True, timeout=90)
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
    finally:
        os.close(fd)
    command = [sys.executable, str(SCRIPTS / 'raw_history_search.py'), '--db', str(db),
               '--program', 'fixture', '--lane', 'lane', '--contains', 'needle']
    proc = subprocess.run(command, capture_output=True, text=True, timeout=90)
    assert json.loads(proc.stdout.splitlines()[-1])['matches'] == 1
    source.rename(tmp_path / 'old.saved')
    os.mkfifo(source)
    proc = subprocess.run(command, capture_output=True, text=True, timeout=90)
    summary = json.loads(proc.stdout.splitlines()[-1])
    assert proc.returncode == 2 and summary['matches'] == 0
    assert 'source-replaced' in summary['reasons']
    raw = load('raw_history_search')
    assert raw.search(alias, b'needle', False, lambda e: None) == (0, 0, ['source-unavailable'])
