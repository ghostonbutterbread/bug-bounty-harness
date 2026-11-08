"""Offline regressions for the reconciled proxy index and history paths."""
import argparse
import json
import sqlite3
import subprocess
from pathlib import Path

from agents.test_standalone_index_review import flow, ix, load, setup_lane


def test_shared_index_preserves_explicit_empty_transport(tmp_path):
    capture = tmp_path / 'capture.mitm'
    flow(capture)
    root = tmp_path / 'lanes'
    state = root / 'hoster-default-8080'
    state.mkdir(parents=True)
    (state / 'state.json').write_text(json.dumps({
        'status': 'stopped', 'flow_file': str(capture), 'transport': 'browser',
    }))
    module = load('mitm_lane')
    values = []
    for transport in ('', None):
        db = tmp_path / ('empty.sqlite' if transport == '' else 'missing.sqlite')
        args = argparse.Namespace(root=str(root), lane='hoster-default-8080',
                                  mitmdump='/usr/bin/mitmdump', db=str(db),
                                  flow_file=str(capture), store_full_requests=True,
                                  transport=transport)
        assert module.index_store(args)['status'] == 'indexed'
        with sqlite3.connect(db) as conn:
            values.append(conn.execute('select transport from requests').fetchone()[0])
    assert values == ['', 'browser']


def test_raw_search_resolves_logical_and_generated_lanes(monkeypatch, tmp_path, capsys):
    real_popen = subprocess.Popen
    module, args = setup_lane(monkeypatch, tmp_path)
    (tmp_path / 'private').mkdir(mode=0o700)
    state = module.start_lane(args)
    flow(Path(state['flow_file']))
    module.stop_lane(args)
    monkeypatch.setattr(module.subprocess, 'Popen', real_popen)
    assert module.index_store(ix(args, tmp_path))['status'] == 'indexed'
    raw = load('raw_history_search')
    cmd = ['--db', ix(args, tmp_path).db, '--program', args.program,
           '--contains', 'owned-fixture', '--lane']
    results = []
    for lane in (args.lane, state['index_lane']):
        rc = raw.main([*cmd, lane])
        result = json.loads(capsys.readouterr().out.splitlines()[-1])
        results.append((rc, result['sources'], result['matches']))
    assert results == [(2, 1, 1), (2, 1, 1)]
    assert raw.index_sources(ix(args, tmp_path).db, 'Other', args.lane) == ([], False)
    # An older database has no alias table; its explicit lane remains readable.
    with sqlite3.connect(ix(args, tmp_path).db) as conn:
        conn.execute('DROP TABLE capture_lane_aliases')
    assert len(raw.index_sources(ix(args, tmp_path).db, args.program, state['index_lane'])[0]) == 1
    assert raw.index_sources(ix(args, tmp_path).db, args.program, args.lane) == ([], False)


def test_raw_alias_never_bypasses_shared_source_owner_check(tmp_path):
    raw = load('raw_history_search')
    capture = tmp_path / 'capture'
    capture.write_bytes(b'fixture')
    st = capture.stat()
    db = tmp_path / 'index.sqlite'
    with sqlite3.connect(db) as conn:
        conn.executescript('''
            CREATE TABLE lanes(lane TEXT, program TEXT, flow_file TEXT, capture_dev INTEGER, capture_ino INTEGER);
            CREATE TABLE requests(lane TEXT, program TEXT, raw_flow_file TEXT, capture_dev INTEGER, capture_ino INTEGER);
            CREATE TABLE capture_lane_aliases(generation_lane TEXT, logical_lane TEXT);
        ''')
        conn.execute('INSERT INTO capture_lane_aliases VALUES (?, ?)', ('generation', 'logical'))
        conn.execute('INSERT INTO lanes VALUES (?, ?, ?, ?, ?)', ('generation', 'A', str(capture), st.st_dev, st.st_ino))
        conn.execute('INSERT INTO requests VALUES (?, ?, ?, ?, ?)', ('other', 'B', str(capture), st.st_dev, st.st_ino))
    assert raw.index_sources(db, 'A', 'logical') == ([], True)
    assert raw.index_sources(db, 'A', 'generation') == ([], True)
    with sqlite3.connect(db) as conn:
        conn.execute('DROP TABLE capture_lane_aliases')
        conn.execute('CREATE TABLE capture_lane_aliases(unrelated TEXT)')
        conn.execute('DELETE FROM requests')
    assert len(raw.index_sources(db, 'A', 'generation')[0]) == 1
    assert raw.index_sources(db, 'A', 'logical') == ([], False)
