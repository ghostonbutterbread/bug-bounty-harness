"""Offline regressions for JS cache review blockers."""
import json
import fcntl
import multiprocessing as mp
import re
import sqlite3
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest
from agents import js_analyzer as J


def _inventory_worker(root, name, entered, release, finished, result):
    root = Path(root)
    url = f'https://example.test/{name}.js'
    source = root / f'{name}.txt'
    source.write_text(url + '\n')
    def fetch(*args, **kwargs):
        entered.set()
        if name == 'a':
            assert release.wait(15)
        else:
            assert finished.wait(15)
        return f'const {name} = true;'.encode(), 200, 'application/javascript'
    args = ['inventory', 'demo', '--input', str(source), '--target-host', 'example.test',
            '--output-root', str(root / name), '--library-root', str(root / 'library'),
            '--integration-index-root', str(root / ('integration-' + name)),
            '--source-maps', 'off', '--disk-free-floor-gib', '0']
    try:
        with patch.object(J, 'http_get', side_effect=fetch):
            result.put((name, J.main(args)))
    except BaseException as exc:
        result.put((name, repr(exc)))
    finally:
        if name == 'a':
            finished.set()


def test_concurrent_inventory_writers_preserve_both_ledger_mappings(tmp_path):
    ctx = mp.get_context('fork')
    a_entered, b_entered, release, finished = (ctx.Event() for _ in range(4))
    result = ctx.Queue()
    a = ctx.Process(target=_inventory_worker, args=(tmp_path, 'a', a_entered, release, finished, result))
    b = ctx.Process(target=_inventory_worker, args=(tmp_path, 'b', b_entered, release, finished, result))
    try:
        a.start()
        assert a_entered.wait(15)
        b.start()
        b_entered.wait(1)  # old code enters fetch using a stale snapshot; locked code waits
        release.set()
        a.join(20)
        b.join(20)
        assert not a.is_alive() and not b.is_alive()
        assert sorted([result.get(timeout=2), result.get(timeout=2)]) == [('a', 0), ('b', 0)]
        ledger = json.loads((tmp_path / 'library' / 'ledger.json').read_text())
        assert sorted(ledger['urls']) == ['https://example.test/a.js', 'https://example.test/b.js']
        assert len(J.read_jsonl(tmp_path / 'library' / 'metadata.jsonl')) == 2
    finally:
        release.set()
        for p in (a, b):
            if p.pid and p.is_alive():
                p.terminate()
                p.join()


def _observe_worker(root, started, entered, result):
    root = Path(root)
    source = root / 'observations.jsonl'
    source.write_text(json.dumps({'sha256': 'observed', 'title': 'review'}) + '\n')
    original = J.append_observations
    def append(**kwargs):
        entered.set()
        return original(**kwargs)
    started.set()
    try:
        with patch.object(J, 'append_observations', side_effect=append):
            result.put(J.main(['observe', 'demo', '--input', str(source), '--library-root', str(root / 'library')]))
    except BaseException as exc:
        result.put(repr(exc))


def test_observe_waits_for_inventory_library_publication(tmp_path):
    ctx = mp.get_context('fork')
    a_entered, release, finished, started, observe_entered = (ctx.Event() for _ in range(5))
    result = ctx.Queue()
    a = ctx.Process(target=_inventory_worker, args=(tmp_path, 'a', a_entered, release, finished, result))
    b = ctx.Process(target=_observe_worker, args=(tmp_path, started, observe_entered, result))
    try:
        a.start()
        assert a_entered.wait(15)
        b.start()
        assert started.wait(15)
        assert not observe_entered.wait(1)
        release.set()
        a.join(20)
        b.join(20)
        assert not a.is_alive() and not b.is_alive()
        assert {result.get(timeout=2), result.get(timeout=2)} == {('a', 0), 0}
        with sqlite3.connect(tmp_path / 'library' / 'js_info.sqlite') as db:
            assert db.execute('SELECT count(*) FROM js_files').fetchone()[0] == 1
            assert db.execute('SELECT count(*) FROM js_observations').fetchone()[0] == 1
    finally:
        release.set()
        for p in (a, b):
            if p.pid and p.is_alive():
                p.terminate()
                p.join()


def test_replay_aggregates_seen_and_trusted_fetch_independently(tmp_path):
    a, b = 'https://example.test/a.js', 'https://example.test/b.js'
    def row(url, observed, fetched=None):
        return dict(url=url, sha256='samehash', generated_at=observed,
                    last_fetched_at=fetched, artifact_path='artifact', byte_count=1)
    rows = [row(a, '2026-01-03T00:00:00Z', '2026-01-02T00:00:00Z'),
            row(b, '2026-01-04T00:00:00Z', '2026-01-01T00:00:00Z'),
            row(a, '2026-01-05T00:00:00Z')]
    path = tmp_path / 'index.sqlite'
    J.write_metadata_db(path, iter(rows), [])
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT first_seen,last_seen,last_fetched_at FROM js_files').fetchone() == (
            '2026-01-03T00:00:00Z', '2026-01-05T00:00:00Z', '2026-01-02T00:00:00Z')
        assert db.execute('SELECT last_seen,last_fetched_at FROM js_url_aliases WHERE js_url=?', (a,)).fetchone() == (
            '2026-01-05T00:00:00Z', '2026-01-02T00:00:00Z')
        assert db.execute('SELECT last_seen,last_fetched_at FROM js_url_aliases WHERE js_url=?', (b,)).fetchone() == (
            '2026-01-04T00:00:00Z', '2026-01-01T00:00:00Z')


def test_replay_compares_fetch_instants_not_timestamp_strings(tmp_path):
    base = dict(url='https://example.test/a.js', sha256='hash', generated_at='2026-01-04T00:00:00Z')
    later = '2026-01-02T00:00:00Z'
    earlier = '2026-01-02T12:00:00+14:00'
    rows = [dict(base, last_fetched_at=later), dict(base, last_fetched_at=earlier),
            dict(base, last_fetched_at='invalid')]
    path = tmp_path / 'index.sqlite'
    J.write_metadata_db(path, iter(rows), [])
    with sqlite3.connect(path) as db:
        for table in ('js_files', 'js_url_aliases'):
            assert db.execute(f'SELECT last_fetched_at FROM {table}').fetchone()[0] == later


@pytest.mark.parametrize('failure', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_library_lock_releases_on_exception_or_cancellation(tmp_path, failure):
    def fail(_):
        raise failure()
    with pytest.raises(failure):
        J._with_library_lock(tmp_path / 'library', fail, Namespace())
    with (tmp_path / 'library' / '.js-writer.lock').open('a+') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(handle, fcntl.LOCK_UN)


def _hold_library_lock(root, entered):
    def hold(_):
        entered.set()
        mp.Event().wait(60)
    J._with_library_lock(Path(root) / 'library', hold, Namespace())


def test_library_lock_released_when_writer_process_is_terminated(tmp_path):
    ctx = mp.get_context('fork')
    entered = ctx.Event()
    process = ctx.Process(target=_hold_library_lock, args=(tmp_path, entered))
    try:
        process.start()
        assert entered.wait(15)
        process.terminate()
        process.join(15)
        assert not process.is_alive()
        with (tmp_path / 'library' / '.js-writer.lock').open('a+') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        if process.is_alive():
            process.terminate()
            process.join()


@pytest.mark.parametrize('command', ['inventory', 'observe'])
def test_writer_resolves_library_only_once_before_lock(tmp_path, command):
    source = tmp_path / 'input'
    source.write_text('https://example.test/a.js\n' if command == 'inventory' else '{"title":"test"}\n')
    args = [command, 'demo', '--input', str(source), '--library-root', str(tmp_path / 'library')]
    if command == 'inventory':
        args += ['--target-host', 'example.test', '--output-root', str(tmp_path / 'output'),
                 '--integration-index-root', str(tmp_path / 'index'), '--source-maps', 'off', '--disk-free-floor-gib', '0']
    name = 'resolve_inventory_paths' if command == 'inventory' else 'resolve_library_root'
    original = getattr(J, name)
    with patch.object(J, name, wraps=original) as resolve, patch.object(J, 'http_get', return_value=(b'const x=1;', 200, 'application/javascript')):
        assert J.main(args) == 0
    assert resolve.call_count == 1


def test_legacy_index_migration_never_converts_old_seen_to_fetch(tmp_path):
    path = tmp_path / 'index.sqlite'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE js_files (sha256 TEXT PRIMARY KEY, artifact_path TEXT NOT NULL, byte_count INTEGER NOT NULL, content_type TEXT, first_seen TEXT, last_seen TEXT, latest_run_id TEXT, target_host TEXT, source_map TEXT, chunk_count INTEGER, signal_counts_json TEXT, metadata_json TEXT NOT NULL)')
        db.execute('CREATE TABLE js_url_aliases (js_url TEXT, sha256 TEXT, first_seen TEXT, last_seen TEXT, latest_run_id TEXT, status INTEGER, content_type TEXT, source TEXT, page_context TEXT, PRIMARY KEY(js_url,sha256))')
        db.execute("INSERT INTO js_files (sha256,artifact_path,byte_count,first_seen,last_seen,metadata_json) VALUES ('h','x',1,'old','bogus','{}')")
        db.execute("INSERT INTO js_url_aliases (js_url,sha256,first_seen,last_seen) VALUES ('u','h','old','bogus')")
    J.write_metadata_db(path, iter([dict(url='u', sha256='h', generated_at='2026-01-01T00:00:00Z')]), [])
    with sqlite3.connect(path) as db:
        for table in ('js_files', 'js_url_aliases'):
            assert db.execute(f'SELECT first_seen,last_seen,last_fetched_at FROM {table}').fetchone() == (
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', None)


def test_documented_stale_selection_uses_current_ledger_and_includes_unknown(tmp_path):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    stamp = lambda dt: dt.isoformat(timespec='seconds').replace('+00:00', 'Z')
    fresh, unknown, stale = (f'https://example.test/{name}.js' for name in ('fresh', 'unknown', 'stale'))
    ledger = {'urls': {
        fresh: {'sha256': 'new', 'status': 200, 'last_fetched_at': stamp(now)},
        unknown: {'sha256': 'other'},
        stale: {'sha256': 'old', 'status': 200, 'last_fetched_at': stamp(now - timedelta(days=8))},
    }, 'files': {'obsolete': {'urls': [fresh], 'last_seen': stamp(now - timedelta(days=30))}}}
    path = tmp_path / 'ledger.json'
    path.write_text(json.dumps(ledger))
    text = (Path(J.__file__).parents[1] / 'skills/js-pull/SKILL.md').read_text()
    match = re.search(r"python3 - .*? <<'PY'[^\n]*\n(.*?)\n\s*PY", text, re.S)
    assert match, 'stale selection must use the documented ledger script'
    import textwrap
    result = subprocess.run([sys.executable, '-c', textwrap.dedent(match.group(1)), str(path)],
                            text=True, capture_output=True, check=True)
    assert set(result.stdout.splitlines()) == {unknown, stale}
