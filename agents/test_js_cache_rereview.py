"""Offline regressions for independent JS cache re-review."""
import fcntl
import hashlib
import json
from datetime import datetime, timezone
import multiprocessing as mp
import os
import signal
import sqlite3
import time
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest
from agents import js_analyzer as J


def test_failed_legacy_migration_rolls_back_before_retry(tmp_path):
    path = tmp_path / 'index.sqlite'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE js_files (sha256 TEXT PRIMARY KEY, artifact_path TEXT NOT NULL, byte_count INTEGER NOT NULL, content_type TEXT, first_seen TEXT, last_seen TEXT, latest_run_id TEXT, target_host TEXT, source_map TEXT, chunk_count INTEGER, signal_counts_json TEXT, metadata_json TEXT NOT NULL)')
        db.execute('CREATE TABLE js_url_aliases (js_url TEXT, sha256 TEXT, first_seen TEXT, last_seen TEXT, latest_run_id TEXT, status INTEGER, content_type TEXT, source TEXT, page_context TEXT, PRIMARY KEY(js_url,sha256))')
        db.execute("INSERT INTO js_files (sha256,artifact_path,byte_count,first_seen,last_seen,metadata_json) VALUES ('h','x',1,'2020','2099','{}')")
        db.execute("INSERT INTO js_url_aliases (js_url,sha256,first_seen,last_seen) VALUES ('u','h','2020','2099')")
    with pytest.raises(ValueError):
        J.write_metadata_db(path, iter([dict(url='u', sha256='h', byte_count='bad')]), [])
    J.write_metadata_db(path, iter([dict(url='u', sha256='h', byte_count=1, generated_at='2026-01-01T00:00:00Z')]), [])
    with sqlite3.connect(path) as db:
        for table in ('js_files', 'js_url_aliases'):
            assert db.execute(f'SELECT first_seen,last_seen,last_fetched_at FROM {table}').fetchone() == ('2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', None)


def _writer_with_blocked_parser(root):
    root = Path(root)
    def parse(_):
        (root / 'entered').write_text(str(os.getpid()))
        while not (root / 'release').exists():
            time.sleep(.05)
        return ''
    def work(_):
        with patch.object(J, '_parse_source_map_comments', side_effect=parse):
            J.last_source_map_directive('//# sourceMappingURL=test.map')
    J._with_library_lock(root / 'library', work, Namespace())


def test_forked_parser_cannot_hold_lock_after_writer_dies(tmp_path):
    process = mp.get_context('fork').Process(target=_writer_with_blocked_parser, args=(tmp_path,))
    process.start()
    try:
        deadline = time.monotonic() + 15
        while not (tmp_path / 'entered').exists() and time.monotonic() < deadline:
            time.sleep(.05)
        assert (tmp_path / 'entered').exists()
        # The parser's child cleanup must not unlock the live writer.
        with (tmp_path / 'library' / '.js-writer.lock').open('a+') as handle:
            with pytest.raises(BlockingIOError):
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert process.pid is not None
        os.kill(process.pid, signal.SIGKILL)
        process.join(10)
        assert process.exitcode == -signal.SIGKILL
        with (tmp_path / 'library' / '.js-writer.lock').open('a+') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        (tmp_path / 'release').touch()
        if process.is_alive():
            process.terminate()
            process.join()


@pytest.mark.parametrize('reverse', [False, True])
def test_replay_latest_fields_follow_latest_observation(tmp_path, reverse):
    newer = dict(url='u', sha256='h', byte_count=1, generated_at='2026-01-03T00:00:00Z', last_fetched_at='2026-01-02T00:00:00Z', status=200, run_id='new', content_type='new-type', target_host='new-host')
    older = dict(url='u', sha256='h', byte_count=1, generated_at='2026-01-01T00:00:00Z', status=403, run_id='old', content_type='old-type', target_host='old-host')
    rows = [older, newer] if reverse else [newer, older]
    path = tmp_path / 'index.sqlite'
    J.write_metadata_db(path, iter(rows), [])
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT last_seen,last_fetched_at,latest_run_id,status,content_type FROM js_url_aliases').fetchone() == ('2026-01-03T00:00:00Z','2026-01-02T00:00:00Z','new',200,'new-type')
        assert db.execute('SELECT latest_run_id,target_host,content_type FROM js_files').fetchone() == ('new','new-host','new-type')


def _corrupt_inventory_fixture(tmp_path):
    url = 'https://example.test/app.js'
    body = b'const correct = true;'
    digest = hashlib.sha256(body).hexdigest()
    library = tmp_path / 'library'
    (library / 'downloads').mkdir(parents=True)
    artifact = library / 'downloads' / f'{digest}.js'
    artifact.write_bytes(b'corrupt bytes')
    fetched = datetime.now(timezone.utc).isoformat(timespec='seconds')
    (library / 'ledger.json').write_text(json.dumps({'urls': {url: {'sha256': digest, 'status': 200, 'last_fetched_at': fetched}}, 'files': {}}))
    source = tmp_path / 'urls'
    source.write_text(url + '\n')
    args = ['inventory', 'demo', '--input', str(source), '--target-host', 'example.test', '--output-root', str(tmp_path / 'out'), '--library-root', str(library), '--integration-index-root', str(tmp_path / 'index'), '--source-maps', 'off', '--disk-free-floor-gib', '0']
    return body, artifact, args


def test_skip_cached_processing_refetches_corrupt_artifact(tmp_path):
    body, _, args = _corrupt_inventory_fixture(tmp_path)
    with patch.object(J, 'http_get', return_value=(body, 200, 'application/javascript')) as fetch:
        assert J.main(args + ['--skip-cached-processing']) == 0
    assert fetch.call_count == 1


def test_refetch_repairs_digest_path_and_prevents_repeat_fetch(tmp_path):
    body, artifact, args = _corrupt_inventory_fixture(tmp_path)
    with patch.object(J, 'http_get', return_value=(body, 200, 'application/javascript')) as fetch:
        assert J.main(args + ['--run-id', 'first']) == 0
        assert fetch.call_count == 1
        assert artifact.read_bytes() == body
        args[args.index('--output-root') + 1] = str(tmp_path / 'out-second')
        assert J.main(args + ['--run-id', 'second']) == 0
        assert fetch.call_count == 1
