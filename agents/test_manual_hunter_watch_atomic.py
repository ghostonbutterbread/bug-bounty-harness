"""Real watch-loop recovery against synthetic local storage and installed Core."""
import contextlib
import io
import json
import os
import select
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bounty_core.ledger as core_ledger
from agents.manual_hunter import ManualHunter


class AtomicManualWatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.hunter = ManualHunter('synthetic_watch', lane='apk', storage_root=self.root / 'storage',
                                   source_root=self.root)
        self.note = self.hunter.drop_dir / 'finding.md'
        self.note.write_text('Title: Watch fixture\nClass: xss\nFile: src/app.js\nDescription: Synthetic.\n')
        self.ledger = self.hunter.storage.ledgers_root / 'ledger.json'

    def rows(self):
        return json.loads(self.ledger.read_text())['findings']

    def test_failed_materialization_is_retried_in_later_poll_without_file_change(self):
        real_refresh = core_ledger.refresh_indexes
        attempts = []
        sleeps = []
        seen = []

        def refresh(*args, **kwargs):
            attempts.append(1)
            if len(attempts) == 1:
                raise OSError('synthetic watch index failure')
            return real_refresh(*args, **kwargs)

        def poll_sleep(delay):
            sleeps.append(delay)
            state = self.hunter.state_store.load()
            row, = self.rows()
            seen.append((state['files'].get(str(self.note)), dict(row)))
            if len(sleeps) == 3:
                raise KeyboardInterrupt

        output = io.StringIO()
        with patch.object(core_ledger, 'refresh_indexes', side_effect=refresh), \
             patch('agents.manual_hunter.time.sleep', side_effect=poll_sleep), \
             contextlib.redirect_stdout(output):
            self.assertEqual(self.hunter.watch(poll_interval=0), 0)
        self.assertIn('synthetic watch index failure', output.getvalue())
        self.assertIsNone(seen[0][0])
        self.assertEqual(seen[0][1]['_atomic_import_pending'], 'evidence_only')
        self.assertEqual(len(attempts), 2)
        self.assertTrue(all(delay >= 0.2 for delay in sleeps))
        self.assertIsNotNone(seen[1][0])
        self.assertEqual(seen[1], seen[2])
        self.assertNotIn('_atomic_import_pending', seen[1][1])
        self.assertEqual(seen[0][1]['fid'], seen[1][1]['fid'])
        self.assertEqual(len(seen[1][1]['sightings']), 1)
        self.assertTrue(Path(seen[1][1]['evidence_path']).is_file())

    def test_restart_retries_pending_and_completed_fingerprint_is_stable(self):
        def fail(*args, **kwargs):
            raise OSError('restart fixture index failure')

        with patch.object(core_ledger, 'refresh_indexes', side_effect=fail), \
             patch('agents.manual_hunter.time.sleep', side_effect=KeyboardInterrupt), \
             contextlib.redirect_stdout(io.StringIO()):
            self.hunter.watch()
        pending, = self.rows()
        self.assertEqual(pending['_atomic_import_pending'], 'evidence_only')
        self.assertNotIn(str(self.note), self.hunter.state_store.load()['files'])

        restarted = ManualHunter('synthetic_watch', lane='apk', storage_root=self.root / 'storage',
                                 source_root=self.root)
        with patch('agents.manual_hunter.time.sleep', side_effect=KeyboardInterrupt), \
             contextlib.redirect_stdout(io.StringIO()):
            restarted.watch()
        completed, = self.rows()
        self.assertEqual(completed['fid'], pending['fid'])
        self.assertNotIn('_atomic_import_pending', completed)
        self.assertEqual(len(completed['sightings']), 1)
        before = self.ledger.read_bytes()
        self.assertIn(str(self.note), restarted.state_store.load()['files'])
        with patch.object(restarted, 'ingest_file', wraps=restarted.ingest_file) as ingest, \
             patch('agents.manual_hunter.time.sleep', side_effect=KeyboardInterrupt), \
             contextlib.redirect_stdout(io.StringIO()):
            restarted.watch()
        ingest.assert_not_called()
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_duplicate_is_recorded_as_handled_without_repeated_comments(self):
        self.assertEqual(self.hunter.ingest_file(self.note), 0)
        before = self.ledger.read_bytes()
        duplicate_note = self.hunter.drop_dir / 'duplicate.md'
        duplicate_note.write_text(self.note.read_text())
        # Both existing notes are handled exactly once, including duplicate comments.
        with patch('agents.manual_hunter.time.sleep', side_effect=KeyboardInterrupt), \
             contextlib.redirect_stdout(io.StringIO()):
            self.hunter.watch(link_duplicate_comment=True)
        comments = self.hunter.storage.ledgers_root / 'manual_comments.jsonl'
        self.assertEqual(len(comments.read_text().splitlines()), 2)
        with patch('agents.manual_hunter.time.sleep', side_effect=KeyboardInterrupt), \
             contextlib.redirect_stdout(io.StringIO()):
            self.hunter.watch(link_duplicate_comment=True)
        self.assertEqual(len(comments.read_text().splitlines()), 2)
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_competing_cli_completes_pending_before_watcher_retry(self):
        ready_r, ready_w = os.pipe()
        release_r, release_w = os.pipe()
        script = '''
import os, sys
import bounty_core.ledger as core
import agents.manual_hunter as manual
root, ready, release = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
hunter = manual.ManualHunter('synthetic_watch', lane='apk', storage_root=root + '/storage', source_root=root)
def fail(*args, **kwargs):
    raise OSError('concurrent fixture index failure')
core.refresh_indexes = fail
calls = 0
def pause(_delay):
    global calls
    calls += 1
    if calls == 1:
        os.write(ready, b'1')
        if os.read(release, 1) != b'1':
            raise RuntimeError('gate closed')
    else:
        raise KeyboardInterrupt
manual.time.sleep = pause
hunter.watch(poll_interval=0)
'''
        env = dict(os.environ, HOME=str(self.root), XDG_CONFIG_HOME=str(self.root / 'config'),
                   XDG_CACHE_HOME=str(self.root / 'cache'), XDG_DATA_HOME=str(self.root / 'data'),
                   TMPDIR=str(self.root))
        try:
            process = subprocess.Popen([sys.executable, '-c', script, str(self.root), str(ready_w), str(release_r)],
                                       cwd=self.root, env=env, pass_fds=(ready_w, release_r),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        finally:
            os.close(ready_w)
            os.close(release_r)

        def cleanup():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)
            os.close(ready_r)
            os.close(release_w)
        self.addCleanup(cleanup)
        self.assertTrue(select.select([ready_r], [], [], 20)[0], 'watcher did not reach poll gate')
        self.assertEqual(os.read(ready_r, 1), b'1')
        pending, = self.rows()
        self.assertEqual(pending['_atomic_import_pending'], 'evidence_only')
        self.assertNotIn(str(self.note), self.hunter.state_store.load()['files'])
        command = [sys.executable, '-m', 'agents.manual_hunter', 'synthetic_watch', '--lane', 'apk',
                   '--root', str(self.root / 'storage'), '--source-root', str(self.root), '--from-file', str(self.note)]
        result = subprocess.run(command, cwd=self.root, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Added finding ' + pending['fid'], result.stdout)
        before = self.ledger.read_bytes()
        os.write(release_w, b'1')
        stdout, stderr = process.communicate(timeout=30)
        self.assertEqual(process.returncode, 0, stdout + stderr)
        self.assertIn('Duplicate: ' + pending['fid'], stdout)
        self.assertEqual(self.ledger.read_bytes(), before)
        completed, = self.rows()
        self.assertNotIn('_atomic_import_pending', completed)
        self.assertEqual(len(completed['sightings']), 1)
        self.assertIn(str(self.note), self.hunter.state_store.load()['files'])


if __name__ == '__main__':
    unittest.main()
