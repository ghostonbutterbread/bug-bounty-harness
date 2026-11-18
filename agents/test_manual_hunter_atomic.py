"""Manual CLI atomic import regressions on disposable synthetic storage."""
import fcntl
import json
import os
import select
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bounty_core.ledger import ledger_add
from bounty_core.storage import resolve_storage


class AtomicManualImportCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.storage = self.root / 'storage'
        self.layout = resolve_storage('synthetic_manual', family='binaries', lane='apk', root_override=self.storage, create=False)
        self.env = {**os.environ, 'HOME': str(self.root), 'XDG_CONFIG_HOME': str(self.root / 'config'),
                    'XDG_CACHE_HOME': str(self.root / 'cache'), 'XDG_DATA_HOME': str(self.root / 'data'),
                    'TMPDIR': str(self.root)}
        self.note = self.root / 'note.md'
        self.note.write_text('Title: Fixture finding\nClass: xss\nFile: src/app.js\nDescription: Synthetic observation.\n')
        self.command = [sys.executable, '-m', 'agents.manual_hunter', 'synthetic_manual', '--lane', 'apk',
                        '--root', str(self.storage), '--source-root', str(self.root), '--from-file', str(self.note)]

    def cli(self, *extra):
        return subprocess.run([*self.command, *extra], cwd=self.root, env=self.env, text=True,
                              capture_output=True, timeout=30)

    @property
    def ledger_path(self):
        return self.layout.ledgers_root / 'ledger.json'

    def test_raw_collision_preserves_ledger_and_retry_adds(self):
        raw = self.layout.reports_root / 'raw' / 'intake.md'
        raw.parent.mkdir(parents=True)
        raw.write_text('raw sentinel')
        ledger_add('synthetic_manual', {'fid': 'raw', 'file': 'old.js', 'line': 3, 'type': 'xss', 'class_name': 'xss'},
                   's', 'v', 'r', 'a', family='binaries', lane='apk', root_override=self.storage)
        before = self.ledger_path.read_bytes()
        result = self.cli()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('reports/raw', result.stderr)
        self.assertEqual(self.ledger_path.read_bytes(), before)
        self.assertEqual(raw.read_text(), 'raw sentinel')
        payload = json.loads(before)
        payload['findings'] = []
        self.ledger_path.write_text(json.dumps(payload))
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Added finding ', result.stdout)
        row, = json.loads(self.ledger_path.read_text())['findings']
        self.assertTrue(Path(row['evidence_path']).is_file())
        self.assertEqual(raw.read_text(), 'raw sentinel')

    def test_duplicate_has_no_new_sighting_and_optional_comment_is_linked(self):
        first = self.cli()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        before = self.ledger_path.read_bytes()
        row, = json.loads(before)['findings']
        self.assertEqual(len(row['sightings']), 1)
        self.assertEqual(row['sightings'][0]['agent'], 'manual-hunter')
        self.assertIn('Evidence packet: ', first.stdout)
        self.assertIn('Added finding ' + row['fid'], first.stdout)
        duplicate = self.cli()
        self.assertEqual(duplicate.returncode, 1, duplicate.stdout + duplicate.stderr)
        self.assertIn('Duplicate: ' + row['fid'] + ' overlaps with Fixture finding', duplicate.stdout)
        self.assertIn('Use --link-duplicate-comment', duplicate.stdout)
        self.assertEqual(self.ledger_path.read_bytes(), before)
        linked = self.cli('--link-duplicate-comment')
        self.assertEqual(linked.returncode, 1, linked.stdout + linked.stderr)
        self.assertIn('Linked duplicate note to ' + row['fid'], linked.stdout)
        self.assertEqual(self.ledger_path.read_bytes(), before)
        comment, = (self.layout.ledgers_root / 'manual_comments.jsonl').read_text().splitlines()
        self.assertEqual(json.loads(comment)['fid'], row['fid'])
        self.assertEqual(json.loads(comment)['raw_note'], self.note.read_text().strip())

    def test_materialization_error_propagates_and_retry_recovers(self):
        script = '''
import runpy, sys
import bounty_core.ledger as ledger
def fail(*args, **kwargs):
    raise OSError("synthetic manual index failure")
ledger.refresh_indexes = fail
sys.argv = ["agents.manual_hunter", *sys.argv[1:]]
runpy.run_module("agents.manual_hunter", run_name="__main__")
'''
        result = subprocess.run([sys.executable, '-c', script, *self.command[3:]], cwd=self.root,
                                env=self.env, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('synthetic manual index failure', result.stderr)
        self.assertNotIn('Duplicate:', result.stdout)
        row, = json.loads(self.ledger_path.read_text())['findings']
        self.assertEqual(row['_atomic_import_pending'], 'evidence_only')
        retry = self.cli()
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertIn('Added finding ' + row['fid'], retry.stdout)
        row, = json.loads(self.ledger_path.read_text())['findings']
        self.assertNotIn('_atomic_import_pending', row)
        self.assertEqual(len(row['sightings']), 1)
        self.assertTrue(Path(row['evidence_path']).is_file())

    def test_killed_cli_recovers_pending_with_same_fid(self):
        ready_r, ready_w = os.pipe()
        release_r, release_w = os.pipe()
        script = '''
import os, runpy, sys
import bounty_core.ledger as ledger
ready, release = map(int, sys.argv[1:3])
sys.argv = ["agents.manual_hunter", *sys.argv[3:]]
original = ledger.refresh_indexes
def gate(*args, **kwargs):
    os.write(ready, b"1")
    os.read(release, 1)
    return original(*args, **kwargs)
ledger.refresh_indexes = gate
runpy.run_module("agents.manual_hunter", run_name="__main__")
'''
        try:
            process = subprocess.Popen([sys.executable, '-c', script, str(ready_w), str(release_r), *self.command[3:]],
                                       cwd=self.root, env=self.env, pass_fds=(ready_w, release_r),
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
        self.assertTrue(select.select([ready_r], [], [], 15)[0], 'CLI did not reach materialization')
        self.assertEqual(os.read(ready_r, 1), b'1')
        row, = json.loads(self.ledger_path.read_text())['findings']
        self.assertEqual(row['_atomic_import_pending'], 'evidence_only')
        with (self.layout.ledgers_root / 'ledger.lock').open('a+') as lock:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        process.kill()
        process.wait(timeout=10)
        retry = self.cli()
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertIn('Added finding ' + row['fid'], retry.stdout)
        recovered, = json.loads(self.ledger_path.read_text())['findings']
        self.assertEqual(recovered['fid'], row['fid'])
        self.assertNotIn('_atomic_import_pending', recovered)
        self.assertEqual(len(recovered['sightings']), 1)
        self.assertTrue(Path(recovered['evidence_path']).is_file())
        self.assertEqual(self.cli().returncode, 1)

    def test_competing_raw_collision_before_lock_leaves_ledger_unchanged(self):
        raw = self.layout.reports_root / 'raw' / 'intake.md'
        raw.parent.mkdir(parents=True)
        raw.write_text('raw sentinel')
        ready_r, ready_w = os.pipe()
        release_r, release_w = os.pipe()
        script = '''
import fcntl, os, runpy, sys
ready, release = map(int, sys.argv[1:3])
sys.argv = ["agents.manual_hunter", *sys.argv[3:]]
original = fcntl.flock
def gate(fd, operation):
    if operation == fcntl.LOCK_EX:
        os.write(ready, b"1")
        os.read(release, 1)
    return original(fd, operation)
fcntl.flock = gate
runpy.run_module("agents.manual_hunter", run_name="__main__")
'''
        try:
            process = subprocess.Popen([sys.executable, '-c', script, str(ready_w), str(release_r), *self.command[3:]],
                                       cwd=self.root, env=self.env, pass_fds=(ready_w, release_r),
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
        self.assertTrue(select.select([ready_r], [], [], 15)[0], 'CLI did not reach lock')
        self.assertEqual(os.read(ready_r, 1), b'1')
        ledger_add('synthetic_manual', {'fid': 'raw', 'file': 'old.js', 'line': 3, 'type': 'xss', 'class_name': 'xss'},
                   's', 'v', 'r', 'a', family='binaries', lane='apk', root_override=self.storage)
        before = self.ledger_path.read_bytes()
        os.write(release_w, b'1')
        stdout, stderr = process.communicate(timeout=15)
        self.assertNotEqual(process.returncode, 0, stdout + stderr)
        self.assertIn('reports/raw', stderr)
        self.assertNotIn('Duplicate:', stdout)
        self.assertEqual(self.ledger_path.read_bytes(), before)
        self.assertEqual(raw.read_text(), 'raw sentinel')

    def test_real_report_registration_consumes_manual_packet(self):
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        row, = json.loads(self.ledger_path.read_text())['findings']
        evidence = Path(row['evidence_path'])
        evidence_before = evidence.read_bytes()
        report = Path(row['report_dir']) / ('fixture-xss-' + row['fid'] + '.md')
        report.write_text('# Synthetic final report\n')
        command = [sys.executable, '-m', 'agents.finding_report', 'synthetic_manual', row['fid'],
                   '--lane', 'apk', '--storage-root', str(self.storage), '--report', str(report)]
        registered = subprocess.run(command, cwd=self.root, env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(registered.returncode, 0, registered.stdout + registered.stderr)
        self.assertEqual(json.loads(registered.stdout)['report_path'], str(report))
        current, = json.loads(self.ledger_path.read_text())['findings']
        self.assertEqual(current['report_path'], str(report))
        self.assertEqual(evidence.read_bytes(), evidence_before)
        self.assertEqual(report.read_text(), '# Synthetic final report\n')
