"""End-to-end sync CLI tests using only disposable synthetic storage."""
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


class AtomicReportImportCLI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        self.storage = self.root / 'storage'
        self.source = self.root / 'source'
        self.source.mkdir()
        self.report = self.source / 'finding.md'
        self.report.write_text('## [CONFIRMED] Synthetic finding\nFile: src/app.js\nClass: xss\n### Description\nOwned fixture.\n')
        self.layout = resolve_storage('synthetic_atomic', family='binaries', lane='apk', root_override=self.storage, create=False)
        self.env = os.environ.copy()
        self.env.update(HOME=str(self.root), XDG_CONFIG_HOME=str(self.root / 'config'),
                        XDG_CACHE_HOME=str(self.root / 'cache'), XDG_DATA_HOME=str(self.root / 'data'),
                        TMPDIR=str(self.root))
        self.command = [sys.executable, '-m', 'agents.sync_reports', 'synthetic_atomic', '--lane', 'apk',
                        '--root', str(self.storage), '--source-dir', str(self.source), '--source-root', str(self.source)]

    def cli(self):
        return subprocess.run(self.command, cwd=self.root, env=self.env, text=True, capture_output=True, timeout=30)

    def start_gated_cli(self, hook):
        ready_r, ready_w = os.pipe()
        release_r, release_w = os.pipe()
        script = '''
import fcntl, os, runpy, sys
import bounty_core.ledger as ledger
ready, release = map(int, sys.argv[1:3])
sys.argv = ["agents.sync_reports", *sys.argv[3:]]
def gate():
    os.write(ready, b"1")
    if os.read(release, 1) != b"1":
        raise RuntimeError("gate closed")
if os.environ["TEST_GATE"] == "before_lock":
    original = fcntl.flock
    def hooked(fd, operation):
        if operation == fcntl.LOCK_EX:
            gate()
        return original(fd, operation)
    fcntl.flock = hooked
else:
    original = ledger.refresh_indexes
    def hooked(*args, **kwargs):
        gate()
        return original(*args, **kwargs)
    ledger.refresh_indexes = hooked
runpy.run_module("agents.sync_reports", run_name="__main__")
'''
        env = {**self.env, 'TEST_GATE': hook}
        try:
            process = subprocess.Popen(
                [sys.executable, '-c', script, str(ready_w), str(release_r), *self.command[3:]],
                cwd=self.root, env=env, pass_fds=(ready_w, release_r),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
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
        self.assertTrue(select.select([ready_r], [], [], 15)[0], 'CLI did not reach gate')
        self.assertEqual(os.read(ready_r, 1), b'1')
        return process, release_w

    @property
    def ledger_path(self):
        return self.layout.ledgers_root / 'ledger.json'

    def test_raw_collision_fails_without_reservation_then_retry_imports(self):
        self.layout.reports_root.joinpath('raw').mkdir(parents=True)
        raw = self.layout.reports_root / 'raw' / 'intake.md'
        raw.write_text('owned raw sentinel')
        ledger_add('synthetic_atomic', {'fid': 'raw', 'file': 'old.js', 'line': 3, 'type': 'xss', 'class_name': 'xss'},
                   's', 'v', 'r', 'a', family='binaries', lane='apk', root_override=self.storage)
        ledger = self.layout.ledgers_root / 'ledger.json'
        before = ledger.read_bytes()
        result = self.cli()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('reports/raw', result.stderr)
        self.assertEqual(ledger.read_bytes(), before)
        self.assertEqual(raw.read_text(), 'owned raw sentinel')
        payload = json.loads(before)
        payload['findings'] = []
        ledger.write_text(json.dumps(payload))
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('ADDED ', result.stdout)
        rows = json.loads(ledger.read_text())['findings']
        self.assertEqual(len(rows), 1)
        self.assertTrue(Path(rows[0]['evidence_path']).is_file())
        self.assertEqual(raw.read_text(), 'owned raw sentinel')
        before = ledger.read_bytes()
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('already exists, skipped', result.stdout)
        self.assertEqual(ledger.read_bytes(), before)

    def test_cli_io_failure_is_not_reported_as_fid_collision(self):
        script = '''
import runpy, sys
import bounty_core.ledger as ledger
def fail(*args, **kwargs):
    raise OSError("synthetic index failure")
ledger.refresh_indexes = fail
sys.argv = ["agents.sync_reports", *sys.argv[1:]]
runpy.run_module("agents.sync_reports", run_name="__main__")
'''
        result = subprocess.run([sys.executable, '-c', script, *self.command[3:]], cwd=self.root,
                                env=self.env, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('synthetic index failure', result.stderr)
        self.assertNotIn('FID collisions', result.stdout)
        self.assertEqual(json.loads(self.ledger_path.read_text())['findings'][0]['_atomic_import_pending'],
                         'evidence_only')
        retry = self.cli()
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertIn('ADDED ', retry.stdout)

    def test_cli_reports_fid_collision_without_misclassifying_it(self):
        first = self.cli()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        before = self.ledger_path.read_bytes()
        fid = json.loads(before)['findings'][0]['fid']
        self.report.write_text(
            f'## [CONFIRMED] Different finding\nFID: {fid}\nFile: src/other.js\n'
            'Class: xss\n### Description\nAnother owned fixture.\n'
        )
        result = self.cli()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('finding FID already assigned: ' + fid, result.stderr)
        self.assertIn('FID collisions: 1 report needs manual reconciliation', result.stdout)
        self.assertEqual(self.ledger_path.read_bytes(), before)

    def test_canonical_raw_report_is_imported_without_modifying_source(self):
        raw = self.layout.reports_root / 'raw' / 'finding.md'
        raw.parent.mkdir(parents=True)
        original = self.report.read_bytes()
        raw.write_bytes(original)
        self.command = [sys.executable, '-m', 'agents.sync_reports', 'synthetic_atomic', '--lane', 'apk',
                        '--root', str(self.storage), '--source-root', str(self.source)]
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('ADDED ', result.stdout)
        self.assertEqual(raw.read_bytes(), original)
        row, = json.loads(self.ledger_path.read_text())['findings']
        self.assertTrue(Path(row['evidence_path']).is_file())
        self.assertFalse((Path(row['report_dir']) / 'REPORT.md').exists())

    def test_killed_cli_recovers_pending_import_on_retry(self):
        process, _release = self.start_gated_cli('materialize')
        pending = json.loads(self.ledger_path.read_text())['findings']
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]['_atomic_import_pending'], 'evidence_only')
        fid = pending[0]['fid']
        # Another process must not acquire the ledger lock during materialization.
        with (self.layout.ledgers_root / 'ledger.lock').open('a+') as lock:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        process.kill()
        process.wait(timeout=10)
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('ADDED ' + fid, result.stdout)
        rows = json.loads(self.ledger_path.read_text())['findings']
        self.assertEqual(len(rows), 1)
        self.assertNotIn('_atomic_import_pending', rows[0])
        self.assertTrue(Path(rows[0]['evidence_path']).is_file())
        self.assertIn('already exists, skipped', self.cli().stdout)

    def test_competing_process_writes_raw_before_lock_and_import_fails_cleanly(self):
        raw = self.layout.reports_root / 'raw' / 'intake.md'
        raw.parent.mkdir(parents=True)
        raw.write_text('intact')
        process, release = self.start_gated_cli('before_lock')
        # Seed from this separate process while the CLI is stopped before flock.
        ledger_add('synthetic_atomic', {'fid': 'raw', 'file': 'old.js', 'line': 3, 'type': 'xss', 'class_name': 'xss'},
                   's', 'v', 'r', 'a', family='binaries', lane='apk', root_override=self.storage)
        before = self.ledger_path.read_bytes()
        os.write(release, b'1')
        stdout, stderr = process.communicate(timeout=15)
        self.assertNotEqual(process.returncode, 0, stdout + stderr)
        self.assertIn('reports/raw', stderr)
        self.assertNotIn('FID collisions', stdout)
        self.assertEqual(self.ledger_path.read_bytes(), before)
        self.assertEqual(raw.read_text(), 'intact')
