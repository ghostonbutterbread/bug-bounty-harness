"""Offline integration tests: run with the system mitmproxy Python, not pytest."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from mitmproxy import connection, http, io, version
from mitmproxy.io import tnetstring

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'skills/chromium-test/scripts/raw_history_search.py'
HISTORICAL = '140d4d5116095281b78061fb13a8780fd81a05d4:skills/chromium-test/scripts/proxy_store.py'


def signature(path):
    return (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode)


class RawHistoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.capture = self.root / 'capture.mitm'
        self.db = self.root / 'old.sqlite'
        self.old = self.root / 'historical_store.py'
        self.old.write_bytes(subprocess.check_output(['git', 'show', HISTORICAL], cwd=ROOT))
        self.make_capture()
        cmd = [sys.executable, '-s', str(self.old), '--db', str(self.db), 'index-lane',
               '--lane', 'lane-a', '--program', 'program-a', '--flow-file', str(self.capture)]
        subprocess.run(cmd, check=True, capture_output=True)

    def tearDown(self):
        self.tmp.cleanup()

    def make_capture(self):
        client = connection.Client(peername=('127.0.0.1', 12345), sockname=('127.0.0.1', 8081), timestamp_start=1.0)
        server = connection.Server(address=('example.test', 443))
        flow = http.HTTPFlow(client, server)
        flow.request = http.Request.make('POST', 'https://example.test/path?x=secret-query', b'needle\x00\xff', {'Authorization': 'secret-token'})
        flow.response = http.Response.make(200, b'needle-response\x00\xff caf\xc3\xa9', {'Set-Cookie': 'secret-cookie'})
        other = http.HTTPFlow(client, server)
        other.request = http.Request.make('GET', 'http://example.test/plain?x=httpneedle', b'')
        other.response = http.Response.make(200, b'http-response', {'X-Test': 'headerneedle'})
        with self.capture.open('wb') as out:
            writer = io.FlowWriter(out)
            writer.add(flow)
            writer.add(flow)  # Same historical UID, distinct occurrence.
            writer.add(other)

    def run_search(self, *args, capture=None):
        cmd = [sys.executable, '-s', str(SCRIPT), '--db', str(self.db), '--program', 'program-a', '--lane', 'lane-a']
        if capture:
            cmd += ['--capture', str(capture)]
        proc = subprocess.run(cmd + list(args), capture_output=True, text=True)
        return proc, [json.loads(line) for line in proc.stdout.splitlines() if json.loads(line)['type'] != 'source']

    def test_real_flow_reader_scans_https_and_http_without_exposing_raw(self):
        before = [signature(p) for p in (self.capture, self.db)]
        proc, events = self.run_search('--contains', 'needle')
        self.assertEqual(proc.returncode, 0, (proc.stderr, events))
        self.assertEqual([e['occurrence'] for e in events[:-1]], [1, 2, 3])
        self.assertEqual(events[-1]['occurrences_read'], 3)
        self.assertEqual(events[-1]['matches'], 3)
        self.assertNotIn('secret-', proc.stdout)
        self.assertNotIn('raw_base64', proc.stdout)
        self.assertEqual(before, [signature(p) for p in (self.capture, self.db)])

    def test_bounded_peek_is_non_consuming_and_never_reads_past_snapshot(self):
        spec = importlib.util.spec_from_file_location('raw_history_search', SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        sample = self.root / 'bounds'
        sample.write_bytes(b'abcdefEXTRA')
        with sample.open('rb', buffering=0) as handle:
            reader = mod.BoundedReader(handle, 6)
            self.assertEqual(reader.peek(4), b'abcd')
            self.assertEqual(reader.tell(), 0)
            self.assertEqual(reader.read(4), b'abcd')
            self.assertEqual(reader.peek(99), b'ef')
            self.assertEqual(reader.tell(), 4)
            self.assertEqual(reader.read(99), b'ef')
            self.assertEqual(reader.peek(1), b'')
            self.assertEqual(reader.read(1), b'')
            handle.seek(1)
            self.assertEqual(reader.peek(2), b'bc')
            self.assertEqual(reader.tell(), 1)
            self.assertEqual(reader.peek(0), b'')
            with mock.patch.object(mod.os, 'pread', side_effect=OSError('private-secret')):
                with self.assertRaises(mod.SourceReadError):
                    reader.peek(1)
            with mock.patch.object(mod.os, 'pread', side_effect=MemoryError):
                with self.assertRaises(MemoryError):
                    reader.peek(1)

    def test_peek_source_error_is_sanitized_at_search_boundary(self):
        if int(version.VERSION.split('.')[0]) < 12:
            self.skipTest('FlowReader in this version does not peek')
        spec = importlib.util.spec_from_file_location('raw_history_search', SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        events = []
        with mock.patch.object(mod.os, 'pread', side_effect=OSError('private-secret')):
            result = mod.search(self.capture, b'needle', False, events.append)
        self.assertEqual(result, (0, 0, ['source-unavailable']))
        self.assertEqual([e['type'] for e in events], ['source'])
        self.assertNotIn('private-secret', repr(events))
        with mock.patch.object(mod.os, 'pread', side_effect=MemoryError):
            with self.assertRaises(MemoryError):
                mod.search(self.capture, b'needle', False, events.append)

    def test_truncation_during_scan_preserves_partial_matches(self):
        spec = importlib.util.spec_from_file_location('raw_history_search', SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        original = self.capture.read_bytes()
        mode = self.capture.stat().st_mode
        events = []
        def truncate(event):
            events.append(event)
            if event['type'] == 'match' and event['occurrence'] == 1:
                with self.capture.open('r+b') as target:
                    target.truncate(event['end_offset'] + 10)
        count, matches, reasons = mod.search(self.capture, b'needle', False, truncate)
        self.assertEqual((count, matches), (1, 1))
        self.assertIn('invalid-or-truncated-capture', reasons)
        self.assertIn('source-changed-during-search', reasons)
        self.assertEqual([e['type'] for e in events], ['source', 'match', 'source-error'])
        self.assertEqual(self.capture.read_bytes(), original[:events[1]['end_offset'] + 10])
        self.assertEqual(self.capture.stat().st_mode, mode)
        self.assertNotIn('secret-', repr(events))

    def test_historical_duplicate_binary_privacy_wal_and_program(self):
        with sqlite3.connect(self.db) as c:
            self.assertEqual(c.execute('select count(*) from requests').fetchone()[0], 2)
        # Keep a real WAL open with new provenance not yet checkpointed.
        other = self.root / 'other.mitm'
        client = connection.Client(peername=('127.0.0.1', 1), sockname=('127.0.0.1', 2), timestamp_start=1.0)
        flow = http.HTTPFlow(client, connection.Server(address=('other.test', 80)))
        flow.request = http.Request.make('GET', 'http://other.test/other-only')
        with other.open('wb') as out:
            io.FlowWriter(out).add(flow)
        db = sqlite3.connect(self.db)
        db.execute('pragma journal_mode=wal')
        db.execute("insert into lanes(lane,program,flow_file) values('other','program-b',?)", (str(other),))
        db.commit()
        originals = [self.db, Path(str(self.db) + '-wal'), Path(str(self.db) + '-shm'), self.capture, other]
        before = [signature(p) for p in originals]
        proc, events = self.run_search('--contains-hex', '6e6565646c6500ff')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual([e['occurrence'] for e in events[:-1]], [1, 2])
        self.assertNotEqual(events[0]['offset'], events[1]['offset'])
        self.assertEqual(events[-1]['status'], 'incomplete')
        self.assertEqual(events[-1]['sources'], 1)
        self.assertNotIn('secret-', proc.stdout)
        self.assertNotIn('raw_base64', proc.stdout)
        self.assertEqual(before, [signature(p) for p in originals])
        proc, events = self.run_search('--contains', 'headerneedle', '--show-raw')
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(events[0]['occurrence'], 3)
        self.assertIn(b'http://', base64.b64decode(events[0]['raw_base64']['url']))
        self.assertIn(b'headerneedle', base64.b64decode(events[0]['raw_base64']['response_headers']))
        proc, events = self.run_search('--contains', 'secret-query', '--show-raw')
        self.assertEqual(len(events) - 1, 2)
        self.assertIn(b'secret-token', base64.b64decode(events[0]['raw_base64']['request_headers']))
        self.assertEqual(base64.b64decode(events[0]['raw_base64']['request_body']), b'needle\x00\xff')
        self.assertIn(b'needle-response\x00\xff', base64.b64decode(events[0]['raw_base64']['response_body']))
        proc, events = self.run_search('--contains', 'café')
        self.assertEqual(events[-1]['matches'], 2)
        self.assertEqual(before, [signature(p) for p in originals])
        proc, events = self.run_search('--contains', 'other-only')
        self.assertEqual(events[-1]['matches'], 0)
        self.assertNotIn(str(other), proc.stdout)
        other_proc = subprocess.run([sys.executable, '-s', str(SCRIPT), '--db', str(self.db), '--program', 'program-b', '--lane', 'other', '--contains', 'other-only'], capture_output=True, text=True)
        self.assertEqual(json.loads(other_proc.stdout.splitlines()[-1])['matches'], 1)
        self.assertEqual(before, [signature(p) for p in originals])
        db.close()
        proc = subprocess.run([sys.executable, '-s', str(SCRIPT), '--db', str(self.db), '--program', 'wrong', '--lane', 'lane-a', '--contains', 'needle'], capture_output=True, text=True)
        self.assertEqual(json.loads(proc.stdout)['sources'], 0)
        self.assertEqual(proc.returncode, 2)

    def test_request_and_response_start_lines_retain_bytes(self):
        client = connection.Client(peername=('127.0.0.1', 1), sockname=('127.0.0.1', 2), timestamp_start=1.0)
        flow = http.HTTPFlow(client, connection.Server(address=('example.test', 443)))
        flow.request = http.Request.make('PATCH', 'https://example.test/original')
        flow.request.data.path = b'/raw-\xff?x=1'
        flow.request.data.http_version = b'HTTP/1.0'
        flow.response = http.Response.make(418, b'')
        flow.response.data.reason = b'Teapot-\xff'
        with self.capture.open('wb') as out:
            io.FlowWriter(out).add(flow)
        for term, expected in [
            ('5041544348202f7261772dff3f783d3120485454502f312e30', 'request_line'),
            ('485454502f312e312034313820546561706f742dff', 'response_line'),
        ]:
            with self.subTest(field=expected):
                proc, events = self.run_search('--contains-hex', term)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(events[-1]['matches'], 1)
                self.assertIn(expected, events[0]['fields'])
                self.assertNotIn('raw_base64', proc.stdout)
        proc, events = self.run_search('--contains', 'PATCH', '--show-raw')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(base64.b64decode(events[0]['raw_base64']['request_line']), b'PATCH /raw-\xff?x=1 HTTP/1.0')
        self.assertEqual(base64.b64decode(events[0]['raw_base64']['response_line']), b'HTTP/1.1 418 Teapot-\xff')

    def test_start_line_absolute_and_connect_forms(self):
        client = connection.Client(peername=('127.0.0.1', 1), sockname=('127.0.0.1', 2), timestamp_start=1.0)
        flow = http.HTTPFlow(client, connection.Server(address=('example.test', 443)))
        flow.request = http.Request.make('GET', 'https://example.test/original')
        flow.request.data.scheme = b'https'
        flow.request.data.authority = b'example.test:443'
        flow.request.data.path = b'/raw-\xff'
        with self.capture.open('wb') as out:
            writer = io.FlowWriter(out)
            writer.add(flow)
            flow.request.data.method = b'CONNECT'
            writer.add(flow)
        for term, occurrence in [(b'GET https://example.test:443/raw-\xff HTTP/1.1', 1),
                                 (b'CONNECT example.test:443 HTTP/1.1', 2)]:
            with self.subTest(occurrence=occurrence):
                proc, events = self.run_search('--contains-hex', term.hex())
                self.assertEqual(proc.returncode, 2, proc.stderr)  # missing response
                self.assertEqual(events[-1]['matches'], 1)
                self.assertEqual(events[0]['occurrence'], occurrence)
                self.assertIn('request_line', events[0]['fields'])

    def test_fallback_uses_mitmdump_python(self):
        if not Path('/usr/bin/mitmdump').is_file():
            self.skipTest('system mitmdump unavailable')
        system_format = int(subprocess.check_output(
            ['/usr/bin/python3', '-s', '-c',
             'from mitmproxy.version import FLOW_FORMAT_VERSION; print(FLOW_FORMAT_VERSION)'], text=True))
        if system_format < version.FLOW_FORMAT_VERSION:
            self.skipTest('system fallback cannot decode newer fixture format')
        command = [sys.executable, '-S', str(SCRIPT), '--db', str(self.db), '--program', 'program-a', '--lane', 'lane-a', '--contains', 'needle']
        proc = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        self.assertEqual(events[-1]['matches'], 3)

    def test_truncation_and_unattributed_capture(self):
        truncated = self.root / 'truncated.mitm'
        truncated.write_bytes(self.capture.read_bytes()[:-10])
        before = signature(truncated)
        proc, events = self.run_search('--contains', 'needle', capture=truncated)
        self.assertEqual(proc.returncode, 2)
        self.assertIn('invalid-or-truncated-capture', events[-1]['reasons'])
        self.assertIn('explicit-capture-provenance-unknown', events[-1]['reasons'])
        self.assertEqual(events[-1]['provenance'], 'unknown')
        self.assertEqual(signature(truncated), before)

    def test_malformed_tnetstrings_preserve_partial_matches_and_summary(self):
        # Keep exactly the first two matching FlowWriter records, then corrupt.
        with self.capture.open('rb') as source:
            reader = iter(io.FlowReader(source).stream())
            flow = next(reader)
            next(reader)
            end = source.tell()
        valid = self.capture.read_bytes()[:end]
        state = flow.get_state()
        state['unexpected-extra'] = 'unique-private-secret'
        suffixes = {
            'unknown-state-key': tnetstring.dumps(state),
            'integer': b'1:1#', 'null': b'0:~', 'bytes': b'3:foo,',
            'boolean': tnetstring.dumps(True), 'float': tnetstring.dumps(1.5),
            'list': tnetstring.dumps([1, b'private-value']),
            'unicode': tnetstring.dumps('private-value'),
            'empty-dict': tnetstring.dumps({}),
            'unhashable-dict-key': b'6:0:]0:~}',
            'unknown-flow-type': tnetstring.dumps({'version': version.FLOW_FORMAT_VERSION, 'type': 'private-type'}),
            'unhashable-version': tnetstring.dumps({'version': [{}], 'type': 'http'}),
            'incomplete-old-flow': tnetstring.dumps({'version': 8, 'request': {}}),
        }
        db = sqlite3.connect(self.db)
        try:
            db.execute('pragma journal_mode=wal')
            db.execute("insert into lanes(lane,program,flow_file) values('other','program-b',?)", (str(self.root / 'other'),))
            db.commit()
            originals = [self.db, Path(str(self.db) + '-wal'), Path(str(self.db) + '-shm'), self.capture]
            for name, suffix in suffixes.items():
                with self.subTest(suffix=name):
                    self.capture.write_bytes(valid + suffix)
                    before = [signature(p) for p in originals]
                    for explicit in (False, True):
                        proc, events = self.run_search('--contains-hex', '6e6565646c6500ff',
                                                       capture=self.capture if explicit else None)
                        self.assertEqual(proc.returncode, 2, (name, explicit, proc.stderr))
                        self.assertEqual(proc.stderr, '')
                        self.assertEqual([e['type'] for e in events], ['match', 'match', 'source-error', 'summary'])
                        self.assertEqual([e['occurrence'] for e in events[:2]], [1, 2])
                        self.assertEqual(events[2]['source'], str(self.capture))
                        self.assertEqual(events[2]['offset'], len(valid))
                        self.assertEqual(events[2]['reason'], 'invalid-or-truncated-capture')
                        self.assertEqual(events[-1]['status'], 'incomplete')
                        self.assertEqual(events[-1]['occurrences_read'], 2)
                        self.assertEqual(events[-1]['matches'], 2)
                        self.assertIn('invalid-or-truncated-capture', events[-1]['reasons'])
                        self.assertNotIn('private-value', proc.stdout)
                        self.assertNotIn('private-type', proc.stdout)
                        self.assertNotIn('secret-', proc.stdout)
                        self.assertNotIn('raw_base64', proc.stdout)
                        self.assertEqual(before, [signature(p) for p in originals])
        finally:
            db.close()

    def test_decoder_exceptions_preserve_matches_and_hide_exception_text(self):
        spec = importlib.util.spec_from_file_location('raw_history_search', SCRIPT)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        original_stream = io.FlowReader.stream
        for error in (RuntimeError, RuntimeWarning, ValueError, OSError):
            with self.subTest(error=error.__name__):
                def failed_stream(reader):
                    yield next(original_stream(reader))
                    raise error('unique-private-secret')
                events = []
                with mock.patch.object(io.FlowReader, 'stream', failed_stream):
                    count, matches, reasons = mod.search(self.capture, b'needle', False, events.append)
                self.assertEqual((count, matches), (1, 1))
                self.assertEqual(reasons, ['invalid-or-truncated-capture'])
                self.assertEqual([event['type'] for event in events], ['source', 'match', 'source-error'])
                self.assertEqual(events[-1]['reason'], 'invalid-or-truncated-capture')
                self.assertNotIn('unique-private-secret', repr(events))

    def test_control_signals_and_non_decoder_errors_are_not_swallowed(self):
        spec = importlib.util.spec_from_file_location('raw_history_search', SCRIPT)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for error in (MemoryError, KeyboardInterrupt, SystemExit):
            with self.subTest(error=error.__name__):
                def failed_stream(_reader):
                    raise error('test')
                    yield
                with mock.patch.object(io.FlowReader, 'stream', failed_stream):
                    with self.assertRaises(error):
                        mod.search(self.capture, b'needle', False, lambda event: None)
        # Errors outside the decoder are not evidence of malformed captures.
        for error in (AttributeError, RuntimeError, ValueError):
            with self.subTest(error=error.__name__):
                with mock.patch.object(mod, 'fields', side_effect=error('test')):
                    with self.assertRaises(error):
                        mod.search(self.capture, b'needle', False, lambda event: None)

    def test_transient_output_oserror_does_not_produce_summary(self):
        spec = importlib.util.spec_from_file_location('raw_history_search', SCRIPT)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        events = []

        def flaky_print(text, flush):
            event = json.loads(text)
            if event['type'] == 'match':
                raise OSError('transient output failure')
            events.append(event)

        with mock.patch.object(mod, 'print', flaky_print, create=True):
            with self.assertRaisesRegex(OSError, 'transient output failure'):
                mod.main(['--db', str(self.db), '--program', 'program-a',
                          '--lane', 'lane-a', '--contains', 'needle'])
        self.assertEqual([event['type'] for event in events], ['source'])

    def test_fields_oserror_propagates(self):
        spec = importlib.util.spec_from_file_location('raw_history_search', SCRIPT)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with mock.patch.object(mod, 'fields', side_effect=OSError('field processing')):
            with self.assertRaisesRegex(OSError, 'field processing'):
                mod.search(self.capture, b'needle', False, lambda event: None)

    def test_source_io_failures_are_sanitized_and_keep_prior_matches(self):
        spec = importlib.util.spec_from_file_location('raw_history_search', SCRIPT)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        proc, events = self.run_search('--contains', 'needle', capture=self.root / 'missing')
        self.assertEqual(proc.returncode, 2)
        self.assertIn('source-unavailable', events[-1]['reasons'])
        self.assertEqual(proc.stderr, '')
        self.capture.chmod(0)
        try:
            if not os.access(self.capture, os.R_OK):  # A privileged runner may bypass mode bits.
                proc, events = self.run_search('--contains', 'needle', capture=self.capture)
                self.assertEqual(proc.returncode, 2)
                self.assertIn('source-unavailable', events[-1]['reasons'])
                self.assertEqual(proc.stderr, '')
        finally:
            self.capture.chmod(0o600)
        with mock.patch.object(mod.Path, 'open', side_effect=PermissionError('private-secret')):
            self.assertEqual(mod.search(self.capture, b'needle', False, lambda e: None),
                             (0, 0, ['source-unavailable']))
        with self.capture.open('rb') as source:
            next(iter(io.FlowReader(source).stream()))
            first_end = source.tell()
        real_open = Path.open

        class FailingHandle:
            def __init__(self, handle):
                self.handle = handle
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return self.handle.__exit__(*args)
            def fileno(self):
                return self.handle.fileno()
            def tell(self):
                return self.handle.tell()
            def read(self, amount=-1):
                if self.handle.tell() >= first_end:
                    raise OSError('private-secret')
                return self.handle.read(amount)

        def open_capture(path, *args, **kwargs):
            return FailingHandle(real_open(path, *args, **kwargs))

        events = []
        with mock.patch.object(mod.Path, 'open', open_capture):
            count, matches, reasons = mod.search(self.capture, b'needle', False, events.append)
        self.assertEqual((count, matches, reasons), (1, 1, ['source-unavailable']))
        self.assertEqual([e['type'] for e in events], ['source', 'match'])
        self.assertNotIn('private-secret', repr(events))

    @unittest.skipUnless(Path('/dev/full').exists(), '/dev/full unavailable')
    def test_persistent_output_failure_exits_nonzero(self):
        with open('/dev/full', 'wb') as full:
            proc = subprocess.run([sys.executable, '-s', str(SCRIPT), '--capture', str(self.capture),
                                   '--program', 'program-a', '--lane', 'lane-a', '--contains', 'needle'],
                                  stdout=full, stderr=subprocess.PIPE, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_append_during_scan_marks_incomplete(self):
        spec = importlib.util.spec_from_file_location('raw_history_search', SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        events = []
        def append(event):
            if event['type'] != 'match':
                return
            events.append(event)
            if len(events) == 1:
                with self.capture.open('ab') as f:
                    f.write(b'concurrent')
        n, matches, reasons = mod.search(self.capture, b'needle', False, append)
        self.assertEqual(n, 3)
        self.assertEqual(matches, 3)
        self.assertIn('source-changed-during-search', reasons)

    def test_aliases_for_same_owner_are_not_duplicate_sources(self):
        hard = self.root / 'hard.mitm'
        symlink = self.root / 'link.mitm'
        os.link(self.capture, hard)
        symlink.symlink_to(self.capture)
        with sqlite3.connect(self.db) as c:
            c.execute("update requests set raw_flow_file=? where rowid = (select min(rowid) from requests)", (str(hard),))
            c.execute("update lanes set flow_file=? where lane='lane-a'", (str(symlink),))
        proc, events = self.run_search('--contains-hex', '6e6565646c6500ff')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(events[-1]['sources'], 1)
        self.assertEqual(events[-1]['matches'], 2)
        self.assertEqual([e['occurrence'] for e in events[:-1]], [1, 2])

    def test_source_replaced_after_discovery_is_not_read(self):
        spec = importlib.util.spec_from_file_location('raw_history_search', SCRIPT)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        sources, ambiguous = mod.index_sources(self.db, 'program-a', 'lane-a')
        self.assertFalse(ambiguous)
        path, identity = sources[0]
        replacement = self.root / 'replacement.mitm'
        replacement.write_bytes(self.capture.read_bytes())
        os.replace(replacement, self.capture)
        events = []
        count, matches, reasons = mod.search(path, b'needle', True, events.append,
                                            expected_identity=identity, check_identity=True)
        self.assertEqual((count, matches, reasons), (0, 0, ['source-replaced']))
        self.assertEqual(events, [])

    def test_hardlink_cross_owner_conflict_is_not_searched(self):
        alias = self.root / 'other-name.mitm'
        os.link(self.capture, alias)
        with sqlite3.connect(self.db) as c:
            c.execute("insert into lanes(lane,program,flow_file) values('lane-b','program-b',?)", (str(alias),))
        before = [signature(p) for p in (self.db, self.capture, alias)]
        proc, events = self.run_search('--contains', 'needle', '--show-raw')
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(events[-1]['sources'], 0)
        self.assertEqual(events[-1]['matches'], 0)
        self.assertIn('conflicting-source-provenance', events[-1]['reasons'])
        self.assertNotIn(str(self.capture), proc.stdout)
        self.assertNotIn(str(alias), proc.stdout)
        self.assertNotIn('raw_base64', proc.stdout)
        self.assertEqual(before, [signature(p) for p in (self.db, self.capture, alias)])

    def test_symlink_cross_owner_conflict_is_not_searched(self):
        alias = self.root / 'other-link.mitm'
        alias.symlink_to(self.capture)
        with sqlite3.connect(self.db) as c:
            c.execute("insert into lanes(lane,program,flow_file) values('lane-b','program-b',?)", (str(alias),))
        proc, events = self.run_search('--contains', 'needle', '--show-raw')
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(events[-1]['sources'], 0)
        self.assertEqual(events[-1]['matches'], 0)
        self.assertIn('conflicting-source-provenance', events[-1]['reasons'])
        self.assertNotIn(str(alias), proc.stdout)
        self.assertNotIn(str(self.capture), proc.stdout)
        self.assertNotIn('raw_base64', proc.stdout)

    def test_malformed_unrelated_index_paths_fail_closed(self):
        for value in (b'\xffprivate-path', b'', 'bad\x00path'):
            with self.subTest(storage_type=type(value).__name__, value=repr(value)):
                with sqlite3.connect(self.db) as c:
                    c.execute("delete from lanes where lane='lane-b'")
                    c.execute("insert into lanes(lane,program,flow_file) values('lane-b','program-b',?)", (value,))
                before = [signature(p) for p in (self.db, self.capture)]
                proc, events = self.run_search('--contains', 'needle', '--show-raw')
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(events[-1]['status'], 'incomplete')
                self.assertEqual(events[-1]['sources'], 0)
                self.assertIn('index-unavailable-or-inconsistent', events[-1]['reasons'])
                self.assertNotIn('Traceback', proc.stderr)
                self.assertNotIn(str(self.capture), proc.stdout)
                self.assertNotIn('raw_base64', proc.stdout)
                self.assertEqual(before, [signature(p) for p in (self.db, self.capture)])

    def test_conflicting_provenance_is_not_searched(self):
        with sqlite3.connect(self.db) as c:
            c.execute("insert into lanes(lane,program,flow_file) values('lane-b','program-b',?)", (str(self.capture),))
        proc, events = self.run_search('--contains', 'needle')
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(events[-1]['sources'], 0)
        self.assertIn('conflicting-source-provenance', events[-1]['reasons'])


if __name__ == '__main__':
    unittest.main()
