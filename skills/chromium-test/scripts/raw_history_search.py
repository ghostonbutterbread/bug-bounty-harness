#!/usr/bin/env python3
"""Read-only, occurrence-oriented search of explicitly selected proxy history."""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile


def stamp(path):
    s = path.stat()
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def index_sources(db, program, lane):
    """Read a stable private copy including WAL; never open SQLite on originals."""
    paths = [Path(str(db) + suffix) for suffix in ('', '-wal', '-shm')]
    before = [stamp(p) if p.exists() else None for p in paths]
    if before[0] is None:
        raise ValueError('missing-index')
    with tempfile.TemporaryDirectory(prefix='raw-history-') as directory:
        dest = Path(directory) / 'index.sqlite'
        for src, suffix, signature in zip(paths, ('', '-wal', '-shm'), before):
            if signature is not None:
                shutil.copyfile(src, Path(str(dest) + suffix))
        after = [stamp(p) if p.exists() else None for p in paths]
        if before != after:
            raise ValueError('index-changed-during-snapshot')
        conn = sqlite3.connect(dest.as_uri() + '?mode=ro', uri=True)
        try:
            # Lane rows can be overwritten; request rows may preserve older paths.
            lanes = conn.execute('SELECT DISTINCT lane, program, flow_file FROM lanes').fetchall()
            rows = conn.execute('SELECT DISTINCT lane, program, raw_flow_file FROM requests').fetchall()
        finally:
            conn.close()
    sources = {}
    ambiguous = False
    for row_lane, row_program, path in lanes + rows:
        if path is None:
            continue
        if not isinstance(path, str) or '\x00' in path:
            raise ValueError('invalid-index-path')
        if not path:
            continue
        expanded = Path(path).expanduser()
        if not expanded.is_absolute():
            if (row_lane, row_program) == (lane, program):
                ambiguous = True
            continue  # Its original working directory is not recorded.
        canonical = os.path.realpath(expanded)
        try:
            identity = stamp(expanded)[:2]
        except OSError:
            identity = None
        key = ('inode', *identity) if identity is not None else ('path', canonical)
        source = sources.setdefault(key, {'owners': set(), 'paths': set(), 'identity': identity})
        source['owners'].add((row_lane, row_program))
        source['paths'].add(str(expanded))
    selected = []
    for source in sources.values():
        owners = source['owners']
        if (lane, program) not in owners:
            continue
        if owners != {(lane, program)}:
            ambiguous = True
            continue
        selected.append((Path(sorted(source['paths'])[0]), source['identity']))
    return sorted(selected), ambiguous


class SourceReadError(Exception):
    """An I/O error from the capture handle, not the decoder or consumer."""


class BoundedReader:
    def __init__(self, handle, size):
        self.handle, self.size = handle, size

    def read(self, amount=-1):
        try:
            remaining = max(0, self.size - self.handle.tell())
            return self.handle.read(remaining if amount < 0 else min(amount, remaining))
        except OSError as exc:
            raise SourceReadError from exc

    def tell(self):
        try:
            return self.handle.tell()
        except OSError as exc:
            raise SourceReadError from exc


def fields(flow):
    request = getattr(flow, 'request', None)
    if request is None:
        return None
    response = getattr(flow, 'response', None)
    req = request.data
    if req.method.upper() == b'CONNECT':
        target = req.authority
    elif req.authority:
        target = req.scheme + b'://' + req.authority + req.path
    else:
        target = req.path
    request_line = b' '.join((req.method, target, req.http_version))
    response_line = (b' '.join((response.data.http_version, str(response.data.status_code).encode('ascii'),
                                response.data.reason)) if response else None)
    result = {
        'request_line': request_line,
        'response_line': response_line,
        'url': request.url.encode('utf-8', 'surrogateescape'),
        'request_headers': b'\r\n'.join(k + b': ' + v for k, v in request.headers.fields),
        'request_body': request.raw_content,
        'response_headers': b'\r\n'.join(k + b': ' + v for k, v in response.headers.fields) if response else None,
        'response_body': response.raw_content if response else None,
    }
    return result


def emit(value):
    print(json.dumps(value, ensure_ascii=True), flush=True)


def search(path, needle, reveal, emit_fn=emit, expected_identity=None, check_identity=False):
    from mitmproxy.io import FlowReader

    reasons = []
    count = matches = 0
    try:
        handle = path.open('rb', buffering=0)
    except OSError:
        return 0, 0, ['source-unavailable']
    with handle:
        try:
            initial = os.fstat(handle.fileno())
            start = stamp(path)
        except OSError:
            return 0, 0, ['source-unavailable']
        if ((initial.st_dev, initial.st_ino) != start[:2]
                or (check_identity and (initial.st_dev, initial.st_ino) != expected_identity)):
            return 0, 0, ['source-replaced']
        emit_fn({'type': 'source', 'source': str(path), 'snapshot_bytes': initial.st_size,
                 'snapshot_mtime_ns': initial.st_mtime_ns})
        reader = BoundedReader(handle, initial.st_size)
        iterator = iter(FlowReader(reader).stream())
        while True:
            try:
                offset = reader.tell()
            except SourceReadError:
                reasons.append('source-unavailable')
                break
            try:
                flow = next(iterator)
            except StopIteration:
                try:
                    if reader.tell() != initial.st_size:
                        reasons.append('unread-source-bytes')
                except SourceReadError:
                    reasons.append('source-unavailable')
                break
            except SourceReadError:
                reasons.append('source-unavailable')
                break
            except MemoryError:
                raise
            except Exception:
                # Decoder exceptions may contain capture data; never emit their text.
                reason = 'invalid-or-truncated-capture'
                reasons.append(reason)
                emit_fn({'type': 'source-error', 'source': str(path), 'offset': offset,
                         'reason': reason})
                break
            count += 1
            data = fields(flow)
            if data is None:
                reasons.append('non-http-flow-not-searched')
                continue
            if getattr(flow, 'response', None) is None:
                reasons.append('response-not-retained')
            if data['request_body'] is None or (getattr(flow, 'response', None) and data['response_body'] is None):
                reasons.append('body-not-retained')
            hits = [name for name, value in data.items() if value is not None and needle in value]
            if hits:
                try:
                    end_offset = reader.tell()
                except SourceReadError:
                    reasons.append('source-unavailable')
                    break
                event = {'type': 'match', 'source': str(path), 'occurrence': count,
                         'offset': offset, 'end_offset': end_offset, 'fields': hits}
                if reveal:
                    event['raw_base64'] = {k: base64.b64encode(v).decode('ascii') if v is not None else None for k, v in data.items()}
                emit_fn(event)
                matches += 1
        try:
            end = os.fstat(handle.fileno())
        except OSError:
            reasons.append('source-unavailable')
        else:
            try:
                path_end = stamp(path)
            except OSError:
                path_end = None
            end_fd = (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns, end.st_ctime_ns)
            if start != end_fd or start != path_end:
                reasons.append('source-changed-during-search')
    return count, matches, sorted(set(reasons))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--program', required=True, help='Exact indexed program')
    parser.add_argument('--lane', required=True, help='Exact indexed lane')
    parser.add_argument('--db', type=Path, default=Path('~/.local/share/ghost/proxy-store/proxy_store.sqlite').expanduser())
    parser.add_argument('--capture', type=Path, help='Explicit unassociated capture; provenance is unknown')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--contains', help='Literal UTF-8 bytes')
    group.add_argument('--contains-hex', help='Literal hexadecimal bytes')
    parser.add_argument('--show-raw', action='store_true', help='Authorized sensitive output: base64 of complete matched fields')
    args = parser.parse_args(argv)
    try:
        needle = bytes.fromhex(args.contains_hex) if args.contains_hex is not None else args.contains.encode('utf-8')
        if not needle:
            raise ValueError('empty search')
    except ValueError:
        parser.error('search must be nonempty valid UTF-8 text or hexadecimal bytes')
    if importlib.util.find_spec('mitmproxy') is None:
        executable = shutil.which('mitmdump')
        shebang = Path(executable).resolve().open('rb').readline(256).decode('utf-8', 'replace').strip() if executable else ''
        python = shebang[2:] if shebang.startswith('#!/') else ''
        if python and Path(python).is_file() and os.environ.get('_BBH_RAW_REEXEC') != '1':
            env = os.environ.copy()
            env['_BBH_RAW_REEXEC'] = '1'
            os.execve(python, [python, '-s', str(Path(__file__).resolve()), *(sys.argv[1:] if argv is None else argv)], env)
        emit({'type': 'summary', 'status': 'incomplete', 'reasons': ['mitmproxy-reader-unavailable']})
        return 2
    reasons = ['historical-capture-fingerprint-unavailable', 'historical-flow-provenance-not-attested']
    if args.capture:
        sources = [(args.capture.expanduser().absolute(), None)]
        reasons.append('explicit-capture-provenance-unknown')
    else:
        try:
            sources, ambiguous = index_sources(args.db.expanduser().absolute(), args.program, args.lane)
            if ambiguous:
                reasons.append('conflicting-source-provenance')
            if not sources:
                reasons.append('no-selected-sources')
        except (OSError, sqlite3.Error, ValueError):
            sources = []
            reasons.append('index-unavailable-or-inconsistent')
    total = matches = 0
    for path, identity in sources:
        n, m, errors = search(path, needle, args.show_raw, expected_identity=identity,
                              check_identity=not bool(args.capture))
        total += n
        matches += m
        reasons.extend(errors)
    emit({'type': 'summary', 'status': 'incomplete', 'program_selection': args.program,
          'lane_selection': args.lane, 'provenance': 'unknown' if args.capture else 'historical-index-metadata',
          'sources': len(sources), 'occurrences_read': total, 'matches': matches,
          'reasons': sorted(set(reasons)), 'coverage': 'selected retained sources only; not all historical traffic'})
    return 2 if any(r not in ('historical-capture-fingerprint-unavailable', 'historical-flow-provenance-not-attested') for r in reasons) else 0


if __name__ == '__main__':
    sys.exit(main())
