from argparse import Namespace
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from agents import artifact_root
from agents import js_analyzer as J


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.delenv('BOUNTY_ARTIFACT_ROOT', raising=False)
    monkeypatch.delenv('JS_ANALYZER_CONFIG', raising=False)
    monkeypatch.setattr(J, 'DEFAULT_CONFIG_PATHS', ())


def test_implicit_stale_config_without_environment_stops_before_io(monkeypatch, tmp_path):
    shared = tmp_path / 'home' / 'Shared' / 'demo'
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'defaults': {'program_root': str(shared)}}))
    monkeypatch.setattr(J, 'DEFAULT_CONFIG_PATHS', (config,))
    with patch.object(J, 'collect_from_page') as fetch, pytest.raises(SystemExit) as error:
        J.main(['inventory', 'demo', '--page', 'https://example.invalid', '--target-host', 'example.invalid'])
    assert str(shared) in str(error.value)
    assert str(config) in str(error.value)
    assert '/mnt/bounty' in str(error.value)
    fetch.assert_not_called()
    assert not shared.exists()


@pytest.mark.parametrize('source', ['argument', 'config_environment'])
def test_explicit_config_retains_shared_choice_even_with_artifact_env(monkeypatch, tmp_path, source):
    shared = tmp_path / 'home' / 'Shared' / 'demo'
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'defaults': {'program_root': str(shared)}}))
    monkeypatch.setenv('BOUNTY_ARTIFACT_ROOT', str(tmp_path / 'local'))
    if source == 'config_environment':
        monkeypatch.setenv('JS_ANALYZER_CONFIG', str(config))
    args = Namespace(program='demo', config=str(config) if source == 'argument' else None,
                     output_root=None, library_root=None, integration_index_root=None)
    output, library, _, _ = J.resolve_inventory_paths(args, 'run')
    assert output == shared / 'web/recon/js/run'
    assert library == shared / 'web/recon/js/_library'


@pytest.mark.parametrize('writer', [J.write_jsonl, J.append_jsonl])
def test_jsonl_preflight_checks_are_bounded_for_many_rows(monkeypatch, tmp_path, writer):
    checks = []
    original = J.preflight_artifact_paths

    def count_checks(*paths):
        checks.append(paths)
        return original(*paths)

    monkeypatch.setattr(J, 'preflight_artifact_paths', count_checks)
    target = tmp_path / 'rows.jsonl'
    rows = [{'index': i} for i in range(10_000)]
    writer(target, rows)
    assert J.read_jsonl(target) == rows
    assert len(checks) <= 50


@pytest.mark.parametrize('writer', [J.write_jsonl, J.append_jsonl])
@pytest.mark.parametrize('row_count', [1, 1000])
def test_jsonl_mount_loss_during_stream_stops_before_publish(monkeypatch, tmp_path, writer, row_count):
    mount = tmp_path / 'mount'
    mount.mkdir()
    preserved = tmp_path / 'preserved'
    target = mount / 'rows.jsonl'
    available = [True]
    monkeypatch.setattr(artifact_root, 'LEGACY_ARTIFACT_ROOT', mount)
    monkeypatch.setattr(os.path, 'ismount', lambda _: available[0])
    yielded = []

    def rows():
        for i in range(row_count + 1):
            if i == 1:
                mount.rename(preserved)
                mount.mkdir()
                available[0] = False
            if i == row_count:
                break
            yielded.append(i)
            yield {'index': i}

    with pytest.raises(SystemExit, match='not mounted'):
        writer(target, rows())
    assert len(yielded) <= 256
    assert not target.exists()
    assert not list(mount.iterdir())
    if writer is J.write_jsonl:
        assert not (preserved / target.name).exists()


def test_append_stops_when_mount_disappears_between_repair_and_append(monkeypatch, tmp_path):
    mount = tmp_path / 'mount'
    mount.mkdir()
    target = mount / 'observations.jsonl'
    target.write_text('{"prior":true}\n')
    original = tmp_path / 'preserved'
    available = [True]
    monkeypatch.setattr(artifact_root, 'LEGACY_ARTIFACT_ROOT', mount)
    monkeypatch.setattr(os.path, 'ismount', lambda _: available[0])
    real_open = Path.open

    class RepairHandle:
        def __init__(self, handle): self.handle = handle
        def __enter__(self): return self.handle
        def __exit__(self, *args):
            self.handle.__exit__(*args)
            mount.rename(original)
            mount.mkdir()
            available[0] = False

    def open_with_loss(path, mode='r', *args, **kwargs):
        handle = real_open(path, mode, *args, **kwargs)
        return RepairHandle(handle) if path == target and mode == 'rb+' else handle

    with patch.object(Path, 'open', open_with_loss), pytest.raises(SystemExit, match='not mounted'):
        J.append_jsonl(target, [{'new': True}])
    assert (original / target.name).read_text() == '{"prior":true}\n'
    assert not target.exists()


@pytest.mark.parametrize('writer', ['bytes', 'text', 'jsonl', 'ledger', 'sqlite'])
def test_mount_loss_after_mkdir_before_next_open_preserves_original(monkeypatch, tmp_path, writer):
    mount = tmp_path / 'mount'
    mount.mkdir()
    parent = mount / 'nested'
    parent.mkdir()
    target = parent / 'artifact'
    target.write_text('durable original\n')
    original = tmp_path / 'preserved'
    available = [True]
    monkeypatch.setattr(artifact_root, 'LEGACY_ARTIFACT_ROOT', mount)
    monkeypatch.setattr(os.path, 'ismount', lambda _: available[0])
    real_mkdir = Path.mkdir

    def mkdir_with_loss(path, *args, **kwargs):
        result = real_mkdir(path, *args, **kwargs)
        if path == parent and available[0]:
            available[0] = False
            mount.rename(original)
            mount.mkdir()
            (mount / 'nested').mkdir()
        return result

    operations = {
        'bytes': lambda: J.write_bytes_checked(target, b'new'),
        'text': lambda: J.write_text_atomic(target, 'new'),
        'jsonl': lambda: J.write_jsonl(target, [{'new': True}]),
        'ledger': lambda: J.save_ledger(target, {}),
        'sqlite': lambda: J.write_observations_table(target, []),
    }
    with patch.object(Path, 'mkdir', mkdir_with_loss), pytest.raises(SystemExit, match='not mounted'):
        operations[writer]()
    assert (original / 'nested' / 'artifact').read_text() == 'durable original\n'
    assert not list((mount / 'nested').iterdir())


def test_missing_explicit_config_fallback_remains_implicit(monkeypatch, tmp_path):
    shared = tmp_path / 'home' / 'Shared' / 'demo'
    config = tmp_path / 'default.json'
    config.write_text(json.dumps({'defaults': {'program_root': str(shared)}}))
    monkeypatch.setattr(J, 'DEFAULT_CONFIG_PATHS', (config,))
    args = Namespace(program='demo', config=str(tmp_path / 'missing.json'), output_root=None,
                     library_root=None, integration_index_root=None)
    with pytest.raises(SystemExit, match='configured Shared bulk') as error:
        J.resolve_inventory_paths(args, 'run')
    assert str(config) in str(error.value)


def test_observe_mount_loss_then_restore_appends_to_original(monkeypatch, tmp_path):
    mount = tmp_path / 'mount'
    library = mount / 'lib'
    library.mkdir(parents=True)
    target = library / 'observations.jsonl'
    target.write_text('{"observation_id":"prior"}\n')
    preserved = tmp_path / 'preserved'
    rows = tmp_path / 'rows.jsonl'
    rows.write_text(json.dumps({'observation_id': 'new', 'title': 'fixture'}) + '\n')
    monkeypatch.setattr(artifact_root, 'LEGACY_ARTIFACT_ROOT', mount)
    available = [True]
    monkeypatch.setattr(os.path, 'ismount', lambda _: available[0])
    real_open = Path.open

    class RepairHandle:
        def __init__(self, handle): self.handle = handle
        def __enter__(self): return self.handle
        def __exit__(self, *args):
            self.handle.__exit__(*args)
            mount.rename(preserved)
            mount.mkdir()
            (mount / 'lib').mkdir()
            available[0] = False

    def lose_after_repair(path, mode='r', *args, **kwargs):
        handle = real_open(path, mode, *args, **kwargs)
        return RepairHandle(handle) if path == target and mode == 'rb+' else handle

    argv = ['observe', 'demo', '--library-root', str(library), '--input', str(rows)]
    with patch.object(Path, 'open', lose_after_repair), pytest.raises(SystemExit, match='not mounted'):
        J.main(argv)
    assert (preserved / 'lib' / target.name).read_text() == '{"observation_id":"prior"}\n'
    assert not target.exists()
    (mount / 'lib').rmdir()
    mount.rmdir()
    preserved.rename(mount)
    available[0] = True
    assert J.main(argv) == 0
    assert [row['observation_id'] for row in J.read_jsonl(target)] == ['prior', 'new']


def test_explicit_config_inventory_and_observe_share_existing_corpus(monkeypatch, tmp_path):
    shared = tmp_path / 'home' / 'Shared' / 'demo'
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'defaults': {'program_root': str(shared)}}))
    monkeypatch.setenv('BOUNTY_ARTIFACT_ROOT', str(tmp_path / 'local'))
    source = tmp_path / 'urls.txt'
    source.write_text('https://example.invalid/a.js\n')
    observations = tmp_path / 'observations.jsonl'
    observations.write_text(json.dumps({'sha256': 'a' * 64, 'title': 'fixture'}) + '\n')
    with patch.object(J, 'http_get', return_value=(b'const fixture = true;', 200, 'application/javascript')):
        assert J.main(['inventory', 'demo', '--config', str(config), '--input', str(source),
                       '--target-host', 'example.invalid', '--source-maps', 'off', '--run-id', 'run',
                       '--disk-free-floor-gib', '0']) == 0
    assert J.main(['observe', 'demo', '--config', str(config), '--input', str(observations)]) == 0
    library = shared / 'web/recon/js/_library'
    assert len(list((library / 'downloads').glob('*.js'))) == 1
    assert len(J.read_jsonl(library / 'observations.jsonl')) == 1
    assert not (tmp_path / 'local').exists()
