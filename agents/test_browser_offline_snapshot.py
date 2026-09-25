"""Synthetic offline snapshot tests; never read a real browser profile."""

from dataclasses import replace
import json
import os
from pathlib import Path
import threading

import pytest

from agents.browser_offline_snapshot import (SnapshotCleanupIncomplete, SnapshotRefused,
                                             TerminalProof, snapshot_stopped_profile)


@pytest.fixture
def fixture(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Default" / "Local Storage" / "leveldb").mkdir(parents=True)
    (source / "Default" / "Cookies").write_bytes(b"SQLite format 3\0 synthetic")
    (source / "Default" / "Local Storage" / "leveldb" / "000003.log").write_bytes(b"leveldb synthetic")
    (source / "Default" / "cert9.db").write_bytes(b"task CA")
    (source / "DevToolsActivePort").write_text("never copy")
    (source / "task-proxy-ca.pem").write_text("never copy")
    dest = tmp_path / "private"
    dest.mkdir(mode=0o700)
    st = source.stat()
    proof = TerminalProof("neon", "example.test", "blue", "g1", "lease-1",
                          str(source), st.st_dev, st.st_ino, "unit-1", "root-1", "cdp-1",
                          True, True, True, True)
    return source, dest, proof


def test_snapshot_copies_state_privately_and_excludes_runtime(fixture, capsys):
    source, dest, proof = fixture
    os.chmod(source / "Default" / "Cookies", 0o600)
    final = snapshot_stopped_profile(source, dest, lambda: proof)
    assert (final / "Default" / "Cookies").read_bytes() == (source / "Default" / "Cookies").read_bytes()
    assert (final / "Default" / "Local Storage" / "leveldb" / "000003.log").exists()
    assert (final / "Default" / "Cookies").stat().st_mode & 0o777 == 0o600
    for name in ("cert9.db", "DevToolsActivePort", "task-proxy-ca.pem"):
        assert not list(final.rglob(name))
    manifest = json.loads((final / "snapshot-manifest.json").read_text())
    assert manifest["source"]["source_inode"] == proof.source_inode
    assert manifest["source"]["account"] == "blue"
    assert manifest["auth_verified"] is False
    assert capsys.readouterr().out == ""
    assert len(list(dest.iterdir())) == 1


@pytest.mark.parametrize("alter", [
    lambda s, d, p: (s / "SingletonLock").write_text("active"),
    lambda s, d, p: (s / "Default" / "escape").symlink_to(d),
    lambda s, d, p: os.chmod(d, 0o755),
])
def test_refuses_lock_symlink_or_public_parent(fixture, alter):
    source, dest, proof = fixture
    alter(source, dest, proof)
    with pytest.raises(SnapshotRefused):
        snapshot_stopped_profile(source, dest, lambda: proof)
    assert not list(dest.glob("snapshot-*"))


def test_refuses_missing_terminal_proof_and_identity_change(fixture):
    source, dest, proof = fixture
    for bad in (replace(proof, cdp_terminal=False), replace(proof, source_inode=0)):
        with pytest.raises(SnapshotRefused):
            snapshot_stopped_profile(source, dest, lambda: bad)
    assert not list(dest.iterdir())


def test_proof_generation_change_rolls_back(fixture):
    source, dest, proof = fixture
    calls = 0
    def reader():
        nonlocal calls
        calls += 1
        return replace(proof, generation="g2") if calls > 5 else proof
    with pytest.raises(SnapshotRefused, match="proof changed"):
        snapshot_stopped_profile(source, dest, reader)
    assert not list(dest.iterdir())


def test_concurrent_file_mutation_rolls_back(fixture, monkeypatch):
    source, dest, proof = fixture
    import agents.browser_offline_snapshot as module
    original = module._check
    changed = threading.Event()
    def mutate(reader, expected, root):
        original(reader, expected, root)
        if not changed.is_set() and list(dest.glob(".snapshot-*")):
            (source / "Default" / "Cookies").write_bytes(b"changed SQLite")
            changed.set()
    monkeypatch.setattr(module, "_check", mutate)
    with pytest.raises(SnapshotRefused, match="changed"):
        snapshot_stopped_profile(source, dest, lambda: proof)
    assert changed.is_set()
    assert not list(dest.iterdir())


def test_source_root_swap_between_check_and_scan_refuses(fixture, monkeypatch):
    source, dest, proof = fixture
    import agents.browser_offline_snapshot as module
    original = module._scan
    def swap(root, identity):
        source.rename(source.with_name("source-old"))
        source.mkdir()
        (source / "Default").mkdir()
        (source / "Default" / "Cookies").write_bytes(b"attacker")
        return original(root, identity)
    monkeypatch.setattr(module, "_scan", swap)
    with pytest.raises(SnapshotRefused, match="physical identity"):
        snapshot_stopped_profile(source, dest, lambda: proof)
    assert not list(dest.iterdir())


def test_root_swap_between_check_and_file_open_refuses(fixture, monkeypatch):
    source, dest, proof = fixture
    import agents.browser_offline_snapshot as module
    original = module._open_parent
    swapped = False
    def swap(root, relative, entries, identity):
        nonlocal swapped
        if not swapped:
            swapped = True
            source.rename(source.with_name("source-old"))
            source.mkdir()
            (source / "Default").mkdir()
            (source / "Default" / "Cookies").write_bytes(b"attacker")
        return original(root, relative, entries, identity)
    monkeypatch.setattr(module, "_open_parent", swap)
    with pytest.raises(SnapshotRefused, match="physical identity"):
        snapshot_stopped_profile(source, dest, lambda: proof)
    assert swapped
    assert not list(dest.iterdir())


def test_excludes_case_variant_nss_and_proxy_ca(fixture):
    source, dest, proof = fixture
    (source / "Default" / "CERT9.DB").write_bytes(b"task CA")
    (source / "Default" / "KEY4.DB").write_bytes(b"private key")
    (source / "Default" / "TASK-PROXY-CA.PEM").write_bytes(b"task CA")
    result = snapshot_stopped_profile(source, dest, lambda: proof)
    for name in ("CERT9.DB", "KEY4.DB", "TASK-PROXY-CA.PEM"):
        assert not (result / "Default" / name).exists()


def test_directory_symlink_swap_during_copy_cannot_escape(fixture, monkeypatch):
    source, dest, proof = fixture
    import agents.browser_offline_snapshot as module
    original = module._open_parent
    swapped = False
    def swap(root, relative, entries, identity):
        nonlocal swapped
        if not swapped:
            swapped = True
            (source / "Default").rename(source / "old-default")
            (source / "Default").symlink_to(dest, target_is_directory=True)
        return original(root, relative, entries, identity)
    monkeypatch.setattr(module, "_open_parent", swap)
    with pytest.raises(SnapshotRefused):
        snapshot_stopped_profile(source, dest, lambda: proof)
    assert swapped
    assert not list(dest.iterdir())



def test_fsync_failure_after_readonly_nested_directory_removes_canary(fixture, monkeypatch):
    source, dest, proof = fixture
    import agents.browser_offline_snapshot as module
    nested = source / "Default" / "Local Storage" / "leveldb"
    canary = b"private synthetic canary"
    (nested / "000003.log").write_bytes(canary)
    os.chmod(nested, 0o555)
    original = module._fsync_dir
    def fail_after_mode(path):
        if path.name == "leveldb":
            assert path.stat().st_mode & 0o777 == 0o555
            assert (path / "000003.log").read_bytes() == canary
            raise OSError("injected private fsync failure")
        return original(path)
    monkeypatch.setattr(module, "_fsync_dir", fail_after_mode)
    with pytest.raises(SnapshotRefused, match="I/O failure") as exc:
        snapshot_stopped_profile(source, dest, lambda: proof)
    assert type(exc.value) is SnapshotRefused
    assert isinstance(exc.value.__cause__, OSError)
    assert "canary" not in str(exc.value)
    assert not list(dest.iterdir())
    assert nested.stat().st_mode & 0o777 == 0o555
    assert (nested / "000003.log").read_bytes() == canary


def test_post_rename_fsync_failure_removes_final(fixture, monkeypatch):
    source, dest, proof = fixture
    import agents.browser_offline_snapshot as module
    original = module._fsync_dir
    parent_calls = 0
    def fail_after_rename(path):
        nonlocal parent_calls
        if path == dest:
            parent_calls += 1
            if parent_calls == 2:
                assert len(list(dest.glob("snapshot-*"))) == 1
                raise OSError("injected post-rename failure")
        return original(path)
    monkeypatch.setattr(module, "_fsync_dir", fail_after_rename)
    with pytest.raises(SnapshotRefused, match="I/O failure") as exc:
        snapshot_stopped_profile(source, dest, lambda: proof)
    assert type(exc.value) is SnapshotRefused
    assert parent_calls == 3  # rollback syncs the parent too
    assert not list(dest.iterdir())


@pytest.mark.parametrize("after_rename", [False, True])
def test_cleanup_failure_reports_residue_and_preserves_original(fixture, monkeypatch, after_rename):
    source, dest, proof = fixture
    import agents.browser_offline_snapshot as module
    canary = b"private synthetic canary"
    (source / "Default" / "Cookies").write_bytes(canary)
    original_sync = module._fsync_dir
    parent_calls = 0
    def fail_after_copy(path):
        nonlocal parent_calls
        if path == dest:
            parent_calls += 1
            if after_rename and parent_calls == 2:
                raise OSError("original private fsync failure")
        if not after_rename and path.name == "Default":
            raise OSError("original private fsync failure")
        return original_sync(path)
    monkeypatch.setattr(module, "_fsync_dir", fail_after_copy)
    def fail_remove(path):
        assert (path / "Default" / "Cookies").read_bytes() == canary
        raise OSError("private cleanup failure")
    monkeypatch.setattr(module.shutil, "rmtree", fail_remove)
    with pytest.raises(SnapshotCleanupIncomplete, match="cleanup incomplete") as exc:
        snapshot_stopped_profile(source, dest, lambda: proof)
    assert isinstance(exc.value.original_failure, OSError)
    assert "original private fsync failure" in str(exc.value.original_failure)
    assert isinstance(exc.value.__cause__, OSError)
    assert "private cleanup failure" in str(exc.value.__cause__)
    assert "canary" not in str(exc.value)
    assert len(list(dest.iterdir())) == 1  # deliberately incomplete, never called clean


def test_silent_cleanup_noop_is_detected(fixture, monkeypatch):
    source, dest, proof = fixture
    import agents.browser_offline_snapshot as module
    monkeypatch.setattr(module, "_open_parent", lambda *args: (_ for _ in ()).throw(OSError("copy failed")))
    monkeypatch.setattr(module.shutil, "rmtree", lambda path: None)
    with pytest.raises(SnapshotCleanupIncomplete, match="cleanup incomplete") as exc:
        snapshot_stopped_profile(source, dest, lambda: proof)
    assert isinstance(exc.value.original_failure, OSError)
    assert isinstance(exc.value.__cause__, OSError)
    assert len(list(dest.iterdir())) == 1


def test_insufficient_disk_and_copy_failure_roll_back(fixture, monkeypatch):
    source, dest, proof = fixture
    import agents.browser_offline_snapshot as module
    real = module.os.statvfs
    monkeypatch.setattr(module.os, "statvfs", lambda path: type("V", (), {"f_bavail": 0, "f_frsize": 1})())
    with pytest.raises(SnapshotRefused, match="disk"):
        snapshot_stopped_profile(source, dest, lambda: proof)
    monkeypatch.setattr(module.os, "statvfs", real)
    original = module._open_parent
    def fail(*args):
        raise OSError("private simulated error")
    monkeypatch.setattr(module, "_open_parent", fail)
    with pytest.raises(SnapshotRefused, match="I/O failure") as exc:
        snapshot_stopped_profile(source, dest, lambda: proof)
    assert "private simulated error" not in str(exc.value)
    assert not list(dest.iterdir())
