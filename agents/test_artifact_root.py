from pathlib import Path

import pytest

from agents.artifact_root import preflight_artifact_paths, resolve_artifact_root


def test_resolve_root_at_invocation_and_expand_user(monkeypatch, tmp_path):
    monkeypatch.delenv("BOUNTY_ARTIFACT_ROOT", raising=False)
    assert resolve_artifact_root() == Path("/mnt/bounty")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BOUNTY_ARTIFACT_ROOT", "~/artifacts")
    assert resolve_artifact_root() == tmp_path / "artifacts"
    monkeypatch.setenv("BOUNTY_ARTIFACT_ROOT", str(tmp_path / "other"))
    assert resolve_artifact_root() == tmp_path / "other"
    monkeypatch.setenv("BOUNTY_ARTIFACT_ROOT", " ")
    with pytest.raises(SystemExit, match="BOUNTY_ARTIFACT_ROOT is empty"):
        resolve_artifact_root()


def test_preflight_checks_mount_and_custom_paths(monkeypatch, tmp_path):
    mount = []
    monkeypatch.setattr("os.path.ismount", lambda path: mount.append(path) or False)
    preflight_artifact_paths(tmp_path / "not-created", Path("/mnt/bounty-other/file"))
    assert not mount
    with pytest.raises(SystemExit, match="/mnt/bounty.*mount"):
        preflight_artifact_paths(Path("/mnt/bounty/not-created"))
    assert mount == [Path("/mnt/bounty")]
    monkeypatch.setattr("os.path.ismount", lambda path: True)
    preflight_artifact_paths(Path("/mnt/bounty/not-created"))


def test_preflight_rejects_symlink_into_unmounted_root(monkeypatch, tmp_path):
    monkeypatch.setattr("os.path.ismount", lambda path: False)
    alias = tmp_path / "alias"
    alias.symlink_to("/mnt/bounty", target_is_directory=True)
    with pytest.raises(SystemExit, match="/mnt/bounty.*mount"):
        preflight_artifact_paths(alias / "not-created")
