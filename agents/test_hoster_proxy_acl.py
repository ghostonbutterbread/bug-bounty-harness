"""Offline real-ACL regression for the owner-approved Hoster mount."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'
sys.path.insert(0, str(SCRIPTS))
import browser_provisioner as managed


def test_standalone_selects_approved_hoster_acl_mount(monkeypatch, tmp_path):
    if not shutil.which('setfacl'):
        pytest.skip('setfacl required')
    spec = importlib.util.spec_from_file_location('acl_mitm_lane', SCRIPTS / 'mitm_lane.py')
    lane = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lane)
    mount = tmp_path / 'bounty'
    web = mount / 'Exact Program/web'
    mount.mkdir()
    os.chmod(mount, 0o2775)
    # Two fixture group IDs model Hoster's approved access and default ACLs.
    subprocess.run(['setfacl', '-m',
                    'g:65533:rwx,g:65534:rwx,m::rwx,d:g:65533:rwx,d:g:65534:rwx,d:m::rwx',
                    str(mount)], check=True)
    web.mkdir(parents=True)
    trusted = {65533, 65534, *(p.stat().st_gid for p in mount.parents), mount.stat().st_gid}
    monkeypatch.setattr(managed, '_capture_trusted_groups', lambda: trusted)
    # The test's private scratch ancestors would otherwise mask the actual ACL
    # behavior. Model them as searchable without changing real shared paths.
    ancestors = {str(p) for p in mount.parents if p != Path('/')}
    ancestor_ids = {(p.stat().st_dev, p.stat().st_ino) for p in mount.parents if p != Path('/')}
    real_lstat, real_fstat = Path.lstat, os.fstat
    def accessible(info):
        values = list(info)
        values[0] = (int(values[0]) | 0o055) & ~0o022
        return os.stat_result(values)
    def lstat(path, *args, **kwargs):
        result = real_lstat(path, *args, **kwargs)
        return accessible(result) if str(path) in ancestors else result
    def fstat(fd):
        result = real_fstat(fd)
        return accessible(result) if (result.st_dev, result.st_ino) in ancestor_ids else result
    monkeypatch.setattr(Path, 'lstat', lstat)
    monkeypatch.setattr(os, 'fstat', fstat)
    monkeypatch.setenv('BOUNTY_ARTIFACT_ROOT', str(mount))
    # A test-only root models the literal approved path without touching /mnt.
    monkeypatch.setattr(lane, 'HOSTER_BOUNTY_ROOT', mount, raising=False)
    monkeypatch.setattr(managed, '_CAPTURE_BOUNTY_ROOT', mount)
    monkeypatch.setattr(lane.os.path, 'ismount', lambda path: Path(path) == mount)
    original_check = lane._safe_existing_directories
    state_root = tmp_path / 'state'
    monkeypatch.setattr(lane, '_safe_existing_directories',
                        lambda path: True if Path(path).is_relative_to(state_root) else original_check(path))
    subprocess.run(['setfacl', '-m', 'd:u:42424242:rwx', str(web)], check=True)
    flow, selected = lane.capture_destination(state_root, 'lane', 'Exact Program')
    assert selected == str(mount)
    assert flow.is_relative_to(web / 'proxy/flows')
    assert flow.parent.stat().st_mode & 0o777 == 0o700
    # The default named writer is inherited but suppressed by private modes.
    assert (web / 'proxy').stat().st_mode & 0o777 == 0o700
    assert os.getxattr(web / 'proxy', 'system.posix_acl_access')
    # The same real ACL on an alternative mounted root must not gain trust.
    monkeypatch.setattr(lane, 'HOSTER_BOUNTY_ROOT', tmp_path / 'approved')
    fallback, selected = lane.capture_destination(state_root, 'other', 'Exact Program')
    assert selected is None
    assert fallback.is_relative_to(state_root)
    monkeypatch.setattr(lane, 'HOSTER_BOUNTY_ROOT', mount)
    # Even if the literal approved name is itself replaced by a symlink,
    # descriptor traversal must reject it rather than trusting its destination.
    alias = tmp_path / 'alias'
    alias.symlink_to(mount, target_is_directory=True)
    monkeypatch.setattr(lane, 'HOSTER_BOUNTY_ROOT', alias)
    monkeypatch.setenv('BOUNTY_ARTIFACT_ROOT', str(alias))
    monkeypatch.setattr(lane.os.path, 'ismount', lambda path: Path(path) in (mount, alias))
    assert lane.capture_destination(state_root, 'alias-lane', 'Exact Program')[1] is None
    monkeypatch.setattr(lane, 'HOSTER_BOUNTY_ROOT', mount)
    monkeypatch.setenv('BOUNTY_ARTIFACT_ROOT', str(mount))
    subprocess.run(['setfacl', '-m', 'g:65532:rwx,m::rwx', str(mount)], check=True)
    assert not lane._safe_mounted_directories(web)
    subprocess.run(['setfacl', '-x', 'g:65532', str(mount)], check=True)
    subprocess.run(['setfacl', '-m', 'u:42424242:rwx,m::rwx', str(mount)], check=True)
    assert not lane._safe_mounted_directories(web)
    subprocess.run(['setfacl', '-m', 'm::r-x', str(mount)], check=True)
    assert lane._safe_mounted_directories(web)
    link = mount / 'link'
    link.symlink_to(web, target_is_directory=True)
    assert not lane._safe_mounted_directories(link)
