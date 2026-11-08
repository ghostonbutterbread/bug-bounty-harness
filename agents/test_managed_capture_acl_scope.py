"""Real-ACL scope regression; all filesystem mutations stay in tmp_path."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'))
import browser_provisioner as managed


@pytest.fixture
def reachable_acl(monkeypatch, tmp_path):
    if not shutil.which('setfacl'):
        pytest.skip('setfacl required')
    # Model the private scratch ancestors as traversable, as in the independent
    # review reproducer; leave the actual ACLs and target modes untouched.
    ids = {(p.stat().st_dev, p.stat().st_ino) for p in (tmp_path, *tmp_path.parents) if p != Path('/')}
    real_fstat = os.fstat
    def exposed(fd):
        info = real_fstat(fd)
        if (info.st_dev, info.st_ino) not in ids:
            return info
        values = list(info)
        values[0] = (int(values[0]) | 0o055) & ~0o022
        return os.stat_result(values)
    monkeypatch.setattr(managed.os, 'fstat', exposed)
    ancestor_groups = {p.stat().st_gid for p in (tmp_path, *tmp_path.parents)}
    monkeypatch.setattr(managed, '_capture_trusted_groups', lambda: {65533, 65534, *ancestor_groups})
    def make(name):
        path = tmp_path / name
        path.mkdir(mode=0o755)
        subprocess.run(['setfacl', '-m', 'g:65533:rwx,g:65534:rwx,m::rwx', str(path)], check=True)
        return path
    return make


def test_configured_state_parent_rejects_approved_group_outside_mount(monkeypatch, reachable_acl):
    # Adapted from the independent review's actual state-allocation reproducer:
    # original oracle established acceptance; the fixed oracle requires refusal.
    external = reachable_acl('external-state')
    monkeypatch.setattr(managed, 'STATE', external / 'manager.sqlite')
    with pytest.raises(PermissionError, match='capture ACL writer'):
        managed._capture_open_dir(external / 'task-proxies', create_from=managed.STATE.parent)
    assert not (external / 'task-proxies').exists()


def test_approved_mount_groups_and_rejects_untrusted_writer(monkeypatch, reachable_acl):
    mount = reachable_acl('bounty')
    web = mount / 'Example' / 'web'
    web.mkdir(parents=True, mode=0o755)
    web.parent.chmod(0o755)
    web.chmod(0o755)
    monkeypatch.setattr(managed, '_CAPTURE_BOUNTY_ROOT', mount)
    fd = managed._capture_open_dir(web)
    os.close(fd)
    subprocess.run(['setfacl', '-m', 'g:65532:rwx,m::rwx', str(web)], check=True)
    with pytest.raises(PermissionError, match='capture ACL writer'):
        managed._capture_open_dir(web)


def test_managed_approved_mount_selects_private_capture(monkeypatch, tmp_path, reachable_acl):
    import browser_profile_lease as profiles
    mount = reachable_acl('approved')
    program = mount / 'Example'
    program.mkdir(mode=0o755)
    program.chmod(0o755)
    monkeypatch.setattr(managed, '_CAPTURE_BOUNTY_ROOT', mount)
    monkeypatch.setattr(profiles, 'DEFAULT_BOUNTY_ROOT', mount)
    monkeypatch.setattr(profiles, 'default_mount_available', lambda: True)
    monkeypatch.setattr(profiles, 'local_filesystem', lambda path: True)
    monkeypatch.setattr(managed, '_capture_local_private_path', lambda path: True)
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    flow, identity = managed.select_task_capture('Example', 'lane', state)
    assert flow == program / 'web/proxy/flows/lane/flows.mitm'
    assert flow.parent.stat().st_mode & 0o777 == 0o700
    assert flow.stat().st_mode & 0o777 == 0o600
    assert identity['file'] and identity['mount']
    assert not (state / 'capture').exists()


def test_unapproved_artifact_override_falls_back_to_private_state(monkeypatch, tmp_path, reachable_acl):
    import browser_profile_lease as profiles
    override = reachable_acl('artifact-override')
    (override / 'Example' / 'web').mkdir(parents=True)
    monkeypatch.setattr(managed, '_CAPTURE_BOUNTY_ROOT', tmp_path / 'approved-only')
    monkeypatch.setattr(profiles, 'DEFAULT_BOUNTY_ROOT', override)
    monkeypatch.setattr(profiles, 'default_mount_available', lambda: True)
    monkeypatch.setattr(profiles, 'local_filesystem', lambda path: True)
    monkeypatch.setattr(managed, '_capture_local_private_path', lambda path: True)
    state = tmp_path / 'private-state'
    state.mkdir(mode=0o700)
    flow, identity = managed.select_task_capture('Example', 'lane', state)
    assert flow == state / 'capture' / 'flows.mitm'
    assert flow.parent.stat().st_mode & 0o777 == 0o700
    assert flow.stat().st_mode & 0o777 == 0o600
    assert identity['file'] and 'mount' not in identity
    assert not (override / 'Example' / 'web' / 'proxy').exists()


def test_same_uid_private_fence_preserves_local_state(monkeypatch, tmp_path, reachable_acl):
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    child = private / 'child'
    child.mkdir(mode=0o755)
    subprocess.run(['setfacl', '-m', 'g:65533:rwx,m::rwx', str(child)], check=True)
    fd = managed._capture_open_dir(child)
    os.close(fd)


def test_literal_root_symlink_and_alias_not_trusted(monkeypatch, tmp_path, reachable_acl):
    target = reachable_acl('target')
    literal = tmp_path / 'bounty'
    literal.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(managed, '_CAPTURE_BOUNTY_ROOT', literal)
    with pytest.raises(OSError):
        managed._capture_open_dir(literal)
    # A different pathname (including a bind alias) cannot match the literal root.
    with pytest.raises(PermissionError, match='capture ACL writer'):
        managed._capture_open_dir(target)


def test_only_named_groups_are_resolved(monkeypatch):
    import types
    calls = []
    def group(name):
        calls.append(name)
        return types.SimpleNamespace(gr_gid={'smb_write': 12, 'ai_smb_write': 34}[name])
    monkeypatch.setattr(managed.grp, 'getgrnam', group)
    assert managed._capture_trusted_groups() == {12, 34}
    assert calls == ['smb_write', 'ai_smb_write']
