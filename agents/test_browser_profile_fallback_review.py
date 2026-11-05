"""Synthetic filesystem and agent-instruction regressions; no real browser state."""
from pathlib import Path
import os
import subprocess

import pytest

from agents.test_browser_profile_lease import load_module, args, ROOT


def test_recorded_network_profile_refused_without_relocation(monkeypatch, tmp_path):
    module = load_module()
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('HARNESS_BOUNTY_ARTIFACT_ROOT', str(tmp_path / 'local'))
    monkeypatch.setattr(module, 'local_filesystem', lambda path: True)
    state = tmp_path / 'state'
    first = module.cmd_acquire(args(module, state, 'acquire', account='anon', agent_id='a', run_id='one', purpose='test'))
    module.cmd_release(args(module, state, 'release', lease_id=first['lease']['lease_id'], agent_id='a', disposition='completed', profile_health='healthy'))
    monkeypatch.setattr(module, 'local_filesystem', lambda path: False)
    result = module.cmd_acquire(args(module, state, 'acquire', account='anon', agent_id='b', run_id='two', purpose='test'))
    assert result['status'] == 'profile-unavailable'
    with module.connect(state / 'browser_profile_leases.sqlite') as conn:
        assert conn.execute('SELECT profile_dir FROM browser_profile_leases').fetchone()[0] == first['lease']['profile_dir']


def test_alias_under_unmounted_bounty_falls_back(monkeypatch, tmp_path):
    module = load_module()
    monkeypatch.setenv('HOME', str(tmp_path))
    mount = tmp_path / 'bounty'
    mount.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(mount, target_is_directory=True)
    monkeypatch.setattr(module, 'DEFAULT_BOUNTY_ROOT', mount)
    monkeypatch.setattr(module, 'default_mount_available', lambda: False)
    monkeypatch.setattr(module, 'local_filesystem', lambda path: True)
    monkeypatch.setenv('HARNESS_BOUNTY_ARTIFACT_ROOT', str(alias / 'subdir'))
    got = module.cmd_acquire(args(module, tmp_path / 'state', 'acquire', account='anon', agent_id='a', run_id='one', purpose='test'))
    assert got['status'] == 'leased'
    assert Path(got['lease']['profile_dir']).is_relative_to(module.fallback_base())


def test_unresolvable_recorded_profile_is_unsafe(monkeypatch, tmp_path):
    module = load_module()
    loop = tmp_path / 'loop'
    loop.symlink_to(loop)
    assert not module.safe_profile_path(loop / 'profile')


def test_unwritable_custom_root_fails_before_lease(monkeypatch, tmp_path):
    module = load_module()
    root = tmp_path / 'custom'
    root.mkdir(mode=0o555)
    root.chmod(0o555)
    monkeypatch.setenv('HARNESS_BOUNTY_ARTIFACT_ROOT', str(root))
    monkeypatch.setattr(module, 'local_filesystem', lambda path: True)
    got = module.cmd_acquire(args(module, tmp_path / 'state', 'acquire', account='anon', agent_id='a', run_id='one', purpose='test'))
    assert got['status'] == 'profile-unavailable'
    assert 'writable' in got['next']


def test_skill_preflights_chosen_profile_not_default_artifact_root():
    skill = (ROOT / 'skills/chromium-test/SKILL.md').read_text()
    assert 'profile_probe="${CHROMIUM_PROFILE_PROBE:?Set CHROMIUM_PROFILE_PROBE to the selected profile path}"' in skill
    assert 'Let the provisioner select' in skill


def test_skill_probe_requires_explicit_selected_path(monkeypatch, tmp_path):
    skill = (ROOT / 'skills/chromium-test/SKILL.md').read_text()
    snippet = skill.split('### Profile filesystem preflight on the browser node', 1)[1].split('```bash\n', 1)[1].split('```', 1)[0]
    env = os.environ.copy()
    env.pop('CHROMIUM_PROFILE_PROBE', None)
    env['HARNESS_BOUNTY_ARTIFACT_ROOT'] = '/unsafe-smb-root'
    missing = subprocess.run(['bash', '-c', snippet], env=env, text=True, capture_output=True)
    assert missing.returncode != 0
    stub = tmp_path / 'findmnt'
    stub.write_text('#!/bin/sh\nprintf "ext4\\n"\n')
    stub.chmod(0o755)
    env['PATH'] = str(tmp_path) + os.pathsep + env['PATH']
    env['CHROMIUM_PROFILE_PROBE'] = str(tmp_path)
    selected = subprocess.run(['bash', '-c', snippet], env=env, text=True, capture_output=True)
    assert selected.returncode == 0 and str(tmp_path) in selected.stdout
    stub.write_text('#!/bin/sh\nprintf "cifs\\n"\n')
    network = subprocess.run(['bash', '-c', snippet], env=env, text=True, capture_output=True)
    assert network.returncode != 0 and 'cifs' in network.stderr


@pytest.mark.parametrize('kind', ['home-shared', 'custom-shared', 'alias-in', 'alias-out', 'neighbor'])
def test_skill_probe_rejects_shared_even_on_local_filesystem(tmp_path, kind):
    skill = (ROOT / 'skills/chromium-test/SKILL.md').read_text()
    snippet = skill.split('### Profile filesystem preflight on the browser node', 1)[1].split('```bash\n', 1)[1].split('```', 1)[0]
    home = tmp_path / 'home'
    home.mkdir()
    shared = home / 'Shared'
    shared.mkdir()
    custom = tmp_path / 'custom-shared'
    custom.mkdir()
    local = tmp_path / 'local'
    local.mkdir()
    (tmp_path / 'alias-in').symlink_to(custom, target_is_directory=True)
    (shared / 'alias-out').symlink_to(local, target_is_directory=True)
    probes = {'home-shared': shared / 'new/profile', 'custom-shared': custom / 'new/profile',
              'alias-in': tmp_path / 'alias-in/new/profile', 'alias-out': shared / 'alias-out/profile',
              'neighbor': tmp_path / 'custom-shared-neighbor'}
    stub = tmp_path / 'findmnt'
    stub.write_text('#!/bin/sh\nprintf "ext4\\n"\n')
    stub.chmod(0o755)
    env = {**os.environ, 'HOME': str(home), 'HARNESS_SHARED_BASE': str(custom),
           'CHROMIUM_PROFILE_PROBE': str(probes[kind]), 'PATH': str(tmp_path) + os.pathsep + os.environ['PATH']}
    got = subprocess.run(['bash', '-c', snippet], env=env, text=True, capture_output=True)
    if kind == 'neighbor':
        assert got.returncode == 0, got.stderr
    else:
        assert got.returncode != 0 and 'Shared' in got.stderr, (got.stdout, got.stderr)
