"""Offline manager/lease fixtures: no real browsers or profiles are touched."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agents.test_browser_provisioner import load, add
from agents.test_browser_profile_lease import args as lease_args
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'))
import browser_profile_lease as profiles


@pytest.fixture
def setup(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.setenv('HARNESS_SHARED_BASE', str(tmp_path / 'Shared'))
    monkeypatch.setattr(profiles, 'local_filesystem', lambda path: True)
    monkeypatch.setattr(m, 'unit_active', lambda unit: False)
    monkeypatch.setattr(m, 'stopped', lambda row: True)
    return m


def put(m, root, lease, relative='demo/web/browser-instances/domain/fixture/slot', *, program='demo', instance='slot'):
    p = root / relative
    add(m, root, lease, p)
    (root / (lease + '.json')).write_text(json.dumps({'instance_key': instance}))
    if program != 'demo':
        c = m.db()
        c.execute('update browsers set program=? where lease_id=?', (program, lease))
        c.commit()
    return p


@pytest.mark.parametrize('value', ['', '   '])
def test_empty_root_uses_default_not_cwd(setup, monkeypatch, tmp_path, value):
    monkeypatch.setenv('HARNESS_BOUNTY_ARTIFACT_ROOT', value)
    monkeypatch.setattr(profiles, 'default_mount_available', lambda: False)
    monkeypatch.chdir(tmp_path)
    assert profiles.artifact_base() == profiles.fallback_base()
    assert profiles.profile_dir('demo', 'domain', 'fixture').is_absolute()
    result = profiles.cmd_acquire(lease_args(profiles, tmp_path / 'lease-state', 'acquire',
                                            account='anon', agent_id='a', run_id='r', purpose='test'))
    assert result['status'] == 'leased'
    path = Path(result['lease']['profile_dir'])
    assert path.is_absolute() and path.is_relative_to(profiles.fallback_base())


@pytest.mark.parametrize('value', ['relative/path', '.', '../parent'])
def test_relative_root_rejected(setup, monkeypatch, value):
    monkeypatch.setenv('HARNESS_BOUNTY_ARTIFACT_ROOT', value)
    with pytest.raises(ValueError, match='HARNESS_BOUNTY_ARTIFACT_ROOT.*absolute'):
        profiles.artifact_base()


@pytest.mark.parametrize('mount_state', ['missing', 'unwritable'])
def test_sweep_fallback_after_default_mount_recovers(setup, monkeypatch, tmp_path, mount_state):
    m = setup
    monkeypatch.delenv('HARNESS_BOUNTY_ARTIFACT_ROOT')
    mount = tmp_path / 'mount'
    mount.mkdir()
    monkeypatch.setattr(profiles, 'DEFAULT_BOUNTY_ROOT', mount)
    monkeypatch.setattr(profiles, 'default_mount_available', lambda: mount_state == 'unwritable')
    real_access = profiles.os.access
    monkeypatch.setattr(profiles.os, 'access', lambda path, mode: False if Path(path) == mount else real_access(path, mode))
    assert profiles.artifact_base() == profiles.fallback_base()
    root = profiles.fallback_base()
    p = put(m, root, 'old', program='task-owned')
    # A recovered mount must not orphan the previously created fallback.
    monkeypatch.setattr(profiles, 'default_mount_available', lambda: True)
    monkeypatch.setattr(profiles.os, 'access', real_access)
    dry, skipped = m.sweep_rows(m.db(), 14, False)
    assert len(dry) == 1 and dry[0]['dry_run'] and not skipped and p.exists()
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert len(removed) == 1 and not skipped and not p.exists()
    assert m.db().execute("select state from browsers where lease_id='old'").fetchone()[0] == 'deleted'


def test_sweep_still_recognizes_previously_recorded_fallback(setup, monkeypatch, tmp_path):
    m = setup
    monkeypatch.delenv('HARNESS_BOUNTY_ARTIFACT_ROOT', raising=False)
    old_root = tmp_path / 'home/.local/share/ghost/browser-runtime'
    path = put(m, old_root, 'old', program='task-owned')
    dry, skipped = m.sweep_rows(m.db(), 14, False)
    assert len(dry) == 1 and dry[0]['dry_run'] and not skipped and path.exists()


def test_root_transitions_protect_legacy_and_do_not_authorize_old_custom(setup, monkeypatch, tmp_path):
    m = setup
    fallback = profiles.fallback_base()
    legacy = put(m, fallback, 'legacy', 'demo/web/browser-profiles/default/fixture', instance='')
    disposable = put(m, fallback, 'disposable', program='task-owned')
    old = put(m, tmp_path / 'former-root', 'former', program='task-owned')
    new = put(m, tmp_path / 'new-root', 'new', program='task-owned')
    monkeypatch.setenv('HARNESS_BOUNTY_ARTIFACT_ROOT', str(tmp_path / 'new-root'))
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert {x['browser_id'] for x in removed} == {'disposable-browser', 'new-browser'}
    assert {x['browser_id']: x['reason'] for x in skipped} == {
        'legacy-browser': 'legacy-auth-retained', 'former-browser': 'not-managed-profile'}
    assert legacy.exists() and old.exists() and not disposable.exists() and not new.exists()


def test_fallback_legacy_physical_alias_protects_keyed_record(setup, tmp_path):
    m = setup
    root = profiles.fallback_base()
    original = put(m, root, 'legacy', 'demo/web/browser-profiles/default/fixture', instance='')
    alias = root / 'demo/web/browser-instances/domain/fixture/slot'
    alias.parent.mkdir(parents=True)
    alias.symlink_to(original, target_is_directory=True)
    add(m, root, 'keyed', alias)
    (root / 'keyed.json').write_text(json.dumps({'instance_key': 'slot'}))
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert not removed and original.exists() and alias.is_symlink()
    assert {x['reason'] for x in skipped} == {'legacy-auth-retained', 'profile-identity-unverified'}


@pytest.mark.parametrize('domain,account', [('wrong-domain', 'fixture'), ('', 'other')])
def test_unkeyed_named_history_survives_mismatched_metadata(setup, domain, account):
    m = setup
    root = profiles.fallback_base()
    path = put(m, root, 'named', 'demo/web/browser-profiles/api.example/fixture', instance='')
    c = m.db()
    c.execute('update browsers set auth_domain=?, account=? where lease_id=?', (domain, account, 'named'))
    c.commit()
    removed, skipped = m.sweep_rows(c, 14, True)
    assert not removed and path.exists()
    assert skipped[0]['reason'] == 'legacy-auth-retained'


def test_mismatched_named_history_protects_disposable_physical_alias(setup, tmp_path):
    m = setup
    root = profiles.fallback_base()
    path = put(m, root, 'candidate', program='task-owned')
    alias = tmp_path / 'named-alias'
    alias.symlink_to(path, target_is_directory=True)
    add(m, root, 'named', alias)
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert not removed and path.exists()
    assert any(r['reason'] == 'legacy-auth-retained' for r in skipped)


@pytest.mark.parametrize('instance', ['', 'slot'])
def test_released_named_canonical_alias_protects_disposable(setup, tmp_path, instance):
    m = setup
    root = profiles.fallback_base()
    path = put(m, root, 'candidate', program='task-owned')
    alias = tmp_path / 'named-alias'
    alias.symlink_to(path, target_is_directory=True)
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as c:
        profiles.init_db(c)
        c.execute("""insert into browser_profile_leases
            (lease_id, program, account_alias, owner_agent_id, owner_run_id, purpose,
             profile_dir, status, created_at, heartbeat_at, expires_at, instance_key)
            values ('historic', 'demo', 'fixture', 'agent', 'run', 'test', ?, 'released', 0, 0, 1, ?)""",
            (str(alias), instance))
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert not removed and path.exists()
    assert skipped[0]['reason'] == 'legacy-auth-retained'


@pytest.mark.parametrize('other_stopped', [False, True])
def test_old_stopped_manager_alias_requires_runtime_proof(setup, tmp_path, monkeypatch, other_stopped):
    m = setup
    root = profiles.fallback_base()
    path = put(m, root, 'candidate', program='task-owned')
    alias = tmp_path / 'other-alias'
    alias.symlink_to(path, target_is_directory=True)
    add(m, root, 'other', alias, state='stopped')
    c = m.db()
    c.execute("update browsers set program='task-owned' where lease_id='other'")
    c.commit()
    checked = []
    def stopped(row):
        checked.append(row['lease_id'])
        return row['lease_id'] != 'other' or other_stopped
    monkeypatch.setattr(m, 'stopped', stopped)
    removed, skipped = m.sweep_rows(c, 14, True)
    assert 'other' in checked
    if other_stopped:
        assert [r['browser_id'] for r in removed] == ['candidate-browser']
        assert not path.exists()
    else:
        assert not removed and path.exists()
        assert any(r['reason'] == 'profile-in-use' for r in skipped)


@pytest.mark.parametrize('root_status', ['live', 'unknown', 'terminal'])
def test_old_alias_pid_only_receipt_requires_dead_root(setup, tmp_path, monkeypatch, root_status):
    m = setup
    root = profiles.fallback_base()
    path = put(m, root, 'candidate', program='task-owned')
    alias = tmp_path / 'pid-alias'
    alias.symlink_to(path, target_is_directory=True)
    add(m, root, 'other', alias)
    (root / 'other.json').write_text(json.dumps({'pid': 1234}))
    c = m.db()
    c.execute("update browsers set program='task-owned' where lease_id='other'")
    c.commit()
    def identity(pid):
        assert pid == 1234
        if root_status == 'unknown':
            raise OSError('unobservable')
        return {'pid': pid} if root_status == 'live' else None
    monkeypatch.setattr(m, 'process_identity', identity)
    removed, _ = m.sweep_rows(c, 14, True)
    assert bool(removed) == (root_status == 'terminal')
    assert path.exists() == (root_status != 'terminal')


@pytest.mark.parametrize('owner', ['unit', 'root', 'unknown-root', 'cdp', 'terminal'])
def test_stopped_alias_checks_actual_runtime(setup, tmp_path, monkeypatch, owner):
    # Load an unpatched stopped() implementation; all OS/CDP boundaries are doubles.
    m = load(monkeypatch, tmp_path)
    root = profiles.fallback_base()
    path = put(m, root, 'candidate', program='task-owned')
    alias = tmp_path / 'runtime-alias'
    alias.symlink_to(path, target_is_directory=True)
    add(m, root, 'other', alias)
    (root / 'other.json').write_text(json.dumps({
        'process_identity': {'pid': 1234}, 'cdp_url': 'http://127.0.0.1:1'}))
    c = m.db()
    c.execute("update browsers set program='task-owned' where lease_id='other'")
    c.commit()
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    monkeypatch.setattr(m, 'unit_inactive', lambda unit: not (owner == 'unit' and unit == 'other-unit'))
    monkeypatch.setattr(m, 'owner_state', lambda _: 'active' if owner == 'root' else
                        'unknown' if owner == 'unknown-root' else 'terminal')
    monkeypatch.setattr(profiles, 'local_cdp_version', lambda _: {'status': 'ready' if owner == 'cdp' else 'closed'})
    monkeypatch.setattr(m, 'stop_recorded', lambda _: pytest.fail('sweep must not stop another owner'))
    removed, _ = m.sweep_rows(c, 14, True)
    assert bool(removed) == (owner == 'terminal')
    assert path.exists() == (owner != 'terminal')


def test_owner_becoming_live_before_delete_is_retained(setup, tmp_path, monkeypatch):
    m = setup
    root = profiles.fallback_base()
    path = put(m, root, 'candidate', program='task-owned')
    alias = tmp_path / 'changing-alias'
    alias.symlink_to(path, target_is_directory=True)
    add(m, root, 'other', alias)
    c = m.db()
    c.execute("update browsers set program='task-owned' where lease_id='other'")
    c.commit()
    checks = []
    def stopped(row):
        if row['lease_id'] == 'other':
            checks.append('other')
            return len(checks) == 1
        return True
    monkeypatch.setattr(m, 'stopped', stopped)
    removed, skipped = m.sweep_rows(c, 14, True)
    assert checks == ['other', 'other']
    assert not removed and path.exists()
    assert any(r['reason'] == 'profile-in-use' for r in skipped)


@pytest.mark.parametrize('block', ['network', 'shared', 'active-unit', 'not-stopped', 'active-alias'])
def test_sweep_keeps_unsafe_or_in_use_fallback(setup, monkeypatch, tmp_path, block):
    m = setup
    root = profiles.fallback_base()
    p = put(m, root, 'old', program='task-owned')
    if block == 'network':
        monkeypatch.setattr(profiles, 'local_filesystem', lambda path: False)
    elif block == 'shared':
        monkeypatch.setenv('HARNESS_SHARED_BASE', str(root))
    elif block == 'active-unit':
        monkeypatch.setattr(m, 'unit_active', lambda unit: True)
    elif block == 'not-stopped':
        monkeypatch.setattr(m, 'stopped', lambda row: False)
    else:
        alias = tmp_path / 'alias'
        alias.symlink_to(p, target_is_directory=True)
        lease_db = m.STATE.parent / 'browser_profile_leases.sqlite'
        with profiles.connect(lease_db) as c:
            profiles.init_db(c)
            c.execute("""insert into browser_profile_leases
                (lease_id, program, account_alias, owner_agent_id, owner_run_id, purpose,
                 profile_dir, status, created_at, heartbeat_at, expires_at, instance_key)
                values ('alias', 'task-owned', 'fixture', 'agent', 'run', 'test', ?, 'active', 0, 0, 1, 'slot')""", (str(alias),))
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert not removed and p.exists() and len(skipped) == 1
    assert skipped[0]['reason'] in {'unsafe-profile-path', 'unit-active', 'browser-not-stopped', 'profile-leased'}


@pytest.mark.parametrize('lease_program,expect_removed', [('demo', False), ('task-owned', True)])
def test_task_owned_sweep_respects_persistent_history_alias(setup, tmp_path, lease_program, expect_removed):
    m = setup
    root = profiles.fallback_base()
    p = put(m, root, 'old', program='task-owned')
    alias = tmp_path / 'historical-alias'
    alias.symlink_to(p, target_is_directory=True)
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as c:
        profiles.init_db(c)
        c.execute("""insert into browser_profile_leases
            (lease_id, program, account_alias, owner_agent_id, owner_run_id, purpose,
             profile_dir, status, created_at, heartbeat_at, expires_at, instance_key)
            values ('historic', ?, 'fixture', 'agent', 'run', 'test', ?, 'released', 0, 0, 1, '')""",
            (lease_program, str(alias)))
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert bool(removed) == expect_removed
    assert p.exists() != expect_removed
    assert not skipped if expect_removed else skipped[0]['reason'] == 'legacy-auth-retained'


def test_unregistered_profile_never_discovered(setup):
    root = profiles.fallback_base()
    profile = root / 'demo/web/browser-instances/domain/fixture/unregistered'
    profile.mkdir(parents=True)
    assert setup.sweep_rows(setup.db(), 14, True) == ([], [])
    assert profile.exists()


def test_relative_historical_manifest_is_not_resolved_from_cwd(setup, monkeypatch, tmp_path):
    m = setup
    root = tmp_path / 'artifacts'
    p = put(m, root, 'old', program='task-owned')
    monkeypatch.chdir(tmp_path)
    c = m.db()
    c.execute('update browsers set profile_dir=? where lease_id=?', (str(p.relative_to(tmp_path)), 'old'))
    c.commit()
    removed, skipped = m.sweep_rows(c, 14, True)
    assert not removed and skipped[0]['reason'] == 'profile-identity-unverified' and p.exists()


def test_active_manager_alias_fences_fallback(setup, tmp_path):
    m = setup
    root = profiles.fallback_base()
    p = put(m, root, 'old', program='task-owned')
    alias = tmp_path / 'active-alias'
    alias.symlink_to(p, target_is_directory=True)
    add(m, root, 'active', alias, state='running')
    c = m.db()
    c.execute("update browsers set program='task-owned' where lease_id='active'")
    c.commit()
    removed, skipped = m.sweep_rows(m.db(), 14, True)
    assert not removed and skipped[0]['reason'] == 'profile-in-use' and p.exists()


@pytest.mark.parametrize('script,argv', [
    ('browser_profile_lease.py', ['acquire', 'demo', 'anon', '--agent-id', 'a', '--run-id', 'r', '--purpose', 'test']),
    ('browser_provisioner.py', ['sweep-stale']),
])
def test_cli_relative_root_fails_before_state_write(setup, monkeypatch, tmp_path, script, argv):
    monkeypatch.setenv('HARNESS_BOUNTY_ARTIFACT_ROOT', 'relative/path')
    state = tmp_path / 'should-not-exist'
    monkeypatch.setenv('BROWSER_PROVISIONER_STATE', str(state / 'manager.sqlite'))
    path = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts' / script
    if script == 'browser_profile_lease.py':
        argv = ['--state-dir', str(state)] + argv
    result = subprocess.run([sys.executable, str(path), *argv], capture_output=True, text=True)
    assert result.returncode == 2
    assert 'HARNESS_BOUNTY_ARTIFACT_ROOT must be an absolute path' in result.stderr
    assert 'Traceback' not in result.stderr and not state.exists()
