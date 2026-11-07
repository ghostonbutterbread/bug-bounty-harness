"""Coordinator-owned team browser: private observation and fail-closed handoff."""
import importlib.util
import asyncio
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'
sys.path.insert(0, str(SCRIPTS))
import browser_profile_lease as profiles
from browser_control import PipeBrowser
from chromium_test import find_chrome_binary
from aiohttp import web
from agents.test_browser_lifecycle import local_display


def fixture(monkeypatch, tmp_path):
    # Set all process/user state roots before loading the provisioner. Never
    # resolve a default live manager DB or profile in this fixture.
    for name in ('HOME', 'XDG_STATE_HOME', 'XDG_DATA_HOME', 'XDG_CONFIG_HOME',
                 'XDG_CACHE_HOME', 'HARNESS_SHARED_BASE', 'HARNESS_BOUNTY_ARTIFACT_ROOT'):
        private_root = tmp_path / name
        private_root.mkdir(mode=0o700)
        monkeypatch.setenv(name, str(private_root))
    state = tmp_path / 'state/manager.sqlite'
    monkeypatch.setenv('BROWSER_PROVISIONER_STATE', str(state))
    spec = importlib.util.spec_from_file_location('team_control_provisioner', SCRIPTS / 'browser_provisioner.py')
    manager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manager)
    assert manager.STATE == state and state.is_relative_to(tmp_path)
    lease = 'team-lease'
    profile = tmp_path / 'profile'
    profile.mkdir()
    launch = tmp_path / 'launch.json'
    launch.write_text(json.dumps({'control_mode': 'pipe-fenced', 'activity_tracking': True,
                                  'driving_mode': 'agent-driven', 'control_socket': str(tmp_path / 'control.sock'),
                                  'cdp_url': 'http://127.0.0.1:9222/private', 'command': ['--headless=new']}))
    with manager.db() as store:
        store.execute('''INSERT INTO browsers
            (lease_id,browser_id,program,account,auth_domain,agent_id,run_id,purpose,unit,
             profile_dir,launch_file,state,tab_count,last_activity,created,updated)
            VALUES (?, 'team-browser','fixture','anon','fixture.invalid','bunny','coordinator',
                    'team','unit-team',?,?,'running',0,?,?,?)''',
            (lease, str(profile), str(launch), time.time(), time.time(), time.time()))
    canonical = state.parent / 'browser_profile_leases.sqlite'
    with profiles.connect(canonical) as store:
        profiles.init_db(store)
        store.execute('''INSERT INTO browser_profile_leases
            (lease_id,program,account_alias,auth_domain,owner_agent_id,owner_run_id,purpose,
             profile_dir,status,browser_status,manager_id,service_unit,cdp_url,created_at,
             heartbeat_at,expires_at)
            VALUES (?,'fixture','anon','fixture.invalid','bunny','coordinator','team',
                    ?,'active','running',?,'unit-team','http://127.0.0.1:9222/private',?,?,?)''',
            (lease, str(profile), manager.manager_id(), time.time(), time.time(), time.time()+300))
    return manager, state, canonical, launch


def test_coordinator_observes_exact_owner_and_adapter_activity_without_claiming_worker(monkeypatch, tmp_path):
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    activity = {'last_activity': 42, 'idle_seconds': 7201, 'attached_clients': 0,
                'inflight': 0, 'reserved_seconds': 0, 'frozen': False}
    monkeypatch.setattr(manager, 'activity_snapshot', lambda row: activity)
    monkeypatch.setattr(manager, 'healthy', lambda row: True)
    result = manager.team_control_status('team-lease', 'bunny', 'coordinator')
    assert result == {'status': 'ok', 'browser_id': 'team-browser',
                      'coordinator': {'agent_id': 'bunny', 'run_id': 'coordinator'},
                      'granted_worker': None, 'activity': activity,
                      'worker_delivery': 'unavailable',
                      'grant_activity_count': None,
                      'controller_quiescent': True, 'controller_reason': None}
    assert 'private' not in json.dumps(result)
    with manager.db() as store:
        assert (store.execute("SELECT agent_id,run_id FROM browsers WHERE lease_id='team-lease'").fetchone()[:]
                == ('bunny', 'coordinator'))
    with profiles.connect(canonical) as store:
        assert store.execute("SELECT owner_agent_id,owner_run_id FROM browser_profile_leases").fetchone()[:] == ('bunny', 'coordinator')


def test_team_status_cli_is_passive_and_refuses_unverified_owner(monkeypatch, tmp_path, capsys):
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(manager, 'healthy', lambda row: True)
    monkeypatch.setattr(manager, 'activity_snapshot', lambda row: {
        'last_activity': 10, 'idle_seconds': 9, 'inflight': 0,
        'attached_clients': 1, 'reserved_seconds': 0, 'frozen': False})
    monkeypatch.setattr(sys, 'argv', ['browser_provisioner.py', 'team-status',
        '--lease-id', 'team-lease', '--agent-id', 'bunny', '--run-id', 'coordinator'])
    with pytest.raises(SystemExit) as result:
        manager.main()
    assert result.value.code == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt['status'] == 'ok' and receipt['activity']['attached_clients'] == 1
    assert receipt['granted_worker'] is None
    with profiles.connect(canonical) as store:
        store.execute("UPDATE browser_profile_leases SET owner_run_id='not-coordinator'")
    with pytest.raises(SystemExit) as result:
        manager.main()
    assert result.value.code == 2
    assert json.loads(capsys.readouterr().out) == {'status': 'not-owner'}


@pytest.mark.parametrize('mutation', ['native', 'manual', 'untracked', 'canonical-url', 'unhealthy'])
def test_team_status_refuses_unsupported_or_unverified_browser(monkeypatch, tmp_path, mutation):
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(manager, 'healthy', lambda row: mutation != 'unhealthy')
    monkeypatch.setattr(manager, 'activity_snapshot', lambda row: {
        'last_activity': 10, 'idle_seconds': 0, 'inflight': 0,
        'attached_clients': 0, 'reserved_seconds': 0, 'frozen': False})
    if mutation == 'canonical-url':
        with profiles.connect(canonical) as store:
            store.execute("UPDATE browser_profile_leases SET cdp_url='http://127.0.0.1:9223/changed'")
    elif mutation != 'unhealthy':
        info = json.loads(launch.read_text())
        if mutation == 'native': info['kasmvnc'] = {'display': ':20'}
        if mutation == 'manual': info['driving_mode'] = 'manual'
        if mutation == 'untracked': info['activity_tracking'] = False
        launch.write_text(json.dumps(info))
    assert manager.team_control_status('team-lease', 'bunny', 'coordinator') == {
        'status': 'unavailable', 'reason': 'control-or-activity-unverified'}


@pytest.mark.parametrize('occupied', ['attached_clients', 'inflight', 'reserved_seconds'])
def test_team_status_does_not_treat_idle_occupied_control_as_handoff_ready(monkeypatch, tmp_path, occupied):
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(manager, 'healthy', lambda row: True)
    activity = {'last_activity': 10, 'idle_seconds': 9000,
                'attached_clients': 0, 'inflight': 0, 'reserved_seconds': 0, 'frozen': False}
    activity[occupied] = 1
    monkeypatch.setattr(manager, 'activity_snapshot', lambda row: activity)
    result = manager.team_control_status('team-lease', 'bunny', 'coordinator')
    assert result['controller_quiescent'] is False
    assert result['controller_reason'] == occupied


def test_team_status_does_not_claim_quiescence_with_incomplete_activity(monkeypatch, tmp_path):
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(manager, 'healthy', lambda row: True)
    monkeypatch.setattr(manager, 'activity_snapshot', lambda row: {'idle_seconds': 9000})
    assert manager.team_control_status('team-lease', 'bunny', 'coordinator') == {
        'status': 'unavailable', 'reason': 'control-or-activity-unverified'}


def test_team_status_refuses_expired_canonical_lease(monkeypatch, tmp_path):
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(manager, 'healthy', lambda row: True)
    monkeypatch.setattr(manager, 'activity_snapshot', lambda row: {
        'last_activity': 10, 'idle_seconds': 0, 'inflight': 0,
        'attached_clients': 0, 'reserved_seconds': 0, 'frozen': False})
    with profiles.connect(canonical) as store:
        store.execute('UPDATE browser_profile_leases SET expires_at=?', (time.time() - 1,))
    assert manager.team_control_status('team-lease', 'bunny', 'coordinator') == {
        'status': 'unavailable', 'reason': 'control-or-activity-unverified'}


def test_dead_coordinator_cannot_retire_outstanding_worker_grant(monkeypatch, tmp_path):
    manager, _, _, _ = fixture(monkeypatch, tmp_path)
    from browser_lifecycle import process_identity
    dead = {**process_identity(os.getpid()), 'start': 'dead-coordinator'}
    with manager.db() as store:
        manager.save_metadata(store, 'team-lease', {'owner': dead, 'ttl': 300})
        store.execute("INSERT INTO team_grants VALUES (?,?,?,?,?,?,?,?)",
                      ('team-lease', 'grant', 'worker-a', 'run-a', 'private-ref', 'old', '{}', 0))
        store.commit()
        row = store.execute("SELECT * FROM browsers WHERE lease_id='team-lease'").fetchone()
        monkeypatch.setattr(manager, 'activity_snapshot', lambda _: dict(idle_seconds=9000,
            inflight=0, reserved_seconds=0, attached_clients=0))
        assert manager.lifecycle_state(store, row) == 'active'
        monkeypatch.setattr(manager, 'unit_active', lambda _: True)
        monkeypatch.setattr(manager, 'lease', lambda *a: {'status': 'renewed'})
        monkeypatch.setattr(manager, 'retire', lambda *a: pytest.fail('outstanding worker retired'))
        monkeypatch.setattr(manager, 'freeze_idle', lambda *a, **k: pytest.fail('outstanding worker frozen'))
        assert manager.cleanup_unused(store) == []
        assert manager.maintain(argparse.Namespace(browser_id='team-browser')) == 0
        store.execute("DELETE FROM team_grants WHERE lease_id='team-lease'")
        store.execute('INSERT INTO team_pending VALUES (?,?)',
                      ('team-lease', json.dumps({'kind': 'grant', 'reference': 'private-ref'})))
        store.commit()
        assert manager.lifecycle_state(store, row) == 'active'
        assert manager.cleanup_unused(store) == []
        store.execute("DELETE FROM team_pending WHERE lease_id='team-lease'")
        store.commit()
        assert manager.lifecycle_state(store, row) == 'terminal'
        monkeypatch.setattr(manager, 'freeze_idle', lambda *a, **k: True)
        called = []
        monkeypatch.setattr(manager, 'retire', lambda *a: called.append('retired') or True)
        assert manager.maintain(argparse.Namespace(browser_id='team-browser')) == 0
        assert called == ['retired']


def test_exact_terminal_stop_clears_stale_worker_grant(monkeypatch, tmp_path):
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    from browser_lifecycle import process_identity
    dead = {**process_identity(os.getpid()), 'start': 'old-process'}
    info = json.loads(launch.read_text())
    info.update(process_identity=dead, unit_invocation='fixture-unit')
    launch.write_text(json.dumps(info))
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'fixture-unit')
    monkeypatch.setattr(manager, 'unit_inactive', lambda unit: True)
    monkeypatch.setattr(profiles, 'local_cdp_version', lambda url: {'status': 'unavailable'})
    root = state.parent / 'team-grants' / 'grant-id'
    root.mkdir(parents=True, mode=0o700)
    root.parent.chmod(0o700)
    reference = root / 'reference.json'
    reference.write_text('{}')
    reference.chmod(0o600)
    with manager.db() as store:
        store.execute('INSERT INTO team_grants VALUES (?,?,?,?,?,?,?,?)',
                      ('team-lease', 'grant-id', 'worker-a', 'run-a', str(reference), info['cdp_url'],
                       json.dumps(dead, sort_keys=True), 0))
        store.commit()
        row = store.execute("SELECT * FROM browsers WHERE lease_id='team-lease'").fetchone()
        assert manager.retire(store, row)
        assert store.execute("SELECT state FROM browsers WHERE lease_id='team-lease'").fetchone()[0] == 'stopped'
        assert store.execute("SELECT COUNT(*) FROM team_grants WHERE lease_id='team-lease'").fetchone()[0] == 0
        assert not reference.exists()
    with profiles.connect(canonical) as leases:
        assert leases.execute("SELECT status FROM browser_profile_leases WHERE lease_id='team-lease'").fetchone()[0] == 'released'


def test_coordinator_grants_private_reference_and_worker_returns_without_changing_owner(monkeypatch, tmp_path, capsys):
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    from browser_lifecycle import process_identity
    identity = process_identity(os.getpid())
    data = json.loads(launch.read_text())
    data.update(process_identity=identity, unit_invocation='unit-invocation')
    launch.write_text(json.dumps(data))
    monkeypatch.setattr(manager, 'healthy', lambda row: True)
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'unit-invocation')
    current = {'url': data['cdp_url'], 'count': 0, 'attached': 0, 'pending': False}
    def control(sock, action='activity', **kwargs):
        if action == 'identity':
            return {'cdp_url': current['url'], 'process_identity': identity,
                    'available': not current['pending'], 'team_pending': current['pending']}
        if action == 'team/fence':
            if current['attached']:
                raise RuntimeError('attached')
            current['url'] = current['url'].rsplit('/', 1)[0] + '/generation-' + str(current['count'])
            current['count'] += 1
            current['pending'] = True
            return {'cdp_url': current['url'], 'fenced': True}
        if action == 'team/activate':
            assert current['pending'] and kwargs['cdp_url'] == current['url']
            current['pending'] = False
            return {'activated': True}
        return {'last_activity': time.time(), 'idle_seconds': 9000,
                'inflight': 0, 'attached_clients': current['attached'],
                'reserved_seconds': 0, 'frozen': False, 'meaningful_count': current['count']}
    monkeypatch.setattr('browser_control.activity_control', control)
    first = manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a')
    assert first['status'] == 'granted' and 'cdp_url' not in json.dumps(first)
    ref_a = Path(first['reference'])
    assert ref_a.stat().st_mode & 0o777 == 0o600
    assert ref_a.parent.stat().st_mode & 0o777 == 0o700
    assert manager.team_consume(ref_a, 'worker-a', 'run-a')['status'] == 'ready'
    monkeypatch.setattr(sys, 'argv', ['browser_provisioner.py', 'team-consume', '--reference', str(ref_a),
                                      '--worker-agent-id', 'worker-a', '--worker-run-id', 'run-a'])
    with pytest.raises(SystemExit) as exit_code:
        manager.main()
    assert exit_code.value.code == 0
    assert json.loads(capsys.readouterr().out) == {'status': 'ready'}
    assert manager.team_consume(ref_a, 'worker-b', 'run-b')['status'] != 'ready'
    current['attached'] = 1
    assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-b', 'run-b')['status'] != 'granted'
    current['attached'] = 0
    # A disconnected controller may still belong to a thinking worker. No
    # passive idle/detach signal authorizes silently replacing its grant.
    assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-b', 'run-b') == {'status': 'busy'}
    assert manager.team_consume(ref_a, 'worker-a', 'run-a')['status'] == 'ready'
    assert manager.team_return(ref_a, 'worker-a', 'run-a')['status'] == 'returned'
    monkeypatch.setattr(sys, 'argv', ['browser_provisioner.py', 'team-grant', '--lease-id', 'team-lease',
                                      '--agent-id', 'bunny', '--run-id', 'coordinator',
                                      '--worker-agent-id', 'worker-b', '--worker-run-id', 'run-b'])
    with pytest.raises(SystemExit) as exit_code:
        manager.main()
    assert exit_code.value.code == 0
    second = json.loads(capsys.readouterr().out)
    assert second['status'] == 'granted'
    assert manager.team_consume(ref_a, 'worker-a', 'run-a')['status'] != 'ready'
    ref_b = Path(second['reference'])
    assert manager.team_consume(ref_b, 'worker-b', 'run-b')['status'] == 'ready'
    status = manager.team_control_status('team-lease', 'bunny', 'coordinator')
    assert status['granted_worker'] == {'agent_id': 'worker-b', 'run_id': 'run-b'}
    assert status['worker_delivery'] == 'private-reference'
    monkeypatch.setattr(sys, 'argv', ['browser_provisioner.py', 'team-return', '--reference', str(ref_b),
                                      '--worker-agent-id', 'worker-b', '--worker-run-id', 'run-b'])
    with pytest.raises(SystemExit) as exit_code:
        manager.main()
    assert exit_code.value.code == 0
    assert json.loads(capsys.readouterr().out) == {'status': 'returned'}
    assert manager.team_consume(ref_b, 'worker-b', 'run-b')['status'] != 'ready'
    with manager.db() as store:
        row = store.execute('SELECT agent_id,run_id FROM browsers WHERE lease_id=?', ('team-lease',)).fetchone()
        assert row[:] == ('bunny', 'coordinator')
    with profiles.connect(canonical) as store:
        row = store.execute('SELECT owner_agent_id,owner_run_id,cdp_url FROM browser_profile_leases').fetchone()
        assert row[:2] == ('bunny', 'coordinator') and row['cdp_url'] == json.loads(launch.read_text())['cdp_url']


def test_lost_grant_reply_retries_same_verified_reference_only(monkeypatch, tmp_path):
    manager, _, canonical, launch = fixture(monkeypatch, tmp_path)
    from browser_lifecycle import process_identity
    info = json.loads(launch.read_text())
    info.update(process_identity=process_identity(os.getpid()), unit_invocation='fixture-unit')
    launch.write_text(json.dumps(info))
    monkeypatch.setattr(manager, 'healthy', lambda row: True)
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'fixture-unit')
    current = {'url': info['cdp_url'], 'pending': False, 'fences': 0}
    def control(sock, action='activity', **kwargs):
        if action == 'identity':
            return {'cdp_url': current['url'], 'process_identity': info['process_identity'],
                    'available': not current['pending'], 'team_pending': current['pending']}
        if action == 'team/fence':
            current['fences'] += 1
            current['url'] += '-fenced'
            current['pending'] = True
            return {'cdp_url': current['url'], 'fenced': True}
        if action == 'team/activate':
            assert kwargs['cdp_url'] == current['url'] and current['pending']
            current['pending'] = False
            return {'activated': True}
        return {'last_activity': 1, 'idle_seconds': 9000, 'attached_clients': 0,
                'inflight': 0, 'reserved_seconds': 0, 'frozen': False}
    monkeypatch.setattr('browser_control.activity_control', control)
    sent = manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a')
    assert sent['status'] == 'granted'
    # The caller discards the successful reply and repeats the exact request.
    retry = manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a')
    assert retry == sent and current['fences'] == 1
    assert manager.team_consume(retry['reference'], 'worker-a', 'run-a') == {'status': 'ready'}
    assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-b', 'run-b') == {'status': 'busy'}
    with profiles.connect(canonical) as store:
        store.execute("UPDATE browser_profile_leases SET owner_run_id='replaced'")
    assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a') != sent


def test_grant_refuses_owner_change_during_fence(monkeypatch, tmp_path):
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    from browser_lifecycle import process_identity
    info = json.loads(launch.read_text())
    info.update(process_identity=process_identity(os.getpid()), unit_invocation='fixture-unit')
    launch.write_text(json.dumps(info))
    monkeypatch.setattr(manager, 'healthy', lambda row: True)
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'fixture-unit')
    current = {'url': info['cdp_url']}
    def control(sock, action='activity', **kwargs):
        if action == 'identity':
            return {'cdp_url': current['url'], 'process_identity': info['process_identity'], 'available': True}
        if action == 'team/fence':
            with profiles.connect(canonical) as store:
                store.execute("UPDATE browser_profile_leases SET manager_id='replaced'")
            current['url'] += '-new'
            return {'cdp_url': current['url'], 'fenced': True}
        return {'last_activity': 1, 'idle_seconds': 9000, 'attached_clients': 0,
                'inflight': 0, 'reserved_seconds': 0, 'frozen': False, 'meaningful_count': 0}
    monkeypatch.setattr('browser_control.activity_control', control)
    assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a')['status'] != 'granted'
    with manager.db() as store:
        assert store.execute('SELECT COUNT(*) FROM team_grants').fetchone()[0] == 0
    assert not list((state.parent / 'team-grants').glob('*/reference.json'))


@pytest.mark.parametrize('fault', ['canonical-drift', 'canonical-write', 'launch-write',
                                   'fence-reply', 'activation-reply', 'activation-expiry',
                                   'activation-owner-drift', 'activation-owner-immediate'])
def test_fenced_publication_is_contained_then_exactly_recovered(monkeypatch, tmp_path, fault):
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    from browser_lifecycle import process_identity
    info = json.loads(launch.read_text())
    info.update(process_identity=process_identity(os.getpid()), unit_invocation='fixture-unit')
    launch.write_text(json.dumps(info))
    monkeypatch.setattr(manager, 'healthy', lambda row: True)
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'fixture-unit')
    current = {'url': info['cdp_url'], 'pending': False, 'fences': 0,
               'activations': 0, 'drifted': False}
    def control(sock, action='activity', **kwargs):
        if action == 'identity':
            if fault == 'activation-owner-drift' and current['activations'] and not current['drifted']:
                with profiles.connect(canonical) as store:
                    store.execute("UPDATE browser_profile_leases SET owner_run_id='other-run'")
                current['drifted'] = True
            return {'cdp_url': current['url'], 'process_identity': info['process_identity'],
                    'available': not current['pending'], 'team_pending': current['pending']}
        if action == 'team/fence':
            if not current['pending']:
                current['fences'] += 1
                current['url'] += '-fenced'
                current['pending'] = True
                if fault == 'canonical-drift':
                    with profiles.connect(canonical) as store:
                        store.execute("UPDATE browser_profile_leases SET manager_id='replaced'")
                if fault == 'fence-reply':
                    raise OSError('injected lost fence reply')
            return {'cdp_url': current['url'], 'fenced': True}
        if action == 'team/activate':
            assert kwargs['cdp_url'] == current['url'] and current['pending']
            current['pending'] = False
            current['activations'] += 1
            if fault == 'activation-owner-immediate':
                with profiles.connect(canonical) as store:
                    store.execute("UPDATE browser_profile_leases SET owner_run_id='other-run'")
            if fault in ('activation-reply', 'activation-expiry', 'activation-owner-drift'):
                raise OSError('injected lost activation reply')
            return {'activated': True}
        return {'last_activity': 1, 'idle_seconds': 9000, 'attached_clients': 0,
                'inflight': 0, 'reserved_seconds': 0, 'frozen': False, 'meaningful_count': 0}
    monkeypatch.setattr('browser_control.activity_control', control)
    if fault == 'canonical-write':
        with profiles.connect(canonical) as store:
            store.execute("CREATE TRIGGER fail_team BEFORE UPDATE OF cdp_url ON browser_profile_leases "
                          "BEGIN SELECT RAISE(FAIL, 'injected canonical write loss'); END")
    if fault == 'launch-write':
        writer = manager.private_json
        fail = {'once': True}
        def write(path, value):
            if Path(path) == launch and fail['once']:
                fail['once'] = False
                raise OSError('injected launch write loss')
            return writer(path, value)
        monkeypatch.setattr(manager, 'private_json', write)
    first = manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a')
    assert first == {'status': 'cleanup-incomplete'}
    assert (current['pending'], current['activations']) == (
        (False, 1) if fault in ('activation-reply', 'activation-expiry',
                              'activation-owner-drift', 'activation-owner-immediate') else (True, 0))
    assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-b', 'run-b') == {'status': 'busy'}
    if fault == 'activation-owner-drift':
        assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a') == {
            'status': 'cleanup-incomplete'}
        assert current['drifted']
        with profiles.connect(canonical) as store:
            store.execute("UPDATE browser_profile_leases SET owner_run_id='coordinator'")
    if fault == 'activation-owner-immediate':
        with profiles.connect(canonical) as store:
            store.execute("UPDATE browser_profile_leases SET owner_run_id='coordinator'")
    if fault == 'activation-expiry':
        with profiles.connect(canonical) as store:
            store.execute('UPDATE browser_profile_leases SET expires_at=?', (time.time() - 1,))
        assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a') == {
            'status': 'cleanup-incomplete'}
        with profiles.connect(canonical) as store:
            store.execute('UPDATE browser_profile_leases SET expires_at=?', (time.time() + 300,))
    if fault == 'canonical-drift':
        with profiles.connect(canonical) as store:
            store.execute('UPDATE browser_profile_leases SET manager_id=?', (manager.manager_id(),))
    if fault == 'canonical-write':
        with profiles.connect(canonical) as store:
            store.execute('DROP TRIGGER fail_team')
    result = manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a')
    assert result['status'] == 'granted' and current['fences'] == current['activations'] == 1
    assert manager.team_consume(result['reference'], 'worker-a', 'run-a') == {'status': 'ready'}
    with profiles.connect(canonical) as store:
        assert store.execute('SELECT cdp_url FROM browser_profile_leases').fetchone()[0] == current['url']
    assert json.loads(launch.read_text())['cdp_url'] == current['url']
    with manager.db() as store:
        assert store.execute('SELECT COUNT(*) FROM team_pending').fetchone()[0] == 0


def test_failed_team_barrier_requires_recheck_before_manager_publishes(monkeypatch, tmp_path):
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    from browser_lifecycle import process_identity
    info = json.loads(launch.read_text())
    info.update(process_identity=process_identity(os.getpid()), unit_invocation='fixture-unit')
    launch.write_text(json.dumps(info))
    monkeypatch.setattr(manager, 'healthy', lambda row: True)
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'fixture-unit')
    current = {'url': info['cdp_url'], 'pending': False, 'barrier': False, 'fences': 0}
    def control(sock, action='activity', **kwargs):
        if action == 'identity':
            return {'cdp_url': current['url'], 'process_identity': info['process_identity'],
                    'available': not current['pending'], 'team_pending': current['pending']}
        if action == 'team/fence':
            current['fences'] += 1
            if not current['pending']:
                current['url'] += '-fenced'
                current['pending'] = True
                raise OSError('barrier interrupted after generation rotation')
            current['barrier'] = True
            return {'cdp_url': current['url'], 'fenced': True}
        if action == 'team/activate':
            assert current['barrier']
            current['pending'] = False
            return {'activated': True}
        return {'last_activity': 1, 'idle_seconds': 0, 'attached_clients': 0,
                'inflight': 0, 'reserved_seconds': 0, 'frozen': False}
    monkeypatch.setattr('browser_control.activity_control', control)
    assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a') == {
        'status': 'cleanup-incomplete'}
    assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a')['status'] == 'granted'
    assert current['barrier'] and current['fences'] == 2


def test_return_publication_failure_keeps_old_grant_blocked_until_exact_retry(monkeypatch, tmp_path):
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    from browser_lifecycle import process_identity
    info = json.loads(launch.read_text())
    info.update(process_identity=process_identity(os.getpid()), unit_invocation='fixture-unit')
    launch.write_text(json.dumps(info))
    monkeypatch.setattr(manager, 'healthy', lambda row: True)
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'fixture-unit')
    current = {'url': info['cdp_url'], 'pending': False, 'fences': 0}
    def control(sock, action='activity', **kwargs):
        if action == 'identity':
            return {'cdp_url': current['url'], 'process_identity': info['process_identity'],
                    'available': not current['pending'], 'team_pending': current['pending']}
        if action == 'team/fence':
            if not current['pending']:
                current['fences'] += 1
                current['url'] += '-fenced'
                current['pending'] = True
            return {'cdp_url': current['url'], 'fenced': True}
        if action == 'team/activate':
            current['pending'] = False
            return {'activated': True}
        return {'last_activity': 1, 'idle_seconds': 9000, 'attached_clients': 0,
                'inflight': 0, 'reserved_seconds': 0, 'frozen': False}
    monkeypatch.setattr('browser_control.activity_control', control)
    first = manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a')
    assert first['status'] == 'granted'
    with profiles.connect(canonical) as store:
        store.execute("CREATE TRIGGER fail_return BEFORE UPDATE OF cdp_url ON browser_profile_leases "
                      "BEGIN SELECT RAISE(FAIL, 'injected return write loss'); END")
    assert manager.team_return(first['reference'], 'worker-a', 'run-a') == {'status': 'cleanup-incomplete'}
    assert current['pending'] and manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-b', 'run-b') == {'status': 'busy'}
    assert manager.team_consume(first['reference'], 'worker-a', 'run-a') == {'status': 'unavailable'}
    with profiles.connect(canonical) as store:
        store.execute('DROP TRIGGER fail_return')
    assert manager.team_return(first['reference'], 'worker-a', 'run-a') == {'status': 'returned'}
    assert not Path(first['reference']).exists()
    second = manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-b', 'run-b')
    assert second['status'] == 'granted' and current['fences'] == 3
    with manager.db() as store:
        assert store.execute('SELECT COUNT(*) FROM team_pending').fetchone()[0] == 0


def test_grant_refuses_controller_attaching_between_snapshot_and_fence(monkeypatch, tmp_path):
    import httpx
    from browser_lifecycle import process_identity
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    info = json.loads(launch.read_text())
    info.update(process_identity=process_identity(os.getpid()), unit_invocation='fixture-unit')
    launch.write_text(json.dumps(info))
    monkeypatch.setattr(manager, 'healthy', lambda row: True)
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'fixture-unit')
    def control(sock, action='activity', **kwargs):
        if action == 'identity':
            return {'cdp_url': info['cdp_url'], 'process_identity': info['process_identity'], 'available': True}
        if action == 'team/fence':
            response = httpx.Response(409, request=httpx.Request('POST', 'http://localhost/team/fence'))
            raise httpx.HTTPStatusError('busy', request=response.request, response=response)
        return {'attached_clients': 0, 'inflight': 0, 'reserved_seconds': 0, 'frozen': False}
    monkeypatch.setattr('browser_control.activity_control', control)
    assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a') == {'status': 'busy'}
    assert not list((state.parent / 'team-grants').glob('*/reference.json'))
    assert not list((state.parent / 'team-grants').iterdir())

@pytest.mark.parametrize('occupied', ['attached', 'inflight', 'reserved', 'frozen'])
def test_private_team_fence_refuses_occupied_browser_even_after_idle(occupied):
    async def scenario():
        bridge = PipeBrowser.__new__(PipeBrowser)
        bridge.token, bridge.port, bridge.epoch = 'old', 9222, 0
        bridge.rotating = bridge.frozen = bridge.quarantined = bridge.team_pending = False
        bridge.transfer = None
        bridge.clients = {}
        bridge.inflight = 0
        bridge.reserved_until = 0
        bridge.last_use = time.monotonic() - 9000
        bridge.call = lambda *args: asyncio.sleep(0, result={'result': {}})
        bridge.mark_activity = lambda: None
        if occupied == 'attached': bridge.clients[object()] = {'session'}
        if occupied == 'inflight': bridge.inflight = 1
        if occupied == 'reserved': bridge.reserved_until = time.monotonic() + 30
        if occupied == 'frozen': bridge.frozen = True
        with pytest.raises(web.HTTPConflict):
            await bridge.team_fence(None)
        assert (bridge.token, bridge.epoch) == ('old', 0)
    asyncio.run(scenario())


def test_private_team_fence_revokes_old_generation_without_requiring_idle():
    async def scenario():
        bridge = PipeBrowser.__new__(PipeBrowser)
        bridge.token, bridge.port, bridge.epoch = 'old', 9222, 0
        bridge.rotating = bridge.frozen = bridge.quarantined = bridge.team_pending = False
        bridge.transfer = None
        bridge.clients = {}
        bridge.inflight = 0
        bridge.reserved_until = 0
        bridge.last_use = time.monotonic()
        bridge.mark_activity = lambda: None
        entered, proceed = asyncio.Event(), asyncio.Event()
        async def barrier(*args):
            entered.set()
            await proceed.wait()
            return {'result': {}}
        bridge.call = barrier
        fencing = asyncio.create_task(bridge.team_fence(None))
        await entered.wait()
        assert bridge.rotating and bridge.epoch == 1 and bridge.token != 'old'
        proceed.set()
        receipt = json.loads((await fencing).text)
        assert receipt['fenced'] is True and receipt['cdp_url'].endswith(bridge.token)
        assert bridge.rotating and bridge.team_pending and bridge.clients == {}
        assert (await bridge.team_fence(None)).status == 200
        class Request:
            async def json(self): return {'cdp_url': receipt['cdp_url']}
        assert json.loads((await bridge.team_activate(Request())).text)['activated']
        assert not bridge.rotating and not bridge.team_pending
    asyncio.run(scenario())


def test_private_team_fence_barrier_failure_keeps_control_closed():
    async def scenario():
        bridge = PipeBrowser.__new__(PipeBrowser)
        bridge.token, bridge.port, bridge.epoch = 'old', 9222, 0
        bridge.rotating = bridge.frozen = bridge.quarantined = bridge.team_pending = False
        bridge.transfer = None
        bridge.clients = {}
        bridge.inflight = 0
        bridge.reserved_until = 0
        bridge.call = lambda *args: asyncio.sleep(0, result={'error': {}})
        with pytest.raises(web.HTTPServiceUnavailable):
            await bridge.team_fence(None)
        assert bridge.rotating and bridge.epoch == 1
    asyncio.run(scenario())


@pytest.mark.parametrize('failure', ['error', 'cancelled'])
def test_private_team_fence_retries_failed_barrier_on_same_generation(failure):
    async def scenario():
        bridge = PipeBrowser.__new__(PipeBrowser)
        bridge.token, bridge.port, bridge.epoch = 'old', 9222, 0
        bridge.rotating = bridge.frozen = bridge.quarantined = bridge.team_pending = False
        bridge.transfer = None
        bridge.clients = {}
        bridge.inflight = 0
        bridge.reserved_until = 0
        attempts = 0
        async def barrier(*args):
            nonlocal attempts
            attempts += 1
            if attempts == 1 and failure == 'cancelled':
                raise asyncio.CancelledError()
            return {'error': {}} if attempts == 1 else {'result': {}}
        bridge.call = barrier
        with pytest.raises((web.HTTPServiceUnavailable, asyncio.CancelledError)):
            await bridge.team_fence(None)
        token = bridge.token
        assert bridge.rotating and bridge.team_pending and token != 'old'
        class Request:
            async def json(self): return {'cdp_url': f'http://127.0.0.1:9222/{token}'}
        with pytest.raises(web.HTTPConflict):
            await bridge.team_activate(Request())
        receipt = json.loads((await bridge.team_fence(None)).text)
        assert receipt['fenced'] and receipt['cdp_url'].endswith(token)
        assert bridge.epoch == 1 and attempts == 2
    asyncio.run(scenario())


@pytest.mark.skipif(os.environ.get('BBH_LOCAL_BROWSER_SMOKE') != '1',
                    reason='opt-in isolated local Chrome')
@pytest.mark.parametrize('local_display', ['headless'], indirect=True)
def test_real_chrome_detached_fence_preserves_browser_and_revokes_old_url(tmp_path, local_display):
    """Adapter fixture only; no authenticated worker route or manager grant."""
    import httpx
    from browser_control import PipeBrowser, activity_control
    chrome = find_chrome_binary()
    assert chrome
    flags, env = local_display
    browser = PipeBrowser([chrome, *flags, '--remote-debugging-pipe', '--no-first-run',
        '--disable-background-networking', '--disable-component-update', '--disable-sync',
        '--user-data-dir=' + str(tmp_path / 'profile'), 'about:blank'],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Keep the Unix path below AF_UNIX's limit despite a long scratch root.
    sock = tmp_path.parent / (tmp_path.name[-1] + '-team.sock')
    try:
        original = browser.serve(0, sock)
        assert activity_control(sock)['attached_clients'] == 0
        with httpx.Client(transport=httpx.HTTPTransport(uds=str(sock)), timeout=10) as client:
            response = client.post('http://localhost/team/fence')
            response.raise_for_status()
            successor = response.json()['cdp_url']
        assert successor != original and browser.process.poll() is None
        assert activity_control(sock, 'identity')['team_pending'] is True
        with pytest.raises(urllib.error.HTTPError) as old:
            urllib.request.urlopen(original + '/json/version', timeout=5)
        assert old.value.code == 410
        with pytest.raises(urllib.error.HTTPError) as unpublished:
            urllib.request.urlopen(successor + '/json/version', timeout=5)
        assert unpublished.value.code == 410
        assert activity_control(sock, 'team/activate', cdp_url=successor)['activated'] is True
        with urllib.request.urlopen(successor + '/json/version', timeout=5) as new:
            assert json.load(new)['Browser']
    finally:
        browser.close()
        sock.unlink(missing_ok=True)
    assert browser.process.poll() is not None
    with pytest.raises((urllib.error.URLError, ConnectionError)):
        urllib.request.urlopen(successor + '/json/version', timeout=5)
    shutil.rmtree(tmp_path / 'profile')
    assert not (tmp_path / 'profile').exists()


@pytest.mark.skipif(os.environ.get('BBH_LOCAL_BROWSER_SMOKE') != '1',
                    reason='opt-in isolated local Chrome')
@pytest.mark.parametrize('local_display', ['headless'], indirect=True)
def test_real_chrome_two_workers_same_process_private_grants_and_exact_cleanup(monkeypatch, tmp_path, local_display):
    from browser_lifecycle import process_identity
    chrome = find_chrome_binary()
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    assert chrome
    flags, env = local_display
    browser = PipeBrowser([chrome, *flags, '--remote-debugging-pipe', '--no-first-run',
        '--disable-background-networking', '--disable-component-update', '--disable-sync',
        '--user-data-dir=' + str(tmp_path / 'profile'), 'about:blank'],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sock = tmp_path.parent / (tmp_path.name[-1] + '-grant.sock')
    assert len(str(sock).encode()) < 107
    successor = None
    try:
        original = browser.serve(0, sock)
        identity = process_identity(browser.process.pid)
        info = json.loads(launch.read_text())
        info.update(cdp_url=original, control_socket=str(sock), process_identity=identity,
                    unit_invocation='fixture-unit')
        launch.write_text(json.dumps(info))
        with profiles.connect(canonical) as store:
            store.execute('UPDATE browser_profile_leases SET cdp_url=?', (original,))
        monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'fixture-unit')
        monkeypatch.setattr(manager, 'healthy', lambda row: (
            process_identity(browser.process.pid) == identity and
            profiles.local_cdp_version(json.loads(launch.read_text())['cdp_url'])['status'] == 'ready'))
        first = manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a')
        assert first['status'] == 'granted', first
        with manager.team_browser(first['reference'], 'worker-a', 'run-a') as controller:
            page = controller.contexts[0].pages[0]
            page.evaluate("window.teamMarker = 'first-worker'")
            assert page.evaluate('window.teamMarker') == 'first-worker'
            busy = manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-b', 'run-b')
            assert busy['status'] == 'busy'
        assert manager.team_control_status('team-lease', 'bunny', 'coordinator')['grant_activity_count'] > 0
        assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-b', 'run-b')['status'] == 'busy'
        assert manager.team_return(first['reference'], 'worker-a', 'run-a')['status'] == 'returned'
        second = manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-b', 'run-b')
        assert second['status'] == 'granted', second
        with pytest.raises(RuntimeError, match='reference unavailable'):
            with manager.team_browser(first['reference'], 'worker-a', 'run-a'):
                pass
        with pytest.raises(urllib.error.HTTPError) as old:
            urllib.request.urlopen(original + '/json/version', timeout=5)
        assert old.value.code == 410
        with manager.team_browser(second['reference'], 'worker-b', 'run-b') as controller:
            assert controller.contexts[0].pages[0].evaluate('window.teamMarker') == 'first-worker'
            assert controller.contexts[0].pages[0].evaluate('window.teamMarker = "second-worker"') == 'second-worker'
        assert manager.team_return(second['reference'], 'worker-b', 'run-b')['status'] == 'returned'
        assert not list((state.parent / 'team-grants').glob('*/reference.json'))
        successor = json.loads(launch.read_text())['cdp_url']
        assert browser.process.poll() is None
        with profiles.connect(canonical) as store:
            row = store.execute('SELECT cdp_url,owner_agent_id,owner_run_id FROM browser_profile_leases').fetchone()
            assert row[:] == (successor, 'bunny', 'coordinator')
    finally:
        browser.close()
        sock.unlink(missing_ok=True)
    assert browser.process.poll() is not None
    if successor:
        with pytest.raises((urllib.error.URLError, ConnectionError)):
            urllib.request.urlopen(successor + '/json/version', timeout=5)
    shutil.rmtree(tmp_path / 'profile')
    assert not (tmp_path / 'profile').exists()
