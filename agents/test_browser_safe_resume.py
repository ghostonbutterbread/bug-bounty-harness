"""Disposable manager fixtures; no live Chrome or systemd calls."""
import argparse
import importlib.util
import json
import time
from types import SimpleNamespace
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / 'skills/chromium-test/scripts/browser_provisioner.py'


def manager(monkeypatch, tmp_path):
    monkeypatch.setenv('BROWSER_PROVISIONER_STATE', str(tmp_path / 'manager.sqlite'))
    spec = importlib.util.spec_from_file_location('browser_safe_resume_fixture', SCRIPT)
    assert spec is not None and spec.loader is not None
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def rows(m, tmp_path, count=4, state='running'):
    c = m.db()
    for n in range(count):
        bid = f'browser-{n}'
        c.execute('INSERT INTO browsers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  (f'lease-{n}', bid, 'demo', 'blue', 'example.test', 'agent', 'run',
                   'fixture', f'unit-{n}', str(tmp_path / f'profile-{n}'),
                   str(tmp_path / f'{bid}.json'), state, 0, 0, 0, 0))
        (tmp_path / f'{bid}.json').write_text(json.dumps({'unit_invocation': f'invocation-{n}',
                                                       'command': ['--headless=new', '--no-proxy-server']}))
    c.commit()
    return c


def result(call):
    with pytest.raises(SystemExit) as exc:
        call()
    return exc.value.code


def test_cleanup_four_live_units_zero_stops(monkeypatch, tmp_path, capsys):
    m = manager(monkeypatch, tmp_path)
    c = rows(m, tmp_path)
    monkeypatch.setattr(m, 'canonical_owner', lambda row, **_: True)
    monkeypatch.setattr(m, 'reservation_blocks', lambda row: False)
    monkeypatch.setattr(m, 'unit_identity', lambda unit: 'invocation-' + unit.rsplit('-', 1)[1])
    monkeypatch.setattr(m, 'unit_active', lambda unit: True)
    monkeypatch.setattr(m, 'healthy', lambda row: True)
    monkeypatch.setattr(m, 'owner_state', lambda owner: 'active')
    monkeypatch.setattr(m, 'activity_snapshot', lambda row: {'idle_seconds': 90000, 'inflight': 0, 'reserved_seconds': 0, 'attached_clients': 0})
    monkeypatch.setattr(m, 'admission', lambda *a: {'status': 'queued'})
    stops = []
    monkeypatch.setattr(m, 'retire', lambda *a: stops.append(a))
    assert result(lambda: m.cleanup(argparse.Namespace(apply=True))) == 0
    output = json.loads(capsys.readouterr().out)
    assert len(output['browsers']) == 4
    assert {entry['result'] for entry in output['browsers']} == {'owner-active-or-unverified'}
    assert output['stopped'] == [] and stops == []
    assert c.execute("SELECT count(*) FROM browsers WHERE state='running'").fetchone()[0] == 4


def test_cleanup_dry_run_and_terminal_apply(monkeypatch, tmp_path, capsys):
    m = manager(monkeypatch, tmp_path)
    rows(m, tmp_path, count=1)
    monkeypatch.setattr(m, 'canonical_owner', lambda row, **_: True)
    monkeypatch.setattr(m, 'reservation_blocks', lambda row: False)
    monkeypatch.setattr(m, 'unit_identity', lambda unit: 'invocation-0')
    monkeypatch.setattr(m, 'unit_active', lambda unit: True)
    monkeypatch.setattr(m, 'healthy', lambda row: True)
    monkeypatch.setattr(m, 'owner_state', lambda owner: 'terminal')
    monkeypatch.setattr(m, 'activity_snapshot', lambda row: {'idle_seconds': 7201, 'inflight': 0, 'reserved_seconds': 0, 'attached_clients': 0})
    monkeypatch.setattr(m, 'admission', lambda *a: {'status': 'queued'})
    stops = []
    monkeypatch.setattr(m, 'freeze_idle', lambda row, threshold, **kw: threshold == 7200 and kw['require_detached'])
    monkeypatch.setattr(m, 'retire', lambda c, row: stops.append(row['browser_id']) or True)
    assert result(lambda: m.cleanup(argparse.Namespace(apply=False))) == 0
    assert json.loads(capsys.readouterr().out)['browsers'][0]['result'] == 'eligible-terminal-idle'
    assert not stops
    assert result(lambda: m.cleanup(argparse.Namespace(apply=True))) == 0
    assert json.loads(capsys.readouterr().out)['stopped'] == ['browser-0']
    assert stops == ['browser-0']


def test_resume_exact_owner_healthy_and_stopped_blocker(monkeypatch, tmp_path, capsys):
    m = manager(monkeypatch, tmp_path)
    c = rows(m, tmp_path, count=1)
    args = argparse.Namespace(browser_id='browser-0', agent_id='agent', run_id='run')
    assert result(lambda: m.resume(argparse.Namespace(**{**vars(args), 'run_id': 'other'}))) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'not-owner'
    monkeypatch.setattr(m, 'canonical_owner', lambda row, **_: True)
    monkeypatch.setattr(m, 'reservation_blocks', lambda row: False)
    monkeypatch.setattr(m, 'lifecycle_state', lambda c, row: 'active')
    monkeypatch.setattr(m, 'healthy', lambda row: True)
    monkeypatch.setattr(m, 'activity_snapshot', lambda row: {'frozen': False, 'last_activity': 0})
    monkeypatch.setattr(m, 'matching_proxy', lambda c, args, row: True)
    monkeypatch.setattr(m, 'unit_active', lambda unit: True)
    monkeypatch.setattr(m, 'proxy_row', lambda c, args: None)
    assert result(lambda: m.resume(args)) == 0
    output = json.loads(capsys.readouterr().out)
    assert output['status'] == 'already-running' and output['browser_id'] == 'browser-0'
    assert output['reconnect_scope'] == 'browser-control-only'
    c.execute("UPDATE browsers SET state='stopped' WHERE browser_id='browser-0'")
    c.commit()
    monkeypatch.setattr(m, 'stopped', lambda row: True)
    assert result(lambda: m.resume(args)) == 2
    output = json.loads(capsys.readouterr().out)
    assert output['reason'] == 'safe-launch-recipe-unavailable'
    assert output['state_lost'] is False


def test_cleanup_refuses_hold_and_missing_canonical_owner(monkeypatch, tmp_path, capsys):
    m = manager(monkeypatch, tmp_path)
    rows(m, tmp_path, count=3)
    monkeypatch.setattr(m, 'canonical_owner', lambda row, **_: row['browser_id'] != 'browser-0')
    monkeypatch.setattr(m, 'reservation_blocks', lambda row: False)
    monkeypatch.setattr(m, 'unit_identity', lambda unit: 'invocation-' + unit.rsplit('-', 1)[1])
    monkeypatch.setattr(m, 'unit_active', lambda unit: True)
    monkeypatch.setattr(m, 'healthy', lambda row: True)
    monkeypatch.setattr(m, 'owner_state', lambda owner: 'terminal')
    monkeypatch.setattr(m, 'activity_snapshot', lambda row: {'idle_seconds': 8000, 'inflight': 0,
        'reserved_seconds': 120 if row['browser_id'] == 'browser-1' else 0,
        'attached_clients': 1 if row['browser_id'] == 'browser-2' else 0})
    monkeypatch.setattr(m, 'admission', lambda *a: {'status': 'queued'})
    monkeypatch.setattr(m, 'retire', lambda *a: pytest.fail('protected browser stopped'))
    assert result(lambda: m.cleanup(argparse.Namespace(apply=True))) == 0
    reasons = [entry['result'] for entry in json.loads(capsys.readouterr().out)['browsers']]
    assert reasons == ['canonical-owner-unverified', 'inflight-or-held', 'controller-attached-or-unverified']


def test_task_owned_lost_profile_refusal(monkeypatch, tmp_path, capsys):
    m = manager(monkeypatch, tmp_path)
    c = rows(m, tmp_path, count=1, state='stopped')
    c.execute("UPDATE browsers SET program='task-owned' WHERE browser_id='browser-0'")
    c.commit()
    monkeypatch.setattr(m, 'canonical_owner', lambda row, **_: True)
    monkeypatch.setattr(m, 'stopped', lambda row: True)
    assert result(lambda: m.resume(argparse.Namespace(browser_id='browser-0', agent_id='agent', run_id='run'))) == 2
    assert json.loads(capsys.readouterr().out)['state_lost'] is True


@pytest.mark.parametrize('command,kasm', [(['chromium'], None), (['chromium', '--headless=new'], {'display': ':20'})])
def test_headed_viewer_protected_in_both_cleanup_paths(monkeypatch, tmp_path, capsys, command, kasm):
    m = manager(monkeypatch, tmp_path)
    c = rows(m, tmp_path, count=1)
    info = {'command': command, 'unit_invocation': 'invocation-0'}
    if kasm is not None:
        info['kasmvnc'] = kasm
    (tmp_path / 'browser-0.json').write_text(json.dumps(info))
    monkeypatch.setattr(m, 'canonical_owner', lambda row, **_: True)
    monkeypatch.setattr(m, 'owner_state', lambda _: 'terminal')
    monkeypatch.setattr(m, 'unit_identity', lambda _: 'invocation-0')
    monkeypatch.setattr(m, 'unit_active', lambda _: True)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    monkeypatch.setattr(m, 'activity_snapshot', lambda _: dict(idle_seconds=9000, inflight=0,
        reserved_seconds=0, attached_clients=0))
    monkeypatch.setattr(m, 'admission', lambda *args: {'status': 'queued'})
    monkeypatch.setattr(m, 'freeze_idle', lambda *args, **kwargs: pytest.fail('viewer must not freeze'))
    monkeypatch.setattr(m, 'retire', lambda *args: pytest.fail('viewer must not stop'))
    assert m.cleanup_unused(c) == []
    assert result(lambda: m.cleanup(argparse.Namespace(apply=True))) == 0
    assert json.loads(capsys.readouterr().out)['browsers'][0]['result'] == 'headed-or-display-unverified'
    assert c.execute("SELECT state FROM browsers WHERE browser_id='browser-0'").fetchone()[0] == 'running'


def test_adapter_reports_attached_socket_even_without_session(monkeypatch, tmp_path):
    manager(monkeypatch, tmp_path)
    spec = importlib.util.spec_from_file_location('browser_control_fixture', SCRIPT.with_name('browser_control.py'))
    assert spec is not None and spec.loader is not None
    browser_control = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(browser_control)
    adapter = SimpleNamespace(last_activity=0, last_use=time.monotonic() - 8000,
        inflight=0, reserved_until=0, frozen=False, clients={object(): set()})
    assert browser_control.PipeBrowser.activity_status(adapter)['attached_clients'] == 1


def prepared_resume(monkeypatch, tmp_path, *, task_owned=True, missing=False, mock_owner=True):
    m = manager(monkeypatch, tmp_path)
    c = rows(m, tmp_path, count=1, state='stopped')
    profile = tmp_path / 'profile-0'
    if not missing:
        profile.mkdir()
    program = 'task-owned' if task_owned else 'demo'
    account = 'task-identity' if task_owned else 'blue'
    domain = 'task' if task_owned else 'example.test'
    c.execute("UPDATE browsers SET program=?,account=?,auth_domain=? WHERE browser_id='browser-0'",
              (program, account, domain))
    c.commit()
    row = c.execute("SELECT * FROM browsers WHERE browser_id='browser-0'").fetchone()
    recipe = dict(version=1, program=program, account=account, auth_domain=domain,
                  profile_dir=str(profile), physical_profile=[1, 2],
                  instance_key='' if task_owned else 'slot-1',
                  instance_selection='legacy' if task_owned else 'explicit', single_policy=False,
                  purpose='fixture', ttl_seconds=1800, idle_seconds=300,
                  min_ram_available_mib=100, min_swap_free_mib=0,
                  memory_high='1G', memory_max='2G', proxy='none',
                  proxy_ownership='task', proxy_cert_mode='none', proxy_server=None,
                  mitm_ca_cert=None, ca_sha256=None, display_backend='default',
                  headless=True, kasmvnc_display=None, kasmvnc_web_port=None,
                  graphics_backend='auto', driving_mode='agent-driven',
                  owner_pid=None, legacy_profile=False)
    import sys
    sys.path.insert(0, str(SCRIPT.parent))
    import browser_profile_lease as profiles
    if not missing:
        recipe['physical_profile'] = list(profiles.physical_profile(profile))
    (tmp_path / 'browser-0.json').write_text(json.dumps(dict(
        launch_recipe=recipe, stop_proof={'cdp_url': 'http://127.0.0.1:9/capability'},
        instance_key=recipe['instance_key'], instance_selection=recipe['instance_selection'],
        process_identity={'pid': 9})))
    if mock_owner:
        monkeypatch.setattr(m, 'canonical_owner', lambda row, **_: True)
    monkeypatch.setattr(m, 'stopped', lambda row: True)
    monkeypatch.setattr(m, 'proxy_row', lambda *a: None)
    return m, c, row, recipe


@pytest.mark.parametrize('missing,removed_after_preflight', [(False, False), (True, False), (False, True)])
def test_resume_dispatches_exact_stopped_task_owned_profile(monkeypatch, tmp_path, capsys, missing, removed_after_preflight):
    m, c, row, recipe = prepared_resume(monkeypatch, tmp_path, missing=missing)
    calls = []
    def child(cmd, **kwargs):
        calls.append(cmd)
        # Child start observes the filesystem only after resume releases its lock.
        if removed_after_preflight:
            Path(row['profile_dir']).rmdir()
        child_state_lost = missing or removed_after_preflight
        if child_state_lost:
            Path(row['profile_dir']).mkdir()
        import browser_profile_lease as profiles
        c.execute('INSERT INTO browsers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  ('new-lease', 'new-id', 'task-owned', 'task-identity', 'task', 'agent', 'run',
                   'fixture', 'new-unit', row['profile_dir'], str(tmp_path / 'new.json'),
                   'running', 0, 0, 1, 1))
        (tmp_path / 'new.json').write_text(json.dumps({'replaces_browser_id': 'browser-0',
                                                       'resumed_state_lost': child_state_lost,
                                                       'instance_key': '',
                                                       'launch_recipe': {'physical_profile': list(
                                                           profiles.physical_profile(row['profile_dir']))}}))
        c.commit()
        return SimpleNamespace(returncode=0, stdout=json.dumps(dict(
            status='started', browser_id='new-id', lease_id='new-lease',
            replaces_browser_id='browser-0')))
    monkeypatch.setattr(m.subprocess, 'run', child)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    assert result(lambda: m.resume(argparse.Namespace(browser_id='browser-0', agent_id='agent', run_id='run'))) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['state_lost'] is (missing or removed_after_preflight)
    assert out['authentication'] == 'browser-native-check-required'
    assert len(calls) == 1 and '--expected-replaces-browser-id' in calls[0]
    assert calls[0][calls[0].index('--url') + 1] == 'about:blank'
    assert '--task-owned' in calls[0] and '--proxy' in calls[0]
    assert c.execute("SELECT state FROM browsers WHERE browser_id='browser-0'").fetchone()[0] == 'stopped'


@pytest.mark.parametrize('mutation,reason', [
    ('missing-proof', 'stop-proof-unavailable'),
    ('changed-profile', 'profile-identity-changed'),
    ('ambiguous-legacy', 'launch-recipe-conflict'),
    ('foreign-owner', 'not-owner'),
])
def test_resume_rejects_unproved_changes_without_dispatch(monkeypatch, tmp_path, capsys, mutation, reason):
    m, c, row, recipe = prepared_resume(monkeypatch, tmp_path)
    if mutation == 'missing-proof':
        data = json.loads(Path(row['launch_file']).read_text()); data.pop('stop_proof')
        Path(row['launch_file']).write_text(json.dumps(data))
    elif mutation == 'changed-profile':
        profile = Path(row['profile_dir']); profile.rename(tmp_path / 'moved-profile'); profile.mkdir()
    elif mutation == 'ambiguous-legacy':
        data = json.loads(Path(row['launch_file']).read_text())
        data['launch_recipe']['legacy_profile'] = True
        Path(row['launch_file']).write_text(json.dumps(data))
    else:
        c.execute("UPDATE browsers SET agent_id='other' WHERE browser_id='browser-0'"); c.commit()
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: pytest.fail('must not dispatch'))
    assert result(lambda: m.resume(argparse.Namespace(browser_id='browser-0', agent_id='agent', run_id='run'))) == 2
    assert json.loads(capsys.readouterr().out).get('reason', reason) == reason


@pytest.mark.parametrize('mutation,reason', [
    ('none', None),
    ('physical', 'profile-identity-changed'),
    ('profile', 'stop-or-ownership-unverified'),
    ('owner', 'stop-or-ownership-unverified'),
    ('manager', 'stop-or-ownership-unverified'),
])
def test_released_canonical_owner_stopped_resume_preflight(monkeypatch, tmp_path, capsys, mutation, reason):
    m, c, row, recipe = prepared_resume(monkeypatch, tmp_path, mock_owner=False)
    import browser_profile_lease as profiles
    db_path = tmp_path / 'browser_profile_leases.sqlite'
    with profiles.connect(db_path) as leases:
        profiles.init_db(leases)
        leases.execute('''INSERT INTO browser_profile_leases
            (lease_id, program, account_alias, auth_domain, owner_agent_id,
             owner_run_id, purpose, profile_dir, status, service_unit,
             created_at, heartbeat_at, expires_at, manager_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (row['lease_id'], row['program'], row['account'], row['auth_domain'],
             row['agent_id'], row['run_id'], row['purpose'], row['profile_dir'],
             'active', row['unit'], 1, 1, 9999999999, m.manager_id()))
    assert m.canonical_owner(row)
    with profiles.connect(db_path) as leases:
        leases.execute('UPDATE browser_profile_leases SET service_unit=? WHERE lease_id=?',
                       ('different-unit', row['lease_id']))
    assert not m.canonical_owner(row)  # Active unit matching is unchanged.
    with profiles.connect(db_path) as leases:
        leases.execute('UPDATE browser_profile_leases SET service_unit=? WHERE lease_id=?',
                       (row['unit'], row['lease_id']))
    released = profiles.cmd_release(argparse.Namespace(state_dir=str(tmp_path),
        lease_id=row['lease_id'], agent_id=row['agent_id'], manager_id=m.manager_id(),
        disposition='completed', profile_health='healthy'))
    assert released['status'] == 'released'
    with profiles.connect(db_path) as leases:
        historical = leases.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?',
                                    (row['lease_id'],)).fetchone()
        assert historical['service_unit'] is None and historical['status'] == 'released'
    assert m.canonical_owner(row, active=False)
    assert not m.canonical_owner(row)  # Released is never an active owner.
    if mutation == 'physical':
        Path(row['profile_dir']).rename(tmp_path / 'moved-profile')
        Path(row['profile_dir']).mkdir()
    elif mutation == 'profile':
        c.execute('UPDATE browsers SET profile_dir=? WHERE browser_id=?',
                  (str(tmp_path / 'other-profile'), row['browser_id']))
        c.commit()
    elif mutation in ('owner', 'manager'):
        with profiles.connect(db_path) as leases:
            leases.execute(f'UPDATE browser_profile_leases SET {"owner_run_id" if mutation == "owner" else "manager_id"}=? WHERE lease_id=?',
                           ('different', row['lease_id']))
    calls = []
    def child(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=2, stdout=json.dumps({'status': 'queued'}))
    monkeypatch.setattr(m.subprocess, 'run', child)
    assert result(lambda: m.resume(argparse.Namespace(browser_id=row['browser_id'],
                                      agent_id=row['agent_id'], run_id=row['run_id']))) == 2
    output = json.loads(capsys.readouterr().out)
    if reason:
        assert output['reason'] == reason and calls == []
    else:
        assert output['status'] == 'queued' and len(calls) == 1
        assert '--expected-replaces-browser-id' in calls[0]
        assert calls[0][calls[0].index('--url') + 1] == 'about:blank'


@pytest.mark.parametrize('stored_state_lost', [True, False, None])
def test_resume_repeat_returns_verified_successor_without_dispatch(monkeypatch, tmp_path, capsys, stored_state_lost):
    m, c, row, recipe = prepared_resume(monkeypatch, tmp_path)
    Path(row['profile_dir']).rename(tmp_path / 'old-profile')
    Path(row['profile_dir']).mkdir()
    import browser_profile_lease as profiles
    replacement_physical = list(profiles.physical_profile(row['profile_dir']))
    c.execute('INSERT INTO browsers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
              ('new-lease', 'new-id', 'task-owned', 'task-identity', 'task', 'agent', 'run',
               'fixture', 'new-unit', row['profile_dir'], str(tmp_path / 'new.json'),
               'running', 0, 0, 1, 1))
    (tmp_path / 'new.json').write_text(json.dumps({'replaces_browser_id': 'browser-0',
                                                   'instance_key': '', 'resumed_state_lost': stored_state_lost,
                                                   'launch_recipe': {'physical_profile': replacement_physical}}))
    c.commit()
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    monkeypatch.setattr(m, 'reservation_blocks', lambda _: False)
    monkeypatch.setattr(m, 'matching_proxy', lambda *a: True)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: pytest.fail('duplicate dispatch'))
    assert result(lambda: m.resume(argparse.Namespace(browser_id='browser-0', agent_id='agent', run_id='run'))) == (2 if stored_state_lost is None else 0)
    out = json.loads(capsys.readouterr().out)
    if stored_state_lost is None:
        assert out['status'] == 'recovery-blocked' and out['reason'] == 'replacement-unverified'
        return
    assert out['status'] == 'already-running' and out['browser_id'] == 'new-id'
    assert out['replaces_browser_id'] == 'browser-0'
    assert out['state_lost'] is stored_state_lost

def test_resume_external_ca_missing_refuses(monkeypatch, tmp_path, capsys):
    m, c, row, recipe = prepared_resume(monkeypatch, tmp_path)
    data = json.loads(Path(row['launch_file']).read_text())
    data['launch_recipe'].update(proxy='external', proxy_cert_mode='import',
                                 proxy_server='http://127.0.0.1:8123',
                                 mitm_ca_cert=str(tmp_path / 'missing-ca.pem'), ca_sha256='abc')
    Path(row['launch_file']).write_text(json.dumps(data))
    monkeypatch.setattr(m, 'endpoint_open', lambda _: True)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: pytest.fail('must not dispatch'))
    assert result(lambda: m.resume(argparse.Namespace(browser_id='browser-0', agent_id='agent', run_id='run'))) == 2
    assert json.loads(capsys.readouterr().out)['reason'] == 'proxy-or-ca-unverified'


def test_start_rechecks_expected_old_identity_before_lease(monkeypatch, tmp_path, capsys):
    m, c, row, recipe = prepared_resume(monkeypatch, tmp_path, task_owned=False)
    import browser_profile_lease as profiles
    monkeypatch.setattr(profiles, 'resolve_account', lambda *a: ({'alias': 'blue'}, {}))
    monkeypatch.setattr(profiles, 'auth_domain_for', lambda *a: 'example.test')
    monkeypatch.setattr(profiles, 'account_lease_eligible', lambda *a: True)
    monkeypatch.setattr(m, 'account_policy', lambda *a: False)
    monkeypatch.setattr(m, 'sweep_rows', lambda *a: ([], []))
    monkeypatch.setattr(m, 'cleanup_unused', lambda *a: [])
    monkeypatch.setattr(m, 'admission', lambda *a: {'status': 'admitted'})
    monkeypatch.setattr(m, 'lease', lambda *a, **kw: pytest.fail('must not acquire'))
    args = argparse.Namespace(program='demo', account='blue', auth_domain='example.test',
        agent_id='agent', run_id='run', purpose='fixture', task_owned=False,
        owner_pid=None, driving_mode='agent-driven', legacy_profile=False,
        instance_key='slot-1', expected_replaces_browser_id='browser-0',
        min_ram_available_mib=100, min_swap_free_mib=0, proxy='none',
        proxy_server=None, mitm_ca_cert=None, proxy_cert_mode='none',
        proxy_ownership='task')
    c.execute("UPDATE browsers SET agent_id='foreign' WHERE browser_id='browser-0'")
    c.commit()
    assert result(lambda: m.start(args)) == 2
    assert json.loads(capsys.readouterr().out)['reason'] == 'expected-old-identity-changed'


def test_release_receipt_retains_private_recipe_and_cdp_stop_proof(monkeypatch, tmp_path):
    m, c, row, recipe = prepared_resume(monkeypatch, tmp_path)
    data = json.loads(Path(row['launch_file']).read_text())
    data.update(cdp_url='http://127.0.0.1:9/capability', replaces_browser_id='older-id',
                command=['--url', 'https://private.example/'], proxy_secret='do-not-retain')
    Path(row['launch_file']).write_text(json.dumps(data))
    m.stop_receipt(row)
    after = json.loads(Path(row['launch_file']).read_text())
    assert after['launch_recipe'] == recipe
    assert after['stop_proof']['cdp_url'] == data['cdp_url']
    assert after['replaces_browser_id'] == 'older-id'
    assert 'cdp_url' not in after and 'command' not in after and 'proxy_secret' not in after


def test_automatic_slot_replay_preserves_manager_selection_proof(monkeypatch, tmp_path, capsys):
    m, c, row, recipe = prepared_resume(monkeypatch, tmp_path, task_owned=False)
    import browser_profile_lease as profiles
    data = json.loads(Path(row['launch_file']).read_text())
    data['instance_key'] = data['launch_recipe']['instance_key'] = 'auto-1'
    data['instance_selection'] = data['launch_recipe']['instance_selection'] = 'automatic'
    account = {'alias': 'blue'}
    data['launch_recipe']['account_auth_policy'] = m.account_auth_policy(account)
    Path(row['launch_file']).write_text(json.dumps(data))
    monkeypatch.setattr(profiles, 'resolve_account', lambda *a: (account, {}))
    monkeypatch.setattr(profiles, 'auth_domain_for', lambda *a: 'example.test')
    monkeypatch.setattr(profiles, 'account_lease_eligible', lambda *a: True)
    monkeypatch.setattr(profiles, 'authorize_auto_slot', lambda *a: 'proof')
    monkeypatch.setattr(m, 'account_policy', lambda *a: False)
    monkeypatch.setattr(m, 'sweep_rows', lambda *a: ([], []))
    monkeypatch.setattr(m, 'cleanup_unused', lambda *a: [])
    monkeypatch.setattr(m, 'admission', lambda *a: {'status': 'admitted'})
    observed = []
    def lease(args, action, *rest):
        observed.extend(rest)
        assert args._selection_proof == 'proof'
        return {'status': 'locked'}
    monkeypatch.setattr(m, 'lease', lease)
    args = argparse.Namespace(program='demo', account='blue', auth_domain='example.test',
        agent_id='agent', run_id='run', purpose='fixture', task_owned=False,
        owner_pid=None, driving_mode='agent-driven', legacy_profile=False,
        instance_key='auto-1', resume_automatic_instance=True,
        expected_replaces_browser_id='browser-0', min_ram_available_mib=100,
        min_swap_free_mib=0, proxy='none', proxy_server=None, mitm_ca_cert=None,
        proxy_cert_mode='none', proxy_ownership='task', url='about:blank',
        ttl_seconds=1800, idle_seconds=300, memory_high='1G', memory_max='2G',
        display_backend='default', kasmvnc_display=None, kasmvnc_web_port=None,
        headless=True, graphics_backend='auto')
    assert result(lambda: m.start(args)) == 2
    assert '--automatic-instance' in observed and '--selection-proof-stdin' in observed
    assert json.loads(capsys.readouterr().out)['status'] == 'queued'
