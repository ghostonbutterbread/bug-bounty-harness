import argparse
import json
import sqlite3

import pytest

from agents.test_browser_provisioner import load, proxy_fixture, start_args


def setup(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    import browser_profile_lease as profiles
    import kasmvnc_session
    monkeypatch.setattr(profiles, 'local_filesystem', lambda _: True)
    monkeypatch.setattr(kasmvnc_session, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(m, 'sweep_rows', lambda *a: ([], []))
    monkeypatch.setattr(m, 'admission', lambda *_: {'status': 'admitted'})
    args = start_args()
    args.account = 'anon'
    req = argparse.Namespace(program='demo', account='anon', auth_domain=None,
        agent_id='agent', run_id='run', purpose='test', ttl_seconds=60,
        state_dir=str(m.STATE.parent), recover_profile=False, manager_id=m.manager_id())
    statuses = []
    def acquire(*_):
        result = profiles.cmd_acquire(req)
        statuses.append(result['status'])
        return result
    monkeypatch.setattr(m, 'lease', acquire)
    return m, args, statuses, profiles


@pytest.mark.parametrize('existing', [False, True])
def test_mode_conflict_preserves_already_owned_lease(monkeypatch, tmp_path, capsys, existing):
    m, args, statuses, profiles = setup(monkeypatch, tmp_path)
    previous = m.lease(None, 'acquire') if existing else None
    proxy_fixture(m, args, tmp_path)
    with pytest.raises(SystemExit) as exc:
        m.start(args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'proxy-conflict'
    assert statuses == (['leased', 'already-owned'] if existing else ['leased'])
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as conn:
        row = conn.execute('select status,profile_health from browser_profile_leases').fetchone()
        assert tuple(row) == (('active', 'unknown') if existing else ('released', 'healthy'))


@pytest.mark.parametrize('same_lease', [True, False])
def test_shifted_legacy_starting_row_is_preserved(monkeypatch, tmp_path, capsys, same_lease):
    m, args, _, _ = setup(monkeypatch, tmp_path)
    lease = m.lease(None, 'acquire')['lease']
    c = m.db()
    lid = lease['lease_id'] if same_lease else 'older-lease'
    c.execute('''INSERT INTO browsers (lease_id,browser_id,program,account,auth_domain,
        agent_id,run_id,purpose,unit,profile_dir,launch_file,state,tab_count,last_activity,created,updated)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (lid, 'old-id', 'demo', 'anon', lease['auth_domain'], 'agent', 'run', 'test',
         'old-purpose', 'browser-old-id', lease['profile_dir'], str(tmp_path / 'old.launch.json'),
         'starting', 0, 0, 0))
    c.commit()
    before = dict(c.execute('select * from browsers').fetchone())
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: pytest.fail('must not dispatch'))
    with pytest.raises(SystemExit) as exc:
        m.start(args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['reason'] == 'start-not-reconciled'
    assert dict(c.execute('select * from browsers').fetchone()) == before


@pytest.mark.parametrize('outcome', ['false', 'exception'])
def test_mode_conflict_release_failure_preserves_primary(monkeypatch, tmp_path, capsys, outcome):
    m, args, _, profiles = setup(monkeypatch, tmp_path)
    proxy_fixture(m, args, tmp_path)
    real_release = m.release_lease
    def fail(*a):
        if outcome == 'exception':
            with monkeypatch.context() as patch:
                def failed_connect(*_):
                    raise sqlite3.OperationalError('secret sqlite details')
                patch.setattr(profiles, 'connect', failed_connect)
                return real_release(*a)
        return False
    monkeypatch.setattr(m, 'release_lease', fail)
    with pytest.raises(SystemExit) as exc:
        m.start(args)
    out = capsys.readouterr()
    assert exc.value.code == 2
    assert json.loads(out.out)['status'] == 'proxy-conflict'
    assert json.loads(out.err) == m.LEASE_RELEASE_UNVERIFIED
    assert 'secret' not in out.out + out.err
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as conn:
        row = conn.execute('select status,profile_health from browser_profile_leases').fetchone()
        assert tuple(row) == ('active', 'unknown')


@pytest.mark.parametrize(('state', 'tab_count', 'shifted', 'expected'), [
    ('starting', 0, False, True),
    ('running', 0, False, False),
    ('stopped', 0, False, False),
    ('launch.launch.json', 'starting', True, True),
    ('launch.launch.json', 'running', True, False),
    ('launch.launch.json', 'stopped', True, False),
    ('launch.launch.json', 'idle-stopped', True, False),
    ('launch.launch.json', 'starting', False, False),
])
def test_starting_shape_does_not_classify_other_rows(monkeypatch, tmp_path, state, tab_count, shifted, expected):
    m, _, _, _ = setup(monkeypatch, tmp_path)
    row = {'browser_id': 'bid', 'profile_dir': 'browser-bid' if shifted else 'profile',
           'state': state, 'tab_count': tab_count}
    assert m.unresolved_browser_start(row) is expected


def test_mode_conflict_mismatched_canonical_owner_is_not_released(monkeypatch, tmp_path, capsys):
    m, args, _, profiles = setup(monkeypatch, tmp_path)
    proxy_fixture(m, args, tmp_path)
    real_release = m.release_lease
    def mismatch(*a):
        with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as conn:
            conn.execute("update browser_profile_leases set owner_run_id='other-run'")
            conn.commit()
        return real_release(*a)
    monkeypatch.setattr(m, 'release_lease', mismatch)
    with pytest.raises(SystemExit):
        m.start(args)
    out = capsys.readouterr()
    assert json.loads(out.out)['status'] == 'proxy-conflict'
    assert json.loads(out.err) == m.LEASE_RELEASE_UNVERIFIED
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as conn:
        assert tuple(conn.execute('select status,profile_health,owner_run_id from browser_profile_leases').fetchone()) == ('active', 'unknown', 'other-run')


def test_request_real_start_child_reports_release_exception(monkeypatch, tmp_path, capsys):
    m, args, _, profiles = setup(monkeypatch, tmp_path)
    args.wait_seconds = 60
    proxy_fixture(m, args, tmp_path)
    monkeypatch.setattr(m, 'maintain', lambda _: None)
    real_run = m.subprocess.run
    child = r'''
import argparse, importlib.util, sqlite3, sys
script = sys.argv[1]
sys.argv = [script] + sys.argv[2:]
spec = importlib.util.spec_from_file_location('fixture_provisioner', script)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
import browser_profile_lease as profiles
import kasmvnc_session
profiles.local_filesystem = lambda _: True
kasmvnc_session.can_bind_localhost = lambda _: True
m.sweep_rows = lambda *a: ([], [])
m.admission = lambda *a: {'status': 'admitted'}
def acquire(args, action, *rest):
    return profiles.cmd_acquire(argparse.Namespace(program=args.program, account=args.account,
        auth_domain=None, agent_id=args.agent_id, run_id=args.run_id, purpose=args.purpose,
        ttl_seconds=args.ttl_seconds, state_dir=str(m.STATE.parent), recover_profile=False,
        manager_id=m.manager_id()))
m.lease = acquire
real_release = m.release_lease
def failed_release(*a):
    def failed_connect(*args):
        raise sqlite3.OperationalError('secret sqlite details')
    profiles.connect = failed_connect
    return real_release(*a)
m.release_lease = failed_release
m.main()
'''
    def run_start(cmd, **kwargs):
        return real_run([cmd[0], '-c', child, cmd[1], *cmd[2:]], **kwargs)
    monkeypatch.setattr(m.subprocess, 'run', run_start)
    with pytest.raises(SystemExit) as exc:
        m.request(args)
    out = capsys.readouterr()
    result = json.loads(out.out)
    assert exc.value.code == 2 and result['status'] == 'proxy-conflict'
    assert result['cleanup']['reason'] == 'lease-release-not-verified'
    assert result['attempts'] == 1 and 'secret' not in out.out + out.err and not out.err
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as conn:
        assert tuple(conn.execute('select status,profile_health from browser_profile_leases').fetchone()) == ('active', 'unknown')


def test_interrupted_start_cannot_dispatch_again(monkeypatch, tmp_path, capsys):
    m, args, statuses, _ = setup(monkeypatch, tmp_path)
    dispatches = []
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    def interrupt(cmd, **kwargs):
        dispatches.append(cmd)
        raise KeyboardInterrupt()
    monkeypatch.setattr(m.subprocess, 'run', interrupt)
    with pytest.raises(KeyboardInterrupt):
        m.start(args)
    first = dict(m.db().execute('select * from browsers').fetchone())
    with pytest.raises(SystemExit) as exc:
        m.start(args)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['reason'] == 'start-not-reconciled'
    assert dict(m.db().execute('select * from browsers').fetchone()) == first
    assert statuses == ['leased', 'already-owned']
    assert len(dispatches) == 1


@pytest.mark.parametrize('existing', [False, True])
@pytest.mark.parametrize('rollback', ['false', 'raise'])
def test_unit_conflict_reports_proxy_cleanup(monkeypatch, tmp_path, capsys, rollback, existing):
    m, args, statuses, profiles = setup(monkeypatch, tmp_path)
    if existing:
        m.lease(None, 'acquire')
    args.proxy, args.proxy_cert_mode = 'mitm', 'import'
    def proxy(c, args):
        c.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state) values(?,?,?,?,?,?,?,?,?,?)", ('agent', 'run', 'demo', 'anon', 'test', 'lane', 8081, 'proxy-unit', str(tmp_path/'fixture'), 'running'))
        c.commit()
        return m.proxy_row(c, args), True
    monkeypatch.setattr(m, 'start_proxy', proxy)
    monkeypatch.setattr(m, 'unit_active', lambda _: True)
    def fail(*_):
        if rollback == 'raise':
            raise RuntimeError('secret-should-not-leak')
        return False
    monkeypatch.setattr(m, 'rollback_proxy', fail)
    with pytest.raises(SystemExit) as exc:
        m.start(args)
    out = capsys.readouterr()
    assert exc.value.code == 2
    assert json.loads(out.out)['status'] == 'browser-unit-conflict'
    assert json.loads(out.err)['reason'] == 'proxy-cleanup-not-verified'
    assert 'secret-should-not-leak' not in out.err
    assert m.proxy_row(m.db(), args)['state'] == 'cleanup-failed'
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as conn:
        row = conn.execute('select status,profile_health from browser_profile_leases').fetchone()
        assert tuple(row) == (('active', 'unknown') if existing else ('released', 'healthy'))


@pytest.mark.parametrize('release', ['false', 'exception'])
@pytest.mark.parametrize('rollback', ['false', 'exception'])
def test_unit_conflict_reports_both_cleanup_failures(monkeypatch, tmp_path, capsys, release, rollback):
    m, args, _, profiles = setup(monkeypatch, tmp_path)
    args.proxy, args.proxy_cert_mode = 'mitm', 'import'
    def proxy(c, args):
        c.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state) values(?,?,?,?,?,?,?,?,?,?)", ('agent', 'run', 'demo', 'anon', 'test', 'lane', 8081, 'proxy-unit', str(tmp_path/'fixture'), 'running'))
        c.commit()
        return m.proxy_row(c, args), True
    monkeypatch.setattr(m, 'start_proxy', proxy)
    monkeypatch.setattr(m, 'unit_active', lambda _: True)
    def failed_rollback(*_):
        if rollback == 'exception':
            raise RuntimeError('secret-proxy-error')
        return False
    def failed_release(*_):
        if release == 'exception':
            raise sqlite3.OperationalError('secret-lease-error')
        return False
    monkeypatch.setattr(m, 'rollback_proxy', failed_rollback)
    monkeypatch.setattr(m, 'release_lease', failed_release)
    with pytest.raises(SystemExit) as exc:
        m.start(args)
    out = capsys.readouterr()
    assert exc.value.code == 2
    assert json.loads(out.out) == {'status': 'browser-unit-conflict'}
    assert [json.loads(line) for line in out.err.splitlines() if line] == [
        m.PROXY_CLEANUP_UNVERIFIED, m.LEASE_RELEASE_UNVERIFIED]
    assert 'secret-' not in out.out + out.err
    assert m.proxy_row(m.db(), args)['state'] == 'cleanup-failed'
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as conn:
        assert tuple(conn.execute('select status,profile_health from browser_profile_leases').fetchone()) == ('active', 'unknown')


@pytest.mark.parametrize('release', ['false', 'exception'])
def test_request_real_child_reports_both_cleanup_failures(monkeypatch, tmp_path, capsys, release):
    m, args, _, profiles = setup(monkeypatch, tmp_path)
    args.proxy, args.proxy_cert_mode, args.wait_seconds = 'mitm', 'import', 60
    monkeypatch.setattr(m, 'maintain', lambda _: None)
    monkeypatch.setattr(m.time, 'sleep', lambda _: pytest.fail('must not retry'))
    real_run = m.subprocess.run
    child = r'''
import argparse, importlib.util, sqlite3, sys
release = sys.argv[1]
script = sys.argv[2]; sys.argv = [script] + sys.argv[3:]
spec = importlib.util.spec_from_file_location('fixture_provisioner', script)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
import browser_profile_lease as profiles, kasmvnc_session
profiles.local_filesystem = lambda _: True
kasmvnc_session.can_bind_localhost = lambda _: True
m.sweep_rows = lambda *a: ([], [])
m.admission = lambda *a: {'status': 'admitted'}
def acquire(args, action, *rest):
    return profiles.cmd_acquire(argparse.Namespace(program=args.program, account=args.account,
        auth_domain=None, agent_id=args.agent_id, run_id=args.run_id, purpose=args.purpose,
        ttl_seconds=args.ttl_seconds, state_dir=str(m.STATE.parent), recover_profile=False,
        manager_id=m.manager_id()))
m.lease = acquire
def proxy(c, a):
    c.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state) values(?,?,?,?,?,?,?,?,?,?)", ('agent','run','demo','anon','test','lane',8081,'proxy-unit',str(m.STATE.parent/'fixture'),'running'))
    c.commit(); return m.proxy_row(c,a), True
m.start_proxy = proxy
m.unit_active = lambda _: True
m.rollback_proxy = lambda *_: False
def failed_release(*_):
    if release == 'exception': raise sqlite3.OperationalError('secret-lease-error')
    return False
m.release_lease = failed_release
m.main()
'''
    child_results = []
    def run_start(cmd, **kwargs):
        result = real_run([cmd[0], '-c', child, release, cmd[1], *cmd[2:]], **kwargs)
        child_results.append(result)
        return result
    monkeypatch.setattr(m.subprocess, 'run', run_start)
    with pytest.raises(SystemExit) as exc:
        m.request(args)
    out = capsys.readouterr()
    result = json.loads(out.out)
    assert exc.value.code == 2 and result['status'] == 'browser-unit-conflict'
    assert result['cleanup']['reason'] == 'lease-release-not-verified'
    assert result['proxy_cleanup']['reason'] == 'proxy-cleanup-not-verified'
    assert result['attempts'] == 1 and not out.err
    assert len(child_results) == 1 and child_results[0].returncode == 2
    assert json.loads(child_results[0].stdout) == {'status': 'browser-unit-conflict'}
    assert [json.loads(line) for line in child_results[0].stderr.splitlines() if line] == [
        m.PROXY_CLEANUP_UNVERIFIED, m.LEASE_RELEASE_UNVERIFIED]
    assert 'secret-' not in out.out + out.err + child_results[0].stdout + child_results[0].stderr
    assert m.proxy_row(m.db(), args)['state'] == 'cleanup-failed'
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as conn:
        assert tuple(conn.execute('select status,profile_health from browser_profile_leases').fetchone()) == ('active', 'unknown')


def test_request_propagates_proxy_cleanup_without_retry(monkeypatch, tmp_path, capsys):
    m, args, _, _ = setup(monkeypatch, tmp_path)
    args.wait_seconds = 60
    monkeypatch.setattr(m, 'maintain', lambda _: None)
    monkeypatch.setattr(m.time, 'sleep', lambda _: pytest.fail('must not retry'))
    signal = {'status': 'cleanup-incomplete', 'reason': 'proxy-cleanup-not-verified'}
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: argparse.Namespace(
        returncode=2, stdout='{"status":"queued"}', stderr='secret\n' + json.dumps(signal) + '\n'))
    with pytest.raises(SystemExit):
        m.request(args)
    out = capsys.readouterr()
    assert json.loads(out.out)['cleanup']['reason'] == 'proxy-cleanup-not-verified'
    assert 'secret' not in out.out and not out.err


@pytest.mark.parametrize('rollback', ['false', 'raise'])
def test_proxy_start_failure_preserves_cause_and_reports_cleanup(monkeypatch, tmp_path, capsys, rollback):
    m, args, _, _ = setup(monkeypatch, tmp_path)
    monkeypatch.setattr(m, 'port_open', lambda _: False)
    monkeypatch.setattr(m, '_capture_local_private_path', lambda _: False)
    def fail(*_):
        if rollback == 'raise':
            raise RuntimeError('secret-should-not-leak')
        return False
    monkeypatch.setattr(m, 'rollback_proxy', fail)
    with pytest.raises(m.ProxyStartupError, match='private task state'):
        m.start_proxy(m.db(), args)
    err = capsys.readouterr().err
    assert json.loads(err) == m.PROXY_CLEANUP_UNVERIFIED
    assert 'secret-should-not-leak' not in err
    assert m.proxy_row(m.db(), args)['state'] == 'cleanup-failed'


def test_request_real_start_child_reports_proxy_cleanup(monkeypatch, tmp_path, capsys):
    m, args, _, _ = setup(monkeypatch, tmp_path)
    args.proxy, args.proxy_cert_mode, args.wait_seconds = 'mitm', 'import', 0
    monkeypatch.setattr(m, 'maintain', lambda _: None)
    real_run = m.subprocess.run
    child = r'''
import argparse, importlib.util, sys
script = sys.argv[1]
sys.argv = [script] + sys.argv[2:]
spec = importlib.util.spec_from_file_location('fixture_provisioner', script)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
import browser_profile_lease as profiles
import kasmvnc_session
profiles.local_filesystem = lambda _: True
kasmvnc_session.can_bind_localhost = lambda _: True
m.sweep_rows = lambda *a: ([], [])
m.admission = lambda *a: {'status': 'admitted'}
m.port_open = lambda _: False
m._capture_local_private_path = lambda _: False
m.rollback_proxy = lambda *a: False
def acquire(args, action, *rest):
    return profiles.cmd_acquire(argparse.Namespace(program=args.program, account=args.account,
        auth_domain=None, agent_id=args.agent_id, run_id=args.run_id, purpose=args.purpose,
        ttl_seconds=args.ttl_seconds, state_dir=str(m.STATE.parent), recover_profile=False,
        manager_id=m.manager_id()))
m.lease = acquire
m.main()
'''
    def run_start(cmd, **kwargs):
        return real_run([cmd[0], '-c', child, cmd[1], *cmd[2:]], **kwargs)
    monkeypatch.setattr(m.subprocess, 'run', run_start)
    with pytest.raises(SystemExit) as exc:
        m.request(args)
    out = capsys.readouterr()
    result = json.loads(out.out)
    assert exc.value.code == 2 and result['status'] == 'proxy-failed'
    assert result['cleanup']['reason'] == 'proxy-cleanup-not-verified'
    assert not out.err
    assert m.proxy_row(m.db(), args)['state'] == 'cleanup-failed'
