"""Fenced, synthetic evidence for read-only shared-default absence."""
import json
import os
import subprocess

import pytest

from agents.test_shared_default_supervision import args, load

TCP_HEADER = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n'
TCP6_HEADER = TCP_HEADER.replace('rem_address', 'remote_address')
TCP_ROW = '   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0\n'


@pytest.fixture
def absent(tmp_path, monkeypatch):
    m = load('mitm_lane')
    root = tmp_path / 'lanes'
    lane = root / m.DEFAULT_SHARED_LANE
    lane.mkdir(parents=True)
    (lane / 'flows.mitm').write_bytes(b'preserved capture')
    proc = tmp_path / 'proc'
    (proc / 'net').mkdir(parents=True)
    cgroups = tmp_path / 'cgroups'
    uid = os.getuid()
    manager = cgroups / 'user.slice' / f'user-{uid}.slice' / f'user@{uid}.service'
    (manager / 'app.slice').mkdir(parents=True)
    (manager / 'init.scope').mkdir()
    (manager / 'init.scope' / 'cgroup.procs').write_text('42\n')
    (proc / 'self' / 'ns').mkdir(parents=True)
    (proc / 'self' / 'ns' / 'net').symlink_to('net:[1234]')
    (proc / '42' / 'ns').mkdir(parents=True)
    (proc / '42' / 'ns' / 'net').symlink_to('net:[1234]')
    (proc / '42' / 'cgroup').write_text(f'0::/user.slice/user-{uid}.slice/user@{uid}.service/init.scope\n')
    for table in ('tcp', 'tcp6'):
        (proc / 'net' / table).write_text(TCP_HEADER if table == 'tcp' else TCP6_HEADER)
    fields = {}
    listed = []
    calls = []
    def command(cmd, env):
        calls.append(cmd)
        action = next(x for x in cmd if x in ('list-units', 'show'))
        if action == 'list-units':
            if 'app.slice' in cmd:
                return subprocess.CompletedProcess(cmd, 0, '', '')
            return subprocess.CompletedProcess(cmd, 0, ''.join(
                f'{unit} loaded inactive dead test\n' for unit in listed), '')
        unit = cmd[cmd.index('show') + 1]
        if unit == 'init.scope':
            return subprocess.CompletedProcess(cmd, 0, f'Id=init.scope\nLoadState=loaded\nActiveState=active\nSubState=running\nControlGroup=/user.slice/user-{uid}.slice/user@{uid}.service/init.scope\n', '')
        data = {'Id': unit, 'LoadState': 'not-found', 'ActiveState': 'inactive',
                'SubState': 'dead', 'MainPID': '0', 'ControlGroup': '', 'Slice': ''}
        data.update(fields.get(unit, {}))
        return subprocess.CompletedProcess(cmd, 0, ''.join(f'{k}={v}\n' for k, v in data.items()), '')
    monkeypatch.setattr(m, 'DEFAULT_ROOT', root)
    monkeypatch.setattr(m, 'PROC_ROOT', proc)
    monkeypatch.setattr(m, 'CGROUP_ROOT', cgroups)
    monkeypatch.setattr(m, 'unit_command', command)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda *_: pytest.fail('unexpected bind'))
    monkeypatch.setattr(m, 'public_ca_digest', lambda *_: pytest.fail('unexpected CA read'))
    monkeypatch.setattr(m, 'write_state', lambda *_: pytest.fail('unexpected write'))
    monkeypatch.setattr(m, 'stop_started_unit', lambda *_: pytest.fail('unexpected stop'))
    return m, root, lane, proc, fields, listed, calls


def test_absent_without_mutation(absent):
    m, root, lane, proc, fields, listed, calls = absent
    before = sorted(str(p.relative_to(lane)) for p in lane.rglob('*'))
    result = m.classify_default_absence(args(root))
    assert result['status'] == 'not-found'
    assert sorted(str(p.relative_to(lane)) for p in lane.rglob('*')) == before
    assert (lane / 'flows.mitm').read_bytes() == b'preserved capture'
    assert sum('list-units' in c for c in calls) >= 2


def test_loaded_inactive_unit_and_cli_schema(absent, monkeypatch, capsys):
    import sys
    m, root, lane, proc, fields, listed, calls = absent
    fields[m.LEGACY_UNIT] = {'LoadState': 'loaded', 'Slice': 'app.slice'}
    monkeypatch.setattr(sys, 'argv', ['mitm_lane.py', '--json', '--root', str(root),
                                     '--lane', m.DEFAULT_SHARED_LANE, 'classify-default-absence'])
    assert m.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {'status': 'not-found', 'lane': m.DEFAULT_SHARED_LANE,
                      'detail': 'Point-in-time read-only classification; recheck under the start lock before dispatch.'}


def test_stopped_record_with_dead_pid_and_recorded_unit(absent, monkeypatch):
    m, root, lane, proc, fields, listed, calls = absent
    unit = 'ghost-mitm-default-8080-' + 'a' * 32 + '.service'
    state = lane / 'state.json'
    data = {'status': 'stopped', 'pid': 202, 'port': 8080, 'unit': unit}
    state.write_text(json.dumps(data))
    before = state.read_bytes()
    def gone(pid, sig):
        assert (pid, sig) == (202, 0)
        raise ProcessLookupError
    monkeypatch.setattr(m.os, 'kill', gone)
    assert m.classify_default_absence(args(root))['status'] == 'stopped'
    assert state.read_bytes() == before
    assert sum('show' in c and unit in c for c in calls) == 2


@pytest.mark.parametrize('change', ['legacy-active', 'fresh-active', 'fresh-unrecorded', 'port4', 'port6',
                                  'invalid-json', 'starting', 'stale-running', 'foreign-unit', 'different-port', 'bad-table',
                                  'missing-proc', 'unit-error', 'list-error', 'unit-cgroup', 'duplicate-fields'])
def test_ambiguous_evidence_is_unknown(absent, monkeypatch, change):
    m, root, lane, proc, fields, listed, calls = absent
    state = lane / 'state.json'
    unit = 'ghost-mitm-default-8080-' + 'a' * 32 + '.service'
    if change == 'legacy-active': fields[m.LEGACY_UNIT] = {'ActiveState': 'active', 'SubState': 'running'}
    if change == 'fresh-active':
        state.write_text(json.dumps({'status': 'stopped', 'unit': unit}))
        fields[unit] = {'ActiveState': 'active', 'SubState': 'running'}
    if change == 'fresh-unrecorded':
        listed.append(unit)
        fields[unit] = {'ActiveState': 'active', 'SubState': 'running'}
    if change in ('port4', 'port6'):
        addr = '00000000' if change == 'port4' else '0' * 32
        (proc / 'net' / ('tcp' if change == 'port4' else 'tcp6')).write_text(
            (TCP_HEADER if change == 'port4' else TCP6_HEADER) + f' 0: {addr}:1F90 {addr}:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 9001 1 0000000000000000 100 0 0 10 0\n')
    if change == 'invalid-json': state.write_text('{oops')
    if change == 'starting': state.write_text('{"status":"starting"}')
    if change == 'stale-running': state.write_text('{"status":"running","pid":202}')
    if change == 'foreign-unit': state.write_text('{"status":"stopped","unit":"other.service"}')
    if change == 'different-port': state.write_text('{"status":"stopped","port":8081}')
    if change == 'bad-table': (proc / 'net/tcp').write_text('local_address\ninvalid\n')
    if change == 'missing-proc': (proc / 'net/tcp6').unlink()
    if change == 'unit-cgroup': fields[m.LEGACY_UNIT] = {'ControlGroup': '/still/populated'}
    if change in ('unit-error', 'list-error', 'duplicate-fields'):
        original = m.unit_command
        def broken(cmd, env):
            result = original(cmd, env)
            if change == 'unit-error' and 'show' in cmd: result.returncode = 1
            if change == 'list-error' and 'list-units' in cmd: result.returncode = 1
            if change == 'duplicate-fields' and 'show' in cmd: result.stdout += 'MainPID=0\n'
            return result
        monkeypatch.setattr(m, 'unit_command', broken)
    before = state.read_bytes() if state.exists() else None
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'
    assert (state.read_bytes() if state.exists() else None) == before
    assert (lane / 'flows.mitm').read_bytes() == b'preserved capture'


def test_cgroup_must_be_absent_or_unpopulated(absent):
    m, root, lane, proc, fields, listed, calls = absent
    uid = os.getuid()
    group = (m.CGROUP_ROOT / 'user.slice' / f'user-{uid}.slice' /
             f'user@{uid}.service' / 'app.slice' / m.LEGACY_UNIT)
    group.mkdir()
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'
    (group / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'
    (group / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
    assert m.classify_default_absence(args(root))['status'] == 'not-found'
    orphan = group.parent / ('ghost-mitm-default-8080-' + 'b' * 32 + '.service')
    orphan.mkdir()
    (orphan / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


def test_reused_or_hidden_recorded_pid_is_unknown(absent, monkeypatch):
    m, root, lane, proc, fields, listed, calls = absent
    (lane / 'state.json').write_text('{"status":"stopped","pid":202}')
    (proc / '202').mkdir()
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'
    (proc / '202').rmdir()
    monkeypatch.setattr(m.os, 'kill', lambda *_: (_ for _ in ()).throw(PermissionError()))
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


def test_changing_state_during_observation_is_unknown(absent, monkeypatch):
    m, root, lane, proc, fields, listed, calls = absent
    original = m.unit_command
    def mutate(cmd, env):
        result = original(cmd, env)
        if len(calls) == 2:
            (lane / 'state.json').write_text('{"status":"stopped"}')
        return result
    monkeypatch.setattr(m, 'unit_command', mutate)
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


def test_fenced_cli_unavailable_supervisor_returns_unknown():
    import sys
    from pathlib import Path
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/mitm_lane.py'
    result = subprocess.run([sys.executable, str(script), '--json', '--lane',
                             'hoster-default-8080', 'classify-default-absence'],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert json.loads(result.stdout)['status'] == 'unknown-state'


def test_outside_exact_scope_does_not_query(absent):
    m, root, lane, proc, fields, listed, calls = absent
    assert m.classify_default_absence(args(root / 'other'))['status'] == 'unknown-state'
    assert m.classify_default_absence(args(root, lane='other'))['status'] == 'unknown-state'
    assert calls == []


def test_real_tcp_header_row_and_truncated_header(absent):
    m, root, lane, proc, fields, listed, calls = absent
    (proc / 'net/tcp').write_text(TCP_HEADER + TCP_ROW)
    assert m.classify_default_absence(args(root))['status'] == 'not-found'
    (proc / 'net/tcp').write_text('local_address\n')
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


def test_realistic_ipv6_row_and_empty_ipv4(absent):
    m, root, lane, proc, fields, listed, calls = absent
    ipv6 = TCP_ROW.replace('0100007F:0050', '00000000000000000000000001000000:0050').replace(
        '00000000:0000 ', '00000000000000000000000000000000:0000 ')
    (proc / 'net/tcp6').write_text(TCP6_HEADER + ipv6)
    assert m.classify_default_absence(args(root))['status'] == 'not-found'


def test_time_wait_kernel_short_row(absent):
    m, root, lane, proc, fields, listed, calls = absent
    row = TCP_ROW.replace(' 0A ', ' 06 ')
    (proc / 'net/tcp').write_text(TCP_HEADER + ' '.join(row.split()[:12]) + '\n')
    assert m.classify_default_absence(args(root))['status'] == 'not-found'


def test_clean_host_without_app_slice(absent):
    m, root, lane, proc, fields, listed, calls = absent
    parent = m.CGROUP_ROOT / 'user.slice' / f'user-{os.getuid()}.slice' / f'user@{os.getuid()}.service' / 'app.slice'
    parent.rmdir()
    assert m.classify_default_absence(args(root))['status'] == 'not-found'


def test_namespace_mismatch_is_unknown(absent):
    m, root, lane, proc, fields, listed, calls = absent
    (proc / '42/ns/net').unlink()
    (proc / '42/ns/net').symlink_to('net:[5678]')
    result = m.classify_default_absence(args(root))
    assert result['status'] == 'unknown-state'
    assert 'namespace' in result['detail'].lower()


def test_long_inactive_unit_list_is_untruncated(absent):
    m, root, lane, proc, fields, listed, calls = absent
    unit = 'ghost-mitm-default-8080-' + 'a' * 32 + '.service'
    listed.append(unit)
    fields[unit] = {'LoadState': 'loaded', 'Slice': 'app.slice'}
    assert m.classify_default_absence(args(root))['status'] == 'not-found'
    assert all('--full' in c and '--no-pager' in c for c in calls if 'list-units' in c)


def test_recorded_listed_inactive_unit_is_not_a_duplicate(absent):
    m, root, lane, proc, fields, listed, calls = absent
    unit = 'ghost-mitm-default-8080-' + 'a' * 32 + '.service'
    (lane / 'state.json').write_text(json.dumps({'status': 'stopped', 'unit': unit}))
    listed.append(unit)
    fields[unit] = {'LoadState': 'loaded', 'Slice': 'app.slice'}
    assert m.classify_default_absence(args(root))['status'] == 'stopped'


def test_listed_loaded_unit_cannot_show_not_found(absent):
    m, root, lane, proc, fields, listed, calls = absent
    listed.append('ghost-mitm-default-8080-' + 'a' * 32 + '.service')
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


@pytest.mark.parametrize('row', [
    'ghost-mitm-default-8080-' + 'a' * 32 + '.service loaded inactive dead\n',
    'ghost-mitm-default-8080-' + 'a' * 32 + '.service loaded active dead description\n',
    'ghost-mitm-default-8080-' + 'a' * 32 + '.service loaded inactive dead \x1b[31mtest\n',
    'ghost-mitm-default-8080-aaaa…service loaded inactive dead description\n',
    '\n',
])
def test_malformed_unit_list_is_unknown(absent, monkeypatch, row):
    m, root, lane, proc, fields, listed, calls = absent
    original = m.unit_command
    def malformed(cmd, env):
        result = original(cmd, env)
        if 'list-units' in cmd:
            result.stdout = row
        return result
    monkeypatch.setattr(m, 'unit_command', malformed)
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


@pytest.mark.parametrize('row', [
    TCP_ROW.replace('00000000:0000', 'bad:0000'),
    TCP_ROW.replace('00000000:00000000', 'bad:00000000'),
    TCP_ROW.replace(' 1000 0 12345 ', ' broken 0 12345 '),
    ' '.join(TCP_ROW.split()[:10]) + '\n',
    ' '.join(TCP_ROW.split()[:12]) + '\n',
    TCP_ROW.replace(' 0 12345 ', ' 0 nope '),
    '\n',
])
def test_malformed_tcp_row_is_unknown(absent, row):
    m, root, lane, proc, fields, listed, calls = absent
    (proc / 'net/tcp').write_text(TCP_HEADER + row)
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


@pytest.mark.parametrize('change', ['no-pids', 'bad-pid', 'missing-ns', 'wrong-cgroup', 'missing-manager'])
def test_unproven_manager_evidence_is_unknown_even_without_app_slice(absent, change):
    m, root, lane, proc, fields, listed, calls = absent
    manager = m.CGROUP_ROOT / 'user.slice' / f'user-{os.getuid()}.slice' / f'user@{os.getuid()}.service'
    (manager / 'app.slice').rmdir()
    if change == 'no-pids': (manager / 'init.scope/cgroup.procs').write_text('')
    if change == 'bad-pid': (manager / 'init.scope/cgroup.procs').write_text('42x\n')
    if change == 'missing-ns': (proc / '42/ns/net').unlink()
    if change == 'wrong-cgroup': (proc / '42/cgroup').write_text('0::/elsewhere\n')
    if change == 'missing-manager': (manager / 'init.scope/cgroup.procs').unlink()
    result = m.classify_default_absence(args(root))
    assert result['status'] == 'unknown-state'
    assert 'namespace' in result['detail'].lower()


def test_absent_app_slice_with_loaded_inactive_unit(absent):
    m, root, lane, proc, fields, listed, calls = absent
    manager = m.CGROUP_ROOT / 'user.slice' / f'user-{os.getuid()}.slice' / f'user@{os.getuid()}.service'
    (manager / 'app.slice').rmdir()
    fields[m.LEGACY_UNIT] = {'LoadState': 'loaded', 'Slice': 'app.slice'}
    assert m.classify_default_absence(args(root))['status'] == 'not-found'
    fields[m.LEGACY_UNIT]['MainPID'] = '42'
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'
    fields[m.LEGACY_UNIT] = {'LoadState': 'loaded', 'Slice': 'app.slice', 'ControlGroup': '/unexpected'}
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'
    fields.clear()
    unit = 'ghost-mitm-default-8080-' + 'a' * 32 + '.service'
    listed.append(unit)
    fields[unit] = {'LoadState': 'loaded', 'Slice': 'app.slice'}
    assert m.classify_default_absence(args(root))['status'] == 'not-found'
    fields[unit]['ActiveState'] = 'active'
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


def test_absent_app_slice_with_active_slice_evidence_is_unknown(absent, monkeypatch):
    m, root, lane, proc, fields, listed, calls = absent
    manager = m.CGROUP_ROOT / 'user.slice' / f'user-{os.getuid()}.slice' / f'user@{os.getuid()}.service'
    (manager / 'app.slice').rmdir()
    original = m.unit_command
    def active_slice(cmd, env):
        result = original(cmd, env)
        if 'list-units' in cmd and 'app.slice' in cmd:
            result.stdout = 'app.slice loaded active active User Application Slice\n'
        return result
    monkeypatch.setattr(m, 'unit_command', active_slice)
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


@pytest.fixture
def manager_witness(absent, monkeypatch):
    m, root, lane, proc, fields, listed, calls = absent
    uid = os.getuid()
    group = f'/user.slice/user-{uid}.slice/user@{uid}.service/session.slice/dbus.service'
    witness = proc / '77'
    (witness / 'ns').mkdir(parents=True)
    (witness / 'ns/net').symlink_to('net:[1234]')
    (witness / 'cgroup').write_text('0::' + group + '\n')
    # Field 22 (starttime) follows 19 post-comm fields.
    (witness / 'stat').write_text('77 (dbus-daemon) ' + ' '.join(['S'] + ['0'] * 18 + ['101']) + '\n')
    data = {'Id': 'dbus.service', 'LoadState': 'loaded', 'ActiveState': 'active',
            'SubState': 'running', 'MainPID': '77', 'InvocationID': 'a' * 32,
            'ControlGroup': group, 'Slice': 'session.slice', 'PrivateNetwork': 'no',
            'NetworkNamespacePath': '', 'JoinsNamespaceOf': ''}
    original_command = m.unit_command
    def command(cmd, env):
        if 'show' in cmd and 'dbus.service' in cmd:
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, ''.join(f'{k}={v}\n' for k, v in data.items()), '')
        return original_command(cmd, env)
    monkeypatch.setattr(m, 'unit_command', command)
    original_readlink = os.readlink
    def readlink(path, *a, **kw):
        if str(path) == str(proc / '42/ns/net'):
            raise PermissionError('manager namespace hidden')
        return original_readlink(path, *a, **kw)
    monkeypatch.setattr(m.os, 'readlink', readlink)
    return absent, data, witness


def test_readable_unisolated_user_service_witness(manager_witness):
    (m, root, *_), data, witness = manager_witness
    assert m.classify_default_absence(args(root))['status'] == 'not-found'


@pytest.mark.parametrize('field,value', [
    ('PrivateNetwork', 'yes'), ('NetworkNamespacePath', '/some/ns'),
    ('JoinsNamespaceOf', 'other.service'), ('InvocationID', '0' * 32),
    ('MainPID', '0'), ('ActiveState', 'inactive'), ('ControlGroup', '/other'),
    ('Slice', 'app.slice'),
])
def test_witness_rejects_unproven_identity_or_network_config(manager_witness, field, value):
    (m, root, *_), data, witness = manager_witness
    data[field] = value
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


def test_witness_rejects_changed_incarnation(manager_witness, monkeypatch):
    (m, root, *_), data, witness = manager_witness
    original = m.unit_command
    count = 0
    def command(cmd, env):
        nonlocal count
        result = original(cmd, env)
        if 'show' in cmd and 'dbus.service' in cmd:
            count += 1
            if count == 2:
                (witness / 'stat').write_text('77 (dbus-daemon) ' + ' '.join(['S'] + ['0'] * 18 + ['102']) + '\n')
        return result
    monkeypatch.setattr(m, 'unit_command', command)
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


def test_witness_rejects_wrong_namespace_and_cgroup(manager_witness):
    (m, root, *_), data, witness = manager_witness
    (witness / 'ns/net').unlink()
    (witness / 'ns/net').symlink_to('net:[5555]')
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'
    (witness / 'ns/net').unlink()
    (witness / 'ns/net').symlink_to('net:[1234]')
    (witness / 'cgroup').write_text('0::/other\n')
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


def test_missing_witness_namespace_or_stat_is_unknown(manager_witness):
    (m, root, *_), data, witness = manager_witness
    (witness / 'ns/net').unlink()
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'
    (witness / 'ns/net').symlink_to('net:[1234]')
    (witness / 'stat').unlink()
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'


def test_changed_witness_invocation_is_unknown(manager_witness, monkeypatch):
    (m, root, *_), data, witness = manager_witness
    original = m.unit_command
    count = 0
    def command(cmd, env):
        nonlocal count
        if 'show' in cmd and 'dbus.service' in cmd:
            count += 1
            if count == 2:
                data['InvocationID'] = 'b' * 32
        return original(cmd, env)
    monkeypatch.setattr(m, 'unit_command', command)
    assert m.classify_default_absence(args(root))['status'] == 'unknown-state'
