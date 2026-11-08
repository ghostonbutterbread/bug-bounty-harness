"""Offline, kernel-fenced synthetic transient-unit observation regressions."""
import json

import pytest

from agents.test_shared_default_supervision import args
from agents.test_shared_default_legacy_observation import legacy


@pytest.fixture
def fresh(legacy):
    m, root, lane, proc, state, original, fields, calls = legacy
    unit = 'ghost-mitm-default-8080-' + 'a' * 32 + '.service'
    flow = lane / 'flows-example.mitm'
    (lane / 'flows.mitm').rename(flow)
    (proc / 'fd/6').unlink()
    (proc / 'fd/6').symlink_to(flow)
    old = b'flows.mitm'
    (proc / 'cmdline').write_bytes((proc / 'cmdline').read_bytes().replace(old, b'flows-example.mitm'))
    fields['ExecStart'] = fields['ExecStart'].replace('flows.mitm', 'flows-example.mitm')
    fields['Id'] = unit
    fields['ControlGroup'] = fields['ControlGroup'].replace('hoster-mitm-default-8080.service', unit)
    (proc / 'cgroup').write_text('0::' + fields['ControlGroup'] + '\n')
    data = {'status': 'running', 'pid': 202, 'port': 8080, 'listen_host': '0.0.0.0',
            'unit': unit, 'flow_file': str(flow), 'ca_cert': str(lane / 'mitmproxy/mitmproxy-ca-cert.pem')}
    state.write_text(json.dumps(data))
    return m, root, lane, proc, state, fields, calls, data


def test_fresh_observation_is_readonly_and_not_ready(fresh):
    m, root, lane, proc, state, fields, calls, data = fresh
    before = state.read_bytes()
    result = m.observe_default(args(root))
    assert result['status'] == 'observed-fresh'
    assert result['unit'] == data['unit'] and result['pid'] == data['pid']
    assert result['signer'] == 'unverified' and 'ca_cert' not in result
    assert state.read_bytes() == before and (lane / 'flows-example.mitm').read_bytes() == b'fixture capture'
    assert len(calls) >= 2 and all(call[3] == data['unit'] for call in calls)
    assert m.status_lane(args(root))['status'] == 'observed-fresh'


def test_unknown_unit_never_falls_back_to_legacy(fresh):
    m, root, lane, proc, state, fields, calls, data = fresh
    data['unit'] = 'unrecognized.service'
    state.write_text(json.dumps(data))
    assert m.status_lane(args(root))['status'] == 'unknown-state'
    assert not calls


@pytest.mark.parametrize('change', ['unit', 'pid', 'flow', 'state-flow-escape', 'invocation', 'race', 'address'])
def test_fresh_observation_rejects_unproven_generation(fresh, monkeypatch, change):
    m, root, lane, proc, state, fields, calls, data = fresh
    if change == 'unit': data['unit'] = 'hoster-mitm-default-8080.service'
    if change == 'pid': data['pid'] = 203
    if change == 'flow': (proc / 'fd/6').unlink()
    if change == 'state-flow-escape': data['flow_file'] = str(lane / '../flows-example.mitm')
    if change == 'invocation': fields['InvocationID'] = '0' * 32
    if change == 'address': (proc / 'net/tcp').write_text((proc / 'net/tcp').read_text().replace('00000000:1F90', '0100007F:1F90'))
    if change == 'race':
        base = m.unit_command
        def changed(cmd, env):
            if len(calls) == 1:
                fields['InvocationID'] = 'b' * 32
            return base(cmd, env)
        monkeypatch.setattr(m, 'unit_command', changed)
    state.write_text(json.dumps(data))
    before = state.read_bytes()
    assert m.observe_default(args(root))['status'] == 'unknown-state'
    assert state.read_bytes() == before


def test_changed_record_during_observation_is_unknown(fresh, monkeypatch):
    m, root, lane, proc, state, fields, calls, data = fresh
    original = m.unit_command
    def change_state(cmd, env):
        result = original(cmd, env)
        if len(calls) == 1:
            data['pid'] = 203
            state.write_text(json.dumps(data))
        return result
    monkeypatch.setattr(m, 'unit_command', change_state)
    assert m.observe_default(args(root))['status'] == 'unknown-state'


def test_fresh_loopback_is_observed_without_socket_probe(fresh):
    m, root, lane, proc, state, fields, calls, data = fresh
    data['listen_host'] = '127.0.0.1'
    state.write_text(json.dumps(data))
    (proc / 'cmdline').write_bytes((proc / 'cmdline').read_bytes().replace(b'0.0.0.0', b'127.0.0.1'))
    fields['ExecStart'] = fields['ExecStart'].replace('0.0.0.0', '127.0.0.1')
    (proc / 'net/tcp').write_text((proc / 'net/tcp').read_text().replace('00000000:1F90', '0100007F:1F90'))
    result = m.observe_default(args(root))
    assert result['status'] == 'observed-fresh' and result['listen_host'] == '127.0.0.1'


def test_wrapper_reports_fresh_as_unverified(tmp_path, monkeypatch):
    from agents.test_shared_default_supervision import load
    from agents.test_shared_default_ca_readiness import wrapper_args
    w = load('hoster_mitm_lane')
    unit = 'ghost-mitm-default-8080-' + 'a' * 32 + '.service'
    monkeypatch.setattr(w, 'run_remote', lambda *_: {'status': 'observed-fresh', 'lane': w.DEFAULT_GENERAL_LANE,
        'unit': unit, 'pid': 202, 'port': 8080, 'listen_host': '0.0.0.0', 'signer': 'unverified', 'secret': 'NO'})
    result = w.status_default(wrapper_args(tmp_path))
    assert result['status'] == 'observed-fresh' and result['signer'] == 'unverified'
    assert 'secret' not in result and 'proxy_server' not in result
