#!/usr/bin/env python3
"""Node-local, resource-gated persistent Chromium provisioner.

Runs on the browser node. It leases an exact account profile, checks that
node's resources, and keeps each Chromium root inside a user-systemd unit.
It never prints CDP URLs, cookies, credentials, or auth-seed locations.
"""

from __future__ import annotations
import argparse, contextlib, functools, hashlib, io, json, os, shutil, socket, sqlite3, subprocess, sys, time, uuid
from urllib.parse import urlsplit
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from browser_lifecycle import StartupDiagnostics, node_lock, owner_state, private_json, process_identity
from chromium_test import resolve_mitm_ca_cert
from mitm_chromium_profile import DEFAULT_CA_CERT, remove_matching_ca

LEASE = ROOT / "browser_profile_lease.py"
CHROMIUM = ROOT / "chromium_test.py"
PROXY_STORE = ROOT / "proxy_store.py"
STATE = Path(
    os.environ.get(
        "BROWSER_PROVISIONER_STATE",
        "~/.local/state/ghost/browser-profile-leases/browser_provisioner.sqlite",
    )
).expanduser()
DEFAULT_RAM_MIB, DEFAULT_SWAP_MIB, DEFAULT_IDLE = 2048, 512, 300
# Seconds to wait for the launcher to write its private record. Chromium must
# stand up a display and reach CDP first, which exceeds a few seconds on a
# loaded host; too small a value kills the unit before it can ever report.
LAUNCH_WAIT_SECONDS = float(os.environ.get("BROWSER_LAUNCH_WAIT_SECONDS", "45"))
MAX_TABS = 5


def emit(o, code=0):
    print(json.dumps(o, sort_keys=True))
    raise SystemExit(code)


def now():
    return time.time()


def slug(s):
    return (
        "".join(c.lower() if c.isalnum() or c in "._-" else "-" for c in s).strip(".-")
        or "unknown"
    )


def db():
    STATE.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(STATE)
    c.row_factory = sqlite3.Row
    c.execute(
        """CREATE TABLE IF NOT EXISTS browsers (lease_id TEXT PRIMARY KEY,browser_id TEXT UNIQUE NOT NULL,program TEXT NOT NULL,account TEXT NOT NULL,auth_domain TEXT NOT NULL DEFAULT 'legacy-global',agent_id TEXT NOT NULL,run_id TEXT NOT NULL,purpose TEXT NOT NULL,unit TEXT NOT NULL,profile_dir TEXT NOT NULL,launch_file TEXT NOT NULL,state TEXT NOT NULL,tab_count INTEGER NOT NULL DEFAULT 0,last_activity REAL NOT NULL,created REAL NOT NULL,updated REAL NOT NULL)"""
    )
    columns = {row["name"] for row in c.execute("pragma table_info(browsers)")}
    if "auth_domain" not in columns:
        c.execute(
            "alter table browsers add column auth_domain TEXT NOT NULL DEFAULT 'legacy-global'"
        )
    c.execute(
        "CREATE TABLE IF NOT EXISTS lifecycle (lease_id TEXT PRIMARY KEY, metadata TEXT NOT NULL)"
    )
    c.execute("""CREATE TABLE IF NOT EXISTS task_proxies (
        agent_id TEXT NOT NULL, run_id TEXT NOT NULL, program TEXT NOT NULL,
        account TEXT NOT NULL, purpose TEXT NOT NULL, lane TEXT PRIMARY KEY,
        port INTEGER UNIQUE NOT NULL, unit TEXT NOT NULL, run_dir TEXT NOT NULL,
        state TEXT NOT NULL, UNIQUE(agent_id, run_id))""")
    columns = {row["name"] for row in c.execute("pragma table_info(task_proxies)")}
    for name, definition in (("updated", "REAL NOT NULL DEFAULT 0"),
                             ("owner", "TEXT"), ("invocation", "TEXT")):
        if name not in columns:
            c.execute(f"alter table task_proxies add column {name} {definition}")
    c.execute("CREATE TABLE IF NOT EXISTS finished_proxies (agent_id TEXT NOT NULL, run_id TEXT NOT NULL, lane TEXT NOT NULL, finished REAL NOT NULL, PRIMARY KEY(agent_id, run_id))")
    # Fixture-only peer metadata. Never persist cookies, storage or a CDP URL here.
    c.execute("""CREATE TABLE IF NOT EXISTS fixture_generations (
        program TEXT NOT NULL, auth_domain TEXT NOT NULL, account TEXT NOT NULL,
        generation INTEGER NOT NULL, source_lease TEXT NOT NULL,
        source_identity TEXT NOT NULL, contract_revision TEXT NOT NULL,
        origin TEXT NOT NULL, PRIMARY KEY(program, auth_domain, account))""")
    c.execute("""CREATE TABLE IF NOT EXISTS fixture_peers (
        lease_id TEXT PRIMARY KEY, program TEXT NOT NULL, auth_domain TEXT NOT NULL,
        account TEXT NOT NULL, generation INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('pending','applying','applied')))""")
    return c


def manager_id():
    """Identity of this node's manager store, not a caller-provided lease label."""
    return hashlib.sha256(str(STATE.resolve()).encode()).hexdigest()


def stopped_reservation(source_lease_id, phase='reserved'):
    """Fixture-only inert fence. No snapshot/copy consumer is activated here."""
    if phase != 'reserved':
        return {'status': 'reservation-unavailable'}
    import browser_profile_lease as profiles
    with node_lock(STATE):
        with db() as manager, profiles.connect(STATE.parent / 'browser_profile_leases.sqlite') as leases:
            profiles.init_db(leases)
            row = manager.execute('SELECT * FROM browsers WHERE lease_id=?', (source_lease_id,)).fetchone()
            if not row or tuple(row[k] for k in ('program','auth_domain','account')) != FIXTURE_POOL:
                return {'status': 'reservation-unavailable'}
            physical = profiles.physical_profile(row['profile_dir'])
            if not physical or row['state'] != 'stopped' or not stopped(row):
                return {'status': 'reservation-unavailable'}
            for other in manager.execute('SELECT * FROM browsers'):
                other_id = profiles.physical_profile(other['profile_dir'])
                if other['profile_dir'] == row['profile_dir'] or other_id == physical:
                    if other_id != physical or other['state'] != 'stopped' or not stopped(other):
                        return {'status': 'reservation-unavailable'}
            leases.execute('BEGIN IMMEDIATE')
            canonical = leases.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?',
                                       (source_lease_id,)).fetchone()
            if not row or not canonical or tuple(row[k] for k in ('program','auth_domain','account')) != FIXTURE_POOL:
                return {'status': 'reservation-unavailable'}
            key = FIXTURE_POOL
            existing = leases.execute('SELECT * FROM browser_stopped_reservations WHERE '
                'program=? AND auth_domain=? AND account_alias=?', key).fetchone()
            info = record_info(row)
            generation = info.get('control_generation')
            root = info.get('process_identity')
            cdp = info.get('cdp_url')
            if (row['state'] != 'stopped' or canonical['status'] != 'released'
                    or canonical['browser_status'] != 'stopped'
                    or canonical['work_state'] != 'terminal'
                    or any(canonical[k] != v for k, v in (
                        ('program', row['program']), ('auth_domain', row['auth_domain']),
                        ('account_alias', row['account']), ('owner_agent_id', row['agent_id']),
                        ('owner_run_id', row['run_id']), ('profile_dir', row['profile_dir']),
                        ('manager_id', manager_id()), ('service_unit', row['unit'])))
                    or not physical or not generation or not root or not cdp
                    or not info.get('unit_invocation')):
                return {'status': 'reservation-unavailable'}
            # Every historical alias of the same directory must be terminal;
            # missing physical evidence is not interpreted as a distinct profile.
            for other in leases.execute('SELECT * FROM browser_profile_leases'):
                other_id = profiles.physical_profile(other['profile_dir'])
                if other['profile_dir'] == row['profile_dir'] or other_id == physical:
                    if other_id != physical or other['status'] != 'released' or other['browser_status'] != 'stopped':
                        return {'status': 'reservation-unavailable'}
            if existing and existing['phase'] != 'released':
                # A retry is idempotent only while the fence is untouched. In
                # particular, never turn an interrupted copy back into reserved.
                if (existing['phase'] != 'reserved'
                        or existing['source_lease'] != source_lease_id
                        or existing['manager_id'] != manager_id()
                        or existing['owner_agent_id'] != row['agent_id']
                        or existing['owner_run_id'] != row['run_id']
                        or existing['service_unit'] != row['unit']
                        or existing['profile_dir'] != row['profile_dir']
                        or existing['root'] != json.dumps(root, sort_keys=True)
                        or existing['cdp_url'] != cdp
                        or existing['unit_invocation'] != info['unit_invocation']
                        or existing['control_generation'] != generation
                        or (existing['profile_device'], existing['profile_inode']) != physical):
                    return {'status': 'reservation-unavailable'}
            elif phase == 'reserved' and not profiles.reservation_conflict(leases, path=row['profile_dir']):
                leases.execute('INSERT OR REPLACE INTO browser_stopped_reservations '
                    '(program,auth_domain,account_alias,source_lease,manager_id,owner_agent_id,'
                    'owner_run_id,control_generation,service_unit,root,cdp_url,profile_dir,'
                    'profile_device,profile_inode,phase,unit_invocation) VALUES '
                    '(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (*key, source_lease_id, manager_id(),
                    row['agent_id'], row['run_id'], generation, row['unit'],
                    json.dumps(root, sort_keys=True), cdp, row['profile_dir'], *physical,
                    phase, info['unit_invocation']))
            else:
                return {'status': 'reservation-unavailable'}
            leases.commit()
            return {'status': 'reserved', 'phase': phase}


def cancel_unstarted_reservation(source_lease_id):
    """Only an untouched reserved fence can be cancelled; copying needs a future verifier."""
    import browser_profile_lease as profiles
    with node_lock(STATE):
        with db() as manager, profiles.connect(STATE.parent / 'browser_profile_leases.sqlite') as leases:
            profiles.init_db(leases)
            row = manager.execute('SELECT * FROM browsers WHERE lease_id=?', (source_lease_id,)).fetchone()
            if not row or tuple(row[k] for k in ('program','auth_domain','account')) != FIXTURE_POOL:
                return {'status': 'reservation-unavailable'}
            physical = profiles.physical_profile(row['profile_dir'])
            if not physical or row['state'] != 'stopped' or not stopped(row):
                return {'status': 'reservation-unavailable'}
            if any(profiles.physical_profile(other['profile_dir']) == physical and
                   (other['state'] != 'stopped' or not stopped(other))
                   for other in manager.execute('SELECT * FROM browsers')):
                return {'status': 'reservation-unavailable'}
            leases.execute('BEGIN IMMEDIATE')
            reserved = leases.execute('SELECT * FROM browser_stopped_reservations WHERE '
                'program=? AND auth_domain=? AND account_alias=?', FIXTURE_POOL).fetchone()
            canonical = leases.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?',
                                       (source_lease_id,)).fetchone()
            info = record_info(row)
            root = info.get('process_identity')
            if (not canonical or not reserved or not root or not info.get('cdp_url')
                    or not info.get('unit_invocation') or not info.get('control_generation')
                    or canonical['status'] != 'released' or canonical['browser_status'] != 'stopped'
                    or canonical['work_state'] != 'terminal'
                    or any(canonical[k] != v for k, v in (
                        ('program', row['program']), ('auth_domain', row['auth_domain']),
                        ('account_alias', row['account']), ('owner_agent_id', row['agent_id']),
                        ('owner_run_id', row['run_id']), ('profile_dir', row['profile_dir']),
                        ('service_unit', row['unit']), ('manager_id', manager_id())))
                    or any(reserved[k] != v for k, v in (
                        ('source_lease', source_lease_id), ('manager_id', manager_id()),
                        ('owner_agent_id', row['agent_id']), ('owner_run_id', row['run_id']),
                        ('profile_dir', row['profile_dir']), ('service_unit', row['unit']),
                        ('root', json.dumps(root, sort_keys=True)),
                        ('cdp_url', info['cdp_url']),
                        ('unit_invocation', info['unit_invocation']),
                        ('control_generation', info['control_generation'])))):
                return {'status': 'reservation-unavailable'}
            # An unresolved alias is uncertainty, not evidence of a distinct
            # profile. Recheck both stores before clearing the physical fence.
            for other in manager.execute('SELECT * FROM browsers'):
                other_id = profiles.physical_profile(other['profile_dir'])
                if (other['profile_dir'] == row['profile_dir'] or other_id == physical):
                    if other_id != physical or other['state'] != 'stopped' or not stopped(other):
                        return {'status': 'reservation-unavailable'}
            for other in leases.execute('SELECT * FROM browser_profile_leases'):
                other_id = profiles.physical_profile(other['profile_dir'])
                if other['profile_dir'] == row['profile_dir'] or other_id == physical:
                    if other_id != physical or other['status'] != 'released' or other['browser_status'] != 'stopped':
                        return {'status': 'reservation-unavailable'}
            if (not reserved or reserved['phase'] != 'reserved'
                    or reserved['source_lease'] != source_lease_id
                    or reserved['manager_id'] != manager_id()
                    or (reserved['profile_device'], reserved['profile_inode']) != physical
                    or reserved['control_generation'] != info['control_generation']):
                return {'status': 'reservation-unavailable'}
            leases.execute("UPDATE browser_stopped_reservations SET phase='released' WHERE "
                           'program=? AND auth_domain=? AND account_alias=?', FIXTURE_POOL)
            leases.commit()
            return {'status': 'released'}


def reservation_blocks(row):
    """Manager admission/cleanup fence; canonical writers use their own transaction."""
    import browser_profile_lease as profiles
    with profiles.connect(STATE.parent / 'browser_profile_leases.sqlite') as leases:
        profiles.init_db(leases)
        leases.execute('BEGIN IMMEDIATE')
        return profiles.reservation_conflict(leases, program=row['program'],
            domain=row['auth_domain'], alias=row['account'], lease_id=row['lease_id'],
            path=row['profile_dir'])


def fixture_pool_reserved(program, domain, account):
    if (slug(program), domain, slug(account)) != FIXTURE_POOL:
        return False
    import browser_profile_lease as profiles
    with profiles.connect(STATE.parent / 'browser_profile_leases.sqlite') as leases:
        profiles.init_db(leases)
        leases.execute('BEGIN IMMEDIATE')
        return profiles.reservation_conflict(leases, program=slug(program),
                                             domain=domain, alias=slug(account))


def manager_transfer_attestation_gate(source_lease_id, destination_lease_id):
    """Private manager-only preflight. Never issue a grant without native auth proof.

    Neither /identity nor a ready CDP endpoint attests authenticated app state,
    and no app-native browser verification/generation contract exists here yet.
    Lease IDs are selectors only; no caller-supplied identity is trusted.
    """
    unavailable = {'status': 'auth-clone-unavailable', 'reason': 'manager-identity-unverified'}
    if (not isinstance(source_lease_id, str) or not isinstance(destination_lease_id, str)
            or not source_lease_id or not destination_lease_id
            or source_lease_id == destination_lease_id):
        return unavailable
    import browser_profile_lease as profiles
    with node_lock(STATE):
        with db() as manager_db, profiles.connect(STATE.parent / 'browser_profile_leases.sqlite') as leases:
            profiles.init_db(leases)
            leases.execute('BEGIN IMMEDIATE')
            if not _transfer_candidates(manager_db, leases, source_lease_id, destination_lease_id):
                return unavailable
            # Missing: an app-native verification hook bound to each exact pipe
            # generation. Do not materialize an auth_generation, identity, or grant.
            return {'status': 'auth-clone-unavailable', 'reason': 'attestation-hook-unavailable'}

def _fixture_policy_pool(manager_db, leases, source_id, destination_id):
    """Read-only exact fixture pool evidence before any browser health probe.

    A mismatch defers to the full candidate gate; it never grants transfer.
    Called only under the manager node lock and canonical write transaction.
    """
    if not source_id or not destination_id or source_id == destination_id:
        return None
    for lid in (source_id, destination_id):
        row = manager_db.execute('SELECT * FROM browsers WHERE lease_id=?', (lid,)).fetchone()
        canonical = leases.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?', (lid,)).fetchone()
        if (not row or not canonical or row['state'] != 'running'
                or canonical['status'] != 'active' or canonical['browser_status'] != 'running'
                or canonical['expires_at'] <= now()
                or tuple(row[k] for k in ('program', 'auth_domain', 'account')) != FIXTURE_POOL
                or any(canonical[k] != v for k, v in (
                    ('program', row['program']), ('auth_domain', row['auth_domain']),
                    ('account_alias', row['account']), ('owner_agent_id', row['agent_id']),
                    ('owner_run_id', row['run_id']), ('profile_dir', row['profile_dir']),
                    ('service_unit', row['unit']), ('manager_id', manager_id())))):
            return None
    return FIXTURE_POOL


def _transfer_candidates(manager_db, leases, source_id, destination_id, *, ticketed=False):
    """Derive both owners from canonical and manager state, never caller claims."""
    import browser_profile_lease as profiles
    if not source_id or not destination_id or source_id == destination_id:
        return None
    candidates = []
    for lid in (source_id, destination_id):
        row = manager_db.execute('SELECT * FROM browsers WHERE lease_id=?', (lid,)).fetchone()
        canonical = leases.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?', (lid,)).fetchone()
        if not row or not canonical or row['state'] != 'running' or canonical['status'] != 'active' or canonical['browser_status'] != 'running' or canonical['expires_at'] <= now():
            return None
        if any(canonical[key] != value for key, value in (
            ('program', row['program']), ('auth_domain', row['auth_domain']),
            ('account_alias', row['account']), ('owner_agent_id', row['agent_id']),
            ('owner_run_id', row['run_id']), ('profile_dir', row['profile_dir']),
            ('service_unit', row['unit']), ('manager_id', manager_id()))):
            return None
        info = record_info(row)
        identity = info.get('process_identity')
        physical = profiles.physical_profile(row['profile_dir'])
        if (canonical['cdp_url'] != info.get('cdp_url')
                or not physical or not identity or owner_state(identity) != 'active'
                or not info.get('unit_invocation')
                or info['unit_invocation'] != unit_identity(row['unit'])
                or info.get('control_mode') != 'pipe-fenced' or
                (not ticketed and not healthy(row)) or
                (ticketed and (not unit_active(row['unit']) or
                 process_identity(identity['pid']) != identity))):
            return None
        candidates.append((row, info, physical))
    if (candidates[0][2] == candidates[1][2]
            or candidates[0][0]['program'] != candidates[1][0]['program']
            or candidates[0][0]['auth_domain'] != candidates[1][0]['auth_domain']
            or candidates[0][0]['account'] != candidates[1][0]['account']):
        return None
    return candidates

FIXTURE_POOL = ('fixture', 'fixture.invalid', 'anon')
FIXTURE_CONTRACT_REVISION = 'localhost-me-host-session-storage-v1'


def _fixture_origin(origin):
    try:
        parsed = urlsplit(origin)
        return (parsed.scheme == 'http' and parsed.hostname == 'localhost'
                and bool(parsed.port) and origin == f'http://localhost:{parsed.port}')
    except (TypeError, ValueError):
        return False


def _fixture_identity(row, info):
    # Opaque, non-secret binding to one physical browser generation and owner.
    fields = (row['lease_id'], row['agent_id'], row['run_id'], row['profile_dir'],
              row['unit'], info['unit_invocation'], info['process_identity'], info['cdp_url'])
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


def _fixture_owner(row, agent_id, run_id):
    return row['agent_id'] == agent_id and row['run_id'] == run_id


def _fixture_source(db_conn, leases, source_id, agent_id, run_id):
    """Resolve an exact healthy source using the same manager/canonical gate."""
    # The two-candidate predicate also requires an empty peer; a source-only
    # promotion must instead validate against its own canonical row.
    import browser_profile_lease as profiles
    row = db_conn.execute('SELECT * FROM browsers WHERE lease_id=?', (source_id,)).fetchone()
    canonical = leases.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?', (source_id,)).fetchone()
    if not row or not canonical or not _fixture_owner(row, agent_id, run_id):
        return None
    if (tuple(row[k] for k in ('program', 'auth_domain', 'account')) != FIXTURE_POOL
            or row['state'] != 'running' or canonical['status'] != 'active'
            or canonical['browser_status'] != 'running' or canonical['expires_at'] <= now()
            or any(canonical[k] != v for k, v in (
                ('program', row['program']), ('auth_domain', row['auth_domain']),
                ('account_alias', row['account']), ('owner_agent_id', agent_id),
                ('owner_run_id', run_id), ('profile_dir', row['profile_dir']),
                ('service_unit', row['unit']), ('manager_id', manager_id())))):
        return None
    info = record_info(row)
    identity = info.get('process_identity')
    if (not profiles.physical_profile(row['profile_dir']) or not identity
            or owner_state(identity) != 'active' or not info.get('unit_invocation')
            or info['unit_invocation'] != unit_identity(row['unit'])
            or info.get('control_mode') != 'pipe-fenced'
            or info.get('control_socket') != str(STATE.parent / (row['browser_id'] + '.sock'))
            or canonical['cdp_url'] != info.get('cdp_url') or not healthy(row)):
        return None
    return row, info


def _fixture_site_contract(origin):
    if str(ROOT.parents[2]) not in sys.path:
        sys.path.insert(0, str(ROOT.parents[2]))
    from agents.browser_auth_site_contract import load_site_contract, SiteContractError
    contract = load_site_contract(STATE.parent / 'fixture-site-contract.json',
        program='fixture', auth_domain='fixture.invalid', account_alias='anon', origin=origin)
    if (contract.cookie_name != '__Host-session' or contract.cookie_domain != 'localhost'
            or contract.cookie_path != '/' or contract.local_storage_keys != ('fixture-credential',)):
        raise SiteContractError('Unsupported fixture state')
    return contract


def _fixture_check_expression(contract):
    # Fixed manager code: URL and selector are JSON data, not executable caller code.
    return """(async () => {
        const response = await fetch(URL, {redirect: 'manual', credentials: 'same-origin'});
        const redirected = response.type === 'opaqueredirect' || response.status >= 300 && response.status < 400;
        if (redirected) return {url: response.url, status: response.status, redirected: true, principal: ''};
        const html = await response.text();
        const element = new DOMParser().parseFromString(html, 'text/html').querySelector(SELECTOR);
        return {url: response.url, status: response.status, redirected: false,
                principal: element ? element.textContent.trim() : ''};
    })()""".replace('URL', json.dumps(contract.check_url)).replace('SELECTOR', json.dumps(contract.principal_selector))


def _fixture_verified_observation(contract, observation):
    from agents.browser_auth_site_contract import SiteContractError, verify_check_response
    try:
        verify_check_response(contract, response_url=observation['url'],
            status=observation['status'], redirected=observation['redirected'],
            principal=observation['principal'])
        return True
    except (SiteContractError, KeyError, TypeError):
        return False


def _fixture_native_source_check(row, info, origin):
    """Probe auth under an exact ticket; never infer release from an end ACK."""
    import httpx
    from agents.browser_auth_site_contract import SiteContractError, verify_cookie_scope
    try:
        contract = _fixture_site_contract(origin)
    except SiteContractError:
        return False
    begin = {'transaction': uuid.uuid4().hex, 'owner': row['lease_id'],
             'generation': info['cdp_url'], 'destination': False}
    binding = {k: begin[k] for k in ('transaction', 'owner', 'generation')}
    ticket = None
    verified = False
    interruption = None
    with httpx.Client(transport=httpx.HTTPTransport(uds=info['control_socket']), timeout=15) as client:
        # A failed begin may have applied. Replay only the manager-derived attempt.
        for _ in range(2):
            try:
                response = client.post('http://localhost/transfer/begin', json=begin)
                response.raise_for_status()
                ticket = response.json()['ticket']
                break
            except BaseException as exc:
                if not isinstance(exc, (OSError, ValueError, KeyError, httpx.HTTPError)):
                    interruption = exc
        if ticket and interruption is None:
            def evaluate(expression):
                response = client.post('http://localhost/transfer/call', json={
                    **binding, 'ticket': ticket, 'method': 'Runtime.evaluate',
                    'params': {'expression': expression, 'returnByValue': True, 'awaitPromise': True}})
                response.raise_for_status()
                result = response.json()
                if 'error' in result or 'exceptionDetails' in result.get('result', {}):
                    return None
                return result['result']['result'].get('value')
            try:
                if evaluate('location.origin') == origin:
                    observation = evaluate(_fixture_check_expression(contract))
                    if (_fixture_verified_observation(contract, observation)
                            and evaluate("localStorage.getItem('fixture-credential')") == 'approved'):
                        response = client.post('http://localhost/transfer/call', json={
                            **binding, 'ticket': ticket, 'method': 'Network.getAllCookies', 'params': {}})
                        response.raise_for_status()
                        cookies = response.json()['result']['cookies']
                        selected = [c for c in cookies if c.get('name') == contract.cookie_name
                                    and c.get('domain') == contract.cookie_domain
                                    and c.get('path') == contract.cookie_path]
                        if len(selected) == 1 and selected[0].get('httpOnly') is True:
                            try:
                                verify_cookie_scope(contract, browser_domain=selected[0]['domain'],
                                    host_only=selected[0].get('hostOnly'), secure=selected[0].get('secure'),
                                    browser_path=selected[0].get('path'))
                                verified = True
                            except SiteContractError:
                                pass
            except BaseException as exc:
                if not isinstance(exc, (OSError, ValueError, KeyError, httpx.HTTPError)):
                    interruption = exc
        if ticket:
            try:
                response = client.post('http://localhost/transfer/end', json={**binding, 'ticket': ticket})
                response.raise_for_status()
            except BaseException as exc:
                if interruption is None and not isinstance(exc, (OSError, ValueError, KeyError, httpx.HTTPError)):
                    interruption = exc
        # Even an applied end with a lost reply needs an independent exact
        # adapter identity/availability readback. Never release another ticket.
        released = False
        try:
            response = client.get('http://localhost/identity')
            response.raise_for_status()
            identity = response.json()
            released = (identity.get('available') is True and identity.get('quarantined') is False
                        and identity.get('cdp_url') == info['cdp_url']
                        and identity.get('process_identity') == info['process_identity'])
        except BaseException as exc:
            if interruption is None and not isinstance(exc, (OSError, ValueError, KeyError, httpx.HTTPError)):
                interruption = exc
    if interruption is not None:
        interruption.add_note('fixture promotion interrupted; source='
                              + ('owner-preserved' if released else 'cleanup-incomplete'))
        raise interruption.with_traceback(interruption.__traceback__)
    return (True if verified and released and ticket else
            'source-cleanup-incomplete' if not released else False)


def manager_fixture_promote(source_lease_id, *, origin, owner_agent_id, owner_run_id):
    """Owner-initiated fixture promotion; records no auth material."""
    import browser_profile_lease as profiles
    from agents.browser_auth_site_contract import SiteContractError
    unavailable = lambda reason: {'status': 'auth-clone-unavailable', 'reason': reason}
    if not _fixture_origin(origin) or not source_lease_id:
        return unavailable('site-contract-unavailable')
    with node_lock(STATE):
        with db() as store, profiles.connect(STATE.parent / 'browser_profile_leases.sqlite') as leases:
            profiles.init_db(leases)
            leases.execute('BEGIN IMMEDIATE')
            source = _fixture_source(store, leases, source_lease_id, owner_agent_id, owner_run_id)
            if not source:
                return unavailable('manager-identity-unverified')
            try:
                _fixture_site_contract(origin)
            except SiteContractError:
                return unavailable('site-contract-unavailable')
            row, info = source
            identity = _fixture_identity(row, info)
            # Keep the ownership lock across the native check and metadata write:
            # concurrent promotions cannot both publish from the same snapshot.
            check = _fixture_native_source_check(row, info, origin)
            if check is not True:
                return unavailable('source-cleanup-incomplete' if check == 'source-cleanup-incomplete'
                                   else 'source-app-check-failed')
            source = _fixture_source(store, leases, source_lease_id, owner_agent_id, owner_run_id)
            if not source or _fixture_identity(*source) != identity:
                return unavailable('source-changed')
            key = FIXTURE_POOL
            old = store.execute('SELECT generation FROM fixture_generations WHERE program=? AND auth_domain=? AND account=?', key).fetchone()
            generation = (old['generation'] if old else 0) + 1
            store.execute('''INSERT INTO fixture_generations VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(program,auth_domain,account) DO UPDATE SET generation=excluded.generation,
                source_lease=excluded.source_lease, source_identity=excluded.source_identity,
                contract_revision=excluded.contract_revision, origin=excluded.origin''',
                (*key, generation, source_lease_id, identity, FIXTURE_CONTRACT_REVISION, origin))
            # Never overwrite a recipient in flight. An applying reservation is
            # held only during transfer outside this lock; reject promotions then.
            if store.execute("SELECT 1 FROM fixture_peers WHERE state='applying'").fetchone():
                store.rollback()
                return unavailable('peer-transfer-in-progress')
            store.execute('''INSERT INTO fixture_peers VALUES (?,?,?,?,?, 'applied')
                ON CONFLICT(lease_id) DO UPDATE SET program=excluded.program,
                auth_domain=excluded.auth_domain, account=excluded.account,
                generation=excluded.generation, state='applied' ''',
                (source_lease_id, *key, generation))
            for peer in store.execute("SELECT lease_id FROM browsers WHERE program=? AND auth_domain=? AND account=? AND lease_id<>?", (*key, source_lease_id)):
                store.execute('''INSERT INTO fixture_peers VALUES (?,?,?,?,?, 'pending')
                    ON CONFLICT(lease_id) DO UPDATE SET program=excluded.program,
                    auth_domain=excluded.auth_domain, account=excluded.account,
                    generation=excluded.generation, state='pending' ''',
                    (peer['lease_id'], *key, generation))
            return {'status': 'fixture-generation-promoted', 'generation': generation}


def manager_fixture_pending(recipient_lease_id):
    """Metadata-only readback; never an instruction to navigate a running peer."""
    with db() as store:
        peer = store.execute('SELECT * FROM fixture_peers WHERE lease_id=?', (recipient_lease_id,)).fetchone()
        current = store.execute('SELECT * FROM browsers WHERE lease_id=?', (recipient_lease_id,)).fetchone()
        if not peer or not current or tuple(current[k] for k in ('program', 'auth_domain', 'account')) != tuple(peer[k] for k in ('program', 'auth_domain', 'account')):
            return {'status': 'auth-clone-unavailable', 'reason': 'pending-peer-unavailable'}
        return {'status': peer['state'], 'generation': peer['generation']}


def manager_fixture_apply(recipient_lease_id, *, generation, owner_agent_id, owner_run_id,
                          approved_boundary=False):
    """Fail closed until a manager-authenticated recipient approval channel exists."""
    return {'status': 'auth-clone-unavailable', 'reason': 'recipient-approval-required'}


def manager_fixture_auth_transfer(source_lease_id, destination_lease_id, *, origin):
    """Private fixture-only synchronous transfer; never a CLI or generic site API.

    Only the disposable pool is supported. The manager selects a private
    fixture contract; the caller cannot supply selectors, scripts or a path.
    """
    from urllib.parse import urlsplit
    import browser_profile_lease as profiles
    import httpx
    if str(ROOT.parents[2]) not in sys.path:
        sys.path.insert(0, str(ROOT.parents[2]))
    from agents.browser_auth_site_contract import (SiteContractError, load_site_contract,
        verify_check_response, verify_cookie_scope)
    unavailable = lambda reason: {'status': 'auth-clone-unavailable', 'reason': reason}
    parsed = urlsplit(origin) if isinstance(origin, str) else None
    if (not parsed or parsed.scheme != 'http' or parsed.hostname != 'localhost'
            or not parsed.port or parsed.path or parsed.query or parsed.fragment
            or origin != f'http://localhost:{parsed.port}'
            or not isinstance(source_lease_id, str) or not isinstance(destination_lease_id, str)):
        return unavailable('site-contract-unavailable')

    class TransferError(Exception):
        pass

    def require(condition, reason):
        if not condition:
            raise TransferError(reason)

    bindings = {}

    def control(client, path, payload=None):
        payload = dict(payload or {})
        if path != 'begin':
            payload.update(bindings[id(client)])
        response = client.post('http://localhost/transfer/' + path, json=payload)
        response.raise_for_status()
        return response.json()

    def call(client, ticket, method, params=None):
        reply = control(client, 'call', {'ticket': ticket, 'method': method, 'params': params or {}})
        require('error' not in reply and 'result' in reply, 'browser-command-failed')
        return reply['result']

    def eval_js(client, ticket, expression):
        result = call(client, ticket, 'Runtime.evaluate',
                      {'expression': expression, 'returnByValue': True, 'awaitPromise': True})
        require('exceptionDetails' not in result, 'app-check-failed')
        return result.get('result', {}).get('value')

    def app_check(client, ticket):
        observation = eval_js(client, ticket, check)
        return _fixture_verified_observation(contract, observation)
    with node_lock(STATE):
        with db() as manager_db, profiles.connect(STATE.parent / 'browser_profile_leases.sqlite') as leases:
            profiles.init_db(leases)
            leases.execute('BEGIN IMMEDIATE')
            peer = manager_db.execute('SELECT 1 FROM fixture_peers WHERE lease_id=?',
                                      (destination_lease_id,)).fetchone()
            if peer:
                return unavailable('recipient-approval-required')
            # Policy flips must deny before healthy() probes either CDP endpoint.
            # This read-only gate verifies both exact owners in manager/canonical
            # rows; the full process, socket and health gate still follows.
            pool = _fixture_policy_pool(manager_db, leases, source_lease_id, destination_lease_id)
            if pool and profiles.single_browser_policy(leases, pool[0], pool[2], pool[1]):
                return unavailable('single-browser-policy')
            candidates = _transfer_candidates(manager_db, leases, source_lease_id, destination_lease_id)
            if not candidates:
                return unavailable('manager-identity-unverified')
            if any((row['program'], row['auth_domain'], row['account']) !=
                   ('fixture', 'fixture.invalid', 'anon') for row, _, _ in candidates):
                return unavailable('site-contract-unavailable')
            if any(info.get('control_socket') != str(STATE.parent / (row['browser_id'] + '.sock'))
                   for row, info, _ in candidates):
                return unavailable('manager-identity-unverified')
            # Both running owners may predate a policy flip. Resolve policy from
            # their verified pool while the manager and canonical locks are held;
            # never authenticate the second browser under effective single mode.
            source_row = candidates[0][0]
            if profiles.single_browser_policy(leases, source_row['program'],
                                              source_row['account'], source_row['auth_domain']):
                return unavailable('single-browser-policy')
            try:
                contract = _fixture_site_contract(origin)
            except SiteContractError:
                return unavailable('site-contract-unavailable')
            check = _fixture_check_expression(contract)

            # This is deliberately a fixture boundary, not a transport for
            # authenticated production accounts or arbitrary origins.
            clients = []
            tickets = []
            uncertain_begin = set()
            imported = False
            cleaned = True
            destination_end_unverified = False
            destination_quarantined = False
            source_recheck_failed = False
            committed_url = None
            activated = False
            activation_attempted = False
            activation_fenced = False
            readback_failure = None
            terminal_disposition = False
            reason = None
            interruption = None
            cleanup_failure = None
            def published_receipt(probe, phase):
                status = control(probe, 'status', {'ticket': tickets[1]})
                identity = probe.get('http://localhost/identity')
                identity.raise_for_status()
                state = identity.json()
                canonical = leases.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?',
                                           (destination_lease_id,)).fetchone()
                launch = record_info(candidates[1][0])
                row, original, _ = candidates[1]
                if not (status.get('phase') == phase and status.get('cdp_url') == committed_url and
                        state.get('quarantined') is False and
                        state.get('available') is (phase == 'finalized') and
                        state.get('process_identity') == original['process_identity'] and
                        state.get('cdp_url') == committed_url and
                        process_identity(original['process_identity']['pid']) == original['process_identity'] and
                        unit_active(row['unit']) and unit_identity(row['unit']) == original['unit_invocation'] and
                        launch.get('cdp_url') == committed_url and
                        launch.get('process_identity') == original['process_identity'] and
                        launch.get('unit_invocation') == original['unit_invocation'] and
                        canonical is not None and canonical['status'] == 'active' and
                        canonical['browser_status'] == 'running' and
                        canonical['owner_agent_id'] == row['agent_id'] and
                        canonical['owner_run_id'] == row['run_id'] and
                        canonical['service_unit'] == row['unit'] and
                        canonical['profile_dir'] == row['profile_dir'] and
                        canonical['manager_id'] == manager_id() and
                        canonical['cdp_url'] == committed_url):
                    return False
                # Exact public endpoint must accept the committed generation.
                public = httpx.get(committed_url + '/json/version', timeout=5)
                public.raise_for_status()
                return public.json().get('webSocketDebuggerUrl') == committed_url.replace('http:', 'ws:') + '/devtools/browser'
            # A post-import exception must not escape before exact recipient disposal.
            try:
                try:
                    for index, (row, info, _) in enumerate(candidates):
                        client = httpx.Client(transport=httpx.HTTPTransport(uds=info['control_socket']), timeout=15)
                        clients.append(client)
                        begin = {'transaction': uuid.uuid4().hex, 'owner': row['lease_id'],
                                 'generation': info['cdp_url'], 'destination': index == 1}
                        bindings[id(client)] = {k: begin[k] for k in ('transaction', 'owner', 'generation')}
                        try:
                            ticket = control(client, 'begin', begin)['ticket']
                        except BaseException as exc:
                            # The adapter may have applied begin before its reply was
                            # lost, including on cancellation. Replay only this
                            # exact manager-derived attempt before releasing it.
                            try:
                                ticket = control(client, 'begin', begin)['ticket']
                            except BaseException:
                                ticket = None
                                uncertain_begin.add(index)
                            tickets.append(ticket)
                            if isinstance(exc, (OSError, ValueError, httpx.HTTPError)):
                                raise TransferError('transfer-control-unavailable') from exc
                            raise
                        tickets.append(ticket)
                    source, destination = clients
                    st, dt = tickets
                    require(eval_js(source, st, 'location.origin') == origin, 'source-origin-mismatch')
                    source_url = eval_js(source, st, 'location.href')
                    require(app_check(source, st), 'source-app-check-failed')
                    # Destination must already be provisioned and at the exact origin;
                    # never overwrite an authenticated or populated destination.
                    require(eval_js(destination, dt, 'location.origin') == origin, 'destination-origin-mismatch')
                    require(not app_check(destination, dt), 'destination-not-empty')
                    require(eval_js(destination, dt, "localStorage.getItem('fixture-credential')") is None,
                            'destination-not-empty')
                    cookies = call(source, st, 'Network.getAllCookies')['cookies']
                    selected = [c for c in cookies if c['domain'] == contract.cookie_domain
                                and c['name'] == contract.cookie_name and c.get('path') == contract.cookie_path]
                    require(len(selected) == 1 and selected[0].get('httpOnly') is True,
                            'source-cookie-unverified')
                    try:
                        verify_cookie_scope(contract, browser_domain=selected[0]['domain'],
                            host_only=selected[0].get('hostOnly'), secure=selected[0].get('secure'),
                            browser_path=selected[0].get('path'))
                    except SiteContractError:
                        raise TransferError('source-cookie-unverified') from None
                    existing = call(destination, dt, 'Network.getAllCookies')['cookies']
                    require(not any(c['domain'] == contract.cookie_domain for c in existing), 'destination-not-empty')
                    storage = eval_js(source, st, "localStorage.getItem('fixture-credential')")
                    require(storage == 'approved', 'source-storage-unverified')
                    imported = True  # cleanup even if the CDP write succeeds but its reply is lost
                    call(destination, dt, 'Network.setCookies', {'cookies': selected})
                    eval_js(destination, dt, 'localStorage.setItem(' + json.dumps('fixture-credential') + ',' + json.dumps(storage) + ')')
                    require(app_check(destination, dt), 'destination-app-check-failed')
                    # Any failure in the post-import source recheck must dispose the
                    # imported recipient, including a lost source command reply.
                    source_recheck_failed = True
                    require(app_check(source, st) and eval_js(source, st, 'location.href') == source_url,
                            'source-changed')
                    source_recheck_failed = False
                    require(bool(_transfer_candidates(manager_db, leases, source_lease_id, destination_lease_id,
                                                      ticketed=True)),
                            'manager-identity-changed')
                    # Manager/canonical ownership stays serialized by node lock and
                    # BEGIN IMMEDIATE; the adapter's exclusive ticket fences CDP.
                except (TransferError, OSError, ValueError, KeyError, httpx.HTTPError) as exc:
                    reason = str(exc) if isinstance(exc, TransferError) else 'transfer-control-unavailable'
                except BaseException as exc:
                    if imported:
                        raise  # The outer boundary owns imported-recipient disposal.
                    interruption = exc
                    reason = 'transfer-interrupted'
                finally:
                    active_failure = sys.exc_info()[1]
                    if imported:
                        try:
                            if reason:
                                destination, dt = clients[1], tickets[1]
                                call(destination, dt, 'Network.deleteCookies',
                                     {'name': contract.cookie_name, 'url': origin + '/'})
                                eval_js(destination, dt, "localStorage.removeItem('fixture-credential')")
                                cleaned = (not app_check(destination, dt) and
                                           eval_js(destination, dt, "localStorage.getItem('fixture-credential')") is None and
                                           not any(c['domain'] == contract.cookie_domain for c in
                                                   call(destination, dt, 'Network.getAllCookies')['cookies']))
                        except BaseException as exc:
                            cleaned = False
                            if active_failure is None and interruption is None:
                                cleanup_failure = exc
                    for index, (client, ticket) in enumerate(zip(clients, tickets)):
                        if index in uncertain_begin:
                            cleaned = False
                            continue
                        if index == 1 and imported and (not cleaned or source_recheck_failed or cleanup_failure):
                            # Keep the recipient private until exact disposal, even
                            # when rollback appears clean after a source failure.
                            continue
                        try:
                            if index == 1 and reason and cleaned:
                                control(client, 'abort', {'ticket': ticket})
                                continue
                            control(client, 'end', {'ticket': ticket})
                            if index == 1 and imported and not reason:
                                destination_quarantined = True
                        except BaseException as exc:
                            if (not isinstance(exc, (OSError, ValueError, httpx.HTTPError))
                                    and active_failure is None and interruption is None and cleanup_failure is None):
                                cleanup_failure = exc
                            if index == 1:
                                cleaned = False
                                if imported:
                                    destination_end_unverified = True
                            else:
                                uncertain_begin.add(0)
                    for client in clients:
                        try:
                            client.close()
                        except BaseException as exc:
                            if active_failure is None and interruption is None and cleanup_failure is None:
                                cleanup_failure = exc
                if cleanup_failure is not None:
                    raise cleanup_failure.with_traceback(cleanup_failure.__traceback__)
                if uncertain_begin:
                    # A missing ticket or lost source-end reply is not proof of
                    # release. Check only this manager-recorded process/generation;
                    # never end an unrelated ticket or dispose the source.
                    for index in tuple(uncertain_begin):
                        try:
                            with httpx.Client(transport=httpx.HTTPTransport(
                                    uds=candidates[index][1]['control_socket']), timeout=15) as probe:
                                reply = probe.get('http://localhost/identity')
                                reply.raise_for_status()
                                observed = reply.json()
                                info = candidates[index][1]
                                if (observed.get('available') is True and
                                        observed.get('quarantined') is False and
                                        observed.get('cdp_url') == info['cdp_url'] and
                                        observed.get('process_identity') == info['process_identity']):
                                    uncertain_begin.remove(index)
                        except BaseException:
                            pass
                    if not imported:
                        cleaned = True
                source_unproved = 0 in uncertain_begin
                if interruption is not None:
                    interruption.add_note(
                        'fixture transfer interrupted; source='
                        + ('cleanup-incomplete' if source_unproved else 'owner-preserved')
                        + '; destination='
                        + ('cleanup-incomplete' if 1 in uncertain_begin else 'owner-preserved')
                    )
                    raise interruption.with_traceback(interruption.__traceback__)
                # Resolve source uncertainty before any destination commit. Even a
                # clean rollback cannot authorize release of an imported recipient
                # when source release or the post-import recheck is unproved.
                if (not reason and not uncertain_begin and not source_recheck_failed and
                        cleaned and destination_quarantined and not destination_end_unverified):
                    try:
                        with httpx.Client(transport=httpx.HTTPTransport(uds=candidates[1][1]['control_socket']), timeout=15) as check_client:
                            bindings[id(check_client)] = bindings[id(clients[1])]
                            identity = check_client.get('http://localhost/identity')
                            identity.raise_for_status()
                            observed = identity.json()
                            require(observed.get('quarantined') is True and
                                    observed.get('cdp_url') == candidates[1][1]['cdp_url'] and
                                    observed.get('process_identity') == candidates[1][1]['process_identity'],
                                    'destination-identity-changed')
                            # Source retains its owner and usable generation. Destination
                            # remains private throughout commit; an ACK is not activation.
                            committed = control(check_client, 'commit', {'ticket': tickets[1]})
                            require(committed.get('quarantined') is True, 'commit-unverified')
                            committed_url = committed['cdp_url']
                            info = record_info(candidates[1][0])
                            require(info.get('cdp_url') == candidates[1][1]['cdp_url'], 'destination-identity-changed')
                            info['cdp_url'] = committed_url
                            private_json(candidates[1][0]['launch_file'], info)
                            leases.execute('UPDATE browser_profile_leases SET cdp_url=? WHERE lease_id=? AND cdp_url=?',
                                           (committed_url, destination_lease_id, candidates[1][1]['cdp_url']))
                            require(leases.execute('SELECT changes()').fetchone()[0] == 1, 'manager-identity-changed')
                            leases.commit()
                            activation_attempted = True
                            require(control(check_client, 'activate', {'ticket': tickets[1]}).get('activated') is True,
                                    'activation-unverified')
                            # ACK alone is not an attestation of the published owner.
                    except BaseException as exc:
                        # The activate ACK (including a cancellation after application)
                        # cannot decide ownership. Reconcile all three exact authorities
                        # before treating the published recipient as committed.
                        if not isinstance(exc, (TransferError, OSError, ValueError, KeyError, httpx.HTTPError)):
                            interruption = exc
                    if committed_url:
                        try:
                            with httpx.Client(transport=httpx.HTTPTransport(
                                    uds=candidates[1][1]['control_socket']), timeout=15) as probe:
                                bindings[id(probe)] = bindings[id(clients[1])]
                                activated = published_receipt(probe, 'activated')
                        except BaseException as exc:
                            # Readback is only evidence of activation, never a
                            # new terminal decision or a replacement for the
                            # original pre-commit interruption.
                            if interruption is None and not isinstance(exc, (OSError, ValueError, KeyError, httpx.HTTPError, TransferError)):
                                readback_failure = exc
                    if activated:
                        # Retire the exact recovery ticket only after manager
                        # ownership/commit evidence. A lost finalize reply is
                        # not permission to leave an unverified public session.
                        finalized = False
                        try:
                            with httpx.Client(transport=httpx.HTTPTransport(
                                    uds=candidates[1][1]['control_socket']), timeout=15) as final_client:
                                bindings[id(final_client)] = bindings[id(clients[1])]
                                require(control(final_client, 'finalize', {'ticket': tickets[1]}).get('finalized') is True,
                                        'finalize-unverified')
                                finalized = published_receipt(final_client, 'finalized')
                        except BaseException:
                            try:
                                with httpx.Client(transport=httpx.HTTPTransport(
                                        uds=candidates[1][1]['control_socket']), timeout=15) as final_probe:
                                    bindings[id(final_probe)] = bindings[id(clients[1])]
                                    finalized = published_receipt(final_probe, 'finalized')
                            except BaseException:
                                pass
                        if not finalized:
                            # Ticket may still be live. Fence before exact disposal;
                            # never report success with an unverified public recipient.
                            activated = False
                            reason = 'finalize-unverified'
                    if activation_attempted and not activated:
                        # A failed activate readback does not prove the URL is
                        # private. Exact adapter recovery revokes admission and
                        # closes already admitted clients before any stop attempt.
                        # One retry handles an applied fence whose ACK was lost.
                        for _ in range(2):
                            try:
                                with httpx.Client(transport=httpx.HTTPTransport(
                                        uds=candidates[1][1]['control_socket']), timeout=15) as fence_client:
                                    bindings[id(fence_client)] = bindings[id(clients[1])]
                                    fenced = control(fence_client, 'fence', {'ticket': tickets[1]})
                                    activation_fenced = (fenced.get('fenced') is True and
                                                         fenced.get('quarantined') is True and
                                                         fenced.get('cdp_url') not in (committed_url, candidates[1][1]['cdp_url']))
                                    if activation_fenced:
                                        break
                            except BaseException:
                                pass  # Never substitute an unsuccessful fence for disposal.
                    # A missing ACK without exact readback is not success. Keep
                    # pre-activation cancellation distinct from post-activation commit.
                    destination_end_unverified = not activated
                    if activated:
                        interruption = None
                if imported and (source_unproved or source_recheck_failed or destination_end_unverified):
                    # The end may have applied even when its reply was lost. Its
                    # ticket cannot be relied on to fence an imported destination.
                    # Dispose only the exact recorded unit, while still holding the
                    # manager/canonical ownership locks; never leave it serving CDP.
                    terminal_disposition = True  # One exact stop attempt, even if interrupted.
                    try:
                        disposed = stop_recorded(candidates[1][0])
                        stop_failure = None
                    except BaseException as exc:
                        disposed = False
                        stop_failure = exc
                    terminal_note = (
                        'fixture transfer terminal activation uncertain; source='
                        + ('release-unverified' if source_unproved else 'owner-preserved')
                        + '; destination=' + ('disposed' if disposed else 'cleanup-incomplete')
                        + ('; public-exposure=possible' if activation_attempted else '')
                        + ('; public-fence=' + ('verified' if activation_fenced else 'unverified') if activation_attempted else '')
                    )
                    if interruption is not None:
                        interruption.add_note(
                            'fixture transfer interrupted before verified activation; source='
                            + ('release-unverified' if source_unproved else 'owner-preserved')
                            + '; destination=' + ('disposed' if disposed else 'cleanup-incomplete')
                            + ('; public-exposure=possible' if activation_attempted else '')
                            + ('; public-fence=' + ('verified' if activation_fenced else 'unverified') if activation_attempted else '')
                        )
                        raise interruption.with_traceback(interruption.__traceback__)
                    if readback_failure is not None or stop_failure is not None:
                        failure = readback_failure or stop_failure
                        assert failure is not None
                        failure.add_note(terminal_note)
                        raise failure.with_traceback(failure.__traceback__)
                    if source_unproved:
                        return {'status': 'auth-clone-unavailable', 'reason': 'source-cleanup-incomplete',
                                'source': 'release-unverified',
                                'destination': 'disposed' if disposed else 'cleanup-incomplete'}
                    if source_recheck_failed:
                        return {'status': 'auth-clone-unavailable', 'reason': reason or 'source-changed',
                                'source': 'owner-preserved',
                                'destination': 'disposed' if disposed else 'cleanup-incomplete'}
                    if disposed:
                        return unavailable('destination-disposed-after-end-uncertainty')
                    if activation_attempted:
                        if activation_fenced:
                            return {'status': 'auth-clone-unavailable',
                                    'reason': 'destination-fenced-after-activation-uncertainty',
                                    'source': 'owner-preserved', 'destination': 'fenced'}
                        return {'status': 'fixture-auth-transfer-terminal-uncertain',
                                'source': 'owner-preserved', 'destination': 'cleanup-incomplete',
                                'public_exposure': 'possible'}
                    return unavailable('destination-cleanup-incomplete')
                if uncertain_begin:
                    return unavailable(('source' if source_unproved else 'destination') + '-cleanup-incomplete')
                if not cleaned:
                    return unavailable('destination-cleanup-unverified')
                return unavailable(reason) if reason else {'status': 'fixture-auth-transferred'}
            finally:
                failure = sys.exc_info()[1]
                if failure is not None and imported and not activated and not terminal_disposition:
                    try:
                        disposed = stop_recorded(candidates[1][0])
                    except BaseException:
                        # Preserve the original cancellation/failure; a second
                        # interruption cannot prove disposal.
                        disposed = False
                    failure.add_note(
                        "fixture transfer interrupted; source release unverified; destination="
                        + ("disposed" if disposed else "cleanup-incomplete")
                    )

def metadata(c, row):
    r = c.execute(
        "select metadata from lifecycle where lease_id=?", (row["lease_id"],)
    ).fetchone()
    return json.loads(r[0]) if r else {}


def save_metadata(c, lid, value):
    c.execute("insert or replace into lifecycle values (?,?)", (lid, json.dumps(value)))
    c.commit()


def reconcile_transfers(c):
    # Recover a process crash between the canonical lease transaction and the
    # manager projection. Never infer a new owner from a run label or idle time.
    database = STATE.parent / "browser_profile_leases.sqlite"
    if not database.exists():
        return
    for row in c.execute("select * from browsers where state='running'").fetchall():
        meta = metadata(c, row)
        pending = meta.get("pending_transfer")
        if not pending:
            continue
        with sqlite3.connect(database) as leases:
            leases.row_factory = sqlite3.Row
            active = leases.execute(
                "select * from browser_profile_leases where profile_dir=? and status='active'",
                (row["profile_dir"],),
            ).fetchone()
        if not active or active["lease_id"] == row["lease_id"]:
            continue
        info = record_info(row)
        if (
            active["owner_agent_id"] != pending["agent_id"]
            or active["owner_run_id"] != pending["run_id"]
            or active["cdp_url"] != info.get("cdp_url")
        ):
            continue
        c.execute(
            "update browsers set lease_id=?,agent_id=?,run_id=?,purpose=?,updated=? where lease_id=?",
            (
                active["lease_id"],
                active["owner_agent_id"],
                active["owner_run_id"],
                active["purpose"],
                now(),
                row["lease_id"],
            ),
        )
        save_metadata(c, active["lease_id"], pending["metadata"])


def serialized(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        with node_lock(STATE):
            reconcile_transfers(db())
            return function(*args, **kwargs)

    return wrapped


def meminfo():
    d = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        k, v = line.split(":", 1)
        d[k] = int(v.strip().split()[0]) // 1024
    return d.get("MemAvailable", 0), d.get("SwapFree", 0)


def admission(ram, swap):
    a, b = meminfo()
    return {
        "status": "admitted" if a >= ram and b >= swap else "rejected",
        "ram_available_mib": a,
        "swap_free_mib": b,
        "required_ram_available_mib": ram,
        "required_swap_free_mib": swap,
    }


def lease(args, *parts):
    selection_proof = getattr(args, '_selection_proof', None)
    manager = hashlib.sha256(str(STATE.resolve()).encode()).hexdigest()
    p = subprocess.run(
        [
            sys.executable,
            str(LEASE),
            "--state-dir",
            str(STATE.parent),
            "--json",
            *parts,
            *(
                ["--manager-id", manager]
                if parts[0] in ("acquire", "renew", "register-browser", "release")
                else []
            ),
        ],
        capture_output=True,
        text=True,
        input=selection_proof + '\n' if selection_proof else None,
    )
    try:
        return json.loads(p.stdout)
    except Exception:
        return {"status": "lease-error", "detail": p.stderr.strip() or p.stdout.strip()}


def sysenv():
    e = os.environ.copy()
    e["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"
    e["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={e['XDG_RUNTIME_DIR']}/bus"
    return e


def unit_active(unit):
    p = subprocess.run(
        ["systemctl", "--user", "is-active", "--quiet", unit], env=sysenv()
    )
    return p.returncode == 0


def unit_inactive(unit):
    result = subprocess.run(
        ["systemctl", "--user", "show", "--property=ActiveState", "--value", unit],
        capture_output=True, text=True, env=sysenv(),
    )
    return result.returncode == 0 and result.stdout.strip() in ("inactive", "failed")


def unit_identity(unit):
    result = subprocess.run(
        ["systemctl", "--user", "show", "--property=InvocationID", "--value", unit],
        capture_output=True,
        text=True,
        env=sysenv(),
    )
    return result.stdout.strip() if result.returncode == 0 else None


def stop_recorded(row):
    info = record_info(row)
    if unit_active(row["unit"]):
        expected = info.get("unit_invocation")
        if not expected or unit_identity(row["unit"]) != expected:
            return False
    stop_unit(row["unit"])
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if stopped(row):
            return True
        time.sleep(0.1)
    return False


def stop_unit(unit):
    subprocess.run(
        ["systemctl", "--user", "stop", unit],
        env=sysenv(),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["systemctl", "--user", "reset-failed", unit],
        env=sysenv(),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def port_open(port):
    with socket.socket() as sock:
        sock.settimeout(.2)
        return sock.connect_ex(("127.0.0.1", port)) == 0

def endpoint_open(address):
    try:
        parsed = urlsplit(address)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        with socket.create_connection((parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)), timeout=.5):
            return True
    except (ValueError, OSError):
        return False

def ca_fingerprint(path):
    try:
        data = path.read_bytes()
        return hashlib.sha256(data).hexdigest() if data else None
    except OSError:
        return None

def replay_clients_absent(port):
    """Unknown socket state is not proof of idleness."""
    try:
        for table in ("/proc/net/tcp", "/proc/net/tcp6"):
            for line in Path(table).read_text().splitlines()[1:]:
                fields = line.split()
                if int(fields[1].rsplit(":", 1)[1], 16) == port and fields[3] != "0A":
                    return False
        return True
    except (OSError, ValueError, IndexError):
        return False

def proxy_quiet(row):
    flow = Path(proxy_metadata(row)["flow_file"])
    cutoff = now() - 7200
    return (row["updated"] < cutoff and replay_clients_absent(row["port"])
            and (not flow.exists() or flow.stat().st_mtime < cutoff))


def proxy_row(c, args):
    return c.execute("select * from task_proxies where agent_id=? and run_id=?",
                     (args.agent_id, args.run_id)).fetchone()


def proxy_metadata(row):
    if not row:
        return None
    root = Path(row["run_dir"])
    return {"lane": row["lane"], "proxy_server": f"http://127.0.0.1:{row['port']}",
            "ca_cert": str(root / "mitmproxy" / "mitmproxy-ca-cert.pem"),
            "flow_file": str(root / "flows.mitm"), "unit": row["unit"], "state": row["state"]}


def mitm_runtime():
    executable = shutil.which("mitmdump")
    if not executable:
        raise RuntimeError("mitmdump is unavailable")
    resolved = Path(executable).resolve()
    shebang = resolved.open("rb").readline().decode("utf-8", errors="replace").strip()
    if not shebang.startswith("#!/") or not Path(shebang[2:]).is_file():
        raise RuntimeError("mitmdump Python interpreter is unavailable")
    return str(resolved), shebang[2:]


def proxy_ready(row):
    ca = Path(proxy_metadata(row)["ca_cert"])
    return (unit_active(row["unit"]) and bool(row["invocation"])
            and unit_identity(row["unit"]) == row["invocation"]
            and port_open(row["port"]) and ca.is_file() and ca.stat().st_size > 0)


def start_proxy(c, args):
    c.execute("BEGIN IMMEDIATE")
    row = proxy_row(c, args)
    if row:
        c.commit()
        if ((row["program"], row["account"], row["purpose"]) !=
                (slug(args.program), slug(args.account), args.purpose)
                or row["state"] != "running" or not proxy_ready(row)):
            emit({"status": "proxy-conflict", "detail": "task listener unavailable or belongs to another request"}, 2)
        return row, False
    port = next((p for p in range(8081, 8091) if not c.execute(
        "select 1 from task_proxies where port=?", (p,)).fetchone() and not port_open(p)), None)
    if port is None:
        c.rollback()
        emit({"status": "proxy-unavailable", "detail": "no task MITM port available"}, 2)
    lane = "task-" + uuid.uuid4().hex
    root = STATE.parent / "task-proxies" / lane
    c.execute("delete from finished_proxies where agent_id=? and run_id=?", (args.agent_id, args.run_id))
    owner = process_identity(args.owner_pid) if getattr(args, "owner_pid", None) else None
    c.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state,updated,owner) values(?,?,?,?,?,?,?,?,?,?,?,?)",
              (args.agent_id, args.run_id, slug(args.program), slug(args.account), args.purpose,
               lane, port, "task-mitm-" + lane, str(root), "starting", now(), json.dumps(owner) if owner else None))
    c.commit()
    row = proxy_row(c, args)
    try:
        root.mkdir(parents=True, mode=0o700)
        os.chmod(root, 0o700)
        conf = root / "mitmproxy"
        conf.mkdir(mode=0o700)
        os.chmod(conf, 0o700)
        cmd = [mitm_runtime()[0], "--listen-host", "127.0.0.1", "--listen-port", str(port),
               "--set", f"confdir={conf}", "--set", "flow_detail=0", "-w", str(root / "flows.mitm")]
        result = subprocess.run(["systemd-run", "--user", "--unit=" + row["unit"],
                                 "--property=UMask=0077", "--property=MemoryMax=512M", "--", *cmd],
                                capture_output=True, text=True, env=sysenv())
        if result.returncode:
            raise RuntimeError("task MITM service failed to start")
        invocation = unit_identity(row["unit"])
        if not invocation:
            raise RuntimeError("task MITM unit identity unavailable")
        c.execute("update task_proxies set invocation=?,updated=? where lane=?", (invocation, now(), lane))
        c.commit()
        row = proxy_row(c, args)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if proxy_ready(row):
                break
            if not unit_active(row["unit"]):
                break
            time.sleep(.1)
        if not proxy_ready(row):
            raise RuntimeError("task MITM listener or CA not ready")
        c.execute("update task_proxies set state='running',updated=? where lane=?", (now(), lane))
        c.commit()
        return proxy_row(c, args), True
    except Exception:
        rollback_proxy(c, proxy_row(c, args))
        raise


def rollback_proxy(c, row):
    if unit_active(row["unit"]):
        if not row["invocation"] or unit_identity(row["unit"]) != row["invocation"]:
            c.execute("update task_proxies set state='cleanup-failed',updated=? where lane=?", (now(), row["lane"]))
            c.commit()
            return False
        stop_unit(row["unit"])
    if unit_active(row["unit"]) or port_open(row["port"]):
        c.execute("update task_proxies set state='cleanup-failed',updated=? where lane=?", (now(), row["lane"]))
        c.commit()
        return False
    c.execute("delete from task_proxies where lane=?", (row["lane"],))
    c.commit()
    return True


def proxy_mode(args):
    if args.proxy == "mitm" and (args.proxy_server or args.mitm_ca_cert or args.proxy_cert_mode != "import" or args.proxy_ownership != "task"):
        emit({"status": "invalid-proxy-options", "detail": "task MITM requires task ownership and CA import"}, 2)
    if args.proxy == "none" and (args.proxy_server or args.mitm_ca_cert):
        emit({"status": "invalid-proxy-options"}, 2)
    if args.proxy == "external" and not args.proxy_server:
        emit({"status": "invalid-proxy-options", "detail": "external requires --proxy-server"}, 2)


def matching_proxy(c, args, row):
    task = proxy_row(c, args)
    info = record_info(row)
    if args.proxy == "mitm":
        if not task or task["state"] != "running" or not proxy_ready(task):
            return False
        expected = proxy_metadata(task)
        return (info.get("proxy_server") == expected["proxy_server"]
                and info.get("proxy_cert_mode") == "import"
                and info.get("proxy_cert_status", {}).get("status") == "trusted"
                and info.get("proxy_cert_status", {}).get("ca_cert") == expected["ca_cert"]
                and bool(info.get("proxy_cert_status", {}).get("ca_sha256"))
                and info["proxy_cert_status"]["ca_sha256"] == ca_fingerprint(Path(expected["ca_cert"])))
    if task or info.get("proxy_server") != (args.proxy_server if args.proxy == "external" else None):
        return False
    if args.proxy == "none":
        return info.get("proxy_cert_mode") == "none" and "--no-proxy-server" in info.get("command", [])
    if not endpoint_open(args.proxy_server):
        return False
    if info.get("proxy_cert_mode") != args.proxy_cert_mode:
        return False
    if args.proxy_cert_mode in ("auto", "import"):
        cert = info.get("proxy_cert_status", {})
        requested = str(resolve_mitm_ca_cert(args.mitm_ca_cert or str(DEFAULT_CA_CERT), args.proxy_server))
        if (cert.get("ca_cert") != requested or cert.get("status") != "trusted"
                or not cert.get("ca_sha256") or cert["ca_sha256"] != ca_fingerprint(Path(requested))):
            return False
    return True


def failed_launch(c, lid, unit):
    stop_unit(unit)
    if unit_active(unit):
        return False
    c.execute("update browsers set state='stopped',updated=? where lease_id=?", (now(), lid))
    c.commit()
    return True


def rollback_failed_browser_proxy(c, task, created, profile):
    if not created:
        return True
    ca = Path(proxy_metadata(task)["ca_cert"])
    try:
        if ca.is_file():
            remove_matching_ca(profile, ca, home_dir=profile / "home")
    except (OSError, RuntimeError, ValueError):
        c.execute("update task_proxies set state='cleanup-failed',updated=? where lane=?", (now(), task["lane"]))
        c.commit()
        return False  # Keep reservation and CA pending explicit recovery.
    return rollback_proxy(c, task)


def safe(row):
    info = record_info(row)
    result = {key: row[key] for key in (
        "browser_id", "lease_id", "program", "account", "auth_domain", "state",
        "tab_count", "last_activity", "created", "updated",
    )}
    result.update(instance_id=row["browser_id"], pane_id=row["browser_id"],
                  instance_key=info.get("instance_key", ""),
                  account_color=info.get("account_color"),
                  driving_mode=info.get("driving_mode", "legacy"))
    activity = activity_snapshot(row) if row["state"] == "running" else None
    if activity and not activity.get("unavailable"):
        result["last_activity"] = activity["last_activity"]
    return result


def release_lease(lease_id, agent, disp="cancelled", health="healthy"):
    return lease(
        None,
        "release",
        "--lease-id",
        lease_id,
        "--agent-id",
        agent,
        "--disposition",
        disp,
        "--profile-health",
        health,
    )


def profile_path(program, account):
    return (
        Path(os.environ.get("HARNESS_BOUNTY_ARTIFACT_ROOT", "/mnt/bounty"))
        / slug(program)
        / "web"
        / "browser-profiles"
        / slug(account)
    )


def record_info(row):
    try:
        return json.loads(Path(row["launch_file"]).read_text())
    except (OSError, ValueError):
        return {}


def healthy(row):
    info = record_info(row)
    if not info.get("cdp_url") or not unit_active(row["unit"]):
        return False
    if owner_state(info.get("process_identity")) != "active":
        return False
    if not info.get("unit_invocation") or info["unit_invocation"] != unit_identity(
        row["unit"]
    ):
        return False
    import browser_profile_lease as profiles

    return profiles.local_cdp_version(info["cdp_url"])["status"] == "ready"


def stopped(row):
    info = record_info(row)
    if unit_active(row["unit"]):
        return False
    identity = info.get("process_identity")
    if row["state"] == "running" and not identity:
        return False
    if identity and owner_state(identity) != "terminal":
        return False
    if info.get("cdp_url"):
        import browser_profile_lease as profiles

        if profiles.local_cdp_version(info["cdp_url"])["status"] == "ready":
            return False
    return True


def browser_blocks_proxy(c, row):
    if row["state"] in ("stopped", "deleted"):
        return unit_active(row["unit"])
    if row["state"] != "starting" or not unit_inactive(row["unit"]):
        return True
    # Interrupted dispatch has no registered process identity, but its launch
    # receipt may contain a PID and CDP endpoint.
    info = record_info(row)
    if info.get("pid"):
        try:
            if process_identity(info["pid"]) is not None:
                return True
        except (OSError, ValueError, TypeError):
            return True
    if not stopped(row) or not unit_inactive(row["unit"]):
        return True
    # Never stop an inactive unit by name: it may have been reused. Preserve
    # lease and profile health; only reconcile the manager's startup intent.
    c.execute("update browsers set state='stopped',updated=? where lease_id=? and state='starting'",
              (now(), row["lease_id"]))
    return False


def stop_receipt(row):
    info = record_info(row)
    private_json(
        row["launch_file"],
        {key: info.get(key) for key in ("process_identity", "unit_invocation", "pid", "instance_key", "instance_selection", "instance_id", "pane_id", "account_color", "driving_mode")},
    )


def stale_singleton_lock(path, row):
    identity = record_info(row).get("process_identity")
    if not identity or owner_state(identity) != "terminal":
        return False
    try:
        return (
            path.is_symlink()
            and str(path.readlink()) == f"{identity['node']}-{identity['pid']}"
            and process_identity(identity["pid"]) is None
        )
    except (OSError, ValueError):
        return False


def retire(c, row, health="healthy"):
    if reservation_blocks(row):
        return False
    if not stop_recorded(row):
        return False
    q = release_lease(row["lease_id"], row["agent_id"], health=health)
    if q.get("status") != "released":
        return False
    c.execute(
        "update browsers set state='stopped',updated=? where lease_id=?",
        (now(), row["lease_id"]),
    )
    c.commit()
    return True


def selected_browser(c, program, alias, domain, key):
    rows = c.execute(
        "SELECT * FROM browsers WHERE program=? AND account=? AND auth_domain=? ORDER BY created DESC",
        (slug(program), slug(alias), domain),
    ).fetchall()
    # Existing legacy manifests may use pre-domain paths. Do not migrate or
    # silently abandon them simply because the canonical path has changed.
    return next((row for row in rows if record_info(row).get("instance_key", "") == key), None)


def quiescent_legacy(c, rows, legacy):
    """Conservatively prove a stopped profile has no observable live root."""
    path = legacy['profile_dir']
    import browser_profile_lease as profiles
    identity = profiles.physical_profile(path)
    if not identity or any(profiles.physical_profile(r['profile_dir']) != identity or r['state'] != 'stopped' or
           unit_active(r['unit']) or not stopped(r) for r in rows if record_info(r).get('instance_key', '') == ''):
        return False
    if os.path.lexists(Path(path) / 'SingletonLock'):
        return False  # Missing receipt cannot authenticate a stale lock owner.
    needle = os.fsencode(path)
    for proc in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            argv = proc.read_bytes().split(b'\0')
        except FileNotFoundError:
            continue
        except (OSError, PermissionError):
            continue  # Another user's process cannot own this user's profile.
        if any(arg == needle or arg == b'--user-data-dir=' + needle or
               (arg.startswith(b'--user-data-dir=') and
                profiles.physical_profile(os.fsdecode(arg.split(b'=', 1)[1])) == identity)
               for arg in argv):
            return False
    return True


def legacy_profile_paths(program, alias, domain):
    import browser_profile_lease as profiles
    scoped = profiles.profile_dir(program, domain, alias)
    return (
        scoped,
        profiles.profile_dir(program, profiles.DEFAULT_LEGACY_AUTH_DOMAIN, alias),
        scoped.parent.parent / slug(alias),
        profiles.shared_base() / profiles.program_key(program) / "ghost" / "chromium-test" / "profiles" / slug(alias),
    )


def shared_profile_rows(c, profile, program):
    import browser_profile_lease as profiles
    identity = profiles.physical_profile(profile)
    if not identity:
        return None
    shared = []
    for row in c.execute("SELECT * FROM browsers"):
        path = row['profile_dir']
        # Old positional inserts into an ALTER TABLE layout shifted the profile
        # into launch_file. Recognize that shape before testing physical aliases.
        if (path == 'browser-' + row['browser_id'] and
                str(row['state']).endswith('.launch.json') and
                str(row['tab_count']) in ('starting', 'running', 'stopped', 'idle-stopped')):
            path = row['launch_file']
        other = profiles.physical_profile(path)
        if other == identity or (other is None and row['program'] == slug(program) and
                                 row['state'] not in ('stopped', 'deleted', 'handed-off')):
            shared.append(row)
    return shared


def automatic_instance(c, args, alias, domain, *, allow_takeover=False, allow_migration=False):
    """Select under the node lock; acquisition/freeze still arbitrate ownership.

    Never copy a legacy profile or treat unobservable native use as idle.
    Explicit slots remain explicit; only manager-created auto slots are pooled.
    """
    import browser_profile_lease as profiles

    rows = c.execute(
        "SELECT * FROM browsers WHERE program=? AND account=? AND auth_domain=? ORDER BY created DESC",
        (slug(args.program), slug(alias), domain),
    ).fetchall()
    latest = {}
    for row in rows:
        latest.setdefault(record_info(row).get("instance_key", ""), row)
    legacy = latest.get("")
    shared = shared_profile_rows(c, legacy['profile_dir'], args.program) if legacy else []
    if legacy:
        if shared is None or any(r['lease_id'] != legacy['lease_id'] and
               (r['state'] != 'stopped' or not stopped(r)) for r in shared):
            if legacy['state'] == 'stopped':
                emit({'status': 'recovery-blocked', 'reason': 'legacy-profile-not-quiescent'}, 2)
            return ""
        if legacy['agent_id'] == args.agent_id and legacy['run_id'] == args.run_id and legacy['state'] == 'running':
            return ""  # Preserve the authenticated legacy profile for its owner/next user.
        pooled_running = any(r['state'] == 'running' and
                             record_info(r).get('instance_selection') == 'automatic'
                             for k, r in latest.items() if k)
        if legacy['state'] == 'stopped' and not quiescent_legacy(c, shared + [r for r in rows if r['lease_id'] not in {s['lease_id'] for s in shared}], legacy):
            emit({'status': 'recovery-blocked', 'reason': 'legacy-profile-not-quiescent'}, 2)
        if legacy['state'] == 'stopped' and not pooled_running:
            return ""  # First request inherits the old authenticated profile.
        if not allow_migration or (legacy['state'] == 'running' and not healthy(legacy)):
            return ""
    # Historical leases and existing disk data are migration boundaries even
    # when no running browser is registered in this manager.
    lease_db = STATE.parent / "browser_profile_leases.sqlite"
    if lease_db.exists() and not legacy:
        with sqlite3.connect(f"file:{lease_db}?mode=ro", uri=True) as leases:
            columns = {r[1] for r in leases.execute("PRAGMA table_info(browser_profile_leases)")}
            if columns:
                key_filter = "AND COALESCE(instance_key, '')=''" if "instance_key" in columns else ""
                if leases.execute(
                    "SELECT 1 FROM browser_profile_leases WHERE program=? AND account_alias=? "
                    "AND (auth_domain=? OR auth_domain IS NULL) " + key_filter + " LIMIT 1",
                    (slug(args.program), slug(alias), domain),
                ).fetchone():
                    return ""
    legacy_paths = legacy_profile_paths(args.program, alias, domain)
    if any(path.exists() for path in legacy_paths) and not legacy:
        return ""
    if legacy:
        manager = hashlib.sha256(str(STATE.resolve()).encode()).hexdigest()
        # Canonical history alone cannot attest to older unkeyed manager
        # projections. Reconcile every such row before opening concurrency;
        # only the selected lease may still be running. A stopped historical
        # row needs its own inactive unit and terminal recorded root/CDP.
        unkeyed = [r for r in rows if record_info(r).get('instance_key', '') == '']
        identity = profiles.physical_profile(legacy['profile_dir'])
        if (shared is None or not identity or any(profiles.physical_profile(r['profile_dir']) != identity or
                (r['lease_id'] != legacy['lease_id'] and
                 (r['state'] != 'stopped' or not stopped(r)))
                for r in unkeyed) or
                any(r['lease_id'] != legacy['lease_id'] and
                    (r['state'] != 'stopped' or not stopped(r)) for r in (shared or [])) or
                Path(legacy['profile_dir']) not in legacy_paths or
                not profiles.register_legacy_auto(lease_db, slug(args.program), slug(alias), domain,
                                                  legacy['profile_dir'], manager, legacy['lease_id'],
                                                  legacy['agent_id'], legacy['run_id'],
                                                  legacy_running=legacy['state'] == 'running')):
            return ""
    pooled = [(key, row) for key, row in latest.items()
              if record_info(row).get("instance_selection") == "automatic"]
    for key, row in pooled:
        if row["state"] == "running" and row["agent_id"] == args.agent_id and row["run_id"] == args.run_id:
            return key
    if allow_takeover:
        for key, row in pooled:
            if row["state"] == "running" and lifecycle_state(c, row) == "idle":
                return key  # start() must win the authoritative adapter freeze.
    for key, row in pooled:
        if row["state"] == "stopped":
            return key  # canonical lease health/policy remains authoritative.
    key = "auto-" + hashlib.sha256((args.agent_id + "\0" + args.run_id).encode()).hexdigest()[:24]
    # The original slot may now belong to an active transferee, or an explicit
    # caller may have used the same key. Never reacquire it by hash coincidence.
    return key if key not in latest else "auto-" + uuid.uuid4().hex


def account_policy(program, alias, domain):
    import browser_profile_lease as profiles
    path = STATE.parent / "browser_profile_leases.sqlite"
    if not path.exists():
        return False
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as leases:
        return profiles.single_browser_policy(leases, program, alias, domain)


def canonical_claim(row, instance, single):
    """Validate the manager projection before revoking any other owner's control.

    The canonical transaction still arbitrates acquisition/transfer. This check
    prevents evicting a stale projection or one of several grandfathered single
    policy browsers when doing so cannot admit this request.
    """
    import browser_profile_lease as profiles
    path = STATE.parent / "browser_profile_leases.sqlite"
    if not path.exists():
        return False
    with profiles.connect(path) as leases:
        active = leases.execute(
            "SELECT * FROM browser_profile_leases WHERE program=? AND account_alias=? "
            "AND (auth_domain=? OR auth_domain IS NULL) AND status='active' "
            "AND (expires_at>? OR manager_id IS NOT NULL OR cdp_url IS NOT NULL)",
            (row["program"], row["account"], row["auth_domain"], now()),
        ).fetchall()
    expected = {
        "lease_id": row["lease_id"], "owner_agent_id": row["agent_id"],
        "owner_run_id": row["run_id"], "profile_dir": row["profile_dir"],
        "instance_key": instance,
        "manager_id": hashlib.sha256(str(STATE.resolve()).encode()).hexdigest(),
    }
    matching = [lease for lease in active if all(lease[key] == value for key, value in expected.items())]
    conflicts = [lease for lease in active if lease["lease_id"] != row["lease_id"]
                 and (single or not instance or not lease["instance_key"] or lease["instance_key"] == instance)]
    return len(matching) == 1 and not conflicts


def select_display(c, args):
    """Reserve an unused display/loopback port while start holds the node lock."""
    if getattr(args, "headless", False) or getattr(args, "display_backend", None) == "default":
        return
    from kasmvnc_session import candidate_web_ports, can_bind_localhost, validate_display, KasmVNCSessionError

    used = set()
    used_ports = set()
    for row in c.execute("SELECT * FROM browsers WHERE state='running'").fetchall():
        session = record_info(row).get("kasmvnc", {})
        display = session.get("display")
        if display:
            used.add(display)
        if session.get("web_port"):
            used_ports.add(session["web_port"])
    requested = getattr(args, "kasmvnc_display", None)
    candidates = [validate_display(requested)] if requested is not None else range(20, 1000)
    for display in candidates:
        if (f":{display}" not in used and not Path(f"/tmp/.X11-unix/X{display}").exists()
                and not Path(f"/tmp/.X{display}-lock").exists()):
            for port in candidate_web_ports(getattr(args, "kasmvnc_web_port", None)):
                if port not in used_ports and can_bind_localhost(port):
                    args.kasmvnc_display = display
                    args.kasmvnc_web_port = port
                    return
            raise KasmVNCSessionError("no unused requested KasmVNC web port available")
    raise KasmVNCSessionError("no unused requested KasmVNC display available")


def activity_snapshot(row):
    info = record_info(row)
    if (not info.get("activity_tracking")
            or info.get("driving_mode") not in (None, "agent-driven")):
        return None
    from browser_control import activity_control
    try:
        return activity_control(info["control_socket"])
    except Exception:
        return {"unavailable": True}


def freeze_idle(row, seconds):
    from browser_control import activity_control
    try:
        return activity_control(record_info(row)["control_socket"], "freeze",
                                idle_seconds=seconds).get("frozen", False)
    except Exception:
        return False


def restore_failed_stop(row):
    # Do not thaw a half-stopped, replaced, or unidentifiable runtime. A healthy
    # exact original runtime can resume under its unchanged owner/generation.
    if not healthy(row):
        return False
    from browser_control import activity_control
    try:
        return activity_control(record_info(row)["control_socket"], "thaw").get("frozen") is False
    except Exception:
        return False


def cleanup_unused(c):
    stopped_ids = []
    for row in c.execute("SELECT * FROM browsers WHERE state='running'").fetchall():
        activity = activity_snapshot(row)
        if (not activity or activity.get("unavailable") or activity["idle_seconds"] < 7200
                or activity["inflight"] or activity["reserved_seconds"]):
            continue
        # Recheck AND freeze in the adapter's event loop, not a stale file snapshot.
        if freeze_idle(row, 7200):
            if retire(c, row):
                stopped_ids.append(row["browser_id"])
            else:
                meta = metadata(c, row)
                meta["control_restored"] = restore_failed_stop(row)
                meta["lifecycle_error"] = "idle-stop-not-verified"
                save_metadata(c, row["lease_id"], meta)
    return stopped_ids


def lifecycle_state(c, row):
    meta = metadata(c, row)
    activity = activity_snapshot(row)
    if activity is not None:
        if activity.get("unavailable"):
            return "activity-unavailable"
        if activity["inflight"] or activity["reserved_seconds"]:
            return "active"
        if owner_state(meta.get("owner")) == "terminal":
            return "terminal"
        return "idle" if activity["idle_seconds"] >= meta.get("idle_claim_seconds", DEFAULT_IDLE) else "active"
    owner = owner_state(meta.get("owner"))
    if meta.get("awaiting_until"):
        if owner == "active" and record_info(row).get("driving_mode") == "manual":
            return "active"
        return "expired-awaiting-input" if now() >= meta["awaiting_until"] else "active"
    return owner


def monitor_unit(bid):
    return "browser-owner-" + bid


def start_watcher(bid):
    command = [
        "systemd-run",
        "--user",
        "--collect",
        "--unit=" + monitor_unit(bid),
        "--property=Restart=on-failure",
    ]
    for key in (
        "BROWSER_PROVISIONER_STATE",
        "HARNESS_BOUNTY_ARTIFACT_ROOT",
        "HARNESS_SHARED_BASE",
    ):
        if key in os.environ:
            command.append("--setenv=" + key + "=" + os.environ[key])
    command += [
        "--",
        sys.executable,
        str(Path(__file__).resolve()),
        "watch",
        "--browser-id",
        bid,
    ]
    result = subprocess.run(command, capture_output=True, text=True, env=sysenv())
    if result.returncode or not unit_active(monitor_unit(bid)):
        raise RuntimeError("could not start browser lifecycle supervisor")


def maintain(args):
    with node_lock(STATE):
        c = db()
        reconcile_transfers(c)
        browser_id = getattr(args, "browser_id", None)
        rows = c.execute(
            "select * from browsers where state='running' AND (? IS NULL OR browser_id=?)",
            (browser_id, browser_id),
        ).fetchall()
        for row in rows:
            meta = metadata(c, row)
            state = lifecycle_state(c, row)
            if not unit_active(row["unit"]) and stopped(row):
                retire(c, row)
                continue
            if state == "activity-unavailable":
                meta["lifecycle_error"] = "activity-probe-unavailable"
                save_metadata(c, row["lease_id"], meta)
                continue
            if state in ("active", "idle"):
                q = lease(
                    None,
                    "renew",
                    "--lease-id",
                    row["lease_id"],
                    "--agent-id",
                    row["agent_id"],
                    "--ttl-seconds",
                    str(meta.get("ttl", 1800)),
                    "--work-state",
                    "awaiting-input" if meta.get("awaiting_until") else "active",
                )
                if q.get("status") != "renewed":
                    meta["lifecycle_error"] = "lease-renewal-rejected"
                    save_metadata(c, row["lease_id"], meta)
                    continue
                if meta.pop("lifecycle_error", None):
                    save_metadata(c, row["lease_id"], meta)
            elif state in ("terminal", "expired-awaiting-input"):
                if activity_snapshot(row) is not None and not freeze_idle(row, 0):
                    continue
                info = record_info(row)
                if (
                    meta.get("proxy_ownership") != "browser"
                    or info.get("kasmvnc")
                    or not any(flag.startswith("--headless") for flag in info.get("command", []))
                    or not info.get("activity_tracking")
                    or info.get("control_mode") != "pipe-fenced"
                ):
                    # The old task's proxy or non-revocable UI cannot safely
                    # remain attached merely to preserve a reconnect window.
                    if not retire(c, row):
                        meta["lifecycle_error"] = "terminal-cleanup-not-verified"
                        save_metadata(c, row["lease_id"], meta)
                    continue
                # Grace admits an immediate replacement without losing the browser. The
                # old control is revoked now, not only when another task arrives.
                if not meta.get("abandoned_at"):
                    info = record_info(row)
                    if info.get("control_mode") == "pipe-fenced":
                        from browser_control import rotate_control

                        try:
                            import browser_profile_lease as profiles
                            profiles.revoke_transfer_identity(
                                STATE.parent / 'browser_profile_leases.sqlite', row['lease_id'])
                            info.update(rotate_control(info["control_socket"]))
                            private_json(row["launch_file"], info)
                        except Exception:
                            meta["lifecycle_error"] = "control-fence-failed"
                            save_metadata(c, row["lease_id"], meta)
                            retire(c, row)
                            continue
                    meta["abandoned_at"] = now()
                    save_metadata(c, row["lease_id"], meta)
                if now() - meta["abandoned_at"] >= 30:
                    retire(c, row)
    return 0


def watch(args):
    while True:
        maintain(args)
        c = db()
        row = c.execute(
            "select * from browsers where browser_id=?", (args.browser_id,)
        ).fetchone()
        c.close()
        if not row or row["state"] != "running":
            return
        time.sleep(5)


@serialized
def start(args):
    proxy_mode(args)
    owner = None
    if getattr(args, "owner_pid", None):
        owner = process_identity(args.owner_pid)
        if not owner:
            emit({"status": "owner-unavailable"}, 2)
    if getattr(args, "task_owned", False):
        if not owner and getattr(args, "driving_mode", None) == "manual":
            emit({"status": "owner-required", "reason": "native-input-untracked",
                  "next": "use agent-driven activity control or supply a task supervisor PID"}, 2)
        if args.program or args.account or args.auth_domain:
            emit({"status": "task-owned-conflicts-with-program"}, 2)
        args.program = "task-owned"
        args.account = (
            "task-"
            + hashlib.sha256((args.agent_id + "\0" + args.run_id).encode()).hexdigest()[
                :24
            ]
        )
        args.auth_domain = "task"
    c = db()
    sweep_rows(c, 14, True)
    import browser_profile_lease as profiles

    account, _ = (
        profiles.resolve_account(args.program, args.account)
        if not getattr(args, "task_owned", False)
        else ({"alias": args.account}, {})
    )
    alias = (account or {}).get("alias", args.account)
    if account is not None and not getattr(args, "task_owned", False) and not profiles.account_lease_eligible(account):
        emit({"status": "account-unavailable"}, 2)
    auth_domain = profiles.auth_domain_for(args, account)
    if fixture_pool_reserved(args.program, auth_domain, alias):
        emit({'status': 'locked', 'reason': 'stopped-profile-reserved'}, 2)
    instance = profiles.instance_key(args)
    automatic = False
    if (account is not None and not instance and not getattr(args, "legacy_profile", False)
            and not getattr(args, "task_owned", False)):
        instance = automatic_instance(c, args, alias, auth_domain)
        automatic = bool(instance)
    row = selected_browser(c, args.program, alias, auth_domain, instance)
    if (row and row["state"] == "running"
            and row["agent_id"] == args.agent_id and row["run_id"] == args.run_id
            and getattr(args, "driving_mode", None) is not None
            and record_info(row).get("driving_mode") != args.driving_mode):
        emit({"status": "locked", "reason": "driving-mode-mismatch", **safe(row)}, 2)
    cleanup_unused(c)
    adm = admission(args.min_ram_available_mib, args.min_swap_free_mib)
    single = account_policy(args.program, alias, auth_domain)
    if (account is not None and not instance and not getattr(args, 'legacy_profile', False)
            and not getattr(args, 'task_owned', False)):
        instance = automatic_instance(c, args, alias, auth_domain,
                                      allow_migration=not single and adm['status'] == 'admitted')
        automatic = bool(instance)
    elif automatic:
        instance = automatic_instance(c, args, alias, auth_domain,
                                      allow_takeover=single or adm["status"] != "admitted")
    row = selected_browser(c, args.program, alias, auth_domain, instance)
    reusable = None
    retired = False
    if row and row["state"] == "running":
        state = lifecycle_state(c, row)
        same = row["agent_id"] == args.agent_id and row["run_id"] == args.run_id
        if (
            same
            and owner
            and state == "active"
            and metadata(c, row).get("owner") not in (None, owner)
        ):
            emit({"status": "locked", "reason": "owner-process-mismatch"}, 2)
        if (
            same
            and state not in ("terminal", "expired-awaiting-input")
            and healthy(row)
        ):
            info = record_info(row)
            if info.get("command"):
                was_headless = any(flag.startswith("--headless") for flag in info["command"])
                strict_kasm = getattr(args, "display_backend", None) == "kasmvnc" and not getattr(args, "headless", False)
                if (was_headless != bool(getattr(args, "headless", False))
                        or (strict_kasm and not info.get("kasmvnc"))):
                    emit({"status": "locked", "reason": "display-mode-mismatch", **safe(row)}, 2)
            if not matching_proxy(c, args, row):
                emit({"status": "proxy-conflict", "detail": "running browser cannot be hot-reconfigured; release it first"}, 2)
            activity = activity_snapshot(row)
            if activity and activity.get("frozen"):
                emit({"status": "recovery-blocked", "reason": "control-frozen", **safe(row)}, 2)
            meta = metadata(c, row)
            if owner and meta.get("owner") is None:
                meta["owner"] = owner
                save_metadata(c, row["lease_id"], meta)
            emit({"status": "already-running", **safe(row), "task_proxy": proxy_metadata(proxy_row(c, args)), "owner_state": state,
                  "watcher_healthy": unit_active(monitor_unit(row["browser_id"]))})
        if not same and state not in ("terminal", "expired-awaiting-input", "idle"):
            emit({"status": "queued" if automatic else "locked", "reason": "owner-" + state, **safe(row)}, 2)
        if not same and state == "idle":
            if instance and not single and adm["status"] == "admitted":
                emit({"status": "queued", "reason": "slot-owned", **safe(row)}, 2)
            if not canonical_claim(row, instance, single):
                emit({"status": "queued", "reason": "canonical-claim-conflict"}, 2)
        info = record_info(row)
        meta = metadata(c, row)
        threshold = meta.get("idle_claim_seconds", DEFAULT_IDLE) if state == "idle" else 0
        if (state == "idle" or activity_snapshot(row) is not None) and not freeze_idle(row, threshold):
            emit({"status": "queued" if automatic else "locked", "reason": "activity-changed", **safe(row)}, 2)
        # A task-scoped MITM lane belongs to its old task. Never relabel it. Only
        # an explicitly browser-owned fixed route can cross task ownership alive.
        compatible = (
            account is not None
            and profiles.account_lease_eligible(account)
            and meta.get("proxy_ownership") == "browser"
            and getattr(args, "proxy_ownership", "task") == "browser"
            and bool(args.proxy_server)
            and args.proxy == "external"
            and matching_proxy(c, args, row)
            and info.get("proxy_server") == args.proxy_server
            and info.get("proxy_cert_mode") == args.proxy_cert_mode
            and not info.get("kasmvnc")
            and info.get("activity_tracking")
            and any(flag.startswith("--headless") for flag in info.get("command", []))
            and getattr(args, "headless", False)
            and getattr(args, "driving_mode", None) != "manual"
        )
        if compatible and info.get("control_mode") == "pipe-fenced" and healthy(row):
            from browser_control import rotate_control

            try:
                profiles.revoke_transfer_identity(
                    STATE.parent / 'browser_profile_leases.sqlite', row['lease_id'])
                rotated = rotate_control(info["control_socket"])
                if rotated.get("fenced"):
                    info.update(rotated)
                    private_json(row["launch_file"], info)
                    reusable = info
            except Exception:
                reusable = None
        if not reusable and not retire(c, row):
            restored = restore_failed_stop(row) if info.get("activity_tracking") else False
            emit({"status": "recovery-blocked", "reason": "stop-not-verified",
                  "control_restored": restored}, 2)
        retired = not reusable
    # Capacity is an admission gate, not a lease outcome. Do not acquire a profile
    # until this node can actually start Chromium: a no-capacity retry must leave
    # the next profile user with a healthy, available profile.
    if reusable:
        adm = {"status": "admitted", "reason": "no-new-process"}
    elif retired:
        adm = admission(args.min_ram_available_mib, args.min_swap_free_mib)
    if adm["status"] != "admitted":
        emit(
            {
                "status": "queued",
                "reason": "no-capacity",
                "retry_after_seconds": 30,
                "admission": adm,
                "retryable": not retired,
            },
            2,
        )
    if not reusable:
        from kasmvnc_session import KasmVNCSessionError
        try:
            select_display(c, args)
        except KasmVNCSessionError:
            emit({"status": "queued", "reason": "display-unavailable", "retry_after_seconds": 30,
                  "retryable": not retired}, 2)
    if reusable:
        manager = hashlib.sha256(str(STATE.resolve()).encode()).hexdigest()
        meta = metadata(c, row)
        meta["pending_transfer"] = {
            "agent_id": args.agent_id,
            "run_id": args.run_id,
            "metadata": {
                "owner": owner,
                "ttl": args.ttl_seconds,
                "idle_claim_seconds": getattr(args, "idle_seconds", DEFAULT_IDLE),
                "proxy_ownership": args.proxy_ownership,
            },
        }
        save_metadata(c, row["lease_id"], meta)
        got = profiles.transfer_managed_lease(
            STATE.parent / "browser_profile_leases.sqlite",
            row["lease_id"],
            manager,
            args.agent_id,
            args.run_id,
            args.purpose,
            args.ttl_seconds,
            reusable["cdp_url"],
            expected={"owner_agent_id": row["agent_id"], "owner_run_id": row["run_id"],
                      "profile_dir": row["profile_dir"], "instance_key": instance,
                      "program": slug(args.program), "account_alias": slug(alias),
                      "auth_domain": auth_domain},
        )
    else:
        stopped_legacy = (row if row and not instance and row['state'] == 'stopped'
                          and not getattr(args, 'task_owned', False) else None)
        shared_stopped = shared_profile_rows(c, stopped_legacy['profile_dir'], args.program) if stopped_legacy else []
        if stopped_legacy and (shared_stopped is None or not quiescent_legacy(c,
                shared_stopped + [r for r in c.execute(
                    'SELECT * FROM browsers WHERE program=? AND account=? AND auth_domain=?',
                    (slug(args.program), slug(alias), auth_domain)).fetchall()
                    if r['lease_id'] not in {s['lease_id'] for s in shared_stopped}], stopped_legacy)):
            emit({'status': 'recovery-blocked', 'reason': 'legacy-profile-not-quiescent'}, 2)
        proof = (profiles.authorize_auto_slot(
            STATE.parent / "browser_profile_leases.sqlite", slug(args.program), slug(alias),
            auth_domain, instance, hashlib.sha256(str(STATE.resolve()).encode()).hexdigest(),
            args.agent_id, args.run_id) if automatic else None)
        args._selection_proof = proof
        got = lease(
            args,
            "acquire",
            args.program,
            args.account,
            *(["--auth-domain", args.auth_domain] if args.auth_domain else []),
            "--agent-id",
            args.agent_id,
            "--run-id",
            args.run_id,
            "--purpose",
            args.purpose,
            "--ttl-seconds",
            str(args.ttl_seconds),
            *(["--recover-profile"] if getattr(args, "recover_profile", False) else []),
            *(["--task-owned"] if getattr(args, "task_owned", False) else []),
            *(["--instance-key", instance] if instance else []),
            *(["--stopped-legacy-lease-id", stopped_legacy['lease_id'],
               "--stopped-legacy-profile-dir", stopped_legacy['profile_dir'],
               "--stopped-legacy-agent-id", stopped_legacy['agent_id'],
               "--stopped-legacy-run-id", stopped_legacy['run_id']] if stopped_legacy else []),
            *(["--automatic-instance", "--selection-proof-stdin"] if automatic else []),
        )
    if got.get("status") not in ("leased", "already-owned"):
        if reusable:
            # Rotation already revoked the old controller. No canonical transfer
            # committed: fence the new generation too and retain the old lease
            # for explicit recovery, without trying a second browser.
            meta = metadata(c, row)
            meta.pop("pending_transfer", None)
            meta["lifecycle_error"] = "canonical-transfer-rejected"
            save_metadata(c, row["lease_id"], meta)
            frozen = freeze_idle(row, 0)
            emit({"status": "recovery-blocked", "reason": "canonical-transfer-rejected",
                  "control_frozen": frozen}, 2)
        if automatic and got.get("status") == "locked":
            got = {**got, "status": "queued", "reason": "account-policy-locked", "retry_after_seconds": 30,
                   "retryable": not retired}
        emit(got, 2)
    lid = got["lease"]["lease_id"]
    resolved_domain = got["lease"].get("auth_domain", auth_domain)
    if reusable:
        t = now()
        c.execute(
            "update browsers set lease_id=?,agent_id=?,run_id=?,purpose=?,state=?,last_activity=?,updated=? where lease_id=?",
            (
                lid,
                args.agent_id,
                args.run_id,
                args.purpose,
                "running",
                t,
                t,
                row["lease_id"],
            ),
        )
        save_metadata(
            c,
            lid,
            {
                "owner": owner,
                "ttl": args.ttl_seconds,
                "idle_claim_seconds": getattr(args, "idle_seconds", DEFAULT_IDLE),
                "proxy_ownership": args.proxy_ownership,
            },
        )
        reg = lease(
            args,
            "register-browser",
            "--lease-id",
            lid,
            "--agent-id",
            args.agent_id,
            "--cdp-url",
            reusable["cdp_url"],
            "--service-unit",
            row["unit"],
        )
        if reg.get("status") != "registered":
            emit({"status": "recovery-blocked", "reason": "register-handoff"}, 2)
        emit(
            {
                "status": "reused",
                "task_proxy": None,
                "fenced": True,
                "watcher_healthy": unit_active(monitor_unit(row["browser_id"])),
                **safe(
                    c.execute(
                        "select * from browsers where lease_id=?", (lid,)
                    ).fetchone()
                ),
            }
        )
    if row is None:
        row = selected_browser(c, args.program, got["lease"].get("account_alias", args.account), resolved_domain, instance)
    if (
        row
        and row["agent_id"] == args.agent_id
        and row["run_id"] == args.run_id
        and row["state"] == "running"
        and healthy(row)
    ):
        if not matching_proxy(c, args, row):
            emit({"status": "proxy-conflict", "detail": "running browser cannot be hot-reconfigured"}, 2)
        emit({"status": "already-running", **safe(row), "task_proxy": proxy_metadata(proxy_row(c, args))})
    task = None
    created = False
    if args.proxy == "mitm":
        try:
            task, created = start_proxy(c, args)
        except Exception as exc:
            release_lease(lid, args.agent_id)
            emit({"status": "proxy-failed", "detail": str(exc)}, 2)
    elif proxy_row(c, args):
        release_lease(lid, args.agent_id)
        emit({"status": "proxy-conflict", "detail": "finish the task proxy before changing mode"}, 2)
    prof = Path(got["lease"]["profile_dir"])
    bid = str(uuid.uuid4())
    unit = "browser-" + bid
    diagnostics_dir = (STATE.parent / "startup" / bid
                       if os.environ.get("BROWSER_STARTUP_DIAGNOSTICS") == "1" else None)
    diagnostics = StartupDiagnostics("manager", diagnostics_dir)
    launch = STATE.parent / (bid + ".launch.json")
    launch.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(launch.parent, 0o700)
    if unit_active(unit):
        if created:
            rollback_proxy(c, task)
        release_lease(lid, args.agent_id)
        emit({"status": "browser-unit-conflict"}, 2)
    # Startup intent is visible to finish before browser dispatch/CDP readiness.
    t = now()
    c.execute("delete from browsers where lease_id=?", (lid,))
    c.execute("""INSERT INTO browsers (
                  lease_id, browser_id, program, account, auth_domain, agent_id, run_id,
                  purpose, unit, profile_dir, launch_file, state, tab_count,
                  last_activity, created, updated
              ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (lid, bid, slug(args.program), slug(got["lease"].get("account_alias", args.account)),
               resolved_domain, args.agent_id, args.run_id, args.purpose, unit,
               str(prof), str(launch), "starting", 0, t, t, t))
    c.commit()
    launch.unlink(missing_ok=True)
    # The unit stays foreground via sleep; Chromium remains inside its cgroup.
    cmd = [
        sys.executable,
        str(CHROMIUM),
        args.program,
        args.purpose,
        "--account",
        args.account,
        "--profile-dir",
        str(prof),
        "--run-id",
        args.run_id,
        "--agent-id",
        args.agent_id,
        "--account-label",
        args.account,
        "--proxy-cert-mode",
        args.proxy_cert_mode if args.proxy != "none" else "none",
        "--driving-mode",
        getattr(args, "driving_mode", None) or "agent-driven",
        "--json",
    ]
    if getattr(args, "task_owned", False):
        cmd += ["--task-owned"]
    if getattr(args, "headless", False):
        cmd += ["--headless"]
    if getattr(args, "graphics_backend", "auto") != "auto":
        cmd += ["--graphics-backend", args.graphics_backend]
    if task:
        cmd += ["--proxy-server", proxy_metadata(task)["proxy_server"],
                "--mitm-ca-cert", proxy_metadata(task)["ca_cert"]]
    elif args.proxy == "none":
        cmd += ["--no-proxy"]
    elif args.proxy_server:
        cmd += ["--proxy-server", args.proxy_server]
    if args.proxy == "external" and args.mitm_ca_cert:
        cmd += ["--mitm-ca-cert", args.mitm_ca_cert]
    if args.url:
        cmd += ["--url", args.url]
    if args.display_backend:
        cmd += ["--display-backend", args.display_backend]
    if args.kasmvnc_display is not None:
        cmd += ["--kasmvnc-display", str(args.kasmvnc_display)]
    if args.kasmvnc_web_port is not None:
        cmd += ["--kasmvnc-web-port", str(args.kasmvnc_web_port)]
    cmd += ["--control-socket", str(STATE.parent / (bid + ".sock"))]
    shell = f"umask 077; BROWSER_PROVISIONER_UNIT={unit}.service {' '.join(__import__('shlex').quote(x) for x in cmd)} > {__import__('shlex').quote(str(launch))}; rc=$?; test $rc -eq 0 || exit $rc; exec sleep infinity"
    run = [
        "systemd-run",
        "--user",
        "--unit=" + unit,
        "--property=MemoryHigh=" + args.memory_high,
        "--property=MemoryMax=" + args.memory_max,
        "--property=CPUWeight=100",
        # Chrome asks the session systemd manager to move its root into an
        # unbounded app scope. Isolate only this browser service's session bus;
        # the provisioner and its systemctl control plane keep the real bus.
        "--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent",
        "--",
        "/bin/bash",
        "-lc",
        shell,
    ]
    # systemd user managers do not inherit the requesting shell environment.
    for key in (
        "BROWSER_PROVISIONER_STATE",
        "HARNESS_BOUNTY_ARTIFACT_ROOT",
        "HARNESS_SHARED_BASE",
        "CHROMIUM_TEST_CHROME",
        "DISPLAY",
        "XAUTHORITY",
    ):
        if key == "CHROMIUM_TEST_CHROME" and getattr(args, "graphics_backend", "auto") == "auto":
            continue
        if key in os.environ:
            run.insert(2, "--setenv=" + key + "=" + os.environ[key])
    if getattr(args, "graphics_backend", "auto") == "auto":
        # User-systemd may retain an old interactive wrapper across sessions.
        # Mask it for this ordinary browser unit so automatic probing selects
        # the real browser even when the manager environment is stale.
        run.insert(2, "--setenv=CHROMIUM_TEST_CHROME=")
    if diagnostics_dir:
        run.insert(2, "--setenv=BROWSER_STARTUP_RECEIPT_DIR=" + str(diagnostics_dir))
    with diagnostics.phase("dispatch"):
        p = subprocess.run(run, capture_output=True, text=True, env=sysenv())
    if p.returncode or not unit_active(unit):
        diagnostics.mark("dispatch", "failed", RuntimeError(), p.returncode)
        if not failed_launch(c, lid, unit):
            emit({"status": "cleanup-incomplete", "reason": "browser-stop-not-verified"}, 2)
        if not rollback_failed_browser_proxy(c, task, created, prof):
            emit({"status": "cleanup-incomplete", "reason": "task-proxy-cleanup-not-verified"}, 2)
        release_lease(lid, args.agent_id)
        emit({"status": "launch-failed", "detail": (p.stderr or p.stdout).strip()}, 2)
    diagnostics.mark("publication")
    deadline = time.time() + LAUNCH_WAIT_SECONDS
    while time.time() < deadline and (
        not launch.exists() or launch.stat().st_size == 0
    ):
        time.sleep(0.2)
    try:
        info = json.loads(launch.read_text())
    except Exception as exc:
        diagnostics.mark("publication", "failed",
                         TimeoutError() if isinstance(exc, FileNotFoundError)
                         or (isinstance(exc, json.JSONDecodeError) and not exc.doc) else exc)
        if not failed_launch(c, lid, unit):
            emit({"status": "cleanup-incomplete", "reason": "browser-stop-not-verified"}, 2)
        if not rollback_failed_browser_proxy(c, task, created, prof):
            emit({"status": "cleanup-incomplete", "reason": "task-proxy-cleanup-not-verified"}, 2)
        release_lease(lid, args.agent_id)
        emit(
            {
                "status": "launch-failed",
                "detail": f"launcher did not produce a valid private record within {LAUNCH_WAIT_SECONDS:g}s (raise BROWSER_LAUNCH_WAIT_SECONDS if the host is slow)",
            },
            2,
        )
    diagnostics.mark("publication", "ready")
    if task and not matching_proxy(c, args, c.execute(
            "select * from browsers where lease_id=?", (lid,)).fetchone()):
        if not failed_launch(c, lid, unit):
            emit({"status": "cleanup-incomplete", "reason": "browser-stop-not-verified"}, 2)
        if not rollback_failed_browser_proxy(c, task, created, prof):
            emit({"status": "cleanup-incomplete", "reason": "task-proxy-cleanup-not-verified"}, 2)
        release_lease(lid, args.agent_id)
        emit({"status": "launch-failed", "detail": "task proxy or imported CA not verified by launcher"}, 2)
    diagnostics.mark("registration")
    reg = lease(
        args,
        "register-browser",
        "--lease-id",
        lid,
        "--agent-id",
        args.agent_id,
        "--cdp-url",
        info["cdp_url"],
        "--service-unit",
        unit,
    )
    if reg.get("status") != "registered":
        diagnostics.mark("registration", "failed", RuntimeError())
        if not failed_launch(c, lid, unit):
            emit({"status": "cleanup-incomplete", "reason": "browser-stop-not-verified"}, 2)
        if not rollback_failed_browser_proxy(c, task, created, prof):
            emit({"status": "cleanup-incomplete", "reason": "task-proxy-cleanup-not-verified"}, 2)
        release_lease(lid, args.agent_id)
        emit(
            {"status": "launch-failed", "detail": "could not register owned browser"}, 2
        )
    diagnostics.mark("registration", "ready")
    info["process_identity"] = (
        process_identity(info["pid"]) if info.get("pid") else None
    )
    info["unit_invocation"] = unit_identity(unit)
    info["account_color"] = (account or {}).get("pwnfox_color")
    info["instance_key"] = instance
    info["instance_selection"] = "automatic" if automatic else "explicit" if instance else "legacy"
    info["instance_id"] = bid
    info["pane_id"] = bid
    private_json(launch, info)
    save_metadata(
        c,
        lid,
        {
            "owner": owner,
            "ttl": args.ttl_seconds,
            "idle_claim_seconds": getattr(args, "idle_seconds", DEFAULT_IDLE),
            "proxy_ownership": getattr(args, "proxy_ownership", "task"),
        },
    )
    t = now()
    c.execute("delete from browsers where lease_id=?", (lid,))
    c.execute(
        """INSERT INTO browsers (
            lease_id, browser_id, program, account, auth_domain, agent_id, run_id,
            purpose, unit, profile_dir, launch_file, state, tab_count,
            last_activity, created, updated
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            lid,
            bid,
            slug(args.program),
            slug(got["lease"].get("account_alias", args.account)),
            got["lease"].get("auth_domain", auth_domain),
            args.agent_id,
            args.run_id,
            args.purpose,
            unit,
            str(prof),
            str(launch),
            "running",
            0,
            t,
            t,
            t,
        ),
    )
    c.commit()
    out = c.execute("select * from browsers where lease_id=?", (lid,)).fetchone()
    try:
        start_watcher(bid)
    except RuntimeError:
        retire(c, out)
        emit(
            {"status": "launch-failed", "reason": "lifecycle-supervisor-unavailable"}, 2
        )
    emit(
        {
            "status": "started",
            "task_proxy": proxy_metadata(task),
            **safe(out),
            "profile_lifetime": "persistent",
            "owner_state": lifecycle_state(c, out),
            "watcher_healthy": unit_active(monitor_unit(bid)),
        }
    )


@serialized
def touch(args):
    c = db()
    r = c.execute(
        "select * from browsers where lease_id=?", (args.lease_id,)
    ).fetchone()
    if not r or r["agent_id"] != args.agent_id or r["state"] != "running":
        emit({"status": "not-owner"}, 2)
    if lifecycle_state(c, r) in ("terminal", "expired-awaiting-input"):
        emit({"status": "owner-terminal"}, 2)
    if (
        args.work_state == "awaiting-input"
        and not 1 <= getattr(args, "awaiting_seconds", 1800) <= 3600
    ):
        emit({"status": "invalid-awaiting-bound"}, 2)
    activity = activity_snapshot(r)
    if activity is not None:
        meta = metadata(c, r)
        if activity.get("unavailable"):
            emit({"status": "activity-unavailable"}, 2)
        if meta.get("awaiting_until") and now() >= meta["awaiting_until"] and args.work_state == "awaiting-input":
            emit({"status": "reservation-expired"}, 2)
        from browser_control import activity_control
        try:
            activity_control(record_info(r)["control_socket"], "reserve",
                             seconds=getattr(args, "awaiting_seconds", 1800) if args.work_state == "awaiting-input" else 0)
        except Exception:
            emit({"status": "reservation-unavailable"}, 2)
    q = lease(
        args,
        "renew",
        "--lease-id",
        args.lease_id,
        "--agent-id",
        args.agent_id,
        "--ttl-seconds",
        str(args.ttl_seconds),
        "--work-state",
        args.work_state,
    )
    if q.get("status") != "renewed":
        emit(q, 2)
    meta = metadata(c, r)
    if args.work_state == "awaiting-input":
        meta.setdefault(
            "awaiting_until", now() + getattr(args, "awaiting_seconds", 1800)
        )
    else:
        meta.pop("awaiting_until", None)
    save_metadata(c, args.lease_id, meta)
    c.execute(
        "update browsers set last_activity=?,updated=? where lease_id=?",
        ((activity["last_activity"] if activity is not None else now()), now(), args.lease_id),
    )
    c.commit()
    emit(
        {
            "status": "touched",
            **safe(
                c.execute(
                    "select * from browsers where lease_id=?", (args.lease_id,)
                ).fetchone()
            ),
        }
    )


def status(args):
    c = db()
    r = c.execute(
        "select * from browsers where lease_id=?", (args.lease_id,)
    ).fetchone()
    if not r or r["agent_id"] != args.agent_id or r["state"] != "running":
        emit({"status": "not-owner"}, 2)
    running = r["state"] == "running" and unit_active(r["unit"])
    emit(
        {
            "status": "ok",
            **safe(r),
            "unit_active": running,
            "browser_healthy": healthy(r) if running else False,
            "owner_state": lifecycle_state(c, r),
            "max_tabs": MAX_TABS,
            "watcher_healthy": unit_active(monitor_unit(r["browser_id"])),
            "activity": activity_snapshot(r),
            "owner_process_state": owner_state(metadata(c, r).get("owner")),
            "lifecycle_error": metadata(c, r).get("lifecycle_error"),
        }
    )


def reap(args):
    maintain(args)
    with node_lock(STATE):
        c = db()
        stopped_ids = cleanup_unused(c)
        c.execute("delete from finished_proxies where finished<?", (now() - 14 * 86400,))
        c.commit()
        # No age-only revocation: a replay can outlive the browser. Require
        # positively terminal task-owner identity and a quiet flow artifact.
        candidates = []
        cutoff = now() - 7200
        for row in c.execute("select * from task_proxies where updated<?", (cutoff,)).fetchall():
            if not row["owner"]:
                continue
            try:
                terminal = owner_state(json.loads(row["owner"])) == "terminal"
            except ValueError:
                continue
            if (not terminal or not proxy_quiet(row)
                    or any(browser_blocks_proxy(c, browser)
                           for browser in c.execute("select * from browsers where agent_id=? and run_id=?",
                                                    (row["agent_id"], row["run_id"])).fetchall())):
                continue
            candidates.append((row["agent_id"], row["run_id"]))
        c.commit()
    recovered = []
    for agent_id, run_id in candidates:
        # Running rows require the same explicit finish semantics; terminal
        # owner is proof that this task can no longer issue direct replay.
        with node_lock(STATE):
            c = db(); row = proxy_row(c, argparse.Namespace(agent_id=agent_id, run_id=run_id))
            if (not row or not row["owner"] or owner_state(json.loads(row["owner"])) != "terminal"
                    or not proxy_quiet(row)):
                continue
            if any(
                browser_blocks_proxy(c, b)
                for b in c.execute("select * from browsers where agent_id=? and run_id=?",
                                   (agent_id, run_id)).fetchall()):
                c.rollback()
                continue
            c.commit()
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    finish_proxy(argparse.Namespace(agent_id=agent_id, run_id=run_id),
                                 recovery=row["state"] != "running", orphan_proven=True)
            except SystemExit as exc:
                if exc.code == 0:
                    recovered.append((agent_id, run_id))
    emit({"status": "ok", "idle_stopped": stopped_ids,
          "proxy_recovered": recovered,
          "policy": "tracked-CDP-idle-7200s; task proxy terminal-owner-and-quiet-flow-7200s"})


@serialized
def release(args):
    c = db()
    r = c.execute(
        "select * from browsers where lease_id=?", (args.lease_id,)
    ).fetchone()
    if not r or r["agent_id"] != args.agent_id or r["state"] != "running":
        emit({"status": "not-owner"}, 2)
    if reservation_blocks(r):
        emit({'status': 'locked', 'reason': 'stopped-profile-reserved'}, 2)
    if not stop_recorded(r):
        info = record_info(r)
        emit(
            {
                "status": "cleanup-incomplete",
                "unit_active": unit_active(r["unit"]),
                "same_invocation": info.get("unit_invocation")
                == unit_identity(r["unit"]),
                "root_state": owner_state(info.get("process_identity")),
            },
            2,
        )
    q = release_lease(
        args.lease_id, args.agent_id, args.disposition, args.profile_health
    )
    if q.get("status") != "released":
        emit(q, 2)
    stop_receipt(r)
    c.execute(
        "update browsers set state='stopped',updated=? where lease_id=?",
        (now(), args.lease_id),
    )
    c.commit()
    emit(
        {
            "status": "released",
            "task_proxy": proxy_metadata(c.execute(
                "select * from task_proxies where agent_id=? and run_id=?",
                (r["agent_id"], r["run_id"])).fetchone()),
            **safe(
                c.execute(
                    "select * from browsers where lease_id=?", (args.lease_id,)
                ).fetchone()
            ),
        }
    )


def task_proxy_status(args):
    row = proxy_row(db(), args)
    if not row:
        emit({"status": "not-found"}, 2)
    emit({"status": "ok", "task_proxy": proxy_metadata(row), "ready": proxy_ready(row)})


@serialized
def task_proxy_finish(args):
    finish_proxy(args)

@serialized
def task_proxy_recover(args):
    finish_proxy(args, recovery=True)

def finish_proxy(args, recovery=False, orphan_proven=False):
    c = db()
    c.execute("BEGIN IMMEDIATE")
    row = proxy_row(c, args)
    if not row:
        done = c.execute("select lane from finished_proxies where agent_id=? and run_id=?",
                         (args.agent_id, args.run_id)).fetchone()
        c.rollback()
        emit({"status": "finished", "lane": done["lane"], "already_finished": True} if done
             else {"status": "not-found"}, 0 if done else 2)
    if recovery and row["state"] == "running":
        c.rollback()
        emit({"status": "proxy-conflict", "detail": "running replay requires explicit finish"}, 2)
    if not recovery and row["state"] in ("starting", "cleanup-failed"):
        c.rollback()
        emit({"status": "proxy-conflict", "detail": "task proxy starting or requires recovery"}, 2)
    browsers = c.execute("select * from browsers where agent_id=? and run_id=?",
                         (args.agent_id, args.run_id)).fetchall()
    if any((browser_blocks_proxy(c, browser) if recovery else
            browser["state"] not in ("stopped", "deleted") or unit_active(browser["unit"]))
           for browser in browsers):
        c.rollback()
        emit({"status": "browser-active", "detail": "release the browser first"}, 2)
    if unit_active(row["unit"]) and (not row["invocation"] or unit_identity(row["unit"]) != row["invocation"]):
        c.rollback()
        emit({"status": "proxy-conflict", "detail": "unit generation unverified"}, 2)
    if recovery and row["state"] in ("starting", "cleanup-failed") and not (orphan_proven or proxy_quiet(row)) and (unit_active(row["unit"]) or port_open(row["port"])):
        c.rollback()
        emit({"status": "proxy-conflict", "detail": "startup listener may have active replay"}, 2)
    c.execute("update task_proxies set state='finishing',updated=? where lane=?", (now(), row["lane"]))
    c.commit()
    if unit_active(row["unit"]):
        stop_unit(row["unit"])
    if unit_active(row["unit"]) or port_open(row["port"]):
        c.execute("update task_proxies set state='stop-failed',updated=? where lane=?", (now(), row["lane"]))
        c.commit()
        emit({"status": "proxy-stop-failed", "reservation": "retained"}, 2)
    c.execute("update task_proxies set state='stopped',updated=? where lane=?", (now(), row["lane"]))
    c.commit()
    ca = Path(proxy_metadata(row)["ca_cert"])
    try:
        for browser in browsers:
            if browser["state"] == "deleted":
                continue
            profile = Path(browser["profile_dir"])
            remove_matching_ca(profile, ca, home_dir=profile / "home")
    except (OSError, RuntimeError, ValueError) as exc:
        emit({"status": "proxy-ca-cleanup-failed", "lane": row["lane"],
              "detail": str(exc), "reservation": "retained"}, 2)
    flow = Path(proxy_metadata(row)["flow_file"])
    if flow.exists() and flow.stat().st_size:
        try:
            python = mitm_runtime()[1]
        except (RuntimeError, OSError):
            emit({"status": "proxy-index-failed", "lane": row["lane"],
                  "detail": "mitmdump Python unavailable; reservation retained"}, 2)
        cmd = [python, str(PROXY_STORE), "--json", "index-lane", "--lane", row["lane"],
               "--lane-root", str(Path(row["run_dir"]).parent), "--flow-file", str(flow),
               "--program", row["program"], "--task", row["purpose"],
               "--agent-id", row["agent_id"], "--run-id", row["run_id"],
               "--account-label", row["account"], "--proxy-host", "127.0.0.1",
               "--proxy-port", str(row["port"]),
               "--proxy-server", proxy_metadata(row)["proxy_server"], "--transport", "mixed"]
        indexed = subprocess.run(cmd, capture_output=True, text=True)
        try:
            result = json.loads(indexed.stdout)
        except ValueError:
            result = {}
        if indexed.returncode or result.get("status") != "indexed":
            emit({"status": "proxy-index-failed", "lane": row["lane"], "reservation": "retained"}, 2)
    c.execute("insert or replace into finished_proxies values(?,?,?,?)",
              (row["agent_id"], row["run_id"], row["lane"], now()))
    c.execute("delete from task_proxies where lane=?", (row["lane"],))
    c.commit()
    emit({"status": "finished", "lane": row["lane"], "flow_file": str(flow),
          "indexed": flow.exists() and bool(flow.stat().st_size)})


def managed_root():
    return Path(os.environ.get("HARNESS_BOUNTY_ARTIFACT_ROOT", "/mnt/bounty")).resolve()


def managed_profile(path):
    try:
        relative = Path(path).resolve().relative_to(managed_root())
    except ValueError:
        return False
    # Only manager-shaped legacy <program>/web/browser-profiles/<account> and
    # auth-domain-scoped <program>/web/browser-profiles/<domain>/<account> qualify.
    return (
        ((len(relative.parts) in (4, 5) and relative.parts[1:3] == ("web", "browser-profiles"))
         or (len(relative.parts) == 6 and relative.parts[1:3] == ("web", "browser-instances")))
        and all(part not in ("", ".", "..") for part in relative.parts)
    )


def sweep_rows(c, older_than_days, confirm):
    import browser_profile_lease as profiles
    def direct_path(p):
        try:
            return p.resolve(strict=True) == p.absolute()
        except (OSError, RuntimeError):
            return False
    cutoff = now() - older_than_days * 86400
    removed = []
    skipped = []
    # The table is the explicit manager-created profile manifest: never discover arbitrary paths.
    for r in c.execute(
        "select * from browsers where state='stopped' and updated<?", (cutoff,)
    ).fetchall():
        if reservation_blocks(r):
            skipped.append({'browser_id': r['browser_id'], 'reason': 'stopped-profile-reserved'})
            continue
        p = Path(r["profile_dir"])
        identity = profiles.physical_profile(p)
        if identity is None or not direct_path(p):
            skipped.append({"browser_id": r["browser_id"], "reason": "profile-identity-unverified"})
            continue
        # Never remove a physical profile through a keyed or historical alias.
        protected = [other for other in c.execute("SELECT * FROM browsers").fetchall()
                     if other['program'] != 'task-owned' and
                     record_info(other).get('instance_key', '') == '' and
                     Path(other['profile_dir']) in legacy_profile_paths(
                         other['program'], other['account'], other['auth_domain'])]
        if r['program'] != 'task-owned' and any(
                profiles.physical_profile(other['profile_dir']) == identity for other in protected):
            skipped.append({"browser_id": r["browser_id"], "reason": "legacy-auth-retained"})
            continue
        # Manager-proven unkeyed persistent profiles predate canonical history.
        # Protect only exact known account paths, never arbitrary or task-owned rows.
        if (r['program'] != 'task-owned' and
                record_info(r).get('instance_key', '') == '' and
                p in legacy_profile_paths(r['program'], r['account'], r['auth_domain'])):
            skipped.append({"browser_id": r["browser_id"], "reason": "legacy-auth-retained"})
            continue
        lease_db = STATE.parent / "browser_profile_leases.sqlite"
        if lease_db.exists():
            with sqlite3.connect(lease_db) as leases:
                columns = {item[1] for item in leases.execute('PRAGMA table_info(browser_profile_leases)')}
                historical = (any(profiles.physical_profile(h[0]) == identity for h in leases.execute(
                    "SELECT profile_dir FROM browser_profile_leases " +
                    ("WHERE COALESCE(instance_key,'')=''" if 'instance_key' in columns else '')
                ).fetchall()) if columns else None)
                marker = (leases.execute("SELECT 1 FROM sqlite_master WHERE name='browser_legacy_auto'").fetchone()
                          and any(profiles.physical_profile(h[0]) == identity for h in leases.execute(
                              "SELECT profile_dir FROM browser_legacy_auto").fetchall()))
                if r['program'] != 'task-owned' and (historical or marker):
                    skipped.append({"browser_id": r["browser_id"], "reason": "legacy-auth-retained"})
                    continue
        if not managed_profile(p):
            skipped.append(
                {"browser_id": r["browser_id"], "reason": "not-managed-profile"}
            )
            continue
        if unit_active(r["unit"]):
            skipped.append({"browser_id": r["browser_id"], "reason": "unit-active"})
            continue
        if os.path.lexists(p / "SingletonLock") and not stale_singleton_lock(
            p / "SingletonLock", r
        ):
            skipped.append(
                {"browser_id": r["browser_id"], "reason": "browser-profile-lock"}
            )
            continue
        lease_db = STATE.parent / "browser_profile_leases.sqlite"
        if lease_db.exists():
            with sqlite3.connect(lease_db) as leases:
                locked = any(profiles.physical_profile(h[0]) in (None, identity) for h in leases.execute(
                    "select profile_dir from browser_profile_leases where status='active'").fetchall())
            if locked:
                skipped.append(
                    {"browser_id": r["browser_id"], "reason": "profile-leased"}
                )
                continue
        others = [other for other in c.execute(
            "select * from browsers where lease_id!=? and state NOT IN ('deleted','handed-off')",
            (r["lease_id"],)).fetchall() if
            profiles.physical_profile(other['profile_dir']) in (None, identity)]
        if any(
            other["state"] != "stopped" or other["updated"] >= cutoff
            for other in others
        ):
            skipped.append({"browser_id": r["browser_id"], "reason": "profile-in-use"})
            continue
        if not stopped(r):
            skipped.append(
                {"browser_id": r["browser_id"], "reason": "browser-not-stopped"}
            )
            continue
        if not p.exists():
            skipped.append({"browser_id": r["browser_id"], "reason": "already-absent"})
            continue
        if not confirm:
            removed.append(
                {"browser_id": r["browser_id"], "profile_dir": str(p), "dry_run": True}
            )
            continue
        if profiles.physical_profile(p) != identity or not direct_path(p):
            skipped.append({"browser_id": r["browser_id"], "reason": "profile-identity-changed"})
            continue
        shutil.rmtree(p)
        c.execute(
            "update browsers set state='deleted',updated=? where lease_id=?",
            (now(), r["lease_id"]),
        )
        removed.append(
            {"browser_id": r["browser_id"], "profile_dir": str(p), "dry_run": False}
        )
    c.commit()
    return removed, skipped


@serialized
def sweep(args):
    removed, skipped = sweep_rows(db(), args.older_than_days, args.confirm)
    emit({"status": "ok", "removed": removed, "skipped": skipped})


def request(args):
    maintain(args)
    deadline = now() + args.wait_seconds
    delay = 30
    attempts = 0
    while True:
        cmd = [
            sys.executable,
            str(Path(__file__).resolve()),
            "start",
            *([args.program, args.account] if args.program and args.account else []),
            *(["--auth-domain", args.auth_domain] if args.auth_domain else []),
            "--agent-id",
            args.agent_id,
            "--run-id",
            args.run_id,
            "--purpose",
            args.purpose,
            "--ttl-seconds",
            str(args.ttl_seconds),
            "--idle-seconds",
            str(args.idle_seconds),
            "--min-ram-available-mib",
            str(args.min_ram_available_mib),
            "--min-swap-free-mib",
            str(args.min_swap_free_mib),
            "--memory-high",
            args.memory_high,
            "--memory-max",
            args.memory_max,
            "--proxy-cert-mode",
            args.proxy_cert_mode,
            "--proxy",
            args.proxy,
        ]
        if getattr(args, "task_owned", False):
            cmd += ["--task-owned"]
        if getattr(args, "headless", False):
            cmd += ["--headless"]
        if getattr(args, "graphics_backend", "auto") != "auto":
            cmd += ["--graphics-backend", args.graphics_backend]
        if getattr(args, "driving_mode", None) is not None:
            cmd += ["--driving-mode", args.driving_mode]
        if getattr(args, "instance_key", None):
            cmd += ["--instance-key", args.instance_key]
        if getattr(args, "legacy_profile", False):
            cmd += ["--legacy-profile"]
        if getattr(args, "owner_pid", None):
            cmd += ["--owner-pid", str(args.owner_pid)]
        if getattr(args, "proxy_ownership", None):
            cmd += ["--proxy-ownership", args.proxy_ownership]
        if args.proxy_server:
            cmd += ["--proxy-server", args.proxy_server]
        if args.mitm_ca_cert:
            cmd += ["--mitm-ca-cert", args.mitm_ca_cert]
        if args.url:
            cmd += ["--url", args.url]
        if args.display_backend:
            cmd += ["--display-backend", args.display_backend]
        if args.kasmvnc_display is not None:
            cmd += ["--kasmvnc-display", str(args.kasmvnc_display)]
        if args.kasmvnc_web_port is not None:
            cmd += ["--kasmvnc-web-port", str(args.kasmvnc_web_port)]
        if getattr(args, "recover_profile", False):
            cmd += ["--recover-profile"]
        p = subprocess.run(cmd, capture_output=True, text=True)
        try:
            result = json.loads(p.stdout)
        except Exception:
            emit(
                {
                    "status": "launch-failed",
                    "detail": "provisioner returned invalid JSON",
                },
                2,
            )
        attempts += 1
        if result.get("status") != "queued" or result.get("retryable") is False:
            result.update(
                {
                    "attempts": attempts,
                    "waited_seconds": args.wait_seconds - max(0, deadline - now()),
                }
            )
            emit(result, p.returncode)
        remaining = deadline - now()
        if remaining <= 0:
            result.update(
                {
                    "status": "queued-timeout",
                    "attempts": attempts,
                    "waited_seconds": args.wait_seconds,
                    "next_retry_after_seconds": min(delay, 300),
                }
            )
            emit(result, 2)
        sleep_for = min(
            float(result.get("retry_after_seconds", delay)), delay, remaining
        )
        time.sleep(max(1, sleep_for))
        delay = min(delay * 2, 120)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("admission")
    a.add_argument("--min-ram-available-mib", type=int, default=DEFAULT_RAM_MIB)
    a.add_argument("--min-swap-free-mib", type=int, default=DEFAULT_SWAP_MIB)
    s = sub.add_parser("start")
    s.add_argument("program", nargs="?")
    s.add_argument("account", nargs="?")
    s.add_argument("--auth-domain")
    s.add_argument("--agent-id", required=True)
    s.add_argument("--run-id", required=True)
    s.add_argument("--purpose", required=True)
    s.add_argument("--url")
    s.add_argument("--ttl-seconds", type=int, default=1800)
    s.add_argument("--idle-seconds", type=int, default=DEFAULT_IDLE)
    s.add_argument("--min-ram-available-mib", type=int, default=DEFAULT_RAM_MIB)
    s.add_argument("--min-swap-free-mib", type=int, default=DEFAULT_SWAP_MIB)
    s.add_argument("--memory-high", default="1G")
    s.add_argument("--memory-max", default="2G")
    s.add_argument(
        "--proxy-cert-mode",
        choices=("auto", "import", "ignore", "none"),
        default="import",
    )
    s.add_argument("--proxy-server")
    s.add_argument("--mitm-ca-cert")
    s.add_argument("--display-backend", choices=("auto", "default", "kasmvnc"))
    s.add_argument("--kasmvnc-display", type=int)
    s.add_argument("--kasmvnc-web-port", type=int)
    s.add_argument(
        "--recover-profile",
        action="store_true",
        help="Lease an unavailable but eligible profile only to repair or re-authenticate it; release healthy before ordinary reuse.",
    )
    r0 = sub.add_parser("request")
    r0.add_argument("program", nargs="?")
    r0.add_argument("account", nargs="?")
    r0.add_argument("--auth-domain")
    r0.add_argument("--agent-id", required=True)
    r0.add_argument("--run-id", required=True)
    r0.add_argument("--purpose", required=True)
    r0.add_argument("--url")
    r0.add_argument("--ttl-seconds", type=int, default=1800)
    r0.add_argument("--idle-seconds", type=int, default=DEFAULT_IDLE)
    r0.add_argument("--wait-seconds", type=int, default=120)
    r0.add_argument("--min-ram-available-mib", type=int, default=DEFAULT_RAM_MIB)
    r0.add_argument("--min-swap-free-mib", type=int, default=DEFAULT_SWAP_MIB)
    r0.add_argument("--memory-high", default="1G")
    r0.add_argument("--memory-max", default="2G")
    r0.add_argument(
        "--proxy-cert-mode",
        choices=("auto", "import", "ignore", "none"),
        default="import",
    )
    r0.add_argument("--proxy-server")
    r0.add_argument("--mitm-ca-cert")
    r0.add_argument("--display-backend", choices=("auto", "default", "kasmvnc"))
    r0.add_argument("--kasmvnc-display", type=int)
    r0.add_argument("--kasmvnc-web-port", type=int)
    r0.add_argument(
        "--recover-profile",
        action="store_true",
        help="Lease an unavailable but eligible profile only to repair or re-authenticate it; release healthy before ordinary reuse.",
    )
    t = sub.add_parser("touch")
    t.add_argument("--lease-id", required=True)
    t.add_argument("--agent-id", required=True)
    t.add_argument("--ttl-seconds", type=int, default=1800)
    t.add_argument(
        "--work-state", choices=("active", "awaiting-input"), default="active"
    )
    q = sub.add_parser("status")
    q.add_argument("--lease-id", required=True)
    q.add_argument("--agent-id", required=True)
    r = sub.add_parser("reap-idle")
    r.add_argument("--idle-seconds", type=int, default=DEFAULT_IDLE)
    w = sub.add_parser("sweep-stale")
    w.add_argument("--older-than-days", type=int, default=14)
    w.add_argument("--confirm", action="store_true")
    x = sub.add_parser("release")
    x.add_argument("--lease-id", required=True)
    x.add_argument("--agent-id", required=True)
    x.add_argument(
        "--disposition", choices=("completed", "handoff", "cancelled"), required=True
    )
    x.add_argument(
        "--profile-health",
        choices=("healthy", "needs-refresh", "needs-cleanup", "unknown"),
        required=True,
    )
    for name in ("task-proxy-status", "task-proxy-finish", "task-proxy-recover"):
        parser = sub.add_parser(name)
        parser.add_argument("--agent-id", required=True)
        parser.add_argument("--run-id", required=True)
    for parser in (s, r0):
        parser.add_argument("--proxy", choices=("mitm", "external", "none"), default="mitm",
                            help="Task-owned MITM by default; external requires an explicit listener; none forces direct routing.")
        parser.add_argument("--driving-mode", choices=("agent-driven", "manual"),
                            help="Fresh browsers default to agent-driven; omitted retries preserve existing mode. Explicit mismatches require release/restart.")
        parser.add_argument("--task-owned", action="store_true")
        selection = parser.add_mutually_exclusive_group()
        selection.add_argument("--instance-key", help="Explicit isolated profile slot; omitted automatically selects safe pool instances, preserving existing legacy profiles.")
        selection.add_argument("--legacy-profile", action="store_true", help="Keep legacy single-profile selection even for a fresh account/domain.")
        parser.add_argument(
            "--owner-pid",
            type=int,
            help="Long-lived task supervisor PID on this node, not this short-lived CLI.",
        )
        parser.add_argument(
            "--proxy-ownership", choices=("task", "browser"), default="task"
        )
        parser.add_argument("--headless", action="store_true")
        parser.add_argument("--graphics-backend", choices=("auto", "external"), default="auto",
                            help="auto probes headed NVK/Vulkan and otherwise uses ANGLE/GL; external leaves flags to the selected executable.")
    t.add_argument("--awaiting-seconds", type=int, default=1800)
    sub.add_parser("maintain")
    watcher = sub.add_parser("watch")
    watcher.add_argument("--browser-id", required=True)
    args = p.parse_args()
    if args.cmd in ("start", "request"):
        import browser_profile_lease as profiles
        try:
            profiles.instance_key(args)
        except ValueError as exc:
            p.error(str(exc))
        if not 1 <= args.idle_seconds < 7200:
            p.error("idle claim window must be between 1 and 7199 seconds")
        if args.ttl_seconds < 30:
            p.error("ttl must be at least 30 seconds")
        if not args.task_owned and (not args.program or not args.account):
            p.error("program and account required unless --task-owned")
    if args.cmd == "maintain":
        maintain(args)
    if args.cmd == "watch":
        watch(args)
    if args.cmd == "admission":
        emit(admission(args.min_ram_available_mib, args.min_swap_free_mib), 0)
    if args.cmd == "start":
        start(args)
    if args.cmd == "request":
        request(args)
    if args.cmd == "touch":
        touch(args)
    if args.cmd == "status":
        status(args)
    if args.cmd == "reap-idle":
        reap(args)
    if args.cmd == "sweep-stale":
        sweep(args)
    if args.cmd == "release":
        release(args)
    if args.cmd == "task-proxy-status":
        task_proxy_status(args)
    if args.cmd == "task-proxy-finish":
        task_proxy_finish(args)
    if args.cmd == "task-proxy-recover":
        task_proxy_recover(args)


if __name__ == "__main__":
    main()
