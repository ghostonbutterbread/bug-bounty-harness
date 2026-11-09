#!/usr/bin/env python3
"""Node-local, resource-gated persistent Chromium provisioner.

Runs on the browser node. It leases an exact account profile, checks that
node's resources, and keeps each Chromium root inside a user-systemd unit.
It never prints CDP URLs, cookies, credentials, or auth-seed locations.
"""

from __future__ import annotations
import argparse, contextlib, errno, functools, grp, hashlib, io, json, os, pwd, re, shutil, socket, sqlite3, stat, struct, subprocess, sys, time, uuid
from urllib.parse import urlsplit
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from browser_lifecycle import StartupDiagnostics, node_lock, owner_state, private_json, process_identity
from chromium_test import resolve_mitm_ca_cert
from mitm_chromium_profile import DEFAULT_CA_CERT, remove_matching_ca
from proxy_store import (
    DEFAULT_AGENT_PORT_MIN, DEFAULT_AGENT_PORT_MAX, DEFAULT_STORE,
    TASK_PROXY_OVERFLOW_PORT_MIN, TASK_PROXY_OVERFLOW_PORT_MAX, active_lease_where,
)

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
# The child-to-request signal contains no exception text or other diagnostic data.
LEASE_RELEASE_UNVERIFIED = {'status': 'cleanup-incomplete', 'reason': 'lease-release-not-verified'}
PROXY_CLEANUP_UNVERIFIED = {'status': 'cleanup-incomplete', 'reason': 'proxy-cleanup-not-verified'}
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
                             ("owner", "TEXT"), ("invocation", "TEXT"),
                             ("exact_program", "TEXT"), ("flow_path", "TEXT"),
                             ("capture_identity", "TEXT"), ("admitted", "INTEGER")):
        if name not in columns:
            c.execute(f"alter table task_proxies add column {name} {definition}")
    c.execute("CREATE TABLE IF NOT EXISTS finished_proxies (agent_id TEXT NOT NULL, run_id TEXT NOT NULL, lane TEXT NOT NULL, finished REAL NOT NULL, PRIMARY KEY(agent_id, run_id))")
    c.execute("""CREATE TABLE IF NOT EXISTS proxy_attempts (
        agent_id TEXT NOT NULL, run_id TEXT NOT NULL, lane TEXT NOT NULL,
        outcome TEXT NOT NULL, PRIMARY KEY(agent_id, run_id))""")
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
    c.execute("""CREATE TABLE IF NOT EXISTS team_grants (
        lease_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL,
        worker_agent_id TEXT NOT NULL, worker_run_id TEXT NOT NULL,
        reference TEXT NOT NULL, generation TEXT NOT NULL,
        process_identity TEXT NOT NULL, baseline INTEGER NOT NULL DEFAULT 0)""")
    c.execute('CREATE TABLE IF NOT EXISTS team_pending (lease_id TEXT PRIMARY KEY, payload TEXT NOT NULL)')
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
            # Inactive is not proof that this is the recorded unit invocation:
            # systemd may have started and stopped a replacement since launch.
            try:
                invocation = unit_identity(row['unit'])
            except Exception:
                return {'status': 'reservation-unavailable'}
            if not invocation or invocation != reserved['unit_invocation'] or invocation != info['unit_invocation']:
                return {'status': 'reservation-unavailable'}
            # stopped() only interprets is-active's nonzero exit; cancellation
            # needs affirmative systemd evidence, including a loaded unit.
            try:
                if not unit_explicitly_inactive(row['unit']):
                    return {'status': 'reservation-unavailable'}
            except Exception:
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

def _transfer_policy_pool(manager_db, leases, source_id, destination_id, *, fixture_only=True):
    """Read-only exact pool evidence before any browser health probe.

    A mismatch defers to the full candidate gate; it never grants transfer.
    Called only under the manager node lock and canonical write transaction.
    """
    if not source_id or not destination_id or source_id == destination_id:
        return None
    rows = []
    for lid in (source_id, destination_id):
        row = manager_db.execute('SELECT * FROM browsers WHERE lease_id=?', (lid,)).fetchone()
        canonical = leases.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?', (lid,)).fetchone()
        if (not row or not canonical or row['state'] != 'running'
                or canonical['status'] != 'active' or canonical['browser_status'] != 'running'
                or canonical['expires_at'] <= now()
                or (fixture_only and tuple(row[k] for k in ('program', 'auth_domain', 'account')) != FIXTURE_POOL)
                or any(canonical[k] != v for k, v in (
                    ('program', row['program']), ('auth_domain', row['auth_domain']),
                    ('account_alias', row['account']), ('owner_agent_id', row['agent_id']),
                    ('owner_run_id', row['run_id']), ('profile_dir', row['profile_dir']),
                    ('service_unit', row['unit']), ('manager_id', manager_id())))):
            return None
        rows.append(row)
    source, dest = rows
    key = ('program', 'auth_domain', 'account')
    return tuple(source[k] for k in key) if all(source[k] == dest[k] for k in key) else None


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

def _auth_contract_filename(pool):
    """Opaque, deterministic manager-only filename for an exact three-part pool."""
    digest = hashlib.sha256(json.dumps(pool, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    return digest + '.json'

def _approved_site_contract(pool, origin):
    if str(ROOT.parents[2]) not in sys.path:
        sys.path.insert(0, str(ROOT.parents[2]))
    from agents.browser_auth_site_contract import load_site_contract, SiteContractError
    contract = load_site_contract(STATE.parent / 'auth-site-contracts' / _auth_contract_filename(pool),
        program=pool[0], auth_domain=pool[1], account_alias=pool[2], origin=origin)
    if pool == FIXTURE_POOL or not origin.startswith('https://'):
        raise SiteContractError('Approved transfer requires a non-fixture HTTPS origin')
    return contract


def _fixture_check_expression(contract, *, omit_credentials=False):
    # Fixed manager code: URL and selector/key are JSON data, not caller code.
    credential_mode = "'omit'" if omit_credentials else "'same-origin'"
    if contract.principal_json_key is not None:
        key = json.dumps(contract.principal_json_key)
        return """(async () => {
            const response = await fetch(%s, {redirect: 'manual', credentials: %s});
            const redirected = response.type === 'opaqueredirect' || response.status >= 300 && response.status < 400;
            if (redirected) return {url: response.url, status: response.status, redirected: true, principal: ''};
            let principal = '';
            try {
                const data = await response.json();
                if (data !== null && typeof data === 'object' && !Array.isArray(data) &&
                    Object.prototype.hasOwnProperty.call(data, %s) && typeof data[%s] === 'string') {
                    principal = data[%s];
                }
            } catch (_) { /* malformed JSON is an unauthenticated observation */ }
            return {url: response.url, status: response.status, redirected: false, principal};
        })()""" % (json.dumps(contract.check_url), credential_mode, key, key, key)
    return """(async () => {
        const response = await fetch(%s, {redirect: 'manual', credentials: %s});
        const redirected = response.type === 'opaqueredirect' || response.status >= 300 && response.status < 400;
        if (redirected) return {url: response.url, status: response.status, redirected: true, principal: ''};
        const html = await response.text();
        const element = new DOMParser().parseFromString(html, 'text/html').querySelector(%s);
        return {url: response.url, status: response.status, redirected: false,
                principal: element ? element.textContent.trim() : ''};
    })()""" % (json.dumps(contract.check_url), credential_mode, json.dumps(contract.principal_selector))


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
    """Compatibility entry: disposable localhost pool only, unchanged receipt."""
    if not _fixture_origin(origin):
        return {'status': 'auth-clone-unavailable', 'reason': 'site-contract-unavailable'}
    return _manager_auth_transfer(source_lease_id, destination_lease_id, origin=origin,
                                  fixture_only=True)

def manager_approved_auth_transfer(source_lease_id, destination_lease_id, *, origin,
                                   source_owner_agent_id, source_owner_run_id,
                                   destination_owner_agent_id, destination_owner_run_id):
    """Privileged coordinator operation for an approved HTTPS pool, empty recipient.

    Lease and owner arguments are assertions, not credentials. Only invoke from
    a manager-controlled process, never expose this as an agent RPC. The private
    contract path and actual pool are derived from canonical manager records.
    """
    try:
        parsed = urlsplit(origin)
        valid = (parsed.scheme == 'https' and parsed.hostname and
                 parsed.netloc == (parsed.hostname + (f':{parsed.port}' if parsed.port else ''))
                 and parsed.port != 443 and origin == f'https://{parsed.netloc}')
    except (TypeError, ValueError):
        valid = False
    if not valid:
        return {'status': 'auth-clone-unavailable', 'reason': 'site-contract-unavailable'}
    owners = ((source_owner_agent_id, source_owner_run_id),
              (destination_owner_agent_id, destination_owner_run_id))
    if any(not isinstance(value, str) or not value for pair in owners for value in pair):
        return {'status': 'auth-clone-unavailable', 'reason': 'manager-identity-unverified'}
    return _manager_auth_transfer(source_lease_id, destination_lease_id, origin=origin,
                                  fixture_only=False, expected_owners=owners)

def _manager_auth_transfer(source_lease_id, destination_lease_id, *, origin,
                           fixture_only, expected_owners=None):
    """Single fenced transaction for both fixture and approved-origin transfer."""
    import browser_profile_lease as profiles
    import httpx
    if str(ROOT.parents[2]) not in sys.path:
        sys.path.insert(0, str(ROOT.parents[2]))
    from agents.browser_auth_site_contract import SiteContractError, verify_cookie_scope, exact_origin_cookie_params
    unavailable = lambda reason: {'status': 'auth-clone-unavailable', 'reason': reason}
    if (not isinstance(source_lease_id, str) or not source_lease_id or
            not isinstance(destination_lease_id, str) or not destination_lease_id or
            source_lease_id == destination_lease_id):
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

    def app_check(client, ticket, *, unauthenticated=False):
        observation = eval_js(client, ticket, negative_check if unauthenticated else check)
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
            pool = _transfer_policy_pool(manager_db, leases, source_lease_id, destination_lease_id,
                                        fixture_only=fixture_only)
            if not fixture_only and not pool:
                return unavailable('manager-identity-unverified')
            if expected_owners and pool:
                rows = [manager_db.execute('SELECT agent_id,run_id FROM browsers WHERE lease_id=?',
                                           (lid,)).fetchone() for lid in (source_lease_id, destination_lease_id)]
                if any(row is None or (row['agent_id'], row['run_id']) != owner
                       for row, owner in zip(rows, expected_owners)):
                    return unavailable('manager-identity-unverified')
            if pool and profiles.single_browser_policy(leases, pool[0], pool[2], pool[1]):
                return unavailable('single-browser-policy')
            candidates = _transfer_candidates(manager_db, leases, source_lease_id, destination_lease_id)
            if not candidates:
                return unavailable('manager-identity-unverified')
            if fixture_only and any(tuple(row[k] for k in ('program','auth_domain','account')) != FIXTURE_POOL
                                    for row, _, _ in candidates):
                return unavailable('site-contract-unavailable')
            if expected_owners and any((row['agent_id'], row['run_id']) != owner
                                       for (row, _, _), owner in zip(candidates, expected_owners)):
                return unavailable('manager-identity-unverified')
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
                actual_pool = tuple(source_row[k] for k in ('program', 'auth_domain', 'account'))
                contract = (_fixture_site_contract(origin) if fixture_only else
                            _approved_site_contract(actual_pool, origin))
            except SiteContractError:
                return unavailable('site-contract-unavailable')
            check = _fixture_check_expression(contract)
            negative_check = (_fixture_check_expression(contract, omit_credentials=True)
                              if not fixture_only else check)
            def reaches_origin(cookie):
                domain = cookie.get('domain', '').lstrip('.')
                return (contract.cookie_domain == domain or
                        contract.cookie_domain.endswith('.' + domain))

            # The approved contract remains a selector, not proof of login:
            # each independently fenced browser must attest its own principal.
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
            exact_mode = False
            selected = []
            storage = {}
            entries = []
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
                    if not fixture_only:
                        require(eval_js(destination, dt, 'localStorage.length') == 0 and
                                eval_js(destination, dt, 'sessionStorage.length') == 0,
                                'destination-not-empty')
                        require(not any(reaches_origin(c) for c in
                                        call(destination, dt, 'Network.getAllCookies')['cookies']),
                                'destination-not-empty')
                    require(not app_check(destination, dt, unauthenticated=not fixture_only),
                            'destination-not-empty')
                    if not fixture_only:
                        require(eval_js(destination, dt, 'localStorage.length') == 0 and
                                eval_js(destination, dt, 'sessionStorage.length') == 0 and
                                not any(reaches_origin(c) for c in
                                        call(destination, dt, 'Network.getAllCookies')['cookies']),
                                'destination-not-empty')
                    for key in contract.local_storage_keys:
                        require(eval_js(destination, dt, 'localStorage.getItem(' + json.dumps(key) + ')') is None,
                                'destination-not-empty')
                    cookies = call(source, st, 'Network.getAllCookies')['cookies']
                    exact_mode = not fixture_only and contract.state_mode == 'exact-origin'
                    source_cookie_snapshot = {}
                    if exact_mode:
                        try:
                            selected = exact_origin_cookie_params(cookies, contract.cookie_domain, origin)
                        except SiteContractError:
                            raise TransferError('source-cookie-unverified') from None
                        # Conversion can narrow an exact-host Domain cookie to
                        # host-only. Retain its raw scope/attributes as well so
                        # that a later source scope change cannot compare equal.
                        source_cookie_snapshot = {
                            (c['name'], c['path']): dict(c) for c in cookies if reaches_origin(c)
                        }
                    else:
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
                    require(not any(reaches_origin(c) if not fixture_only else
                                    c['domain'] == contract.cookie_domain for c in existing),
                            'destination-not-empty')
                    if exact_mode:
                        require(eval_js(source, st, 'sessionStorage.length') == 0,
                                'source-storage-unverified')
                        entries = eval_js(source, st, 'Object.entries(localStorage)')
                        require(type(entries) is list and len(entries) <= 64 and
                                all(type(pair) is list and len(pair) == 2 and
                                    all(type(item) is str for item in pair) for pair in entries),
                                'source-storage-unverified')
                        storage = dict(entries)
                        require(len(storage) == len(entries) and
                                sum(len(k.encode()) + len(v.encode()) for k, v in storage.items()) <= 65536,
                                'source-storage-unverified')
                    else:
                        storage = {key: eval_js(source, st, 'localStorage.getItem(' + json.dumps(key) + ')')
                                   for key in contract.local_storage_keys}
                        require(all(isinstance(value, str) and value and
                                    (not fixture_only or value == 'approved') for value in storage.values()),
                                'source-storage-unverified')
                    imported = True  # cleanup even if the CDP write succeeds but its reply is lost
                    call(destination, dt, 'Network.setCookies', {'cookies': selected})
                    for key, value in storage.items():
                        eval_js(destination, dt, 'localStorage.setItem(' + json.dumps(key) + ',' + json.dumps(value) + ')')
                    if exact_mode:
                        try:
                            copied = exact_origin_cookie_params(
                                call(destination, dt, 'Network.getAllCookies')['cookies'],
                                contract.cookie_domain, origin)
                        except SiteContractError:
                            raise TransferError('destination-cookie-unverified') from None
                        host_only = {(c['name'], c['path']) for c in selected if 'domain' not in c}
                        if host_only:
                            child = origin.replace('://', '://probe.', 1)
                            child_cookies = call(destination, dt, 'Network.getCookies',
                                {'urls': [child + c['path'] for c in selected if 'domain' not in c]})['cookies']
                            require(type(child_cookies) is list and
                                    all(type(c) is dict and (c.get('name'), c.get('path')) not in host_only
                                        for c in child_cookies), 'destination-cookie-unverified')
                        require(copied == selected and
                                eval_js(destination, dt, 'Object.entries(localStorage)') == entries,
                                'destination-state-unverified')
                    # Even a failed or interrupted recipient check must be followed
                    # by source principal/state proof before rollback can release
                    # an imported recipient. Preserve the original interruption.
                    source_recheck_failed = True
                    recipient_check_error = None
                    try:
                        recipient_passed = app_check(destination, dt)
                    except BaseException as exc:
                        recipient_passed = False
                        recipient_check_error = exc
                    source_unchanged = False
                    try:
                        source_unchanged = (app_check(source, st) and
                                            eval_js(source, st, 'location.href') == source_url)
                        if source_unchanged and exact_mode:
                            try:
                                rechecked_cookies = call(source, st, 'Network.getAllCookies')['cookies']
                                source_unchanged = (exact_origin_cookie_params(
                                    rechecked_cookies, contract.cookie_domain, origin) == selected and
                                    {(c['name'], c['path']): c for c in rechecked_cookies
                                     if reaches_origin(c)} == source_cookie_snapshot)
                            except SiteContractError:
                                source_unchanged = False
                            if source_unchanged:
                                source_unchanged = eval_js(source, st, 'Object.entries(localStorage)') == entries
                    except BaseException:
                        if recipient_check_error is None:
                            raise
                    if source_unchanged:
                        source_recheck_failed = False
                    if recipient_check_error is not None:
                        raise recipient_check_error.with_traceback(recipient_check_error.__traceback__)
                    require(source_unchanged, 'source-changed')
                    require(recipient_passed, 'destination-app-check-failed')
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
                            if reason or active_failure is not None:
                                destination, dt = clients[1], tickets[1]
                                for cookie in (selected if exact_mode else [{'name': contract.cookie_name,
                                                                               'url': origin + contract.cookie_path,
                                                                               'path': contract.cookie_path}]):
                                    call(destination, dt, 'Network.deleteCookies',
                                         {k: cookie[k] for k in ('name', 'url', 'domain', 'path') if k in cookie})
                                for key in storage:
                                    eval_js(destination, dt, 'localStorage.removeItem(' + json.dumps(key) + ')')
                                cleaned = (not app_check(destination, dt, unauthenticated=not fixture_only) and
                                           ((eval_js(destination, dt, 'localStorage.length') == 0 and
                                             eval_js(destination, dt, 'sessionStorage.length') == 0)
                                            if not fixture_only else
                                            all(eval_js(destination, dt, 'localStorage.getItem(' + json.dumps(key) + ')') is None
                                                for key in contract.local_storage_keys)) and
                                           not any(reaches_origin(c) if not fixture_only else
                                                   c['domain'] == contract.cookie_domain for c in
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
                    if isinstance(cleanup_failure, (OSError, ValueError, KeyError, httpx.HTTPError)):
                        reason = 'destination-cleanup-incomplete'
                    else:
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
                # An end ACK does not prove the source is usable. Independently
                # read the exact original process and public generation before
                # publishing the recipient; never alter or stop the source.
                if imported and not fixture_only and 0 not in uncertain_begin:
                    try:
                        with httpx.Client(transport=httpx.HTTPTransport(
                                uds=candidates[0][1]['control_socket']), timeout=15) as source_probe:
                            reply = source_probe.get('http://localhost/identity')
                            reply.raise_for_status()
                            observed = reply.json()
                            info = candidates[0][1]
                            if not (observed.get('available') is True and observed.get('quarantined') is False
                                    and observed.get('cdp_url') == info['cdp_url']
                                    and observed.get('process_identity') == info['process_identity']):
                                uncertain_begin.add(0)
                    except BaseException:
                        uncertain_begin.add(0)
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
                if imported and (source_unproved or source_recheck_failed or destination_end_unverified or not cleaned):
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
                    if not cleaned:
                        return {'status': 'auth-clone-unavailable', 'reason': 'destination-cleanup-incomplete',
                                'source': 'owner-preserved', 'destination': 'cleanup-incomplete'}
                    if activation_attempted:
                        if activation_fenced:
                            return {'status': 'auth-clone-unavailable',
                                    'reason': 'destination-fenced-after-activation-uncertainty',
                                    'source': 'owner-preserved', 'destination': 'fenced'}
                        return {'status': 'fixture-auth-transfer-terminal-uncertain' if fixture_only else 'auth-transfer-terminal-uncertain',
                                'source': 'owner-preserved', 'destination': 'cleanup-incomplete',
                                'public_exposure': 'possible'}
                    return unavailable('destination-cleanup-incomplete')
                if uncertain_begin:
                    return unavailable(('source' if source_unproved else 'destination') + '-cleanup-incomplete')
                if not cleaned:
                    return unavailable('destination-cleanup-unverified')
                return unavailable(reason) if reason else {'status':
                    'fixture-auth-transferred' if fixture_only else 'auth-transferred'}
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


def unit_explicitly_inactive(unit):
    """Cancellation proof: an existing loaded unit must report inactive."""
    result = subprocess.run(
        ["systemctl", "--user", "show", "--property=ActiveState",
         "--property=LoadState", unit],
        capture_output=True, text=True, env=sysenv(),
    )
    if result.returncode != 0:
        return False
    lines = result.stdout.splitlines()
    return len(lines) == 2 and set(lines) == {"ActiveState=inactive", "LoadState=loaded"}


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
    path = proxy_metadata(row)["flow_file"]
    if path is None:
        return False
    flow = Path(path)
    cutoff = now() - 7200
    return (row["updated"] < cutoff and replay_clients_absent(row["port"])
            and (not flow.exists() or flow.stat().st_mtime < cutoff))


def proxy_row(c, args):
    return c.execute("select * from task_proxies where agent_id=? and run_id=?",
                     (args.agent_id, args.run_id)).fetchone()


_CAPTURE_BOUNTY_ROOT = Path('/mnt/bounty')


def _capture_trusted_groups():
    groups = set()
    for name in ('smb_write', 'ai_smb_write'):
        try:
            groups.add(grp.getgrnam(name).gr_gid)
        except KeyError:
            pass
    return groups


def _capture_trusted_user(uid, groups):
    if uid in (0, os.geteuid()):
        return True
    try:
        user = pwd.getpwuid(uid)
        return bool(groups.intersection(os.getgrouplist(user.pw_name, user.pw_gid)))
    except (KeyError, OSError):
        return False


def _capture_open_dir(path, *, create_from=None):
    """Walk trusted directories without symlinks; create only below program."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('invalid capture directory')
    approved_groups = _capture_trusted_groups() if path.is_relative_to(_CAPTURE_BOUNTY_ROOT) else set()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    protected = False
    current = Path('/')
    try:
        for part in (*path.parts[1:], None):
            # Trust the named groups only inside the literal approved chain;
            # ancestor checks and unrelated state/override paths stay conservative.
            groups = approved_groups if current.is_relative_to(_CAPTURE_BOUNTY_ROOT) else set()
            info = os.fstat(fd)
            if not _capture_trusted_user(info.st_uid, groups):
                raise PermissionError('untrusted capture directory owner')
            try:
                acl = os.getxattr(fd, 'system.posix_acl_access')
            except OSError as exc:
                if exc.errno != errno.ENODATA:
                    raise PermissionError('capture ACL unavailable') from exc
                acl = None
            entries = {}
            if acl is not None:
                if len(acl) < 4 or (len(acl) - 4) % 8 or struct.unpack_from('<I', acl)[0] != 2:
                    raise PermissionError('invalid capture ACL')
                for tag, perms, ident in struct.iter_unpack('<HHI', acl[4:]):
                    if tag not in (1, 2, 4, 8, 16, 32) or perms & ~7 or (tag, ident) in entries:
                        raise PermissionError('invalid capture ACL')
                    entries[tag, ident] = perms
                if any((tag, 0xffffffff) not in entries for tag in (1, 4, 16, 32)):
                    raise PermissionError('incomplete capture ACL')
                mask = entries[16, 0xffffffff]
                group = entries[4, 0xffffffff] & mask
                other = entries[32, 0xffffffff]
            else:
                mask = (info.st_mode >> 3) & 7
                group, other = mask, info.st_mode & 7
            if not protected and not info.st_mode & stat.S_ISVTX:
                if other & 2 or (group & 2 and info.st_gid not in groups):
                    raise PermissionError('untrusted capture directory writer')
                for (tag, ident), perms in entries.items():
                    if perms & mask & 2 and ((tag == 2 and not _capture_trusted_user(ident, groups))
                                             or (tag == 8 and ident not in groups)):
                        raise PermissionError('untrusted capture ACL writer')
            if info.st_uid == os.geteuid() and not info.st_mode & 0o077:
                protected = True
            if part is None:
                return fd
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if create_from is None or not current.is_relative_to(create_from):
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            current /= part
    except BaseException:
        os.close(fd)
        raise


class CaptureNotAllocated(OSError):
    """Allocation definitely did not create a capture file."""


def _capture_file(directory, name='flows.mitm'):
    try:
        parent = _capture_open_dir(directory.parent)
    except OSError as exc:
        raise CaptureNotAllocated('capture parent unavailable') from exc
    try:
        try:
            os.mkdir(directory.name, 0o700, dir_fd=parent)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EPERM, errno.EROFS):
                raise
            raise CaptureNotAllocated('capture directory allocation failed') from exc
        child = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            os.fchmod(child, 0o700)
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=child)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        finally:
            os.close(child)
    finally:
        os.close(parent)
    return directory / name


def _capture_local_private_path(path):
    """Reject Shared and non-local filesystems without following path aliases."""
    import browser_profile_lease as profiles
    path = path.absolute()
    try:
        shared_roots = (Path.home() / 'Shared', profiles.shared_base())
        for shared in shared_roots:
            shared = shared.expanduser().absolute()
            if path.is_relative_to(shared) or path.resolve().is_relative_to(shared.resolve()):
                return False
        mounts = []
        def unescape(value):
            return Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), value))
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            left, right = line.split(' - ', 1)
            fields = left.split()
            mounts.append((unescape(fields[4]), fields[2], unescape(fields[3]), right.split()[0]))
        def backing(candidate):
            matches = [entry for entry in mounts if candidate.is_relative_to(entry[0])]
            depth = max(len(entry[0].parts) for entry in matches)
            choices = [entry for entry in matches if len(entry[0].parts) == depth]
            if len(choices) != 1:
                raise ValueError('ambiguous capture mount')
            target, device, root, kind = choices[0]
            return device, root / candidate.relative_to(target), kind
        device, backing_path, kind = backing(path.resolve())
        if kind not in {'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'f2fs', 'zfs', 'tmpfs'}:
            return False
        for shared in shared_roots:
            shared_device, shared_path, _ = backing(shared.expanduser().resolve())
            if device == shared_device and backing_path.is_relative_to(shared_path):
                return False
        return True
    except (OSError, ValueError, IndexError, RuntimeError):
        return False


def _capture_identity(flow, mount=None):
    """Bind a capture to its private directory/file and mounted root inodes."""
    if not _capture_local_private_path(flow):
        raise PermissionError('capture is on Shared or non-local storage')
    fd = _capture_open_dir(flow.parent)
    try:
        directory = os.fstat(fd)
        f = os.open(flow.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(f)
            if (directory.st_uid != os.geteuid() or directory.st_mode & 0o077
                    or info.st_uid != os.geteuid() or info.st_mode & 0o077
                    or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                raise PermissionError('capture file is not private')
            result = {'directory': [directory.st_dev, directory.st_ino], 'file': [info.st_dev, info.st_ino]}
        finally:
            os.close(f)
    finally:
        os.close(fd)
    if mount is not None:
        import browser_profile_lease as profiles
        if not profiles.default_mount_available() or not profiles.local_filesystem(flow.parent):
            raise OSError('capture mount unavailable')
        root = mount.stat()
        result['mount'] = [root.st_dev, root.st_ino]
    return result


def select_task_capture(program, lane, root, allocation_state=None):
    """Prefer an existing exact mounted program; otherwise use the private run."""
    import browser_profile_lease as profiles
    mount = profiles.DEFAULT_BOUNTY_ROOT
    if (isinstance(program, str) and program not in ('', '.', '..')
            and '/' not in program and '\0' not in program):
        try:
            if not profiles.default_mount_available() or not profiles.local_filesystem(mount / program):
                raise OSError('mount unavailable')
            program_dir = mount / program
            if not _capture_local_private_path(program_dir):
                raise OSError('capture program is on Shared or non-local storage')
            fd = _capture_open_dir(program_dir)
            os.close(fd)
            parent = program_dir / 'web' / 'proxy' / 'flows'
            if not _capture_local_private_path(parent):
                raise OSError('capture directory is on Shared or non-local storage')
            fd = _capture_open_dir(parent, create_from=program_dir)
            os.close(fd)
            if not _capture_local_private_path(parent):
                raise OSError('capture directory is on Shared or non-local storage')
            # From allocation onward, failure is ambiguous: never silently
            # fall back and abandon a file that may already have been created.
        except (OSError, ValueError):
            parent = None
        if parent is not None:
            if allocation_state:
                allocation_state(True)
            try:
                flow = _capture_file(parent / lane)
            except CaptureNotAllocated:
                if allocation_state:
                    allocation_state(False)
            else:
                return flow, _capture_identity(flow, mount)
    if allocation_state:
        allocation_state(True)
    flow = _capture_file(root / 'capture')
    return flow, _capture_identity(flow)


def verify_task_capture(row):
    if not row['flow_path']:
        if row['capture_identity']:
            raise OSError('capture allocation was not committed')
        return  # pre-migration legacy rows use run_dir/flows.mitm
    import browser_profile_lease as profiles
    expected = json.loads(row['capture_identity'])
    mount = profiles.DEFAULT_BOUNTY_ROOT if 'mount' in expected else None
    if _capture_identity(Path(row['flow_path']), mount) != expected:
        raise OSError('capture generation changed')


def _launch_verified_capture(flow, expected, command):
    """Open the recorded file in the service, without truncation, before exec."""
    import browser_profile_lease as profiles
    flow = Path(flow)
    if not _capture_local_private_path(flow):
        raise OSError('capture is on Shared or non-local storage')
    mount_fd = None
    directory_fd = None
    file_fd = None
    try:
        if 'mount' in expected:
            if not profiles.default_mount_available() or not profiles.local_filesystem(flow.parent):
                raise OSError('capture mount unavailable')
            mount_fd = _capture_open_dir(profiles.DEFAULT_BOUNTY_ROOT)
            mount = os.fstat(mount_fd)
            if [mount.st_dev, mount.st_ino] != expected['mount']:
                raise OSError('capture mount changed')
        directory_fd = _capture_open_dir(flow.parent)
        directory = os.fstat(directory_fd)
        file_fd = os.open(flow.name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        info = os.fstat(file_fd)
        if ([directory.st_dev, directory.st_ino] != expected['directory']
                or [info.st_dev, info.st_ino] != expected['file']):
            raise OSError('capture generation changed')
        if (directory.st_uid != os.geteuid() or directory.st_mode & 0o077
                or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise OSError('capture file is not private')
        os.set_inheritable(file_fd, True)
        os.execv(command[0], [*command, '-w', f'/proc/self/fd/{file_fd}'])
    finally:
        for fd in (file_fd, directory_fd, mount_fd):
            if fd is not None:
                os.close(fd)


def proxy_metadata(row):
    if not row:
        return None
    root = Path(row["run_dir"])
    return {"lane": row["lane"], "proxy_server": f"http://127.0.0.1:{row['port']}",
            "ca_cert": str(root / "mitmproxy" / "mitmproxy-ca-cert.pem"),
            "flow_file": (None if row['capture_identity'] in ('allocation-pending', 'allocation-not-started') and not row['flow_path']
                          else row['flow_path'] or str(root / "flows.mitm")), "unit": row["unit"], "state": row["state"]}


class ProxyStartupError(RuntimeError):
    """A fixed, operator-safe proxy startup diagnostic."""


CAPTURE_UNCERTAIN_DETAIL = ("capture or service dispatch is uncertain; reservation retained. "
                            "Do not retry or replace the capture. Use task-proxy-status for the "
                            "recorded lane and identity; with the manager stopped and its lock "
                            "held, preserve the capture and state, verify unit and port ownership, "
                            "and manually reconcile the service and capture evidence")


def proxy_owner_matches(row, owner):
    try:
        recorded = json.loads(row["owner"]) if row["owner"] else None
    except (ValueError, TypeError):
        return False
    return (not row["owner"] or isinstance(recorded, dict)) and recorded == owner


def request_proxy_owner_matches(c, args, owner):
    if args.proxy != "mitm":
        return True
    task = proxy_row(c, args)
    if getattr(args, "owner_pid", None) and process_identity(args.owner_pid) != owner:
        return False
    return bool(task and proxy_owner_matches(task, owner))


def mitm_runtime():
    executable = shutil.which("mitmdump")
    if not executable:
        raise ProxyStartupError("mitmdump is unavailable")
    resolved = Path(executable).resolve()
    shebang = resolved.open("rb").readline().decode("utf-8", errors="replace").strip()
    interpreter = shebang[2:] if shebang.startswith("#!/") else ""
    if not Path(interpreter).is_file():
        raise ProxyStartupError("mitmdump Python interpreter is unavailable")
    if Path(interpreter).resolve().name in {"sh", "bash", "dash", "zsh", "ksh", "fish"}:
        raise ProxyStartupError("mitmdump shell wrapper unsupported; select a Python entrypoint")
    return str(resolved), interpreter


def proxy_ready(row):
    try:
        verify_task_capture(row)
    except (OSError, ValueError, TypeError):
        return False
    ca = Path(proxy_metadata(row)["ca_cert"])
    return (unit_active(row["unit"]) and bool(row["invocation"])
            and unit_identity(row["unit"]) == row["invocation"]
            and port_open(row["port"]) and ca.is_file() and ca.stat().st_size > 0)


def proxy_program_matches(row, program):
    if program is None:
        return False
    exact = row["exact_program"]
    return exact == program if exact is not None else row["program"] == slug(program)


def start_proxy(c, args):
    c.execute("BEGIN IMMEDIATE")
    owner = None
    if getattr(args, "owner_pid", None):
        owner = process_identity(args.owner_pid)
        if not owner or (getattr(args, "_owner_identity", None) is not None
                         and owner != args._owner_identity):
            c.rollback()
            emit({"status": "owner-unavailable"}, 2)
    row = proxy_row(c, args)
    if row:
        c.commit()
        if (not proxy_program_matches(row, args.program)
                or (row["account"], row["purpose"]) != (slug(args.account), args.purpose)
                or not proxy_owner_matches(row, owner)
                or row["state"] != "running" or not proxy_ready(row)):
            emit({"status": "proxy-conflict", "detail": "task listener unavailable or belongs to another request"}, 2)
        return row, False
    port = next((p for p in range(DEFAULT_AGENT_PORT_MIN, DEFAULT_AGENT_PORT_MAX + 1) if not c.execute(
        "select 1 from task_proxies where port=?", (p,)).fetchone() and not port_open(p)), None)
    if port is None:
        # An old custom standalone lease may predate the reserved overflow boundary.
        blocked = set()
        try:
            if DEFAULT_STORE.exists():
                with contextlib.closing(sqlite3.connect(f"{DEFAULT_STORE.as_uri()}?mode=ro", uri=True)) as leases:
                    stamp = time.time()
                    blocked = {row[0] for row in leases.execute(
                        f"select proxy_port from proxy_leases where {active_lease_where(stamp)}", (stamp,))}
        except sqlite3.Error:
            c.rollback()
            emit({"status": "proxy-unavailable", "detail": "standalone lease state unavailable"}, 2)
        port = next((p for p in range(TASK_PROXY_OVERFLOW_PORT_MIN, TASK_PROXY_OVERFLOW_PORT_MAX + 1)
                     if p not in blocked and not c.execute(
                         "select 1 from task_proxies where port=?", (p,)).fetchone() and not port_open(p)), None)
    if port is None:
        c.rollback()
        emit({"status": "proxy-unavailable", "detail": "no task MITM port available"}, 2)
    lane = "task-" + uuid.uuid4().hex
    root = STATE.parent / "task-proxies" / lane
    c.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state,updated,owner,exact_program,admitted,capture_identity) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
              (args.agent_id, args.run_id, slug(args.program), slug(args.account), args.purpose,
               lane, port, "task-mitm-" + lane, str(root), "starting", now(), json.dumps(owner) if owner else None, args.program, 0, 'allocation-not-started'))
    c.execute("insert or replace into proxy_attempts values(?,?,?,?)", (args.agent_id, args.run_id, lane, "starting"))
    c.commit()
    row = proxy_row(c, args)
    try:
        if not _capture_local_private_path(root):
            raise ProxyStartupError('private task state is on Shared or non-local storage')
        parent = _capture_open_dir(root.parent, create_from=STATE.parent)
        try:
            os.mkdir(root.name, 0o700, dir_fd=parent)
            root_fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                os.fchmod(root_fd, 0o700)
            finally:
                os.close(root_fd)
        finally:
            os.close(parent)
        conf = root / "mitmproxy"
        conf.mkdir(mode=0o700)
        os.chmod(conf, 0o700)
        capture_program = None if getattr(args, 'task_owned', False) else args.program
        def allocation_state(pending):
            identity = 'allocation-pending' if pending else 'allocation-not-started'
            c.execute("update task_proxies set capture_identity=? where lane=?", (identity, lane))
            c.commit()
        try:
            flow, identity = select_task_capture(capture_program, lane, root, allocation_state)
        except CaptureNotAllocated:
            allocation_state(False)
            raise
        c.execute("update task_proxies set flow_path=?,capture_identity=? where lane=?",
                  (str(flow), json.dumps(identity, sort_keys=True), lane))
        c.commit()
        row = proxy_row(c, args)
        verify_task_capture(row)
        executable, _ = mitm_runtime()
        cmd = [sys.executable, str(Path(__file__).resolve()), '--verified-capture-launch',
               str(flow), row['capture_identity'], executable, "--listen-host", "127.0.0.1",
               "--listen-port", str(port), "--set", f"confdir={conf}", "--set", "flow_detail=0"]
        unit = ["systemd-run", "--user", "--unit=" + row["unit"],
                "--property=UMask=0077", "--property=MemoryMax=512M"]
        if executable == "/usr/bin/mitmdump":
            unit.append("--setenv=PYTHONNOUSERSITE=1")
        # Persist uncertainty before dispatch: systemd-run or this process may
        # fail after the service has opened (or rejected) the capture.
        c.execute("update proxy_attempts set outcome='capture-uncertain' where agent_id=? and run_id=? and lane=?",
                  (args.agent_id, args.run_id, lane))
        c.commit()
        result = subprocess.run([*unit, "--", *cmd], capture_output=True, text=True, env=sysenv())
        if result.returncode:
            raise ProxyStartupError("task MITM service failed to start")
        invocation = unit_identity(row["unit"])
        if not invocation:
            raise ProxyStartupError("task MITM unit identity unavailable")
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
            raise ProxyStartupError("task MITM listener or CA not ready")
        c.execute("update task_proxies set state='running',admitted=1,updated=? where lane=?", (now(), lane))
        c.execute("update proxy_attempts set outcome='running' where agent_id=? and run_id=? and lane=?", (args.agent_id, args.run_id, lane))
        c.commit()
        return proxy_row(c, args), True
    except Exception:
        c.rollback()
        rollback_proxy_with_signal(c, proxy_row(c, args))
        attempt = c.execute("select outcome from proxy_attempts where agent_id=? and run_id=? and lane=?",
                            (args.agent_id, args.run_id, lane)).fetchone()
        if attempt and attempt['outcome'] == 'capture-uncertain':
            raise ProxyStartupError(CAPTURE_UNCERTAIN_DETAIL) from None
        raise


def rollback_proxy_with_signal(c, row):
    """Keep an uncertain proxy reserved and report cleanup without leaking errors."""
    try:
        # Mark before cleanup so an exception cannot make a live lane reusable.
        c.execute("update task_proxies set state='cleanup-failed',updated=? where lane=?", (now(), row['lane']))
        c.commit()
        cleaned = rollback_proxy(c, row)
    except Exception:
        c.rollback()
        cleaned = False
    if not cleaned:
        print('\n' + json.dumps(PROXY_CLEANUP_UNVERIFIED), file=sys.stderr)
    return cleaned


def rollback_proxy(c, row):
    attempt = c.execute("select outcome from proxy_attempts where agent_id=? and run_id=? and lane=?",
                        (row['agent_id'], row['run_id'], row['lane'])).fetchone()
    uncertain = bool(attempt and attempt['outcome'] == 'capture-uncertain')
    if row['flow_path']:
        try:
            verify_task_capture(row)
        except (OSError, ValueError, TypeError, KeyError):
            uncertain = True
    if uncertain:
        c.execute("update task_proxies set state='cleanup-failed',updated=? where lane=?", (now(), row['lane']))
        c.execute("update proxy_attempts set outcome='capture-uncertain' where agent_id=? and run_id=? and lane=?",
                  (row['agent_id'], row['run_id'], row['lane']))
        c.commit()
        return False
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
    if row['capture_identity'] == 'allocation-pending':
        c.execute("update task_proxies set state='cleanup-failed',updated=? where lane=?", (now(), row['lane']))
        c.commit()
        return False  # An interrupted allocation may have created an unrecorded file.
    try:
        c.execute("delete from task_proxies where lane=?", (row["lane"],))
        c.execute("update proxy_attempts set outcome='aborted' where agent_id=? and run_id=? and lane=?",
                  (row["agent_id"], row["run_id"], row["lane"]))
        c.commit()
    except BaseException:
        c.rollback()
        raise
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
        if (not task or not proxy_program_matches(task, getattr(args, "program", None))
                or task["state"] != "running" or not proxy_ready(task)):
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
    row = c.execute('SELECT * FROM browsers WHERE lease_id=? AND unit=? AND state=?',
                    (lid, unit, 'starting')).fetchone()
    if not row or not stopped(row):
        return False
    info = record_info(row)
    try:
        if info.get('pid') and process_identity(info['pid']) is not None:
            return False
    except (OSError, ValueError, TypeError):
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


def release_lease(c, lease_id, agent, disp="cancelled", health: str | None = "healthy", expected_run=None):
    """Release a failed start while the entry point holds the node lock.

    Never infer prelaunch from canonical not-started alone: the manager may
    already have committed a starting row and dispatched Chromium.
    """
    import browser_profile_lease as profiles
    c.commit()
    with profiles.connect(STATE.parent / 'browser_profile_leases.sqlite') as leases:
        profiles.init_db(leases)
        leases.execute('BEGIN IMMEDIATE')
        row = c.execute('SELECT * FROM browsers WHERE lease_id=?', (lease_id,)).fetchone()
        canonical = leases.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?', (lease_id,)).fetchone()
        if (not canonical or canonical['status'] != 'active'
                or canonical['manager_id'] != manager_id()
                or canonical['owner_agent_id'] != agent
                or (expected_run is not None and canonical['owner_run_id'] != expected_run)
                or canonical['browser_status'] != 'not-started'
                or canonical['cdp_url'] is not None or canonical['service_unit'] is not None
                or (row and (row['state'] != 'stopped'
                    or any(canonical[key] != value for key, value in (
                        ('program', row['program']), ('account_alias', row['account']),
                        ('auth_domain', row['auth_domain']), ('owner_run_id', row['run_id']),
                        ('profile_dir', row['profile_dir']), ('owner_agent_id', row['agent_id'])))
                    or not stopped(row)
                    or (record_info(row).get('pid') and
                        process_identity(record_info(row)['pid']) is not None)))
                or profiles.reservation_conflict(leases, program=canonical['program'],
                    domain=canonical['auth_domain'], alias=canonical['account_alias'],
                    lease_id=lease_id, path=canonical['profile_dir'])):
            return False
        if health is None:
            # A prelaunch failure did not repair or touch the profile. Preserve
            # the health that canonical acquisition used for this exact slot.
            previous = leases.execute(
                "SELECT profile_health FROM browser_profile_leases WHERE program=? AND account_alias=? "
                "AND auth_domain=? AND instance_key=? AND status='released' ORDER BY released_at DESC LIMIT 1",
                (canonical['program'], canonical['account_alias'], canonical['auth_domain'], canonical['instance_key']),
            ).fetchone()
            health = previous['profile_health'] if previous else 'healthy'
        profiles.release_owned_in_transaction(leases, canonical,
            disposition=disp, profile_health=health)
        leases.commit()
        return True


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
    # A failed is-active query is indistinguishable from a stopped unit by
    # exit code alone. Require an affirmative terminal systemd state.
    if not unit_inactive(row["unit"]):
        return False
    identity = info.get("process_identity")
    if row["state"] == "running" and not identity:
        return False
    if identity and owner_state(identity) != "terminal":
        return False
    cdp_url = info.get("cdp_url") or info.get("stop_proof", {}).get("cdp_url")
    if cdp_url:
        import browser_profile_lease as profiles

        if profiles.local_cdp_version(cdp_url)["status"] == "ready":
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
    proof = {"cdp_url": info.get("cdp_url"), "unit_invocation": info.get("unit_invocation")}
    private_json(
        row["launch_file"],
        {**{key: info.get(key) for key in ("process_identity", "unit_invocation", "pid", "instance_key", "instance_selection", "instance_id", "pane_id", "account_color", "driving_mode", "launch_recipe", "replaces_browser_id", "resumed_state_lost")}, "stop_proof": proof},
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


def fenced_stop_release(c, lease_id, agent_id, *, disposition='cancelled', health='healthy'):
    """Stop only the exact manager/canonical owner, with both locks held.

    node_lock is held by the entry point. Canonical initialization precedes its
    write lock; no subprocess may release that lock between proof and stop.
    A committed canonical release with a stale running manager row is recoverable
    only from the same exact identity and independently verified terminal root.
    """
    import browser_profile_lease as profiles
    c.commit()  # manager writes from earlier maintenance must not hold a DB lock
    with profiles.connect(STATE.parent / 'browser_profile_leases.sqlite') as leases:
        profiles.init_db(leases)
        leases.execute('BEGIN IMMEDIATE')
        row = c.execute('SELECT * FROM browsers WHERE lease_id=?', (lease_id,)).fetchone()
        canonical = leases.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?', (lease_id,)).fetchone()
        if not row or row['agent_id'] != agent_id or row['state'] != 'running' or not canonical:
            return False
        info = record_info(row)
        proof = info.get('stop_proof', {})
        recovering = canonical['status'] == 'released'
        if (canonical['status'] not in ('active', 'released')
                or any(canonical[key] != value for key, value in (
                    ('manager_id', manager_id()), ('program', row['program']),
                    ('auth_domain', row['auth_domain']), ('account_alias', row['account']),
                    ('owner_agent_id', row['agent_id']), ('owner_run_id', row['run_id']),
                    ('profile_dir', row['profile_dir'])))
                or not info.get('process_identity') or not info.get('unit_invocation')
                or not info.get('cdp_url', proof.get('cdp_url'))
                or (recovering and (canonical['browser_status'] != 'stopped'
                    or canonical['work_state'] != 'terminal'
                    or canonical['service_unit'] is not None or canonical['cdp_url'] is not None
                    or proof.get('unit_invocation') != info['unit_invocation']))
                or (not recovering and (canonical['service_unit'] != row['unit']
                    or canonical['cdp_url'] != (info.get('cdp_url') or proof.get('cdp_url'))
                    or canonical['browser_status'] != 'running'))):
            return False
        if profiles.reservation_conflict(leases, program=row['program'],
                domain=row['auth_domain'], alias=row['account'], lease_id=lease_id,
                path=row['profile_dir']):
            return False
        # A live unit must match the recorded invocation before stopping it.
        # After an interrupted stop an unloaded unit can lose InvocationID:
        # accept that case only with independent terminal unit/root/CDP proof.
        invocation = unit_identity(row['unit'])
        if invocation and invocation != info['unit_invocation']:
            return False
        if not recovering and not invocation and not stopped(row):
            return False
        if recovering:
            if not stopped(row):
                return False
        else:
            if owner_state(info['process_identity']) not in ('active', 'terminal'):
                return False
            if not stopped(row) and not stop_recorded(row):
                return False
            if not proof:
                stop_receipt(row)
            profiles.release_owned_in_transaction(leases, canonical,
                disposition=disposition, profile_health=health)
            leases.commit()
            # A lost commit reply is resolved on retry using the persisted
            # stop proof, exact released row, and terminal root/CDP evidence.
        c.execute("update browsers set state='stopped',updated=? where lease_id=? and state='running'",
                  (now(), lease_id))
        # Exact terminal root/unit/CDP proof invalidates any outstanding worker
        # capability or interrupted publication; a stopped browser cannot hand off.
        references = [r[0] for r in c.execute('SELECT reference FROM team_grants WHERE lease_id=?', (lease_id,))]
        pending = _team_pending(c, lease_id)
        if pending and pending.get('reference'):
            references.append(pending['reference'])
        c.execute('DELETE FROM team_grants WHERE lease_id=?', (lease_id,))
        c.execute('DELETE FROM team_pending WHERE lease_id=?', (lease_id,))
        c.commit()
        for reference in references:
            path = Path(reference)
            if path.name == 'reference.json' and path.parent.parent == STATE.parent / 'team-grants':
                try:
                    path.unlink(missing_ok=True)
                    path.parent.rmdir()
                except OSError:
                    pass
        return True


def retire(c, row, health="healthy"):
    return fenced_stop_release(c, row['lease_id'], row['agent_id'], health=health)


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


def shifted_legacy_browser_row(row):
    # Positional inserts into an ALTER TABLE layout shifted these fields.
    return (row['profile_dir'] == 'browser-' + row['browser_id'] and
            str(row['state']).endswith('.launch.json') and
            str(row['tab_count']) in ('starting', 'running', 'stopped', 'idle-stopped'))


def unresolved_browser_start(row):
    return row['state'] == 'starting' or (
        shifted_legacy_browser_row(row) and row['tab_count'] == 'starting')


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
        if shifted_legacy_browser_row(row):
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


def team_control_status(lease_id, coordinator_agent_id, coordinator_run_id):
    """Passive coordinator view; activity is attributed to the current generation."""
    with node_lock(STATE):
        with db() as store:
            row = store.execute('SELECT * FROM browsers WHERE lease_id=?', (lease_id,)).fetchone()
            if (not row or row['agent_id'] != coordinator_agent_id
                    or row['run_id'] != coordinator_run_id or not canonical_owner(row)):
                return {'status': 'not-owner'}
            info = record_info(row)
            activity = activity_snapshot(row) if row['state'] == 'running' else None
            if (row['state'] != 'running' or info.get('control_mode') != 'pipe-fenced'
                    or info.get('driving_mode') not in (None, 'agent-driven')
                    or not info.get('activity_tracking') or not cleanup_headless(row)
                    or not healthy(row) or activity is None or activity.get('unavailable')
                    or not all(key in activity for key in (
                        'last_activity', 'idle_seconds', 'attached_clients', 'inflight',
                        'reserved_seconds', 'frozen'))):
                return {'status': 'unavailable', 'reason': 'control-or-activity-unverified'}
            import browser_profile_lease as profiles
            with profiles.connect(STATE.parent / 'browser_profile_leases.sqlite') as leases:
                canonical = leases.execute('SELECT cdp_url,expires_at FROM browser_profile_leases WHERE lease_id=?',
                                           (lease_id,)).fetchone()
            if (not canonical or canonical['expires_at'] <= now()
                    or canonical['cdp_url'] != info.get('cdp_url')):
                return {'status': 'unavailable', 'reason': 'control-or-activity-unverified'}
            grant = store.execute('SELECT * FROM team_grants WHERE lease_id=?', (lease_id,)).fetchone()
            if grant and (grant['generation'] != info['cdp_url'] or
                    grant['process_identity'] != json.dumps(info.get('process_identity'), sort_keys=True) or
                    not _team_reference(grant['reference'], grant['worker_agent_id'], grant['worker_run_id'], store)):
                return {'status': 'unavailable', 'reason': 'control-or-activity-unverified'}
            reason = next((key for key in ('frozen', 'attached_clients', 'inflight', 'reserved_seconds')
                           if activity.get(key)), None)
            return {'status': 'ok', 'browser_id': row['browser_id'],
                    'coordinator': {'agent_id': row['agent_id'], 'run_id': row['run_id']},
                    'granted_worker': ({'agent_id': grant['worker_agent_id'], 'run_id': grant['worker_run_id']}
                                       if grant else None), 'activity': activity,
                    'worker_delivery': 'private-reference' if grant else 'unavailable',
                    'grant_activity_count': (max(0, activity['meaningful_count'] - grant['baseline'])
                                              if grant and isinstance(activity.get('meaningful_count'), int) else None),
                    'controller_quiescent': reason is None, 'controller_reason': reason}


def _team_attestation(store, lease_id, coordinator_agent_id=None, coordinator_run_id=None):
    """Re-read the exact coordinator lease, process and private adapter generation."""
    from browser_control import activity_control
    row = store.execute('SELECT * FROM browsers WHERE lease_id=?', (lease_id,)).fetchone()
    if not row or (coordinator_agent_id is not None and
                   (row['agent_id'], row['run_id']) != (coordinator_agent_id, coordinator_run_id)):
        return None, None, None, 'not-owner'
    info = record_info(row)
    if (row['state'] != 'running' or not canonical_owner(row) or not cleanup_headless(row)
            or info.get('control_mode') != 'pipe-fenced' or not info.get('activity_tracking')
            or info.get('driving_mode') not in (None, 'agent-driven')
            or not isinstance(info.get('process_identity'), dict)
            or not info.get('unit_invocation') or not healthy(row)):
        return None, None, None, 'unavailable'
    try:
        if (process_identity(info['process_identity']['pid']) != info['process_identity']
                or unit_identity(row['unit']) != info['unit_invocation']):
            return None, None, None, 'unavailable'
        with sqlite3.connect(f"file:{STATE.parent / 'browser_profile_leases.sqlite'}?mode=ro", uri=True) as leases:
            canonical = leases.execute('SELECT cdp_url,expires_at FROM browser_profile_leases WHERE lease_id=?',
                                       (lease_id,)).fetchone()
        if not canonical or canonical[0] != info.get('cdp_url') or canonical[1] <= now():
            return None, None, None, 'unavailable'
        observed = activity_control(info['control_socket'], 'identity')
        activity = activity_control(info['control_socket'])
        if (observed.get('available') is not True or observed.get('cdp_url') != info['cdp_url']
                or observed.get('process_identity') != info['process_identity']
                or not all(k in activity for k in ('attached_clients', 'inflight', 'reserved_seconds', 'frozen'))):
            return None, None, None, 'unavailable'
        return row, info, activity, None
    except Exception:
        return None, None, None, 'unavailable'


def _team_reference(reference, worker_agent_id, worker_run_id, store):
    """Possession of a manager-created private file is the trusted same-UID channel."""
    import stat
    path = Path(reference)
    root = STATE.parent / 'team-grants'
    try:
        if (path.parent.parent != root or path.name != 'reference.json'
                or path.is_symlink() or path.parent.is_symlink() or root.is_symlink()
                or any(p.stat().st_uid != os.getuid() for p in (root, path.parent))
                or any(stat.S_IMODE(p.stat().st_mode) != 0o700 for p in (root, path.parent))):
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            file_stat = os.fstat(stream.fileno())
            if file_stat.st_uid != os.getuid() or stat.S_IMODE(file_stat.st_mode) != 0o600:
                return None
            ref = json.load(stream)
        if (ref.get('worker_agent_id'), ref.get('worker_run_id')) != (worker_agent_id, worker_run_id):
            return None
        grant = store.execute('SELECT * FROM team_grants WHERE lease_id=?', (ref['lease_id'],)).fetchone()
        if not grant or any(ref.get(key) != grant[column] for key, column in (
                ('grant_id', 'grant_id'), ('generation', 'generation'),
                ('worker_agent_id', 'worker_agent_id'), ('worker_run_id', 'worker_run_id'))):
            return None
        if grant['reference'] != str(path):
            return None
        return ref
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        return None


def _team_worker_url(reference, worker_agent_id, worker_run_id):
    with node_lock(STATE):
        with db() as store:
            ref = _team_reference(reference, worker_agent_id, worker_run_id, store)
            if not ref:
                return None
            row, info, _, error = _team_attestation(store, ref['lease_id'])
            grant = store.execute('SELECT * FROM team_grants WHERE lease_id=?', (ref['lease_id'],)).fetchone()
            if (error or grant['process_identity'] != json.dumps(info['process_identity'], sort_keys=True)
                    or grant['generation'] != info['cdp_url']):
                return None
            return info['cdp_url']


def team_consume(reference, worker_agent_id, worker_run_id):
    """Safe preflight for the worker CLI; use team_browser() to drive CDP."""
    return {'status': 'ready' if _team_worker_url(reference, worker_agent_id, worker_run_id) else 'unavailable'}


@contextlib.contextmanager
def team_browser(reference, worker_agent_id, worker_run_id):
    """Worker Playwright controller. Raw CDP stays inside this API, not stdout."""
    url = _team_worker_url(reference, worker_agent_id, worker_run_id)
    if not url:
        raise RuntimeError('team browser reference unavailable')
    from playwright.sync_api import sync_playwright
    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.connect_over_cdp(url)
        except Exception:
            raise RuntimeError('team browser connection unavailable') from None
        try:
            yield browser
        finally:
            browser.close()


def _team_publish(store, row, info, successor, grant):
    """Reconcile the private launch file and both registries under node lock."""
    info['cdp_url'] = successor
    private_json(row['launch_file'], info)
    store.execute('ATTACH DATABASE ? AS canonical', (str(STATE.parent / 'browser_profile_leases.sqlite'),))
    store.execute('BEGIN IMMEDIATE')
    try:
        changed = store.execute('UPDATE canonical.browser_profile_leases SET cdp_url=? '
            'WHERE lease_id=? AND cdp_url IN (?,?) AND status=? AND browser_status=? '
            'AND owner_agent_id=? AND owner_run_id=? AND manager_id=? AND program=? '
            'AND account_alias=? AND auth_domain=? AND profile_dir=? AND service_unit=? '
            'AND expires_at>?',
            (successor, row['lease_id'], grant['previous'], successor, 'active', 'running',
             row['agent_id'], row['run_id'], manager_id(), row['program'], row['account'],
             row['auth_domain'], row['profile_dir'], row['unit'], now()))
        if changed.rowcount != 1:
            raise RuntimeError('canonical generation changed')
        if grant and not grant.get('remove'):
            store.execute('INSERT OR REPLACE INTO team_grants '
                '(lease_id,grant_id,worker_agent_id,worker_run_id,reference,generation,process_identity,baseline) '
                'VALUES (?,?,?,?,?,?,?,?)', (row['lease_id'], grant['id'], grant['agent'], grant['run'],
                grant['reference'], successor, json.dumps(info['process_identity'], sort_keys=True), grant['baseline']))
        else:
            store.execute('DELETE FROM team_grants WHERE lease_id=?', (row['lease_id'],))
        store.commit()
    except BaseException:
        store.rollback()
        raise
    finally:
        store.execute('DETACH DATABASE canonical')


def _team_pending(store, lease_id):
    row = store.execute('SELECT payload FROM team_pending WHERE lease_id=?', (lease_id,)).fetchone()
    return json.loads(row['payload']) if row else None


def _team_complete(store, lease_id, pending):
    """Recover a fenced transition only for its exact recorded owner/runtime."""
    from browser_control import activity_control
    row = store.execute('SELECT * FROM browsers WHERE lease_id=?', (lease_id,)).fetchone()
    if not row or row['state'] != 'running' or not canonical_owner(row):
        return {'status': 'cleanup-incomplete'}
    info = record_info(row)
    if (not cleanup_headless(row) or info.get('cdp_url') not in (pending['previous'], pending.get('successor'))
            or info.get('process_identity') != pending['process_identity']
            or info.get('unit_invocation') != pending['unit_invocation']):
        return {'status': 'cleanup-incomplete'}
    try:
        if (process_identity(pending['process_identity']['pid']) != pending['process_identity']
                or unit_identity(row['unit']) != pending['unit_invocation']):
            return {'status': 'cleanup-incomplete'}
        observed = activity_control(info['control_socket'], 'identity')
        if observed.get('process_identity') != pending['process_identity']:
            return {'status': 'cleanup-incomplete'}
        barrier_proved = False
        if observed.get('cdp_url') == pending['previous'] and observed.get('available') is True:
            try:
                fenced = activity_control(info['control_socket'], 'team/fence')
            except Exception as exc:
                from httpx import HTTPStatusError
                if isinstance(exc, HTTPStatusError) and exc.response.status_code == 409:
                    # A rejected fence never rotated; allow a fresh attempt.
                    store.execute('DELETE FROM team_pending WHERE lease_id=?', (lease_id,))
                    store.commit()
                    if pending['kind'] == 'grant':
                        try:
                            Path(pending['reference']).parent.rmdir()
                        except OSError:
                            pass
                    return {'status': 'busy'}
                return {'status': 'cleanup-incomplete'}
            if fenced.get('fenced') is not True:
                return {'status': 'cleanup-incomplete'}
            observed = activity_control(info['control_socket'], 'identity')
            barrier_proved = fenced.get('cdp_url') == observed.get('cdp_url')
            if not barrier_proved:
                return {'status': 'cleanup-incomplete'}
        successor = observed.get('cdp_url')
        if (not successor or successor == pending['previous']
                or observed.get('process_identity') != pending['process_identity']):
            return {'status': 'cleanup-incomplete'}
        if pending.get('successor') and successor != pending['successor']:
            return {'status': 'cleanup-incomplete'}
        if not pending.get('successor'):
            pending['successor'] = successor
            store.execute('UPDATE team_pending SET payload=? WHERE lease_id=?',
                          (json.dumps(pending), lease_id))
            store.commit()
        if observed.get('team_pending') is True and not barrier_proved:
            # Even when a prior fence rotated before a failed/lost CDP barrier,
            # its exact generation is not publishable until the adapter retries
            # and confirms that barrier on the same token.
            fenced = activity_control(info['control_socket'], 'team/fence')
            if fenced.get('fenced') is not True or fenced.get('cdp_url') != successor:
                return {'status': 'cleanup-incomplete'}
            observed = activity_control(info['control_socket'], 'identity')
        if observed.get('team_pending') is not True:
            # Only a committed generation may be available after a lost reply.
            if observed.get('available') is not True or info.get('cdp_url') != successor:
                return {'status': 'cleanup-incomplete'}
        else:
            if observed.get('available') is not False:
                return {'status': 'cleanup-incomplete'}
        if pending['kind'] == 'grant':
            reference = Path(pending['reference'])
            private_json(reference, {'lease_id': lease_id, 'grant_id': pending['id'],
                'worker_agent_id': pending['agent'], 'worker_run_id': pending['run'],
                'generation': successor})
        if observed.get('team_pending') is True:
            grant = {**pending, 'remove': pending['kind'] == 'return'}
            _team_publish(store, row, info, successor, grant)
            activated = activity_control(info['control_socket'], 'team/activate', cdp_url=successor)
            if activated.get('activated') is not True:
                return {'status': 'cleanup-incomplete'}
        verified = activity_control(info['control_socket'], 'identity')
        if (verified.get('cdp_url') != successor or verified.get('process_identity') != pending['process_identity']
                or verified.get('available') is not True or verified.get('team_pending') is not False
                or record_info(row).get('cdp_url') != successor):
            return {'status': 'cleanup-incomplete'}
        with sqlite3.connect(f"file:{STATE.parent / 'browser_profile_leases.sqlite'}?mode=ro", uri=True) as leases:
            canonical = leases.execute(
                'SELECT cdp_url,status,browser_status,owner_agent_id,owner_run_id,manager_id,'
                'program,account_alias,auth_domain,profile_dir,service_unit,expires_at '
                'FROM browser_profile_leases WHERE lease_id=?', (lease_id,)).fetchone()
            expected = (successor, 'active', 'running', row['agent_id'], row['run_id'],
                        manager_id(), row['program'], row['account'], row['auth_domain'],
                        row['profile_dir'], row['unit'])
            if not canonical or canonical[:-1] != expected or canonical[-1] <= now():
                return {'status': 'cleanup-incomplete'}
        if pending['kind'] == 'grant':
            if not _team_reference(pending['reference'], pending['agent'], pending['run'], store):
                return {'status': 'cleanup-incomplete'}
        else:
            if store.execute('SELECT 1 FROM team_grants WHERE lease_id=?', (lease_id,)).fetchone():
                return {'status': 'cleanup-incomplete'}
        store.execute('DELETE FROM team_pending WHERE lease_id=?', (lease_id,))
        store.commit()
        if pending['kind'] == 'return':
            old = Path(pending['reference'])
            try:
                old.unlink(missing_ok=True)
                old.parent.rmdir()
            except OSError:
                pass  # DB and adapter have already revoked the old capability.
            return {'status': 'returned'}
        return {'status': 'granted', 'reference': pending['reference'], 'browser_id': row['browser_id']}
    except Exception:
        # Journal and adapter remain fenced (or published) for an exact retry.
        return {'status': 'cleanup-incomplete'}


def team_grant(lease_id, coordinator_agent_id, coordinator_run_id, worker_agent_id, worker_run_id):
    """Fence the idle controller at a checkpoint; never transfer profile/proxy ownership."""
    if not worker_agent_id or not worker_run_id or (worker_agent_id, worker_run_id) == (coordinator_agent_id, coordinator_run_id):
        return {'status': 'unavailable'}
    with node_lock(STATE):
        with db() as store:
            pending = _team_pending(store, lease_id)
            if pending:
                if ((pending['owner'], pending['owner_run'], pending['agent'], pending['run'], pending['kind'])
                        != (coordinator_agent_id, coordinator_run_id, worker_agent_id, worker_run_id, 'grant')):
                    return {'status': 'busy'}
                return _team_complete(store, lease_id, pending)
            row, info, activity, error = _team_attestation(store, lease_id, coordinator_agent_id, coordinator_run_id)
            if error:
                return {'status': error}
            grant = store.execute('SELECT * FROM team_grants WHERE lease_id=?', (lease_id,)).fetchone()
            if grant:
                # Lost successful reply: return only the same verified capability.
                if ((grant['worker_agent_id'], grant['worker_run_id']) == (worker_agent_id, worker_run_id)
                        and grant['generation'] == info['cdp_url']
                        and grant['process_identity'] == json.dumps(info['process_identity'], sort_keys=True)
                        and _team_reference(grant['reference'], worker_agent_id, worker_run_id, store)):
                    return {'status': 'granted', 'reference': grant['reference'], 'browser_id': row['browser_id']}
                return {'status': 'busy'}
            if any(activity[k] for k in ('attached_clients', 'inflight', 'reserved_seconds', 'frozen')):
                return {'status': 'busy'}
            root = STATE.parent / 'team-grants'
            try:
                root.mkdir(mode=0o700, exist_ok=True)
                if root.is_symlink() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o777 != 0o700:
                    return {'status': 'unavailable'}
                grant_id = uuid.uuid4().hex
                directory = root / grant_id
                directory.mkdir(mode=0o700)
                pending = {'kind': 'grant', 'previous': info['cdp_url'], 'id': grant_id,
                    'agent': worker_agent_id, 'run': worker_run_id,
                    'owner': coordinator_agent_id, 'owner_run': coordinator_run_id,
                    'reference': str(directory / 'reference.json'),
                    'baseline': activity.get('meaningful_count', 0),
                    'process_identity': info['process_identity'], 'unit_invocation': info['unit_invocation']}
                store.execute('INSERT INTO team_pending VALUES (?,?)', (lease_id, json.dumps(pending)))
                store.commit()  # Recoverable intent must precede adapter fence.
                return _team_complete(store, lease_id, pending)
            except Exception:
                return {'status': 'cleanup-incomplete'}


def team_return(reference, worker_agent_id, worker_run_id):
    with node_lock(STATE):
        with db() as store:
            try:
                lease_id = json.loads(Path(reference).read_text())['lease_id']
            except (OSError, ValueError, KeyError):
                return {'status': 'unavailable'}
            pending = _team_pending(store, lease_id)
            if pending:
                if (pending['kind'], pending['reference'], pending['agent'], pending['run']) != (
                        'return', str(reference), worker_agent_id, worker_run_id):
                    return {'status': 'busy'}
                return _team_complete(store, lease_id, pending)
            ref = _team_reference(reference, worker_agent_id, worker_run_id, store)
            if not ref:
                return {'status': 'unavailable'}
            row, info, activity, error = _team_attestation(store, lease_id)
            if error:
                return {'status': 'unavailable'}
            if any(activity[k] for k in ('attached_clients', 'inflight', 'reserved_seconds', 'frozen')):
                return {'status': 'busy'}
            pending = {'kind': 'return', 'previous': info['cdp_url'], 'id': '',
                'agent': worker_agent_id, 'run': worker_run_id,
                'owner': row['agent_id'], 'owner_run': row['run_id'],
                'reference': str(reference), 'baseline': 0,
                'process_identity': info['process_identity'], 'unit_invocation': info['unit_invocation']}
            store.execute('INSERT INTO team_pending VALUES (?,?)', (lease_id, json.dumps(pending)))
            store.commit()
            return _team_complete(store, lease_id, pending)


def freeze_idle(row, seconds, *, require_detached=False):
    from browser_control import activity_control
    try:
        return activity_control(record_info(row)["control_socket"], "freeze",
                                idle_seconds=seconds, require_detached=require_detached).get("frozen", False)
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


def cleanup_headless(row):
    """CDP detachment cannot attest a headed/native viewer is quiescent."""
    info = record_info(row)
    return ("kasmvnc" not in info
            and any(str(flag).startswith("--headless") for flag in info.get("command", [])))


def cleanup_unused(c):
    stopped_ids = []
    for row in c.execute("SELECT * FROM browsers WHERE state='running'").fetchall():
        if (c.execute('SELECT 1 FROM team_grants WHERE lease_id=?', (row['lease_id'],)).fetchone()
                or _team_pending(c, row['lease_id'])
                or not canonical_owner(row) or not cleanup_headless(row)
                or owner_state(metadata(c, row).get("owner")) != "terminal"):
            continue
        activity = activity_snapshot(row)
        if (not activity or activity.get("unavailable") or activity["idle_seconds"] < 7200
                or activity["inflight"] or activity["reserved_seconds"]
                or activity.get("attached_clients", 1)):
            continue
        # Recheck AND freeze in the adapter's event loop, not a stale file snapshot.
        if freeze_idle(row, 7200, require_detached=True):
            if (canonical_owner(row) and cleanup_headless(row)
                    and owner_state(metadata(c, row).get("owner")) == "terminal" and retire(c, row)):
                stopped_ids.append(row["browser_id"])
            else:
                meta = metadata(c, row)
                meta["control_restored"] = restore_failed_stop(row)
                meta["lifecycle_error"] = "idle-stop-not-verified"
                save_metadata(c, row["lease_id"], meta)
    return stopped_ids


def canonical_owner(row, *, active=True):
    """The manager projection alone cannot authorize stopping or reconnecting."""
    path = STATE.parent / "browser_profile_leases.sqlite"
    if not path.exists():
        return False
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as leases:
            leases.row_factory = sqlite3.Row
            lease_row = leases.execute(
                "SELECT * FROM browser_profile_leases WHERE lease_id=?", (row["lease_id"],)
            ).fetchone()
        identity = (("manager_id", manager_id()), ("program", row["program"]),
                    ("account_alias", row["account"]), ("auth_domain", row["auth_domain"]),
                    ("owner_agent_id", row["agent_id"]), ("owner_run_id", row["run_id"]),
                    ("profile_dir", row["profile_dir"]))
        # Release clears the transient unit, but retains the exact historical
        # manager, account, owner and profile identity needed for stopped replay.
        return bool(lease_row and lease_row["status"] == ("active" if active else "released")
                    and all(lease_row[k] == value for k, value in identity)
                    and (not active or lease_row["service_unit"] == row["unit"]))
    except (sqlite3.Error, OSError, KeyError):
        return False


@serialized
def cleanup(args):
    """Opt-in capacity cleanup; never infer abandonment from browser age alone."""
    c = db()
    entries = []
    for row in c.execute("SELECT * FROM browsers WHERE state='running' ORDER BY created").fetchall():
        reason = "uncertain"
        info = record_info(row)
        meta = metadata(c, row)
        if not canonical_owner(row):
            reason = "canonical-owner-unverified"
        elif not cleanup_headless(row):
            reason = "headed-or-display-unverified"
        elif reservation_blocks(row):
            reason = "profile-reserved"
        elif not info.get("unit_invocation") or unit_identity(row["unit"]) != info["unit_invocation"]:
            reason = "unit-identity-unverified"
        elif not unit_active(row["unit"]) or not healthy(row):
            reason = "runtime-unverified"
        elif (c.execute('SELECT 1 FROM team_grants WHERE lease_id=?', (row['lease_id'],)).fetchone()
              or _team_pending(c, row['lease_id'])):
            reason = "worker-grant-outstanding"
        elif owner_state(meta.get("owner")) != "terminal":
            reason = "owner-active-or-unverified"
        else:
            activity = activity_snapshot(row)
            if not activity or activity.get("unavailable"):
                reason = "activity-unavailable"
            elif activity.get("inflight") or activity.get("reserved_seconds"):
                reason = "inflight-or-held"
            elif activity.get("attached_clients", 1):
                reason = "controller-attached-or-unverified"
            elif activity.get("idle_seconds", 0) < 7200:
                reason = "idle-below-7200"
            elif activity.get("frozen"):
                reason = "control-already-frozen"
            else:
                reason = "eligible-terminal-idle"
        if reason == "eligible-terminal-idle" and args.apply:
            if not freeze_idle(row, 7200, require_detached=True):
                reason = "activity-changed"
            elif (not canonical_owner(row) or not cleanup_headless(row)
                  or owner_state(metadata(c, row).get("owner")) != "terminal"):
                restore_failed_stop(row)
                reason = "owner-changed"
            elif retire(c, row):
                reason = "stopped"
            else:
                restored = restore_failed_stop(row)
                reason = "stop-not-verified-control-restored" if restored else "stop-not-verified-control-frozen"
        entries.append({"browser_id": row["browser_id"], "result": reason})
    emit({"status": "ok", "mode": "apply" if args.apply else "dry-run",
          "admission": admission(DEFAULT_RAM_MIB, DEFAULT_SWAP_MIB),
          "browsers": entries, "stopped": [e["browser_id"] for e in entries if e["result"] == "stopped"]})


def resume(args):
    # Do not hold the node lock across request: start acquires it in a child.
    with node_lock(STATE):
        c = db()
        row = c.execute("SELECT * FROM browsers WHERE browser_id=?", (args.browser_id,)).fetchone()
        if not row or row["agent_id"] != args.agent_id or row["run_id"] != args.run_id:
            emit({"status": "not-owner"}, 2)
        if row["state"] == "running":
            require_safe_running_profile(row)
            resume_running(c, row, args)
        if row["state"] != "stopped" or not canonical_owner(row, active=False) or not stopped(row):
            emit({"status": "recovery-blocked", "reason": "stop-or-ownership-unverified"}, 2)
        info = record_info(row)
        recipe = info.get("launch_recipe")
        if not isinstance(recipe, dict) or recipe.get("version") != 1:
            emit({"status": "recovery-blocked", "reason": "safe-launch-recipe-unavailable",
                  "state_lost": row["program"] == "task-owned" and not Path(row["profile_dir"]).exists()}, 2)
        if not isinstance(info.get("stop_proof"), dict) or not info["stop_proof"].get("cdp_url"):
            emit({"status": "recovery-blocked", "reason": "stop-proof-unavailable"}, 2)
        if not resume_recipe_valid(row, recipe):
            emit({"status": "recovery-blocked", "reason": "launch-recipe-conflict"}, 2)
        program = resume_program(recipe, proxy_row(c, args))
        if program is None:
            emit({"status": "recovery-blocked", "reason": "launch-recipe-conflict"}, 2)
        import browser_profile_lease as profiles
        successors = [other for other in c.execute("SELECT * FROM browsers WHERE browser_id!=?", (row["browser_id"],))
                      if record_info(other).get("replaces_browser_id") == row["browser_id"]]
        profile = Path(row["profile_dir"])
        lost = row["program"] == "task-owned" and not os.path.lexists(profile)
        if not lost and not successors and (not profile.is_dir() or profiles.physical_profile(profile) is None
                         or list(profiles.physical_profile(profile)) != recipe["physical_profile"]):
            emit({"status": "recovery-blocked", "reason": "profile-identity-changed"}, 2)
        if recipe["proxy"] == "mitm":
            task = proxy_row(c, args)
            if not task or task["state"] != "running" or not proxy_ready(task):
                emit({"status": "recovery-blocked", "reason": "proxy-or-ca-unverified"}, 2)
            if (proxy_metadata(task)["proxy_server"] != recipe["proxy_server"]
                    or ca_fingerprint(Path(proxy_metadata(task)["ca_cert"])) != recipe["ca_sha256"]):
                emit({"status": "recovery-blocked", "reason": "proxy-or-ca-unverified"}, 2)
        elif proxy_row(c, args):
            emit({"status": "recovery-blocked", "reason": "proxy-or-ca-unverified"}, 2)
        if recipe["proxy"] == "external":
            if (not endpoint_open(recipe["proxy_server"]) or
                    not Path(recipe["mitm_ca_cert"]).is_file() or
                    ca_fingerprint(Path(recipe["mitm_ca_cert"])) != recipe["ca_sha256"]):
                emit({"status": "recovery-blocked", "reason": "proxy-or-ca-unverified"}, 2)
        if recipe["program"] != "task-owned":
            account, _ = profiles.resolve_account(program, recipe["account"])
            if not account or account.get("alias") != row["account"] or not profiles.account_lease_eligible(account):
                emit({"status": "recovery-blocked", "reason": "account-identity-changed"}, 2)
            check = argparse.Namespace(program=program, account=recipe["account"],
                                       auth_domain=recipe["auth_domain"])
            if (profiles.auth_domain_for(check, account) != row["auth_domain"] or
                    account_policy(row["program"], row["account"], row["auth_domain"]) != recipe["single_policy"] or
                    account_auth_policy(account) != recipe.get("account_auth_policy")):
                emit({"status": "recovery-blocked", "reason": "account-policy-changed"}, 2)
        # A newer row for this physical slot is never the old ID's successor by inference.
        if successors:
            successor = max(successors, key=lambda item: item["created"])
            successor_info = record_info(successor)
            successor_recipe = successor_info.get("launch_recipe")
            physical = profiles.physical_profile(successor["profile_dir"])
            if (successor["state"] == "running" and successor["agent_id"] == args.agent_id
                    and successor["run_id"] == args.run_id and canonical_owner(successor)
                    and successor["profile_dir"] == row["profile_dir"]
                    and successor_info.get("instance_key") == recipe["instance_key"]
                    and isinstance(successor_info.get("resumed_state_lost"), bool)
                    and isinstance(successor_recipe, dict) and physical is not None
                    and list(physical) == successor_recipe.get("physical_profile")
                    and not reservation_blocks(successor) and healthy(successor)
                    and matching_proxy(c, argparse.Namespace(
                        agent_id=args.agent_id, run_id=args.run_id, program=program, proxy=recipe["proxy"],
                        proxy_server=recipe["proxy_server"],
                        proxy_cert_mode=recipe["proxy_cert_mode"],
                        mitm_ca_cert=recipe["mitm_ca_cert"]), successor)):
                require_safe_running_profile(successor)
                emit({"status": "already-running", **safe(successor),
                      "replaces_browser_id": row["browser_id"],
                      "state_lost": successor_info["resumed_state_lost"],
                      "authentication": "browser-native-check-required"})
            emit({"status": "recovery-blocked", "reason": "replacement-unverified"}, 2)
        # Child start repeats exact row/physical/slot checks inside the node lock.
        expected = row["browser_id"]
    cmd = [sys.executable, str(Path(__file__).resolve()), "request",
           *([program, recipe["account"]] if recipe["program"] != "task-owned" else []),
           "--agent-id", args.agent_id, "--run-id", args.run_id,
           "--purpose", recipe["purpose"], "--url", "about:blank",
           "--auth-domain", recipe["auth_domain"]] if recipe["program"] != "task-owned" else [
           sys.executable, str(Path(__file__).resolve()), "request", "--task-owned",
           "--agent-id", args.agent_id, "--run-id", args.run_id,
           "--purpose", recipe["purpose"], "--url", "about:blank"]
    for name in ("ttl_seconds", "idle_seconds", "min_ram_available_mib", "min_swap_free_mib",
                 "memory_high", "memory_max", "proxy", "proxy_cert_mode", "proxy_ownership",
                 "graphics_backend", "driving_mode"):
        cmd += ["--" + name.replace("_", "-"), str(recipe[name])]
    for name in ("headless", "legacy_profile"):
        if recipe[name]:
            cmd += ["--" + name.replace("_", "-")]
    for name in ("instance_key", "display_backend", "kasmvnc_display", "kasmvnc_web_port"):
        if recipe.get(name) is not None:
            cmd += ["--" + name.replace("_", "-"), str(recipe[name])]
    if recipe.get("instance_selection") == "automatic":
        cmd += ["--resume-automatic-instance"]
    if recipe["proxy"] == "external":
        cmd += ["--proxy-server", recipe["proxy_server"],
                "--mitm-ca-cert", recipe["mitm_ca_cert"]]
    cmd += ["--expected-replaces-browser-id", expected]
    p = subprocess.run(cmd, capture_output=True, text=True)
    try:
        result = json.loads(p.stdout)
    except ValueError:
        emit({"status": "recovery-blocked", "reason": "request-result-unverified"}, 2)
    if result.get("status") in ("started", "already-running"):
        with node_lock(STATE):
            current = db().execute("SELECT * FROM browsers WHERE browser_id=?",
                                   (result.get("browser_id"),)).fetchone()
            current_info = record_info(current) if current is not None else {}
            verified = (result.get("replaces_browser_id") == expected and current is not None
                        and current["state"] == "running" and current["lease_id"] == result.get("lease_id")
                        and current["agent_id"] == args.agent_id and current["run_id"] == args.run_id
                        and current["profile_dir"] == row["profile_dir"] and canonical_owner(current)
                        and healthy(current) and current_info.get("replaces_browser_id") == expected
                        and isinstance(current_info.get("resumed_state_lost"), bool)
                        and list(profiles.physical_profile(current["profile_dir"]) or ()) ==
                            current_info.get("launch_recipe", {}).get("physical_profile"))
        if not verified:
            emit({"status": "recovery-blocked", "reason": "replacement-publication-unverified"}, 2)
        require_safe_running_profile(current)
        result["state_lost"] = current_info["resumed_state_lost"]
        result["authentication"] = "browser-native-check-required"
    emit(result, p.returncode)


def require_safe_running_profile(row):
    import browser_profile_lease as profiles
    path = Path(row['profile_dir'])
    if not path.is_dir() or not profiles.safe_profile_path(path):
        emit({'status': 'profile-unavailable', 'next': 'The recorded running profile is on an unsafe or unavailable filesystem; preserve it and inspect its backing.'}, 2)


def resume_program(recipe, task):
    """Keep exact request names; recover legacy names from the owned proxy row."""
    program = recipe.get('program')
    exact = recipe.get('exact_program')
    if exact is not None:
        return exact if isinstance(exact, str) and slug(exact) == program else None
    if task and task['program'] == program:
        return task['exact_program'] or program
    return program


def resume_running(c, row, args):
        if not canonical_owner(row) or reservation_blocks(row):
            emit({"status": "recovery-blocked", "reason": "canonical-owner-unverified"}, 2)
        if lifecycle_state(c, row) in ("terminal", "expired-awaiting-input", "activity-unavailable"):
            emit({"status": "recovery-blocked", "reason": "owner-or-activity-unverified"}, 2)
        if not healthy(row):
            emit({"status": "recovery-blocked", "reason": "runtime-unverified"}, 2)
        info = record_info(row)
        activity = activity_snapshot(row)
        if activity and (activity.get("unavailable") or activity.get("frozen")):
            emit({"status": "recovery-blocked", "reason": "control-unavailable"}, 2)
        mode = "none" if "--no-proxy-server" in info.get("command", []) else "external"
        task = proxy_row(c, args)
        if task:
            mode = "mitm"
        recipe = info.get('launch_recipe') or {'program': row['program']}
        proxy_args = argparse.Namespace(agent_id=args.agent_id, run_id=args.run_id,
            program=resume_program(recipe, task), proxy=mode, proxy_server=info.get("proxy_server"),
            proxy_cert_mode=info.get("proxy_cert_mode"),
            mitm_ca_cert=info.get("proxy_cert_status", {}).get("ca_cert"))
        if not matching_proxy(c, proxy_args, row):
            emit({"status": "recovery-blocked", "reason": "proxy-or-ca-unverified"}, 2)
        emit({"status": "already-running", **safe(row),
              "reconnect_scope": "browser-control-only",
              "task_proxy": proxy_metadata(proxy_row(c, args)),
              "watcher_healthy": unit_active(monitor_unit(row["browser_id"]))})


def resume_recipe_valid(row, recipe):
    fields = ("program", "account", "auth_domain", "profile_dir")
    return (all(recipe.get(key) == row[key] for key in fields)
            and recipe.get("instance_key") == record_info(row).get("instance_key")
            and (row["program"] == "task-owned" or bool(recipe.get("instance_key")))
            and recipe.get("instance_selection") == record_info(row).get("instance_selection")
            and recipe.get("instance_selection") in ("automatic", "explicit", "legacy")
            and recipe.get("proxy") in ("mitm", "none", "external")
            and recipe.get("proxy_cert_mode") == ("none" if recipe.get("proxy") == "none" else "import")
            and recipe.get("owner_pid") is None and not recipe.get("legacy_profile")
            and recipe.get("purpose") == row["purpose"]
            and all(key in recipe for key in ("physical_profile", "ttl_seconds", "idle_seconds",
                    "min_ram_available_mib", "min_swap_free_mib", "memory_high", "memory_max",
                    "proxy_ownership", "graphics_backend", "driving_mode", "headless",
                    "single_policy", "proxy_server", "mitm_ca_cert", "ca_sha256"))
            and isinstance(recipe.get("physical_profile"), list)
            and (recipe.get("proxy") != "external" or
                 (isinstance(recipe.get("proxy_server"), str) and
                  isinstance(recipe.get("mitm_ca_cert"), str) and
                  isinstance(recipe.get("ca_sha256"), str)))
            and (recipe.get("proxy") != "mitm" or
                 (isinstance(recipe.get("proxy_server"), str) and
                  isinstance(recipe.get("ca_sha256"), str))))


def account_auth_policy(account):
    """Fingerprint non-secret auth source selectors, never credential material."""
    return hashlib.sha256(json.dumps({key: account.get(key) for key in
        ("auth_seed_ref", "credential_ref", "auth_refresh_source", "auth_host_filter")},
        sort_keys=True).encode()).hexdigest() if account else None


def lifecycle_state(c, row):
    meta = metadata(c, row)
    activity = activity_snapshot(row)
    if activity is not None:
        if activity.get("unavailable"):
            return "activity-unavailable"
        if activity["inflight"] or activity["reserved_seconds"]:
            return "active"
        # Coordinator death and detached CDP are not evidence of worker return.
        if (c.execute('SELECT 1 FROM team_grants WHERE lease_id=?', (row['lease_id'],)).fetchone()
                or _team_pending(c, row['lease_id'])):
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
                if canonical_owner(row):
                    if not retire(c, row):
                        meta["lifecycle_error"] = "terminal-cleanup-not-verified"
                        save_metadata(c, row["lease_id"], meta)
                else:
                    meta["lifecycle_error"] = "canonical-owner-unverified"
                    save_metadata(c, row["lease_id"], meta)
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
                if not canonical_owner(row):
                    meta["lifecycle_error"] = "canonical-owner-unverified"
                    save_metadata(c, row["lease_id"], meta)
                    continue
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
        args._owner_identity = owner
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
    if row and row['state'] == 'running':
        require_safe_running_profile(row)
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
    if row and row['state'] == 'running':
        require_safe_running_profile(row)
    reusable = None
    replacing = None
    source_profile_lost = False
    if getattr(args, "expected_replaces_browser_id", None):
        replacing = c.execute("SELECT * FROM browsers WHERE browser_id=?",
                              (args.expected_replaces_browser_id,)).fetchone()
        if (not replacing or replacing["state"] != "stopped" or
                replacing["agent_id"] != args.agent_id or replacing["run_id"] != args.run_id or
                not canonical_owner(replacing, active=False) or not stopped(replacing) or
                row is None or row["browser_id"] != replacing["browser_id"] or
                record_info(replacing).get("instance_key") != instance):
            emit({"status": "recovery-blocked", "reason": "expected-old-identity-changed"}, 2)
        recipe = record_info(replacing).get("launch_recipe")
        physical = profiles.physical_profile(replacing["profile_dir"])
        source_profile_lost = physical is None and args.task_owned and not os.path.lexists(replacing["profile_dir"])
        if (not isinstance(recipe, dict) or not resume_recipe_valid(replacing, recipe) or
                resume_program(recipe, proxy_row(c, args)) != args.program or
                recipe["single_policy"] != account_policy(args.program, alias, auth_domain) or
                (physical is None and not (args.task_owned and not os.path.lexists(replacing["profile_dir"]))) or
                (physical is not None and list(physical) != recipe["physical_profile"])):
            emit({"status": "recovery-blocked", "reason": "expected-profile-or-policy-changed"}, 2)
        if bool(getattr(args, "resume_automatic_instance", False)) != (recipe["instance_selection"] == "automatic"):
            emit({"status": "recovery-blocked", "reason": "expected-instance-selection-changed"}, 2)
        automatic = recipe["instance_selection"] == "automatic"
        if recipe["proxy"] != args.proxy or recipe["proxy_ownership"] != args.proxy_ownership or \
                recipe["proxy_cert_mode"] != ("none" if args.proxy == "none" else args.proxy_cert_mode) or \
                recipe["driving_mode"] != (args.driving_mode or "agent-driven") or \
                recipe["headless"] != bool(args.headless) or recipe["graphics_backend"] != args.graphics_backend:
            emit({"status": "recovery-blocked", "reason": "expected-launch-options-changed"}, 2)
        if (args.url != "about:blank" or args.purpose != recipe["purpose"] or
                any(getattr(args, key) != recipe[key] for key in (
                    "ttl_seconds", "idle_seconds", "min_ram_available_mib", "min_swap_free_mib",
                    "memory_high", "memory_max", "display_backend", "kasmvnc_display",
                    "kasmvnc_web_port")) or
                getattr(args, "owner_pid", None) is not None):
            emit({"status": "recovery-blocked", "reason": "expected-launch-options-changed"}, 2)
        if not args.task_owned and account_auth_policy(account) != recipe.get("account_auth_policy"):
            emit({"status": "recovery-blocked", "reason": "expected-auth-policy-changed"}, 2)
        if args.proxy == "mitm":
            task = proxy_row(c, args)
            if (not task or task["state"] != "running" or not proxy_ready(task) or
                    proxy_metadata(task)["proxy_server"] != recipe["proxy_server"] or
                    ca_fingerprint(Path(proxy_metadata(task)["ca_cert"])) != recipe["ca_sha256"]):
                emit({"status": "recovery-blocked", "reason": "expected-proxy-changed"}, 2)
        elif proxy_row(c, args) or (args.proxy == "external" and
                (args.proxy_server != recipe["proxy_server"] or
                 ca_fingerprint(Path(args.mitm_ca_cert)) != recipe["ca_sha256"] or
                 not endpoint_open(args.proxy_server))):
            emit({"status": "recovery-blocked", "reason": "expected-proxy-changed"}, 2)
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
            if not request_proxy_owner_matches(c, args, owner) or not matching_proxy(c, args, row):
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
                "next": "run browser_provisioner.py cleanup (dry-run), then cleanup --apply only for proven terminal idle owners; retry this exact request without changing agent/run/account",
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
    # A durable starting row may represent a unit already accepted by systemd.
    # Preserve its identity and lease until an operator reconciles the unit.
    pending = c.execute("select * from browsers where lease_id=?", (lid,)).fetchone()
    if (row and unresolved_browser_start(row)) or (pending and unresolved_browser_start(pending)):
        emit({"status": "recovery-blocked", "reason": "start-not-reconciled",
              "next": "reconcile the recorded browser unit and lease before retrying"}, 2)
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
        if not request_proxy_owner_matches(c, args, owner) or not matching_proxy(c, args, row):
            emit({"status": "proxy-conflict", "detail": "running browser cannot be hot-reconfigured"}, 2)
        emit({"status": "already-running", **safe(row), "task_proxy": proxy_metadata(proxy_row(c, args))})
    task = None
    created = False
    if args.proxy == "mitm":
        try:
            task, created = start_proxy(c, args)
        except (SystemExit, Exception) as exc:
            # Compensate only a lease created by this start, through the fenced
            # release. A prelaunch failure cannot establish profile health.
            if got.get("status") == "leased":
                try:
                    released = release_lease(c, lid, args.agent_id, "cancelled", None, args.run_id)
                except Exception:
                    released = False
                if not released:
                    # Isolate the fixed signal even if prior stderr lacks a newline.
                    print('\n' + json.dumps(LEASE_RELEASE_UNVERIFIED), file=sys.stderr)
            if isinstance(exc, SystemExit):
                raise
            failure = {"status": "proxy-failed"}
            if isinstance(exc, ProxyStartupError):
                failure["detail"] = str(exc)
            emit(failure, 2)
    elif proxy_row(c, args):
        if got.get("status") == "leased":
            try:
                released = release_lease(c, lid, args.agent_id, "cancelled", None, args.run_id)
            except Exception:
                released = False
            if not released:
                print('\n' + json.dumps(LEASE_RELEASE_UNVERIFIED), file=sys.stderr)
        emit({"status": "proxy-conflict", "detail": "finish the task proxy before changing mode"}, 2)
    prof = Path(got["lease"]["profile_dir"])
    if replacing and str(prof) != replacing["profile_dir"]:
        if not release_lease(c, lid, args.agent_id):
            emit({'status': 'cleanup-incomplete', 'reason': 'lease-release-not-verified'}, 2)
        emit({"status": "recovery-blocked", "reason": "acquired-profile-changed"}, 2)
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
            rollback_proxy_with_signal(c, task)
        if got.get("status") == "leased":
            try:
                released = release_lease(c, lid, args.agent_id, "cancelled", None, args.run_id)
            except Exception:
                released = False
            if not released:
                print('\n' + json.dumps(LEASE_RELEASE_UNVERIFIED), file=sys.stderr)
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
        if not release_lease(c, lid, args.agent_id):
            emit({'status': 'cleanup-incomplete', 'reason': 'lease-release-not-verified'}, 2)
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
        if not release_lease(c, lid, args.agent_id):
            emit({'status': 'cleanup-incomplete', 'reason': 'lease-release-not-verified'}, 2)
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
        if not release_lease(c, lid, args.agent_id):
            emit({'status': 'cleanup-incomplete', 'reason': 'lease-release-not-verified'}, 2)
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
        if not release_lease(c, lid, args.agent_id):
            emit({'status': 'cleanup-incomplete', 'reason': 'lease-release-not-verified'}, 2)
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
    physical = profiles.physical_profile(prof)
    if physical is not None:
        info["launch_recipe"] = {
            "version": 1, "program": slug(args.program), "exact_program": args.program,
            "account": slug(got["lease"].get("account_alias", args.account)),
            "auth_domain": resolved_domain, "profile_dir": str(prof),
            "physical_profile": list(physical), "instance_key": instance,
            "instance_selection": info["instance_selection"],
            "single_policy": single, "purpose": args.purpose,
            "account_auth_policy": account_auth_policy(account),
            "ttl_seconds": args.ttl_seconds, "idle_seconds": args.idle_seconds,
            "min_ram_available_mib": args.min_ram_available_mib,
            "min_swap_free_mib": args.min_swap_free_mib,
            "memory_high": args.memory_high, "memory_max": args.memory_max,
            "proxy": args.proxy, "proxy_ownership": args.proxy_ownership,
            "proxy_cert_mode": args.proxy_cert_mode if args.proxy != "none" else "none",
            "proxy_server": (proxy_metadata(task)["proxy_server"] if task else args.proxy_server),
            "mitm_ca_cert": (info.get("proxy_cert_status") or {}).get("ca_cert") if args.proxy == "external" else None,
            "ca_sha256": (info.get("proxy_cert_status") or {}).get("ca_sha256"),
            "display_backend": args.display_backend, "headless": bool(args.headless),
            "kasmvnc_display": args.kasmvnc_display, "kasmvnc_web_port": args.kasmvnc_web_port,
            "graphics_backend": args.graphics_backend,
            "driving_mode": args.driving_mode or "agent-driven",
            "owner_pid": args.owner_pid, "legacy_profile": bool(args.legacy_profile),
        }
    if replacing:
        info["replaces_browser_id"] = replacing["browser_id"]
        info["resumed_state_lost"] = source_profile_lost
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
            **({"replaces_browser_id": replacing["browser_id"]} if replacing else {}),
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
        browser_blocked = {}
        for browser in c.execute("select * from browsers where state='running'").fetchall():
            if not canonical_owner(browser):
                reason = "canonical-owner-unverified"
            elif not cleanup_headless(browser):
                reason = "headed-or-display-unverified"
            elif owner_state(metadata(c, browser).get("owner")) != "terminal":
                reason = "task-owner-not-terminal-or-unrecorded"
            else:
                activity = activity_snapshot(browser)
                error = metadata(c, browser).get("lifecycle_error")
                if error:
                    reason = "cleanup-not-verified"
                elif not activity or activity.get("unavailable"):
                    reason = "activity-unavailable"
                elif (activity["idle_seconds"] >= 7200 and not activity["inflight"]
                      and not activity["reserved_seconds"] and not activity.get("attached_clients", 1)):
                    reason = "idle-freeze-or-stop-unverified"
                else:
                    reason = "activity-recent-or-attached"
            browser_blocked[reason] = browser_blocked.get(reason, 0) + 1
        c.execute("""delete from finished_proxies where finished<?
                  and not exists (select 1 from proxy_attempts a
                    where a.agent_id=finished_proxies.agent_id
                      and a.run_id=finished_proxies.run_id and a.outcome!='finished')
                  and not exists (select 1 from task_proxies p
                    where p.agent_id=finished_proxies.agent_id and p.run_id=finished_proxies.run_id)""",
                  (now() - 14 * 86400,))
        c.commit()
        # No age-only revocation: a replay can outlive the browser. Require
        # positively terminal task-owner identity and a quiet flow artifact.
        candidates = []
        proxy_blocked = {}
        cutoff = now() - 7200
        for row in c.execute("select * from task_proxies where updated<?", (cutoff,)).fetchall():
            if not row["owner"]:
                reason = "task-owner-unrecorded"
                proxy_blocked[reason] = proxy_blocked.get(reason, 0) + 1
                continue
            try:
                terminal = owner_state(json.loads(row["owner"])) == "terminal"
            except ValueError:
                reason = "task-owner-invalid"
                proxy_blocked[reason] = proxy_blocked.get(reason, 0) + 1
                continue
            if not terminal:
                reason = "task-owner-not-terminal"
            elif not proxy_quiet(row):
                reason = "flow-or-replay-not-quiet"
            elif any(browser_blocks_proxy(c, browser)
                     for browser in c.execute("select * from browsers where agent_id=? and run_id=?",
                                              (row["agent_id"], row["run_id"])).fetchall()):
                reason = "browser-not-released"
            else:
                candidates.append((row["agent_id"], row["run_id"], row["lane"]))
                continue
            proxy_blocked[reason] = proxy_blocked.get(reason, 0) + 1
        c.commit()
    recovered = []
    for agent_id, run_id, lane in candidates:
        # Running rows require the same explicit finish semantics; terminal
        # owner is proof that this task can no longer issue direct replay.
        with node_lock(STATE):
            c = db(); row = proxy_row(c, argparse.Namespace(agent_id=agent_id, run_id=run_id))
            if (not row or row["lane"] != lane or not row["owner"] or owner_state(json.loads(row["owner"])) != "terminal"
                    or not proxy_quiet(row)):
                continue
            if any(
                browser_blocks_proxy(c, b)
                for b in c.execute("select * from browsers where agent_id=? and run_id=?",
                                   (agent_id, run_id)).fetchall()):
                c.rollback()
                continue
            c.commit()
            output = io.StringIO()
            try:
                with contextlib.redirect_stdout(output):
                    finish_proxy(argparse.Namespace(agent_id=agent_id, run_id=run_id, expected_lane=lane),
                                 recovery=row["state"] != "running", orphan_proven=True)
            except SystemExit as exc:
                if exc.code == 0:
                    recovered.append((agent_id, run_id))
                else:
                    try:
                        status = json.loads(output.getvalue()).get("status")
                    except ValueError:
                        status = None
                    # Use a fixed category: never copy error details, paths or flows.
                    reason = status if status in ("browser-active", "proxy-conflict",
                                                  "proxy-stop-failed", "proxy-ca-cleanup-failed",
                                                  "proxy-index-failed") else "finish-not-verified"
                    proxy_blocked[reason] = proxy_blocked.get(reason, 0) + 1
    emit({"status": "ok", "idle_stopped": stopped_ids,
          "proxy_recovered": recovered,
          "browser_blocked": browser_blocked, "proxy_blocked": proxy_blocked,
          "policy": "tracked-CDP-idle-7200s; task proxy terminal-owner-and-quiet-flow-7200s"})


@serialized
def release(args):
    c = db()
    r = c.execute(
        "select * from browsers where lease_id=?", (args.lease_id,)
    ).fetchone()
    if not r or r["agent_id"] != args.agent_id or r["state"] != "running":
        emit({"status": "not-owner"}, 2)
    if not fenced_stop_release(c, args.lease_id, args.agent_id,
                               disposition=args.disposition, health=args.profile_health):
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


PENDING_RECOVERY_DETAIL = (
    "Capture allocation may have created an unrecorded file. Preserve the reservation "
    "and all captures; do not retry allocation or delete files. With the manager stopped "
    "and its lock held, an operator must confirm the unit and port are inactive, inspect "
    "the lane under the exact program's web/proxy/flows and the private run directory, "
    "preserve any capture, and back up manager state before manual reconciliation. "
    "Do not remove the reservation while allocation or listener ownership is uncertain."
)


def task_proxy_status(args):
    c = db()
    row = proxy_row(c, args)
    if not row:
        emit({"status": "not-found"}, 2)
    attempt = c.execute("select outcome from proxy_attempts where agent_id=? and run_id=? and lane=?",
                        (row['agent_id'], row['run_id'], row['lane'])).fetchone()
    if attempt and attempt['outcome'] == 'capture-uncertain':
        emit({'status': 'capture-uncertain', 'task_proxy': proxy_metadata(row),
              'capture_identity': row['capture_identity'], 'exact_program': row['exact_program'],
              'run_dir': row['run_dir'], 'ready': False, 'reservation': 'retained',
              'detail': CAPTURE_UNCERTAIN_DETAIL})
    if row['capture_identity'] == 'allocation-pending':
        emit({"status": "allocation-pending", "task_proxy": proxy_metadata(row),
              "ready": False, "reservation": "retained", "detail": PENDING_RECOVERY_DETAIL,
              "exact_program": row['exact_program'], "run_dir": row['run_dir']})
    emit({"status": "ok", "task_proxy": proxy_metadata(row), "ready": proxy_ready(row)})


@serialized
def task_proxy_finish(args):
    finish_proxy(args)

@serialized
def task_proxy_recover(args):
    finish_proxy(args, recovery=True)

def finish_capture_index(row):
    """Index bytes from the verified inode while retaining its logical path."""
    flow = Path(proxy_metadata(row)['flow_file'])
    fd = None
    try:
        verify_task_capture(row)
        try:
            if row['flow_path']:
                directory = _capture_open_dir(flow.parent)
                try:
                    expected = json.loads(row['capture_identity'])
                    d = os.fstat(directory)
                    if [d.st_dev, d.st_ino] != expected['directory']:
                        raise OSError('capture directory changed')
                    fd = os.open(flow.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                finally:
                    os.close(directory)
            else:
                fd = os.open(flow, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            if row['flow_path']:
                raise
        if fd is not None:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise OSError('capture is not a regular file')
            if row['flow_path'] and (
                    [info.st_dev, info.st_ino] != expected['file']
                    or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1):
                raise OSError('capture file changed or is not private')
        indexed_capture = fd is not None and info.st_size > 0
        if indexed_capture:
            try:
                executable, python = mitm_runtime()
            except (RuntimeError, OSError):
                emit({'status': 'proxy-index-failed', 'lane': row['lane'],
                      'detail': 'mitmdump Python unavailable; reservation retained'}, 2)
            cmd = [python, *(['-s'] if executable == '/usr/bin/mitmdump' else []), str(PROXY_STORE), '--json', 'index-lane', '--lane', row['lane'],
                   '--lane-root', str(Path(row['run_dir']).parent), '--flow-file', str(flow), '--flow-fd', str(fd),
                   '--program', row['exact_program'] or row['program'], '--task', row['purpose'],
                   '--agent-id', row['agent_id'], '--run-id', row['run_id'],
                   '--account-label', row['account'], '--proxy-host', '127.0.0.1',
                   '--proxy-port', str(row['port']), '--proxy-server', proxy_metadata(row)['proxy_server'], '--transport', 'mixed']
            try:
                indexed = subprocess.run(cmd, capture_output=True, text=True, pass_fds=(fd,))
            except OSError:
                emit({'status': 'proxy-index-failed', 'lane': row['lane'],
                      'detail': 'could not start indexer; reservation retained', 'reservation': 'retained'}, 2)
            try:
                result = json.loads(indexed.stdout)
            except ValueError:
                result = {}
            if indexed.returncode or result.get('status') != 'indexed':
                emit({'status': 'proxy-index-failed', 'lane': row['lane'], 'reservation': 'retained'}, 2)
        verify_task_capture(row)
        if fd is not None:
            current = os.stat(flow, follow_symlinks=False)
            pinned = os.fstat(fd)
            if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
                raise OSError('capture path changed')
        return flow, bool(indexed_capture)
    except (OSError, ValueError, TypeError, KeyError):
        emit({'status': 'proxy-capture-unavailable', 'lane': row['lane'],
              'detail': 'recorded capture unavailable or changed', 'reservation': 'retained'}, 2)
    finally:
        if fd is not None:
            os.close(fd)


def finish_proxy(args, recovery=False, orphan_proven=False):
    c = db()
    c.execute("BEGIN IMMEDIATE")
    row = proxy_row(c, args)
    expected_lane = getattr(args, "expected_lane", None)
    if row and expected_lane is not None and row["lane"] != expected_lane:
        c.rollback()
        emit({"status": "proxy-conflict", "detail": "task proxy generation mismatch"}, 2)
    if not row:
        attempt = c.execute("select lane,outcome from proxy_attempts where agent_id=? and run_id=?",
                            (args.agent_id, args.run_id)).fetchone()
        if attempt and expected_lane is not None and attempt["lane"] != expected_lane:
            c.rollback()
            emit({"status": "proxy-conflict", "detail": "task proxy generation mismatch"}, 2)
        if attempt and attempt["outcome"] != "finished":
            c.rollback()
            terminal = attempt["outcome"] in ("aborted", "admission-unknown")
            emit({"status": attempt["outcome"] if terminal else "proxy-conflict",
                  "lane": attempt["lane"], "already_finished": False},
                 0 if terminal else 2)
        done = c.execute("select lane from finished_proxies where agent_id=? and run_id=?",
                         (args.agent_id, args.run_id)).fetchone()
        c.rollback()
        if done and expected_lane is not None and done["lane"] != expected_lane:
            emit({"status": "proxy-conflict", "detail": "task proxy generation mismatch"}, 2)
        if attempt and done and attempt["lane"] != done["lane"]:
            emit({"status": "proxy-conflict", "detail": "receipt generation mismatch"}, 2)
        emit({"status": "finished", "lane": done["lane"], "already_finished": True} if done
             else {"status": "not-found"}, 0 if done else 2)
    attempt = c.execute("select outcome from proxy_attempts where agent_id=? and run_id=? and lane=?",
                        (row['agent_id'], row['run_id'], row['lane'])).fetchone()
    if attempt and attempt['outcome'] == 'capture-uncertain':
        c.rollback()
        emit({'status': 'proxy-capture-unavailable', 'lane': row['lane'],
              'reservation': 'retained', 'detail': CAPTURE_UNCERTAIN_DETAIL}, 2)
    # An interrupted pre-dispatch start can still lose its allocated inode
    # before recovery. Remember that observation, even if the path is restored.
    if (recovery and attempt and attempt['outcome'] == 'starting'
            and row['admitted'] == 0 and row['flow_path']):
        try:
            verify_task_capture(row)
        except (OSError, ValueError, TypeError, KeyError):
            c.execute("update task_proxies set state='cleanup-failed',updated=? where lane=?", (now(), row['lane']))
            c.execute("update proxy_attempts set outcome='capture-uncertain' where agent_id=? and run_id=? and lane=?",
                      (row['agent_id'], row['run_id'], row['lane']))
            c.commit()
            emit({'status': 'proxy-capture-unavailable', 'lane': row['lane'],
                  'reservation': 'retained', 'detail': CAPTURE_UNCERTAIN_DETAIL}, 2)
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
    if row['capture_identity'] == 'allocation-not-started':
        c.rollback()
        if not recovery:
            emit({'status': 'proxy-conflict', 'detail': 'task proxy requires recovery'}, 2)
        if rollback_proxy(c, row):
            emit({'status': 'aborted', 'lane': row['lane'], 'already_finished': False})
        emit({'status': 'proxy-stop-failed', 'reservation': 'retained'}, 2)
    admitted = row["admitted"]
    if admitted is None and row["state"] in ("starting", "running"):
        admitted = int(row["state"] == "running")
    c.execute("update task_proxies set state='finishing',admitted=?,updated=? where lane=?", (admitted, now(), row["lane"]))
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
    if row['capture_identity'] == 'allocation-pending':
        emit({"status": "proxy-capture-unavailable", "lane": row['lane'],
              "reservation": "retained", "detail": PENDING_RECOVERY_DETAIL}, 2)
    flow, indexed_capture = finish_capture_index(row)
    outcome = "finished" if admitted == 1 else "aborted" if admitted == 0 else "admission-unknown"
    try:
        if admitted == 1:
            c.execute("insert or replace into finished_proxies values(?,?,?,?)",
                      (row["agent_id"], row["run_id"], row["lane"], now()))
        c.execute("insert or replace into proxy_attempts values(?,?,?,?)",
                  (row["agent_id"], row["run_id"], row["lane"], outcome))
        c.execute("delete from task_proxies where lane=?", (row["lane"],))
        c.commit()
    except Exception:
        c.rollback()
        raise
    emit({"status": outcome, "lane": row["lane"], "flow_file": str(flow),
          "indexed": indexed_capture})


def managed_profile(path):
    import browser_profile_lease as profiles
    # A recovered mount or changed fallback must not orphan managed history.
    # Former arbitrary overrides are deliberately not discovery/cleanup roots.
    legacy_fallback = Path.home() / '.local' / 'share' / 'ghost' / 'browser-runtime'
    roots = (profiles.configured_artifact_base(), profiles.DEFAULT_BOUNTY_ROOT,
             profiles.fallback_base(), legacy_fallback)
    for root in roots:
        try:
            relative = Path(path).resolve().relative_to(root.resolve())
        except (ValueError, OSError, RuntimeError):
            continue
        # Only manager-shaped legacy and domain-scoped paths qualify.
        if (((len(relative.parts) in (4, 5) and relative.parts[1:3] == ("web", "browser-profiles"))
             or (len(relative.parts) == 6 and relative.parts[1:3] == ("web", "browser-instances")))
                and all(part not in ("", ".", "..") for part in relative.parts)):
            return True
    return False


def manager_legacy_profile(row):
    """Unkeyed named manager history is persistent, even with mismatched metadata."""
    return row['program'] != 'task-owned' and not record_info(row).get('instance_key')


def sweep_runtime_stopped(row):
    """Read-only proof for a sweep owner, including old PID-only receipts."""
    if not stopped(row):
        return False
    info = record_info(row)
    if info.get('pid') and not info.get('process_identity'):
        try:
            return process_identity(info['pid']) is None
        except (OSError, ValueError, TypeError):
            return False
    return True


def sweep_rows(c, older_than_days, confirm):
    import browser_profile_lease as profiles
    def direct_path(p):
        try:
            return p.is_absolute() and p.resolve(strict=True) == p.absolute()
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
        if not managed_profile(p):
            skipped.append({"browser_id": r["browser_id"], "reason": "not-managed-profile"})
            continue
        # Never remove a physical profile through a keyed or historical alias.
        protected = [other for other in c.execute("SELECT * FROM browsers").fetchall()
                     if manager_legacy_profile(other)]
        if any(profiles.physical_profile(other['profile_dir']) == identity for other in protected):
            skipped.append({"browser_id": r["browser_id"], "reason": "legacy-auth-retained"})
            continue
        lease_db = STATE.parent / "browser_profile_leases.sqlite"
        if lease_db.exists():
            with sqlite3.connect(lease_db) as leases:
                columns = {item[1] for item in leases.execute('PRAGMA table_info(browser_profile_leases)')}
                filters = []
                # A disposable manager row must not override another account's
                # persistent canonical history through the same physical inode.
                if 'program' in columns:
                    filters.append("COALESCE(program,'')!='task-owned'")
                historical = (any(profiles.physical_profile(h[0]) == identity for h in leases.execute(
                    "SELECT profile_dir FROM browser_profile_leases " +
                    ("WHERE " + " AND ".join(filters) if filters else '')
                ).fetchall()) if columns else None)
                marker = (leases.execute("SELECT 1 FROM sqlite_master WHERE name='browser_legacy_auto'").fetchone()
                          and any(profiles.physical_profile(h[0]) == identity for h in leases.execute(
                              "SELECT profile_dir FROM browser_legacy_auto").fetchall()))
                if historical or marker:
                    skipped.append({"browser_id": r["browser_id"], "reason": "legacy-auth-retained"})
                    continue
        if not profiles.safe_profile_path(p):
            skipped.append({"browser_id": r["browser_id"], "reason": "unsafe-profile-path"})
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
            or not sweep_runtime_stopped(other)
            for other in others
        ):
            skipped.append({"browser_id": r["browser_id"], "reason": "profile-in-use"})
            continue
        if not sweep_runtime_stopped(r):
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
        if (profiles.physical_profile(p) != identity or not direct_path(p)
                or not profiles.safe_profile_path(p)):
            skipped.append({"browser_id": r["browser_id"], "reason": "profile-identity-changed"})
            continue
        if not sweep_runtime_stopped(r) or any(not sweep_runtime_stopped(other) for other in others):
            skipped.append({"browser_id": r["browser_id"], "reason": "profile-in-use"})
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
        if getattr(args, "expected_replaces_browser_id", None):
            cmd += ["--expected-replaces-browser-id", args.expected_replaces_browser_id]
        if getattr(args, "resume_automatic_instance", False):
            cmd += ["--resume-automatic-instance"]
        p = subprocess.run(cmd, capture_output=True, text=True)
        invalid_json = False
        result: dict
        try:
            result = json.loads(p.stdout)
            if not isinstance(result, dict):
                raise ValueError("provisioner returned non-object JSON")
        except ValueError:
            invalid_json = True
            result = {
                "status": "launch-failed",
                "detail": "provisioner returned invalid JSON",
            }
        # Recognize only our fixed child signal; never relay arbitrary stderr.
        stderr_lines = getattr(p, 'stderr', '').splitlines()
        cleanup_unverified = json.dumps(LEASE_RELEASE_UNVERIFIED) in stderr_lines
        proxy_cleanup_unverified = json.dumps(PROXY_CLEANUP_UNVERIFIED) in stderr_lines
        if cleanup_unverified:
            result['cleanup'] = {
                **LEASE_RELEASE_UNVERIFIED,
                'action': 'Inspect the canonical lease for this agent and run; resolve it only after verifying ownership and browser state.',
            }
        if proxy_cleanup_unverified:
            result['proxy_cleanup' if cleanup_unverified else 'cleanup'] = {
                **PROXY_CLEANUP_UNVERIFIED,
                'action': 'Reconcile the task proxy and its capture before retrying.',
            }
        if invalid_json:
            emit(result, 2)
        attempts += 1
        if cleanup_unverified or proxy_cleanup_unverified or result.get("status") != "queued" or result.get("retryable") is False:
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
    team = sub.add_parser('team-status', help='Passively inspect coordinator-owned CDP activity; does not issue worker control')
    team.add_argument('--lease-id', required=True)
    team.add_argument('--agent-id', required=True)
    team.add_argument('--run-id', required=True)
    grant = sub.add_parser('team-grant', help='Fence and hand a private worker reference to an exact run')
    grant.add_argument('--lease-id', required=True)
    grant.add_argument('--agent-id', required=True, help='Coordinator agent')
    grant.add_argument('--run-id', required=True, help='Coordinator run')
    grant.add_argument('--worker-agent-id', required=True)
    grant.add_argument('--worker-run-id', required=True)
    for name in ('team-consume', 'team-return'):
        worker = sub.add_parser(name, help='Use the privately delivered worker reference')
        worker.add_argument('--reference', required=True)
        worker.add_argument('--worker-agent-id', required=True)
        worker.add_argument('--worker-run-id', required=True)
    clean = sub.add_parser("cleanup", help="Inspect capacity and eligible terminal idle browsers; dry-run unless --apply")
    clean.add_argument("--apply", action="store_true")
    res = sub.add_parser("resume", help="Reconnect the exact healthy running browser ID or safely reprovision a verified stopped ID")
    res.add_argument("--browser-id", required=True)
    res.add_argument("--agent-id", required=True)
    res.add_argument("--run-id", required=True)
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
        if name != "task-proxy-status":
            parser.add_argument("--expected-lane", help="Lane from the original task-proxy receipt; reject other generations.")
    for parser in (s, r0):
        parser.add_argument("--expected-replaces-browser-id", help=argparse.SUPPRESS)
        parser.add_argument("--resume-automatic-instance", action="store_true", help=argparse.SUPPRESS)
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
    if args.cmd in ("start", "request", "sweep-stale"):
        import browser_profile_lease as profiles
        try:
            profiles.configured_artifact_base()
        except ValueError as exc:
            p.error(str(exc))
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
    if args.cmd == 'team-status':
        result = team_control_status(args.lease_id, args.agent_id, args.run_id)
        emit(result, 0 if result['status'] == 'ok' else 2)
    if args.cmd == 'team-grant':
        result = team_grant(args.lease_id, args.agent_id, args.run_id,
                            args.worker_agent_id, args.worker_run_id)
        emit(result, 0 if result['status'] == 'granted' else 2)
    if args.cmd in ('team-consume', 'team-return'):
        result = (team_consume if args.cmd == 'team-consume' else team_return)(
            args.reference, args.worker_agent_id, args.worker_run_id)
        emit(result, 0 if result['status'] in ('ready', 'returned') else 2)
    if args.cmd == "cleanup":
        cleanup(args)
    if args.cmd == "resume":
        resume(args)
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
    if len(sys.argv) >= 6 and sys.argv[1] == '--verified-capture-launch':
        try:
            _launch_verified_capture(sys.argv[2], json.loads(sys.argv[3]), sys.argv[4:])
        except (OSError, ValueError, TypeError, KeyError) as exc:
            print(f'verified capture launch failed: {exc}; preserve the capture and reconcile the mount/generation', file=sys.stderr)
            raise SystemExit(1)
    else:
        main()
