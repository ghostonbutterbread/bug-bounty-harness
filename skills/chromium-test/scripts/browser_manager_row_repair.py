#!/usr/bin/env python3
"""Plan exact-cohort historical manager rows; gated terminal-history repair.

Never copies/deletes profiles or changes canonical leases. Run on the browser node
only after stopping manager/watcher launchers and verifying owner termination.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

from browser_lifecycle import node_lock, owner_state
from browser_provisioner import unit_identity

OLD = ('lease_id', 'browser_id', 'program', 'account', 'agent_id', 'run_id',
       'purpose', 'unit', 'profile_dir', 'launch_file', 'state', 'tab_count',
       'last_activity', 'created', 'updated', 'auth_domain')
VALUES = ('lease_id', 'browser_id', 'program', 'account', 'auth_domain', 'agent_id',
          'run_id', 'purpose', 'unit', 'profile_dir', 'launch_file', 'state',
          'tab_count', 'last_activity', 'created', 'updated')
REPAIRED = VALUES[4:]
TERMINAL_LEASES = ('released', 'expired')
LEASE_FIELDS = {'program': 'program', 'account': 'account_alias',
                'auth_domain': 'auth_domain', 'agent_id': 'owner_agent_id',
                'run_id': 'owner_run_id', 'purpose': 'purpose',
                'profile_dir': 'profile_dir', 'unit': 'service_unit'}


class Refused(Exception):
    pass


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


def open_db(path, *, writable=False):
    if not path.is_file() or path.is_symlink():
        raise Refused('database-missing-or-symlink')
    mode = 'rw' if writable else 'ro'
    conn = sqlite3.connect(f'file:{path}?mode={mode}', uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def layout(conn):
    cols = tuple(r['name'] for r in conn.execute('PRAGMA table_info(browsers)'))
    if cols != OLD:
        raise Refused('unsupported-manager-layout')
    expected = {'lease_id', 'program', 'account_alias', 'auth_domain',
                'owner_agent_id', 'owner_run_id', 'purpose', 'profile_dir',
                'status', 'service_unit'}
    cols = {r['name'] for r in conn.execute('PRAGMA lease.table_info(browser_profile_leases)')}
    if not expected <= cols:
        raise Refused('unsupported-lease-layout')


def no_profile_process(profile, receipt):
    """Independently inspect /proc; unreadable command lines are not absence."""
    from browser_profile_lease import physical_profile
    identity = physical_profile(profile)
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal() or int(entry.name) == os.getpid():
            continue
        try:
            cmd = (entry / 'cmdline').read_bytes().split(b'\0')
        except FileNotFoundError:
            continue  # exited while scanning
        except (OSError, PermissionError):
            raise Refused('process-scan-unknown')
        args = [v.decode('utf-8', 'surrogateescape') for v in cmd]
        dirs = [v.split('=', 1)[1] for v in args if v.startswith('--user-data-dir=')]
        dirs += [args[i + 1] for i, v in enumerate(args[:-1]) if v == '--user-data-dir']
        if (profile in dirs or (identity and any(physical_profile(v) == identity for v in dirs)) or
                (receipt.get('pid') and str(receipt['pid']) == entry.name)):
            raise Refused('profile-process-present')


def runtime_quiescent(row, receipt, lease, metadata):
    """Fail closed on uncertain live state, including unavailable systemd."""
    if lease['status'] not in TERMINAL_LEASES or row['state'] == 'running':
        raise Refused('lease-not-terminal-or-row-active')
    shifted = str(row['state']).endswith('.launch.json')
    unit = row['profile_dir'] if shifted else row['unit']
    if unit != 'browser-' + row['browser_id']:
        raise Refused('unit-identity')
    import subprocess
    from browser_provisioner import sysenv
    for name in (unit, 'browser-owner-' + row['browser_id']):
        result = subprocess.run(['systemctl', '--user', 'show', name,
                                 '-p', 'ActiveState', '-p', 'LoadState',
                                 '-p', 'MainPID', '-p', 'ControlGroup'],
                                capture_output=True, text=True, env=sysenv())
        if result.returncode != 0:
            raise Refused('unit-active-or-unknown')
        fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if (fields.get('ActiveState') != 'inactive' or
                fields.get('LoadState') not in ('loaded', 'not-found') or
                fields.get('MainPID') != '0' or fields.get('ControlGroup') != ''):
            raise Refused('unit-active-or-unknown')
    if metadata.get('owner') and owner_state(metadata['owner']) != 'terminal':
        raise Refused('task-owner-active-or-unknown')
    identity = receipt.get('process_identity')
    if identity and owner_state(identity) != 'terminal':
        raise Refused('root-active-or-unknown')
    if receipt.get('unit_invocation'):
        current = unit_identity(unit)
        if current is None or current == receipt['unit_invocation']:
            raise Refused('unit-invocation-present-or-unknown')
    profile = row['launch_file'] if shifted else row['profile_dir']
    if os.path.lexists(Path(profile) / 'SingletonLock'):
        raise Refused('profile-lock-present')
    no_profile_process(profile, receipt)
    # An unreachable CDP endpoint alone is not proof of absence; a reachable or
    # unclassifiable endpoint must still block even after the process scan.
    if receipt.get('cdp_url'):
        import socket
        from urllib.parse import urlparse
        parsed = urlparse(receipt['cdp_url'])
        if parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', 'localhost', '[::1]', '::1') or not parsed.port:
            raise Refused('cdp-url-unknown')
        try:
            with socket.create_connection((parsed.hostname, parsed.port), timeout=2):
                raise Refused('cdp-active-or-unknown')
        except ConnectionRefusedError:
            pass  # only positive refused connection is evidence of closed port
        except OSError:
            raise Refused('cdp-active-or-unknown')


def inspect(conn, program, account, *, probe=None):
    layout(conn)
    candidates, blocked, evidence = [], {}, {}
    manager_dir = Path(next(r['file'] for r in conn.execute('PRAGMA database_list') if r['name'] == 'main')).parent
    for r in conn.execute('SELECT * FROM browsers WHERE program=? AND account=? ORDER BY lease_id', (program, account)):
        row = dict(r)
        # Exactly the historical shift signature, not an arbitrary malformed row.
        signature = (row['tab_count'] in ('running', 'idle-stopped') and row['last_activity'] == 0 and
                     isinstance(row['state'], str) and row['state'].endswith('.launch.json'))
        idle = row['state'] == 'idle-stopped' and row['tab_count'] == 0
        if not signature and not idle:
            if (row['tab_count'] == 'running' or
                isinstance(row['state'], str) and row['state'].endswith('.launch.json')):
                blocked[digest(row['lease_id'])[:16]] = 'unknown-malformed-row'
            continue
        lid = row['lease_id']
        try:
            if signature:
                repaired = dict(zip(VALUES, (row[k] for k in OLD)))
                # SQLite TEXT affinity stringifies the displaced updated timestamp.
                if repaired['state'] not in ('running', 'idle-stopped') or repaired['tab_count'] != 0 or not all(isinstance(repaired[k], (int, float)) for k in ('last_activity', 'created')):
                    raise Refused('shift-signature')
                repaired['updated'] = float(repaired['updated'])
                # Only apply after terminal lease and live-root checks: the
                # historical 'running' projection must not survive that proof.
                repaired['state'] = 'stopped'
            else:
                repaired = dict(row)
                repaired['state'] = 'stopped'
            lease = conn.execute('SELECT * FROM lease.browser_profile_leases WHERE lease_id=?', (lid,)).fetchone()
            if lease is None:
                raise Refused('lease-missing')
            if any(repaired[k] != lease[v] for k, v in LEASE_FIELDS.items()
                   if not (k == 'unit' and lease[v] is None) and not
                   (k == 'auth_domain' and lease[v] is None and repaired[k] == 'legacy-global')):
                raise Refused('lease-conflict')
            if not repaired['unit'] == 'browser-' + repaired['browser_id']:
                raise Refused('unit-identity')
            if Path(repaired['launch_file']) != manager_dir / (repaired['browser_id'] + '.launch.json'):
                raise Refused('launch-identity')
            if not Path(repaired['profile_dir']).is_absolute() or Path(repaired['profile_dir']).is_symlink() or (signature and not Path(repaired['profile_dir']).is_dir()):
                raise Refused('profile-path-unknown')
            # Another active lease can name the same physical directory through
            # a symlink. Unknown identity within this exact account also fences.
            from browser_profile_lease import physical_profile
            identity = physical_profile(repaired['profile_dir'])
            for owner in conn.execute("SELECT lease_id,profile_dir,program,account_alias,auth_domain FROM lease.browser_profile_leases WHERE lease_id!=? AND status='active'", (lid,)):
                other = physical_profile(owner['profile_dir'])
                same_pool = ((owner['program'], owner['account_alias']) ==
                             (repaired['program'], repaired['account']) and
                             (owner['auth_domain'] == repaired['auth_domain'] or
                              owner['auth_domain'] is None and repaired['auth_domain'] == 'legacy-global'))
                if owner['profile_dir'] == repaired['profile_dir'] or (identity and other == identity) or (same_pool and other is None):
                    raise Refused('profile-other-owner')
            if lease['status'] not in TERMINAL_LEASES:
                raise Refused('lease-not-terminal')
            if idle and lease['profile_dir'] != repaired['profile_dir']:
                raise Refused('profile-other-owner')
            path = Path(repaired['launch_file'])
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise Refused('receipt-path-unknown')
            receipt = json.loads(path.read_text()) if path.is_file() else {}
            if not isinstance(receipt, dict):
                raise Refused('receipt-invalid')
            fields = {'instance_id': 'browser_id', 'profile_dir': 'profile_dir',
                      'agent_id': 'agent_id', 'run_id': 'run_id', 'program': 'program',
                      'task': 'purpose', 'account_label': 'account'}
            if any(receipt[k] != repaired[v] for k, v in fields.items() if k in receipt):
                raise Refused('receipt-conflict')
            if any(receipt[k] != repaired['unit'] for k in ('unit', 'service_unit') if k in receipt):
                raise Refused('receipt-conflict')
            # Sparse/missing historical receipts are never evidence of identity.
            # Canonical lease and exact launch path attest identity; live checks
            # are mandatory at apply for every candidate.
            if probe:
                meta_row = conn.execute('SELECT metadata FROM lifecycle WHERE lease_id=?', (lid,)).fetchone()
                metadata = json.loads(meta_row['metadata']) if meta_row else {}
                probe(row, receipt, lease, metadata)
            candidates.append((row, repaired))
            evidence[digest(lid)[:16]] = ('idle-stopped' if idle else 'missing' if not path.is_file() else
                                           'complete' if all(k in receipt for k in fields) and receipt.get('process_identity') else
                                           'sparse')
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            blocked[digest(lid)[:16]] = 'invalid-evidence'
        except Refused as exc:
            blocked[digest(lid)[:16]] = str(exc)
    return candidates, blocked, evidence


def snapshot(path, destination):
    if destination.exists():
        raise Refused('backup-exists')
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        with open_db(path) as src, sqlite3.connect(destination) as dst:
            src.backup(dst)
        os.chmod(destination, 0o600)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def backup_pair(manager, canonical, directory):
    """Each attempt owns a fresh pair; discard both if either snapshot fails."""
    import uuid
    stem = uuid.uuid4().hex
    first = directory / (stem + '.manager.sqlite')
    second = directory / (stem + '.lease.sqlite')
    try:
        snapshot(manager, first)
        snapshot(canonical, second)
    except BaseException:
        first.unlink(missing_ok=True)
        second.unlink(missing_ok=True)
        raise
    return first, second


def run(manager, program, account, *, apply=False, plan_hash=None, confirmed=False, backup_dir=None, probe=None, before_update=None):
    manager = Path(manager).expanduser().absolute()
    canonical = manager.parent / 'browser_profile_leases.sqlite'
    if apply and (not program or not account or not confirmed or not plan_hash or backup_dir is None):
        raise Refused('apply-requires-exact-cohort-plan-owner-terminal-confirmation-and-backup-dir')
    if apply and (Path(backup_dir).is_symlink() or not Path(backup_dir).is_dir() or
                  os.stat(backup_dir).st_mode & 0o077):
        raise Refused('backup-directory-must-be-private')
    # Shared node lock coordinates manager commands; ATTACH + BEGIN IMMEDIATE
    # also locks both SQLite writers. Canonical DB is never updated.
    with node_lock(manager) if apply else __import__('contextlib').nullcontext():
        with open_db(manager, writable=apply) as conn:
            if not canonical.is_file() or canonical.is_symlink():
                raise Refused('canonical-db-missing-or-symlink')
            lease_uri = str(canonical) if apply else f'file:{canonical}?mode=ro'
            conn.execute('ATTACH DATABASE ? AS lease', (lease_uri,))
            if apply:
                # Reserve both attached databases before copying either. A
                # canonical writer does not share the node lock; BEGIN IMMEDIATE
                # excludes it until the snapshots and update are complete.
                conn.execute('BEGIN IMMEDIATE')
            try:
                if apply:
                    backup_pair(manager, canonical, Path(backup_dir))
                # Bind the approval to *every* manager row in the selected
                # cohort, including ignored and quarantined history. A change
                # to an excluded row or its runtime refusal must invalidate the
                # plan even when the eligible candidate set is unchanged.
                observed = [(r['lease_id'], digest(dict(r))) for r in conn.execute(
                    'SELECT * FROM browsers WHERE program=? AND account=? ORDER BY lease_id',
                    (program, account))]
                candidates, blocked, evidence = inspect(conn, program, account, probe=probe or (runtime_quiescent if apply else None))
                plan = digest({'program': program, 'account': account,
                               'observed': observed, 'blocked': blocked,
                               'candidates': [(r['lease_id'], digest(r), digest(v), evidence[digest(r['lease_id'])[:16]])
                                              for r, v in candidates]})
                receipt = {'status': 'planned' if not apply else 'refused', 'program': program,
                           'account': account, 'observed_count': len(observed),
                           'candidate_count': len(candidates), 'blocked_count': len(blocked),
                           'blocked': blocked, 'evidence': evidence, 'plan_hash': plan}
                if apply:
                    if plan != plan_hash or not candidates:
                        raise Refused('plan-changed-or-no-eligible-rows')
                    for raw, target in candidates:
                        if before_update:
                            before_update(conn, raw)
                        cols = REPAIRED if raw['state'] != 'idle-stopped' else ('state',)
                        sql = 'UPDATE browsers SET ' + ', '.join(k + '=?' for k in cols) + ' WHERE lease_id=? AND ' + ' AND '.join(k + ' IS ?' for k in OLD)
                        values = [target[k] for k in cols] + [raw['lease_id']] + [raw[k] for k in OLD]
                        if conn.execute(sql, values).rowcount != 1:
                            raise Refused('manager-row-race')
                    conn.commit()
                    receipt['status'] = 'applied'
                    receipt['applied_count'] = len(candidates)
                return receipt
            except BaseException:
                if apply:
                    conn.rollback()
                raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manager-db', required=True)
    parser.add_argument('--program', required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--probe-runtime', action='store_true',
                        help='Apply-time liveness checks during the read-only plan; use its hash for apply.')
    parser.add_argument('--plan-hash')
    parser.add_argument('--owner-terminal-confirmed', action='store_true')
    parser.add_argument('--backup-dir')
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.manager_db, args.program, args.account, apply=args.apply,
                             plan_hash=args.plan_hash, confirmed=args.owner_terminal_confirmed,
                             backup_dir=args.backup_dir,
                             probe=runtime_quiescent if args.probe_runtime else None), sort_keys=True))
    except (Refused, sqlite3.Error, OSError) as exc:
        print(json.dumps({'status': 'refused', 'reason': str(exc) if isinstance(exc, Refused) else 'database-or-runtime-error'}))
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
