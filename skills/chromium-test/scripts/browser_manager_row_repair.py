#!/usr/bin/env python3
"""Read-only plan for historical positional manager rows; gated local Blue repair.

Never copies/deletes profiles or changes canonical leases. Run on the browser node
only after stopping the manager/watcher launchers and verifying owner termination.
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
from browser_profile_lease import local_cdp_version

OLD = ('lease_id', 'browser_id', 'program', 'account', 'agent_id', 'run_id',
       'purpose', 'unit', 'profile_dir', 'launch_file', 'state', 'tab_count',
       'last_activity', 'created', 'updated', 'auth_domain')
VALUES = ('lease_id', 'browser_id', 'program', 'account', 'auth_domain', 'agent_id',
          'run_id', 'purpose', 'unit', 'profile_dir', 'launch_file', 'state',
          'tab_count', 'last_activity', 'created', 'updated')
REPAIRED = VALUES[4:]
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


def runtime_quiescent(row, receipt, lease, metadata):
    """Fail closed on any uncertain runtime check, including unavailable systemd."""
    if lease['status'] != 'released' or row['state'] == 'running':
        raise Refused('lease-not-released-or-row-active')
    unit = row['profile_dir']
    if not unit.endswith('.service') and not unit.startswith('browser-'):
        raise Refused('unit-shape')
    # systemctl is-active distinguishes inactive from unavailable; do not use
    # provisioner's boolean helper alone (which treats errors as inactive).
    import subprocess
    from browser_provisioner import sysenv
    for name in (unit, 'browser-owner-' + row['browser_id']):
        result = subprocess.run(['systemctl', '--user', 'is-active', name],
                                capture_output=True, text=True, env=sysenv())
        if result.returncode != 3 or result.stdout.strip() != 'inactive':
            raise Refused('unit-active-or-unknown')
    if not metadata.get('owner') or owner_state(metadata['owner']) != 'terminal':
        raise Refused('task-owner-active-or-unknown')
    identity = receipt.get('process_identity')
    if not identity or owner_state(identity) != 'terminal':
        raise Refused('root-active-or-unknown')
    current_invocation = unit_identity(unit)
    if not receipt.get('unit_invocation') or current_invocation is None or current_invocation == receipt['unit_invocation']:
        raise Refused('unit-invocation-present-or-unknown')
    if os.path.lexists(Path(row['launch_file']) / 'SingletonLock'):
        raise Refused('profile-lock-present')
    url = receipt.get('cdp_url')
    if not url or local_cdp_version(url)['status'] != 'unreachable':
        raise Refused('cdp-active-or-unknown')


def inspect(conn, program, *, probe=None):
    layout(conn)
    candidates, blocked = [], {}
    for r in conn.execute('SELECT * FROM browsers WHERE program=? ORDER BY lease_id', (program,)):
        row = dict(r)
        # Exactly the historical shift signature, not an arbitrary malformed row.
        signature = (row['tab_count'] == 'running' and row['last_activity'] == 0 and
                     isinstance(row['state'], str) and row['state'].endswith('.launch.json'))
        if not signature:
            if (row['tab_count'] == 'running' or
                isinstance(row['state'], str) and row['state'].endswith('.launch.json')):
                blocked[digest(row['lease_id'])[:16]] = 'unknown-malformed-row'
            continue
        lid = row['lease_id']
        try:
            repaired = dict(zip(VALUES, (row[k] for k in OLD)))
            # SQLite TEXT affinity stringifies the displaced updated timestamp.
            if repaired['state'] != 'running' or repaired['tab_count'] != 0 or not all(isinstance(repaired[k], (int, float)) for k in ('last_activity', 'created')):
                raise Refused('shift-signature')
            repaired['updated'] = float(repaired['updated'])
            lease = conn.execute('SELECT * FROM lease.browser_profile_leases WHERE lease_id=?', (lid,)).fetchone()
            if lease is None:
                raise Refused('lease-missing')
            if any(repaired[k] != lease[v] for k, v in LEASE_FIELDS.items()):
                raise Refused('lease-conflict')
            if not repaired['unit'] == 'browser-' + repaired['browser_id']:
                raise Refused('unit-identity')
            if Path(repaired['launch_file']).name != repaired['browser_id'] + '.launch.json':
                raise Refused('launch-identity')
            # Strict receipt: missing or conflicting evidence is quarantined, not inferred.
            path = Path(repaired['launch_file'])
            if not path.is_file() or path.is_symlink():
                raise Refused('receipt-missing')
            receipt = json.loads(path.read_text())
            if (receipt.get('instance_id') != repaired['browser_id'] or
                receipt.get('profile_dir') != repaired['profile_dir'] or
                receipt.get('agent_id') != repaired['agent_id'] or
                receipt.get('run_id') != repaired['run_id'] or
                receipt.get('program') != repaired['program'] or
                receipt.get('task') != repaired['purpose']):
                raise Refused('receipt-conflict')
            if receipt.get('account_label') != repaired['account']:
                raise Refused('receipt-account-conflict')
            # Domain is attested by the canonical lease; the launcher did not
            # emit a domain. Never infer it from the profile path.
            if probe:
                meta_row = conn.execute('SELECT metadata FROM lifecycle WHERE lease_id=?', (lid,)).fetchone()
                metadata = json.loads(meta_row['metadata']) if meta_row else {}
                probe(row, receipt, lease, metadata)
            elif lease['status'] == 'active':
                raise Refused('active-lease')
            candidates.append((row, repaired))
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            blocked[digest(lid)[:16]] = 'invalid-evidence'
        except Refused as exc:
            blocked[digest(lid)[:16]] = str(exc)
    return candidates, blocked


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


def run(manager, program, *, apply=False, plan_hash=None, confirmed=False, backup_dir=None, probe=None, before_update=None):
    manager = Path(manager).expanduser().absolute()
    canonical = manager.parent / 'browser_profile_leases.sqlite'
    if apply and (program != 'blue' or not confirmed or not plan_hash or backup_dir is None):
        raise Refused('apply-requires-blue-plan-owner-terminal-confirmation-and-backup-dir')
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
                # Backup before mutation, while the manager node lock is held.
                stem = digest([str(manager), plan_hash])[:20]
                snapshot(manager, Path(backup_dir) / (stem + '.manager.sqlite'))
                snapshot(canonical, Path(backup_dir) / (stem + '.lease.sqlite'))
                conn.execute('BEGIN IMMEDIATE')
            try:
                candidates, blocked = inspect(conn, program, probe=probe or (runtime_quiescent if apply else None))
                plan = digest([(r['lease_id'], digest(r), digest(v)) for r, v in candidates])
                receipt = {'status': 'planned' if not apply else 'refused', 'program': program,
                           'candidate_count': len(candidates), 'blocked_count': len(blocked),
                           'blocked': blocked, 'plan_hash': plan}
                if apply:
                    if blocked or plan != plan_hash or not candidates:
                        raise Refused('plan-changed-or-blocked')
                    for raw, target in candidates:
                        if before_update:
                            before_update(conn, raw)
                        cols = REPAIRED
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
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--plan-hash')
    parser.add_argument('--owner-terminal-confirmed', action='store_true')
    parser.add_argument('--backup-dir')
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.manager_db, args.program, apply=args.apply,
                             plan_hash=args.plan_hash, confirmed=args.owner_terminal_confirmed,
                             backup_dir=args.backup_dir), sort_keys=True))
    except (Refused, sqlite3.Error, OSError) as exc:
        print(json.dumps({'status': 'refused', 'reason': str(exc) if isinstance(exc, Refused) else 'database-or-runtime-error'}))
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
