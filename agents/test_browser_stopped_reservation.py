"""Disposable DB/profile fixtures only; no running browser or account access."""
import importlib.util
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'
sys.path.insert(0, str(SCRIPTS))
import browser_profile_lease as profiles
import browser_provisioner as manager


class ReservationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.path = self.base / 'profile'
        self.path.mkdir()
        self.state = self.base / 'manager.sqlite'
        self.state_patch = patch.object(manager, 'STATE', self.state)
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)
        self.info = {'control_generation': 'generation-one', 'process_identity': {'pid': 4242},
                     'cdp_url': 'http://127.0.0.1:9999', 'unit_invocation': 'invocation-one'}
        self.stop_patch = patch.object(manager, 'stopped', return_value=True)
        self.stop_patch.start()
        self.addCleanup(self.stop_patch.stop)
        self.info_patch = patch.object(manager, 'record_info', return_value=self.info)
        self.info_patch.start()
        self.addCleanup(self.info_patch.stop)
        self.identity_patch = patch.object(manager, 'unit_identity', return_value='invocation-one')
        self.identity = self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)
        self.unit_state_patch = patch.object(manager, 'unit_explicitly_inactive', return_value=True)
        self.unit_state_patch.start()
        self.addCleanup(self.unit_state_patch.stop)
        self.lease_db = self.base / 'browser_profile_leases.sqlite'
        with profiles.connect(self.lease_db) as c:
            profiles.init_db(c)
            c.execute("""INSERT INTO browser_profile_leases
                (lease_id,program,account_alias,auth_domain,owner_agent_id,owner_run_id,purpose,
                 profile_dir,status,browser_status,work_state,created_at,heartbeat_at,expires_at,
                 manager_id,service_unit) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ('source','fixture','anon','fixture.invalid','agent','run','test',str(self.path),
                 'released','stopped','terminal',1,1,2,manager.manager_id(),'unit-one'))
        with manager.db() as c:
            c.execute("""INSERT INTO browsers
                (lease_id,browser_id,program,account,auth_domain,agent_id,run_id,purpose,unit,
                 profile_dir,launch_file,state,last_activity,created,updated)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ('source','browser-one','fixture','anon','fixture.invalid','agent','run','test',
                 'unit-one',str(self.path),str(self.base/'launch.json'),'stopped',1,1,1))

    def reserve(self):
        self.assertEqual(manager.stopped_reservation('source')['status'], 'reserved')

    def test_reservation_persists_and_fences_physical_alias(self):
        self.reserve()
        alias = self.base/'alias'
        alias.symlink_to(self.path, target_is_directory=True)
        with profiles.connect(self.lease_db) as c:
            profiles.init_db(c)
            c.execute('BEGIN IMMEDIATE')
            self.assertTrue(profiles.reservation_conflict(c, path=str(alias)))
            self.assertTrue(profiles.reservation_conflict(c, program='fixture', domain='fixture.invalid', alias='anon'))
        self.assertTrue(manager.fixture_pool_reserved('fixture','fixture.invalid','anon'))
        self.assertEqual(manager.stopped_reservation('source')['status'], 'reserved')
        self.assertEqual(manager.stopped_reservation('source','copying')['status'], 'reservation-unavailable')

    def test_direct_transfer_and_release_rejected(self):
        self.reserve()
        with profiles.connect(self.lease_db) as c:
            c.execute("UPDATE browser_profile_leases SET status='active' WHERE lease_id='source'")
        self.assertEqual(profiles.transfer_managed_lease(self.lease_db,'source',manager.manager_id(),
            'other','run','test',60,'http://127.0.0.1:9999')['reason'], 'stopped-profile-reserved')
        args = SimpleNamespace(state_dir=str(self.base), lease_id='source',agent_id='agent',manager_id=manager.manager_id(),
                               disposition='completed',profile_health='healthy')
        self.assertEqual(profiles.cmd_release(args)['reason'], 'stopped-profile-reserved')

    def test_alias_nonterminal_and_generation_fail_closed(self):
        alias = self.base/'alias'
        alias.symlink_to(self.path, target_is_directory=True)
        with manager.db() as c:
            c.execute("""INSERT INTO browsers
                (lease_id,browser_id,program,account,auth_domain,agent_id,run_id,purpose,unit,
                 profile_dir,launch_file,state,last_activity,created,updated)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ('alias','browser-two','fixture','anon','fixture.invalid','agent','run','test',
                 'unit-two',str(alias),str(self.base/'other.json'),'running',1,1,1))
        self.assertEqual(manager.stopped_reservation('source')['status'], 'reservation-unavailable')
        with manager.db() as c:
            c.execute("UPDATE browsers SET state='stopped' WHERE lease_id='alias'")
        self.reserve()
        self.info['control_generation'] = 'generation-two'
        self.assertEqual(manager.stopped_reservation('source')['status'], 'reservation-unavailable')

    def test_uncertain_reservation_stays_fenced(self):
        self.reserve()
        with profiles.connect(self.lease_db) as c:
            c.execute("UPDATE browser_stopped_reservations SET phase='uncertain'")
        self.assertEqual(manager.stopped_reservation('source')['status'], 'reservation-unavailable')
        self.assertTrue(manager.fixture_pool_reserved('fixture','fixture.invalid','anon'))

    def test_atomic_race_reservation_vs_canonical_writer(self):
        self.reserve()
        results = []
        def writer():
            with profiles.connect(self.lease_db) as c:
                profiles.init_db(c)
                c.execute('BEGIN IMMEDIATE')
                results.append(profiles.reservation_conflict(c, path=str(self.path)))
        threads = [threading.Thread(target=writer) for _ in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(results, [True, True])

    def test_direct_acquire_policy_flip_and_cancel(self):
        self.reserve()
        with profiles.connect(self.lease_db) as c:
            profiles.init_resource_policy(c)
            c.execute("INSERT INTO browser_concurrency_policy VALUES (?,?,?,?)",
                      ('fixture','anon','fixture.invalid','multiple'))
        args = SimpleNamespace(state_dir=str(self.base), program='fixture', account='anon',
            auth_domain='fixture.invalid', instance_key='separate', task_owned=False,
            agent_id='agent-two', run_id='run-two', purpose='fixture', recover_profile=False,
            ttl_seconds=60, manager_id=None, automatic_instance=False)
        account = {'alias':'anon','profile_kind':'anonymous','lifecycle':'active',
                   'browser_lease_enabled':True}
        with patch.object(profiles, 'resolve_account', return_value=(account, {'accounts':[]})):
            self.assertEqual(profiles.cmd_acquire(args)['reason'], 'stopped-profile-reserved')
        self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'released')
        self.assertFalse(manager.fixture_pool_reserved('fixture','fixture.invalid','anon'))

    def test_cancel_rejects_independent_unit_invocation_drift(self):
        self.reserve()
        # Launch receipt remains unchanged; the inactive unit is a new invocation.
        with patch.object(manager, 'unit_identity', return_value='invocation-two') as identity:
            self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'reservation-unavailable')
            identity.assert_called_once_with('unit-one')
        self.assertTrue(manager.fixture_pool_reserved('fixture', 'fixture.invalid', 'anon'))

    def test_cancel_rejects_missing_or_failed_unit_identity(self):
        self.reserve()
        for value in (None, '', OSError('unit unavailable'), RuntimeError('probe failed')):
            with self.subTest(value=repr(value)):
                with patch.object(manager, 'unit_identity', side_effect=value if isinstance(value, Exception) else None,
                                  return_value=value if not isinstance(value, Exception) else None) as identity:
                    self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'reservation-unavailable')
                    identity.assert_called_once_with('unit-one')
                self.assertTrue(manager.fixture_pool_reserved('fixture', 'fixture.invalid', 'anon'))

    def test_cancel_matching_inactive_unit_releases_fence(self):
        self.reserve()
        with patch.object(manager, 'unit_explicitly_inactive', return_value=True) as state:
            self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'released')
            state.assert_called_once_with('unit-one')
        self.identity.assert_called_once_with('unit-one')
        self.assertFalse(manager.fixture_pool_reserved('fixture','fixture.invalid','anon'))

    def test_cancel_requires_independent_terminal_unit_state(self):
        self.reserve()
        # The manager row, root and CDP are terminal, and InvocationID matches.
        # Neither an is-active nonzero exit nor a show error proves inactivity.
        self.stop_patch.stop()
        self.unit_state_patch.stop()
        with (patch.object(manager, 'unit_active', return_value=False),
              patch.object(manager, 'owner_state', return_value='terminal'),
              patch.object(profiles, 'local_cdp_version', return_value={'status':'unavailable'})):
            for active, load, code in (('unknown', 'loaded', 0), ('failed', 'loaded', 0),
                                       ('inactive', 'not-found', 0), ('', '', 0),
                                       ('inactive', 'loaded', 1),
                                       ('inactive', 'loaded', 0)):
                with self.subTest(active=active, load=load, code=code):
                    result = SimpleNamespace(returncode=code,
                        stdout=f'ActiveState={active}\nLoadState={load}\n')
                    with patch.object(manager.subprocess, 'run', return_value=result) as run:
                        expected = 'released' if (active, load, code) == ('inactive', 'loaded', 0) else 'reservation-unavailable'
                        self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], expected)
                        run.assert_called_once_with(
                            ['systemctl', '--user', 'show', '--property=ActiveState',
                             '--property=LoadState', 'unit-one'],
                            capture_output=True, text=True, env=manager.sysenv())
                    with profiles.connect(self.lease_db) as c:
                        phase = c.execute('SELECT phase FROM browser_stopped_reservations').fetchone()['phase']
                    self.assertEqual(phase, 'released' if expected == 'released' else 'reserved')

    def test_cancel_systemd_state_probe_exception_keeps_fence(self):
        self.reserve()
        self.unit_state_patch.stop()
        with patch.object(manager.subprocess, 'run', side_effect=OSError('bus unavailable')):
            self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'reservation-unavailable')
        self.assertTrue(manager.fixture_pool_reserved('fixture','fixture.invalid','anon'))

    def test_uncertain_cannot_cancel(self):
        self.reserve()
        with profiles.connect(self.lease_db) as c:
            c.execute("UPDATE browser_stopped_reservations SET phase='copying'")
        self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'reservation-unavailable')
        self.assertTrue(manager.fixture_pool_reserved('fixture','fixture.invalid','anon'))

    def test_copying_retry_cannot_downgrade_then_cancel(self):
        self.reserve()
        for phase in ('copying', 'uncertain'):
            with self.subTest(phase=phase):
                with profiles.connect(self.lease_db) as c:
                    c.execute('UPDATE browser_stopped_reservations SET phase=?', (phase,))
                self.assertEqual(manager.stopped_reservation('source')['status'], 'reservation-unavailable')
                self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'reservation-unavailable')
                with profiles.connect(self.lease_db) as c:
                    self.assertEqual(c.execute('SELECT phase FROM browser_stopped_reservations').fetchone()['phase'], phase)
        self.assertTrue(manager.fixture_pool_reserved('fixture','fixture.invalid','anon'))

    def test_cancel_rechecks_recorded_identity_and_canonical_owner(self):
        for target, column, changed in (
            ('manager', 'agent_id', 'different'), ('manager', 'run_id', 'different'),
            ('manager', 'unit', 'different'), ('manager', 'profile_dir', 'different'),
            ('canonical', 'owner_agent_id', 'different'), ('canonical', 'owner_run_id', 'different'),
            ('canonical', 'manager_id', 'different'), ('canonical', 'service_unit', 'different'),
            ('canonical', 'profile_dir', 'different'), ('canonical', 'work_state', 'active'),
            ('record', 'process_identity', {'pid': 9999}),
            ('record', 'cdp_url', 'http://127.0.0.1:8888'),
            ('record', 'unit_invocation', 'different'),
            ('record', 'control_generation', 'different'),
        ):
            with self.subTest(target=target, column=column):
                self.reserve()
                path = self.state if target == 'manager' else self.lease_db
                table = 'browsers' if target == 'manager' else 'browser_profile_leases'
                original = self.info[column] if target == 'record' else self._original_value(column)
                if target == 'record':
                    self.info[column] = changed
                else:
                    with sqlite3.connect(path) as c:
                        c.execute(f'UPDATE {table} SET {column}=? WHERE lease_id=?', (changed, 'source'))
                self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'reservation-unavailable')
                self.assertTrue(manager.fixture_pool_reserved('fixture','fixture.invalid','anon'))
                if target == 'record':
                    self.info[column] = original
                else:
                    with sqlite3.connect(path) as c:
                        c.execute(f'UPDATE {table} SET {column}=? WHERE lease_id=?',
                                  (original, 'source'))

    def _original_value(self, column):
        return {'agent_id':'agent', 'run_id':'run', 'unit':'unit-one', 'profile_dir':str(self.path),
                'owner_agent_id':'agent', 'owner_run_id':'run', 'manager_id':manager.manager_id(),
                'service_unit':'unit-one', 'work_state':'terminal'}[column]

    def test_cancel_rejects_alias_uncertainty_and_inode_drift(self):
        self.reserve()
        alias = self.base/'alias'
        alias.symlink_to(self.path, target_is_directory=True)
        with manager.db() as c:
            c.execute("""INSERT INTO browsers
                (lease_id,browser_id,program,account,auth_domain,agent_id,run_id,purpose,unit,
                 profile_dir,launch_file,state,last_activity,created,updated)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ('alias','browser-two','fixture','anon','fixture.invalid','agent','run','test',
                 'unit-two',str(alias),str(self.base/'other.json'),'running',1,1,1))
        self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'reservation-unavailable')
        with manager.db() as c:
            c.execute("DELETE FROM browsers WHERE lease_id='alias'")
        self.path.rename(self.base/'old-profile')
        self.path.mkdir()
        self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'reservation-unavailable')

    def test_cancel_missing_proof_and_changed_fence_fail_closed(self):
        self.reserve()
        for column, changed in (('owner_agent_id', 'other'), ('owner_run_id', 'other'),
                ('root', '{}'), ('cdp_url', 'http://127.0.0.1:8888'),
                ('service_unit', 'other'), ('unit_invocation', None),
                ('manager_id', 'other'), ('profile_dir', 'other')):
            with self.subTest(column=column):
                with profiles.connect(self.lease_db) as c:
                    original = c.execute(f'SELECT {column} FROM browser_stopped_reservations').fetchone()[0]
                    c.execute(f'UPDATE browser_stopped_reservations SET {column}=?', (changed,))
                self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'reservation-unavailable')
                with profiles.connect(self.lease_db) as c:
                    c.execute(f'UPDATE browser_stopped_reservations SET {column}=?', (original,))
        original = self.info.pop('cdp_url')
        self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'reservation-unavailable')
        self.info['cdp_url'] = original
        with profiles.connect(self.lease_db) as c:
            c.execute("DELETE FROM browser_profile_leases WHERE lease_id='source'")
        self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'reservation-unavailable')


if __name__ == '__main__':
    unittest.main()
