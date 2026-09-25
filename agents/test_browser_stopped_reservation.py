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

    def test_uncertain_cannot_cancel(self):
        self.reserve()
        with profiles.connect(self.lease_db) as c:
            c.execute("UPDATE browser_stopped_reservations SET phase='copying'")
        self.assertEqual(manager.cancel_unstarted_reservation('source')['status'], 'reservation-unavailable')
        self.assertTrue(manager.fixture_pool_reserved('fixture','fixture.invalid','anon'))


if __name__ == '__main__':
    unittest.main()
