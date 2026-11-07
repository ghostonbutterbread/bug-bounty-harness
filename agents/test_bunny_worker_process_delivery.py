"""Opt-in local proof that two worker processes consume one team browser."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

import pytest

from agents.test_browser_lifecycle import local_display
from agents.test_browser_team_control import fixture
from browser_control import PipeBrowser
from chromium_test import find_chrome_binary
import browser_profile_lease as profiles
from browser_lifecycle import process_identity


# A worker receives only the reference and its own run identity on a private
# stdin channel. The child never prints or receives the raw CDP bearer URL.
WORKER = '''
import json, os, sys
import browser_provisioner as manager
request = json.load(sys.stdin)
manager.unit_identity = lambda unit: 'fixture-unit'
manager.healthy = lambda row: True  # The fixture does not launch systemd.
with manager.team_browser(request['reference'], request['agent'], request['run']) as browser:
    page = browser.contexts[0].pages[0]
    if request['write']:
        page.evaluate("window.teamMarker = 'worker-a'")
    marker = page.evaluate('window.teamMarker')
print(json.dumps({'pid': os.getpid(), 'marker': marker}))
'''


@pytest.mark.skipif(os.environ.get('BBH_LOCAL_BROWSER_SMOKE') != '1',
                    reason='opt-in isolated local Chrome')
@pytest.mark.parametrize('local_display', ['headless'], indirect=True)
def test_two_separate_worker_processes_drive_same_coordinator_browser(monkeypatch, tmp_path, local_display):
    chrome = find_chrome_binary()
    manager, state, canonical, launch = fixture(monkeypatch, tmp_path)
    assert chrome
    flags, env = local_display
    browser = PipeBrowser([chrome, *flags, '--remote-debugging-pipe', '--no-first-run',
        '--disable-background-networking', '--disable-component-update', '--disable-sync',
        '--user-data-dir=' + str(tmp_path / 'profile'), 'about:blank'],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sock = tmp_path.parent / (tmp_path.name[-1] + '-workers.sock')
    assert len(str(sock).encode()) < 107
    final_url = None
    try:
        original_url = browser.serve(0, sock)
        identity = process_identity(browser.process.pid)
        info = json.loads(launch.read_text())
        info.update(cdp_url=original_url, control_socket=str(sock), process_identity=identity,
                    unit_invocation='fixture-unit')
        launch.write_text(json.dumps(info))
        with profiles.connect(canonical) as store:
            store.execute('UPDATE browser_profile_leases SET cdp_url=?', (original_url,))
        monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'fixture-unit')
        monkeypatch.setattr(manager, 'healthy', lambda row: process_identity(browser.process.pid) == identity)
        worker_env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] /
                                                    'skills/chromium-test/scripts'))

        def drive(reference, agent, run, write):
            result = subprocess.run([sys.executable, '-c', WORKER],
                input=json.dumps({'reference': reference, 'agent': agent, 'run': run,
                                  'write': write}), capture_output=True, text=True,
                env=worker_env, timeout=30)
            assert result.returncode == 0, result.stderr[-400:]
            assert 'cdp_url' not in result.stdout and 'http://127.0.0.1:' not in result.stdout
            return json.loads(result.stdout)

        first = manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-a', 'run-a')
        assert first['status'] == 'granted'
        receipt_a = drive(first['reference'], 'worker-a', 'run-a', True)
        assert receipt_a['pid'] != os.getpid() and receipt_a['marker'] == 'worker-a'
        assert manager.team_control_status('team-lease', 'bunny', 'coordinator')['grant_activity_count'] > 0
        assert manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-b', 'run-b') == {'status': 'busy'}
        assert manager.team_return(first['reference'], 'worker-a', 'run-a')['status'] == 'returned'
        second = manager.team_grant('team-lease', 'bunny', 'coordinator', 'worker-b', 'run-b')
        assert second['status'] == 'granted'
        receipt_b = drive(second['reference'], 'worker-b', 'run-b', False)
        assert receipt_b['pid'] != receipt_a['pid'] and receipt_b['marker'] == 'worker-a'
        assert manager.team_consume(first['reference'], 'worker-a', 'run-a') == {'status': 'unavailable'}
        assert manager.team_return(second['reference'], 'worker-b', 'run-b')['status'] == 'returned'
        final_url = json.loads(launch.read_text())['cdp_url']
        assert browser.process.poll() is None
        with profiles.connect(canonical) as store:
            row = store.execute('SELECT cdp_url,owner_agent_id,owner_run_id FROM browser_profile_leases').fetchone()
            assert row[:] == (final_url, 'bunny', 'coordinator')
        assert not list((state.parent / 'team-grants').glob('*/reference.json'))
    finally:
        browser.close()
        sock.unlink(missing_ok=True)
    assert browser.process.poll() is not None
    if final_url:
        with pytest.raises((urllib.error.URLError, ConnectionError)):
            urllib.request.urlopen(final_url + '/json/version', timeout=5)
    shutil.rmtree(tmp_path / 'profile')
    assert not (tmp_path / 'profile').exists()
