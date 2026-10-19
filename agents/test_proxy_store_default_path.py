"""The default proxy index reuses the local store, never an artifact alias."""

import importlib.util
import json
import os
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "skills/chromium-test/scripts"


def run_store(home, *args):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "proxy_store.py"), "--json", *args],
        env={**os.environ, "HOME": str(home)}, capture_output=True, text=True,
    )


def test_default_store_reuses_existing_local_database_and_reservations(tmp_path):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    db = home / ".local/share/ghost/proxy-store/proxy_store.sqlite"
    db.parent.mkdir(parents=True, mode=0o700)
    os.chmod(db.parent, 0o2770)  # Host's existing real-directory mode.
    spec = importlib.util.spec_from_file_location("proxy_store", SCRIPTS / "proxy_store.py")
    store = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(store)
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        store.init_db(conn)
        conn.execute("""INSERT INTO proxy_leases
            (lease_id, lane, proxy_host, proxy_port, proxy_server, status, started_at, updated_at)
            VALUES ('old', 'old', 'hoster', 8081, 'http://hoster:8081', 'active', 1, 1)""")
        conn.execute("""INSERT INTO requests (flow_uid, lane, host, method, path_key, indexed_at)
            VALUES ('old-flow', 'old', 'example.test', 'GET', '/old', 1)""")
        conn.commit()
    os.chmod(db, 0o600)
    before = db.stat()

    blocked = run_store(home, "lease-acquire", "--port", "8081")
    assert blocked.returncode != 0
    assert "group/world writable" in blocked.stderr
    assert stat.S_IMODE(db.parent.stat().st_mode) == 0o2770
    assert db.stat().st_ino == before.st_ino
    assert not (home / ".local/state/ghost/proxy-store").exists()

    # Simulate a deliberate operator permission change on the fixture only.
    os.chmod(db.parent, 0o700)
    result = run_store(home, "init")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"status": "initialized", "db": str(db)}
    assert db.stat().st_ino == before.st_ino
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    fenced = run_store(home, "lease-acquire", "--port", "8081")
    assert fenced.returncode == 0, fenced.stderr
    assert json.loads(fenced.stdout)["status"] == "no-free-port"
    visible = run_store(home, "query")
    assert visible.returncode == 0, visible.stderr
    assert json.loads(visible.stdout)["rows"][0]["flow_uid"] == "old-flow"
    assert not (home / ".local/state/ghost/proxy-store").exists()

    # The standalone lane index and task-proxy-finish's bare store invocation
    # must select this same default, without a second allocator/database.
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); import mitm_lane; "
        "sys.argv=['mitm_lane.py','index-store']; print(mitm_lane.parse_args().db)"
    )
    lane = subprocess.run(
        [sys.executable, "-c", code, str(SCRIPTS)],
        env={**os.environ, "HOME": str(home)}, capture_output=True, text=True, check=True,
    )
    assert lane.stdout.strip() == str(db)


@pytest.mark.parametrize("action", [["init"], ["query"], ["lease-acquire", "--port", "8081"]])
def test_default_store_refuses_artifact_symlink_without_touching_target(tmp_path, action):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    artifact = tmp_path / "artifact-mount"
    artifact.mkdir(mode=0o770)
    os.chmod(artifact, 0o770)
    alias = home / ".local/share/ghost/proxy-store"
    alias.parent.mkdir(parents=True)
    alias.symlink_to(artifact, target_is_directory=True)
    result = run_store(home, *action)
    assert result.returncode != 0
    assert alias.is_symlink()
    assert not (artifact / "proxy_store.sqlite").exists()
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o770
    assert not (home / ".local/state/ghost/proxy-store").exists()


def test_default_store_refuses_dangling_symlink(tmp_path):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    alias = home / ".local/share/ghost/proxy-store"
    alias.parent.mkdir(parents=True)
    alias.symlink_to(tmp_path / "missing-artifact", target_is_directory=True)
    result = run_store(home, "init")
    assert result.returncode != 0
    assert alias.is_symlink()
    assert not (tmp_path / "missing-artifact").exists()
