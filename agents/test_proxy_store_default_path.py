"""Default proxy index path must remain separate from artifact-mounted legacy data."""

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


def test_default_store_indexes_outside_legacy_artifact_symlink(tmp_path):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    artifact = tmp_path / "artifact-mount"
    artifact.mkdir(mode=0o770)
    legacy = home / ".local/share/ghost/proxy-store"
    legacy.parent.mkdir(parents=True)
    legacy.symlink_to(artifact, target_is_directory=True)
    env = {**os.environ, "HOME": str(home)}
    spec = importlib.util.spec_from_file_location("proxy_store", SCRIPTS / "proxy_store.py")
    store = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(store)
    with sqlite3.connect(artifact / "proxy_store.sqlite") as old:
        old.row_factory = sqlite3.Row
        store.init_db(old)
        old.execute("""INSERT INTO proxy_leases
            (lease_id, lane, proxy_host, proxy_port, proxy_server, status, started_at, updated_at)
            VALUES ('old', 'old', 'hoster', 8081, 'http://hoster:8081', 'active', 1, 1)""")
        old.execute("""INSERT INTO requests (flow_uid, lane, host, method, path_key, indexed_at)
            VALUES ('old-flow', 'old', 'example.test', 'GET', '/old', 1)""")
        old.commit()
    command = [sys.executable, str(SCRIPTS / "proxy_store.py"), "--json"]
    blocked = subprocess.run(command + ["lease-acquire", "--port", "8081"],
                             env=env, capture_output=True, text=True)
    db = home / ".local/state/ghost/proxy-store/proxy_store.sqlite"
    assert blocked.returncode != 0
    assert "legacy proxy store" in blocked.stderr.lower()
    assert not db.exists()
    assert legacy.is_symlink()
    explicit = subprocess.run(command[:2] + ["--db", str(legacy / "proxy_store.sqlite"), "init"],
                              env=env, capture_output=True, text=True)
    assert explicit.returncode != 0  # The private opener must not follow the symlink.
    assert not db.exists()

    # Fixture models an operator-completed frozen backup (not an app copy):
    # the old path is decommissioned only after its SQLite state is transferred.
    db.parent.mkdir(parents=True, mode=0o700)
    with sqlite3.connect(artifact / "proxy_store.sqlite") as old, sqlite3.connect(db) as new:
        old.backup(new)
    legacy.unlink()
    result = subprocess.run(command + ["init"],
        env=env, capture_output=True, text=True, check=True,
    )
    db = home / ".local/state/ghost/proxy-store/proxy_store.sqlite"
    assert json.loads(result.stdout) == {"status": "initialized", "db": str(db)}
    assert db.is_file()
    assert (artifact / "proxy_store.sqlite").is_file()
    with sqlite3.connect(artifact / "proxy_store.sqlite") as old:
        assert old.execute("SELECT proxy_port FROM proxy_leases").fetchone()[0] == 8081
    assert not legacy.exists()
    assert stat.S_IMODE(db.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='lanes'").fetchone()
        assert conn.execute("SELECT proxy_port FROM proxy_leases").fetchone()[0] == 8081
    fenced = subprocess.run(command + ["lease-acquire", "--port", "8081"],
                            env=env, capture_output=True, text=True, check=True)
    assert json.loads(fenced.stdout)["status"] == "no-free-port"
    visible = subprocess.run(command + ["query"], env=env, capture_output=True,
                             text=True, check=True)
    assert json.loads(visible.stdout)["rows"][0]["flow_uid"] == "old-flow"

    # The standalone lane index and task-proxy-finish (which invokes the store
    # without --db) must select the same new default, without migrating old data.
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); import mitm_lane; "
        "sys.argv=['mitm_lane.py','index-store']; print(mitm_lane.parse_args().db)"
    )
    lane = subprocess.run(
        [sys.executable, "-c", code, str(SCRIPTS)],
        env=env, capture_output=True, text=True, check=True,
    )
    assert lane.stdout.strip() == str(db)


@pytest.mark.parametrize("legacy_kind", ["directory", "dangling-symlink"])
@pytest.mark.parametrize("action", [["init"], ["query"], ["lease-acquire", "--port", "8081"]])
def test_legacy_path_blocks_default_even_when_new_database_exists(tmp_path, legacy_kind, action):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    legacy = home / ".local/share/ghost/proxy-store"
    legacy.parent.mkdir(parents=True)
    if legacy_kind == "directory":
        legacy.mkdir()
    else:
        legacy.symlink_to(tmp_path / "missing-mount")
    db = home / ".local/state/ghost/proxy-store/proxy_store.sqlite"
    db.parent.mkdir(parents=True, mode=0o700)
    db.touch(mode=0o600)
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "proxy_store.py"), "--db", str(db), "--json", *action],
        env={**os.environ, "HOME": str(home)}, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "Legacy proxy store" in result.stderr
    assert db.stat().st_size == 0


def test_default_store_still_refuses_new_symlink(tmp_path):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    target = tmp_path / "artifact-mount"
    target.mkdir(mode=0o770)
    os.chmod(target, 0o770)
    parent = home / ".local/state/ghost/proxy-store"
    parent.parent.mkdir(parents=True)
    parent.symlink_to(target, target_is_directory=True)
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "proxy_store.py"), "--json", "init"],
        env={**os.environ, "HOME": str(home)}, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "proxy_store.sqlite" not in [p.name for p in target.iterdir()]
    assert stat.S_IMODE(target.stat().st_mode) == 0o770
