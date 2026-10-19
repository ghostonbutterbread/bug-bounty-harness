"""Default proxy index path must remain separate from artifact-mounted legacy data."""

import json
import os
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path


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

    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "proxy_store.py"), "--json", "init"],
        env=env, capture_output=True, text=True, check=True,
    )
    db = home / ".local/state/ghost/proxy-store/proxy_store.sqlite"
    assert json.loads(result.stdout) == {"status": "initialized", "db": str(db)}
    assert db.is_file()
    assert not list(artifact.iterdir())
    assert legacy.is_symlink()
    assert stat.S_IMODE(db.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='lanes'").fetchone()

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
