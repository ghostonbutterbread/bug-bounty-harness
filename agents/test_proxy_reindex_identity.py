"""Real-flow regression coverage for ownership of reindexed lane metadata."""
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest


STORE = Path(__file__).parents[1] / "skills/chromium-test/scripts/proxy_store.py"


@pytest.mark.parametrize("change", ["program", "agent", "run", "path", "missing-old", "missing-new", "legacy-relative", "canonical", "relative"])
def test_reindexed_lane_ownership(tmp_path, change):
    executable = shutil.which("mitmdump")
    if not executable:
        pytest.skip("real mitmproxy required")
    executable = Path(executable).resolve()
    python = executable.open("rb").readline().decode().strip()[2:]
    first = tmp_path / "first.mitm"
    second = tmp_path / "second.mitm" if change == "path" else first
    generator = (
        "import sys; from mitmproxy import http,connection; from mitmproxy.io import FlowWriter; "
        "f=http.HTTPFlow(connection.Client(peername=('127.0.0.1',1),sockname=('127.0.0.1',2),timestamp_start=1),connection.Server(address=('example.test',80))); "
        "f.request=http.Request.make('GET','http://example.test/'+sys.argv[2]); "
        "out=open(sys.argv[1],'wb'); FlowWriter(out).add(f); out.close()"
    )
    db = tmp_path / "index.sqlite"
    common = [python, *(["-s"] if str(executable) == "/usr/bin/mitmdump" else []), str(STORE),
              "--db", str(db), "index-lane", "--lane", "default", "--lane-root", str(tmp_path)]
    old = ["--program", "alpha", "--agent-id", "agent-a", "--run-id", "run-a"]
    new = old.copy()
    if change in ("program", "agent", "run"):
        flag = {"program": "--program", "agent": "--agent-id", "run": "--run-id"}[change]
        new[new.index(flag) + 1] += "-different"
    elif change == "missing-old":
        del old[4:6]
    elif change == "missing-new":
        del new[4:6]
    subprocess.run([python, "-c", generator, str(first), "old"], check=True)
    first_arg = first.name if change == "relative" else str(first)
    subprocess.run(common + ["--flow-file", first_arg] + old + ["--runtime-host", "host-a",
                   "--browser-profile-id", "profile-a", "--session-source", "source-a", "--note", "note-a"],
                   check=True, capture_output=True, cwd=tmp_path)
    if change == "legacy-relative":
        with sqlite3.connect(db) as conn:
            conn.execute("update lanes set flow_file=?", (first.name,))
    if change == "canonical":
        second = tmp_path / "alias.mitm"
        second.symlink_to(first)
    subprocess.run([python, "-c", generator, str(second), "new"], check=True)
    subprocess.run(common + ["--flow-file", str(second)] + new, check=True, capture_output=True, cwd=tmp_path)
    with sqlite3.connect(db) as conn:
        same_capture = change in ("canonical", "relative")
        expected = ("host-a", "profile-a", "source-a") if same_capture else (None, None, None)
        note = "note-a" if same_capture else None
        assert conn.execute("select runtime_host,browser_profile_id,session_source,note from lanes where lane='default'").fetchone() == (*expected, note)
        assert conn.execute("select runtime_host,browser_profile_id,session_source from requests where path='/new'").fetchone() == expected
        assert conn.execute("select runtime_host,browser_profile_id,session_source from requests where path='/old'").fetchone() == ("host-a", "profile-a", "source-a")
