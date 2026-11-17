"""Deferred legacy idle regression: its old skill-block parser is obsolete.

This unfinished untracked experiment is preserved for the future idle feature,
not evidence for the SSH-disconnect-only change. Rewrite the fixture to drive
the then-current entry point before removing the explicit skip.
"""

import pytest

pytestmark = pytest.mark.skip(reason="idle detection is unimplemented; legacy skill-block fixture needs rewrite")

import os
from pathlib import Path
import signal
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/nebula-browser-lane/SKILL.md"


def test_documented_entry_releases_after_observed_idle(tmp_path):
    text = SKILL.read_text()
    section = text.split("## Lock + CDP tunnel", 1)[1].split("## Headed Chrome", 1)[0]
    command = section.split("```bash\n", 1)[1].split("```", 1)[0]
    lock = tmp_path / "lane.lock"
    ready = tmp_path / "lane.ready"
    command = command.replace("/tmp/nebula-lane.lock", str(lock))
    command = command.replace("/tmp/nebula-lane.ready", str(ready))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    ssh = bindir / "ssh"
    ssh.write_text('#!/bin/sh\nfor arg do last=$arg; done\nexec /bin/sh -c "$last"\n')
    ssh.chmod(0o755)
    herdr = bindir / "herdr"
    herdr.write_text(
        '#!/bin/sh\nprintf \'%s\\n\' '
        "'{\"pane_id\":\"w1:p1\",\"agent_status\":\"idle\","
        "\"agent_session\":{\"source\":\"herdr:omp\",\"agent\":\"omp\","
        "\"kind\":\"id\",\"value\":\"session-1\"}}'\n"
    )
    herdr.chmod(0o755)
    env = {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
        "TMPDIR": str(tmp_path),
        "HERDR_SESSION": "fixture",
        "HERDR_PANE_ID": "w1:p1",
        "PI_SESSION_ID": "session-1",
        # Proposed short test setting; production default must be 15 minutes.
        "NEBULA_IDLE_TIMEOUT_SECONDS": "0.5",
    }
    # This actually executes the skill's Bash block, with SSH confined to a
    # disposable local subprocess and the real flock utility on a fixture file.
    command += f'\nsleep 2\nflock -n "{lock}" true\n'
    with (tmp_path / "output").open("w+") as output:
        process = subprocess.Popen(
            ["/bin/bash", "-c", command], env=env, stdout=output,
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            result = process.wait(timeout=15)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        output.seek(0)
        log = output.read()
    assert "nebula lane lock held by pid" in log, f"fixture failed to acquire lock: {log}"
    assert result == 0, f"idle owner retained lock after configured threshold; output: {log}"
