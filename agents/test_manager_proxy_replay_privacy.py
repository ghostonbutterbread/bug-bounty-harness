"""Isolated regression demonstrating the legacy replay artifact boundary.

Run with pytest --basetemp inside $TMPDIR; this starts only loopback fixtures and
never invokes the user's systemd manager or the provisioner's normal state.
"""
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/chromium-test/scripts"
MITMDUMP = shutil.which("mitmdump") or ""


@pytest.mark.skipif(not MITMDUMP, reason="real mitmdump required")
def test_replay_files_are_private_with_default_umask(tmp_path):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    fixture = tmp_path / "fixture"
    fixture.mkdir(mode=0o700)
    lane = fixture / "lanes" / "owned"
    lane.mkdir(parents=True, mode=0o700)
    lane.chmod(0o755)  # Existing shared ancestors must not be chmodded.
    conf = fixture / "ca"
    conf.mkdir(mode=0o700)
    flow = lane / "source.mitm"
    env = {k: v for k, v in os.environ.items() if k.lower() not in
           {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
    env.update({"HOME": str(home), "XDG_CONFIG_HOME": str(home / "config"),
                "XDG_CACHE_HOME": str(home / "cache"),
                "XDG_DATA_HOME": str(home / "data"),
                "XDG_STATE_HOME": str(home / "state"),
                "TMPDIR": str(fixture),
                "BROWSER_PROVISIONER_STATE": str(fixture / "manager.sqlite"),
                "HARNESS_BOUNTY_ARTIFACT_ROOT": str(fixture / "artifacts"),
                "HARNESS_SHARED_BASE": str(fixture / "shared")})

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"fixture-only")

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    proxy = subprocess.Popen([MITMDUMP, "--listen-host", "127.0.0.1", "--listen-port", str(port),
                              "--set", f"confdir={conf}", "--set", "flow_detail=0", "-w", str(flow)],
                             env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, umask=0o077)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if proxy.poll() is not None:
                pytest.fail("fixture mitmdump exited before readiness")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.1):
                    break
            except OSError:
                time.sleep(.1)
        else:
            pytest.fail("fixture mitmdump did not listen")
        request = subprocess.run(["/usr/bin/curl", "--silent", "--fail", "--noproxy", "",
                                  "--proxy", f"http://127.0.0.1:{port}",
                                  f"http://127.0.0.1:{server.server_port}/fixture"],
                                 env=env, capture_output=True, timeout=15, check=True)
        assert request.stdout == b"fixture-only"
    finally:
        if proxy.poll() is None:
            os.killpg(proxy.pid, signal.SIGTERM)
        proxy.wait(timeout=15)
    try:
        assert flow.is_file() and flow.stat().st_size > 0
        unrelated = lane / "old-artifact"
        unrelated.write_text("do not modify")
        unrelated.chmod(0o644)
        # The old timestamp-based names could already be files or symlinks.
        old_files = []
        for stamp in range(int(time.time()) - 2, int(time.time()) + 61):
            old_flow = lane / f"replay-{stamp}.mitm"
            old_log = lane / f"replay-{stamp}.log"
            old_flow.symlink_to(unrelated)
            old_log.write_text("old log")
            old_log.chmod(0o644)
            old_files.append((old_flow, old_log))
        replay_paths = []
        for _ in range(2):
            replay = subprocess.run([sys.executable, str(SCRIPTS / "mitm_lane.py"), "--json",
                                     "--root", str(fixture / "lanes"), "--lane", "owned",
                                     "--mitmdump", MITMDUMP, "replay-flows", "--flow-file", str(flow)],
                                    env=env, capture_output=True, text=True, timeout=40, umask=0o022)
            assert replay.returncode == 0, (replay.returncode, replay.stderr)
            result = json.loads(replay.stdout)
            assert result["status"] == "replayed"
            capture, log = Path(result["replay_file"]), Path(result["replay_log"])
            assert capture.parent == log.parent and capture.parent.parent == lane
            assert capture.parent.stat().st_mode & 0o777 == 0o700
            assert all(p.is_file() and p.stat().st_mode & 0o777 == 0o600 for p in (capture, log))
            assert b"server connect" in log.read_bytes()
            inspect = subprocess.run([MITMDUMP, "-n", "-r", str(capture)], env=env,
                                     capture_output=True, text=True, timeout=20, check=True)
            assert "/fixture" in inspect.stdout and "200" in inspect.stdout
            replay_paths.append((capture, log))
        assert replay_paths[0][0].parent != replay_paths[1][0].parent
        assert unrelated.read_text() == "do not modify"
        assert unrelated.stat().st_mode & 0o777 == 0o644
        assert lane.stat().st_mode & 0o777 == 0o755
        assert all(f.is_symlink() and l.read_text() == "old log" and
                   l.stat().st_mode & 0o777 == 0o644 for f, l in old_files)
        plain = subprocess.run([sys.executable, str(SCRIPTS / "mitm_lane.py"),
                                "--root", str(fixture / "lanes"), "--lane", "owned",
                                "--mitmdump", MITMDUMP, "replay-flows", "--flow-file", str(flow)],
                               env=env, capture_output=True, text=True, timeout=40, umask=0o022)
        assert plain.returncode == 0, plain.stderr
        assert plain.stdout.startswith("replayed:")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.skipif(not MITMDUMP, reason="real mitmdump required")
def test_replay_error_is_reported_and_log_is_private(tmp_path):
    lane = tmp_path / "lanes" / "owned"
    lane.mkdir(parents=True)
    flow = lane / "broken.mitm"
    flow.write_text("not a mitmproxy flow")
    replay = subprocess.run([sys.executable, str(SCRIPTS / "mitm_lane.py"), "--json",
                             "--root", str(lane.parent), "--lane", "owned",
                             "--mitmdump", MITMDUMP, "replay-flows", "--flow-file", str(flow)],
                            capture_output=True, text=True, timeout=40, umask=0o022)
    assert replay.returncode == 2
    result = json.loads(replay.stdout)
    assert result["status"] == "replay-failed" and result["returncode"] != 0
    log = Path(result["replay_log"])
    assert log.stat().st_mode & 0o777 == 0o600
    assert log.read_text().strip()


def test_capture_is_private_before_mitmdump_opens_it(tmp_path):
    lane = tmp_path / "lanes" / "owned"
    lane.mkdir(parents=True)
    flow = lane / "source.mitm"
    flow.write_text("fixture")
    executable = tmp_path / "mitmdump-check"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "p = pathlib.Path(sys.argv[sys.argv.index('-w') + 1])\n"
        "assert p.is_file() and p.stat().st_mode & 0o777 == 0o600\n"
        "assert p.parent.stat().st_mode & 0o777 == 0o700\n"
        "p.write_text('capture marker')\n"
        "print('log marker')\n"
    )
    executable.chmod(0o700)
    replay = subprocess.run([sys.executable, str(SCRIPTS / "mitm_lane.py"), "--json",
                             "--root", str(lane.parent), "--lane", "owned",
                             "--mitmdump", str(executable), "replay-flows", "--flow-file", str(flow)],
                            capture_output=True, text=True, timeout=10, umask=0o022)
    assert replay.returncode == 0, (replay.stdout, replay.stderr)
    result = json.loads(replay.stdout)
    assert Path(result["replay_file"]).read_text() == "capture marker"
    log = Path(result["replay_log"])
    assert log.read_text() == "log marker\n"
    assert log.stat().st_mode & 0o777 == 0o600
