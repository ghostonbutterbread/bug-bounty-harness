#!/usr/bin/env python3
"""Hold the Nebula lane lock and CDP tunnel until stopped or SSH disconnects."""
import argparse
import os
import secrets
import selectors
import shlex
import signal
import subprocess
import sys
import time


class Stopped(Exception):
    pass


def stop_signal(_signum, _frame):
    raise Stopped()


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, stop_signal)

    token = "nebula-lane-ready-" + secrets.token_hex(16)
    inner = f"printf '%s\\n' {shlex.quote(token)}; exec cat >/dev/null"
    remote = "flock -n -E 73 /tmp/nebula-lane.lock sh -c " + shlex.quote(inner)
    command = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
               "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
               "-L", "9333:127.0.0.1:9333", "nebula", remote]
    child = None
    try:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        assert child.stdout is not None
        deadline = time.monotonic() + 15
        buffer = b""
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                events = selector.select(deadline - time.monotonic())
                if not events:
                    break
                data = os.read(child.stdout.fileno(), 4096)
                if not data:
                    try:
                        code = child.wait(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        print("nebula lane SSH closed readiness output; defer", file=sys.stderr)
                        return 1
                    if code == 73:
                        print("nebula lane locked; defer", file=sys.stderr)
                    else:
                        print(f"nebula lane SSH failed before readiness (exit {code}); "
                              "connection or local forwarding port 9333 may have failed; defer",
                              file=sys.stderr)
                    return 1
                buffer += data
                if len(buffer) > 65536:
                    print("nebula lane unexpected SSH output; defer", file=sys.stderr)
                    return 1
                if token.encode() in buffer.splitlines():
                    print(f"nebula lane lock held (ssh pid {child.pid})", flush=True)
                    code = child.wait()
                    print(f"nebula lane SSH ended (exit {code}); stop lane work and re-acquire", file=sys.stderr)
                    return 1
        print("nebula lane readiness timed out; defer", file=sys.stderr)
        return 1
    except Stopped:
        return 0
    except OSError as exc:
        print(f"nebula lane SSH start/read failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if child is not None:
            if child.stdin is not None:
                child.stdin.close()
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            if child.stdout is not None:
                child.stdout.close()


if __name__ == "__main__":
    sys.exit(main())
