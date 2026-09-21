#!/usr/bin/env python3
"""Node-local process identity and serialized provisioner lifecycle primitives."""

import contextlib
import fcntl
import json
import os
from pathlib import Path
import socket


def process_identity(pid):
    """Linux PID + start tick + boot + node; never infer death on access errors."""
    try:
        text = Path(f"/proc/{int(pid)}/stat").read_text()
        fields = text[text.rindex(")") + 2 :].split()
        if fields[0] == "Z":
            return None
        return {
            "pid": int(pid),
            "start": fields[19],
            "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "node": socket.gethostname(),
        }
    except FileNotFoundError:
        return None


def owner_state(identity):
    if not identity or identity.get("node") != socket.gethostname():
        return "unknown"
    try:
        current = process_identity(identity["pid"])
    except (OSError, ValueError, KeyError):
        return "unknown"
    return "active" if current == identity else "terminal"


@contextlib.contextmanager
def node_lock(state):
    state.parent.mkdir(parents=True, exist_ok=True)
    with open(state.with_suffix(".lock"), "a") as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def private_json(path, data):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".new")
    with open(
        temporary, "w", opener=lambda p, flags: os.open(p, flags, 0o600)
    ) as stream:
        json.dump(data, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
