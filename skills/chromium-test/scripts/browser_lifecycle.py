#!/usr/bin/env python3
"""Node-local process identity and serialized provisioner lifecycle primitives."""

import contextlib
import fcntl
import json
import os
from pathlib import Path
import socket
import time
import threading
import tempfile


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


# Interactive agent runtimes whose process lifetime bounds the task that issued
# a browser request. Matching is by executable/script basename only.
AGENT_RUNTIMES = frozenset({
    "aider", "claude", "codex", "crush", "cursor-agent", "droid", "gemini",
    "goose", "grok", "hermes", "omp", "opencode", "pi", "qwen",
})
_INTERPRETERS = frozenset({"bun", "deno", "node", "nodejs", "python", "python3"})
_PROC = Path("/proc")


def _process_names(pid):
    comm = (_PROC / str(pid) / "comm").read_text().strip()
    argv = [a.decode(errors="replace") for a in (_PROC / str(pid) / "cmdline").read_bytes().split(b"\0") if a]
    names = {comm}
    if argv:
        first = os.path.basename(argv[0])
        names.add(first)
        # `node /path/to/claude` or `python3 /path/to/hermes`: the script names the runtime.
        if (first in _INTERPRETERS or first.startswith("python3.")) and len(argv) > 1 \
                and not argv[1].startswith("-"):
            script, extension = os.path.splitext(os.path.basename(argv[1]))
            names.add(script if extension in (".js", ".mjs", ".py") else script + extension)
    return names


def _parent_pid(pid):
    text = (_PROC / str(pid) / "stat").read_text()
    return int(text[text.rindex(")") + 2 :].split()[1])


def agent_supervisor_identity(start_pid=None, max_depth=32):
    """Exact identity of the nearest ancestor that is a known agent runtime.

    This is the default lifecycle owner when a request omits ``--owner-pid``:
    an agent that exits without releasing its browser leaves a terminal owner,
    which the existing exact-owner maintain/retire path already reclaims.
    A request with no such ancestor (for example a one-shot SSH command from
    another host) stays ownerless, exactly as before. Unreadable /proc state
    yields no owner rather than a guessed one.
    """
    pid = os.getppid() if start_pid is None else int(start_pid)
    for _ in range(max_depth):
        if pid <= 1:
            return None
        try:
            names = _process_names(pid)
            parent = _parent_pid(pid)
        except (OSError, ValueError, IndexError):
            return None
        if names & AGENT_RUNTIMES:
            try:
                return process_identity(pid)
            except (OSError, ValueError):
                return None
        pid = parent
    return None


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


class StartupDiagnostics:
    """Opt-in bounded metadata, never exception messages or raw browser output.

    One private snapshot per component, at most 32 events. stderr is drained but
    only the first 64 KiB is counted; no byte content is retained or persisted.
    Counting rather than regex redaction makes arbitrary secrets safe by design.
    Diagnostics are best-effort and must not change the launch result.
    """

    PHASES = frozenset({"dispatch", "publication", "registration", "launcher-entry",
                        "preparation", "adapter-import", "spawn", "adapter-bind", "pipe-ready",
                        "auth-application", "record-publication", "exec"})
    LIMIT = 65536

    def __init__(self, component, directory=None):
        assert component in {"manager", "launcher", "exec"}
        directory = directory or os.environ.get("BROWSER_STARTUP_RECEIPT_DIR")
        self.path = Path(directory) / (component + ".json") if directory else None
        self.started = time.monotonic()
        self.events = []
        self.stderr_bytes = 0
        self.lock = threading.Lock()

    def mark(self, phase, outcome="begin", error=None, returncode=None):
        if not self.path:
            return
        assert phase in self.PHASES
        assert outcome in {"begin", "ready", "failed"}
        category = ("dependency" if isinstance(error, ImportError) else
                    "timeout" if isinstance(error, TimeoutError) else
                    "connection" if isinstance(error, ConnectionError) else
                    "os-error" if isinstance(error, OSError) else
                    "unexpected" if error is not None else "none")
        with self.lock:
            if len(self.events) >= 32:
                return
            event = {"phase": phase, "outcome": outcome,
                     "elapsed_ms": max(0, round((time.monotonic() - self.started) * 1000)),
                     "error_category": category}
            if type(returncode) is int:
                event["returncode"] = returncode
            self.events.append(event)
            self._save()

    def failed(self, error, returncode=None):
        # Do not relabel a dependency failure as a later enclosing phase.
        if self.events and self.events[-1]["outcome"] != "failed":
            self.mark(self.events[-1]["phase"], "failed", error, returncode)

    def _save(self):
        temporary = None
        try:
            # No fsync on the startup critical path. Atomic rename prevents a
            # killed launcher leaving a half JSON receipt. Parent is task-owned.
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.path.parent.stat().st_mode & 0o077:
                return
            fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".receipt-")
            with os.fdopen(fd, "w") as stream:
                json.dump({"schema": 1, "started_monotonic_ms": round(self.started * 1000),
                           "events": self.events,
                           "stderr_bytes_observed": self.stderr_bytes,
                           "stderr_limit_reached": self.stderr_bytes == self.LIMIT,
                           "stderr_content": "not-collected"}, stream)
            os.replace(temporary, self.path)
        except OSError:
            pass
        finally:
            if temporary:
                with contextlib.suppress(OSError):
                    os.unlink(temporary)

    @contextlib.contextmanager
    def phase(self, phase):
        self.mark(phase)
        try:
            yield
        except BaseException as exc:
            self.mark(phase, "failed", exc)
            raise
        else:
            self.mark(phase, "ready")

    def drain_stderr(self, stream):
        """Drain without retaining bytes; only three bounded snapshot updates."""
        def drain():
            first = True
            try:
                while chunk := os.read(stream.fileno(), 4096):
                    with self.lock:
                        before = self.stderr_bytes
                        self.stderr_bytes = min(self.LIMIT, before + len(chunk))
                        if first or before < self.LIMIT == self.stderr_bytes:
                            self._save()
                        first = False
            except OSError:
                pass
            finally:
                stream.close()
                with self.lock:
                    self._save()
        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        return thread
