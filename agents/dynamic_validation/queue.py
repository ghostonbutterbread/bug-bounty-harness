"""Sequential lock and queue primitives for live validation tasks."""

from __future__ import annotations

import fcntl
import hashlib
import re
from collections import defaultdict, deque
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Callable, Iterator, TypeVar

from .models import ValidationTask

T = TypeVar("T")
LOCK_FILENAME_SANITIZER_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _lock_filename(key: str) -> str:
    slug = LOCK_FILENAME_SANITIZER_RE.sub("_", key).strip("._") or "validation-scope"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"{slug[:96]}-{digest}.lock"


class ScopedTaskQueue:
    """Process-local sequential queue keyed by target/lane/account/vm."""

    def __init__(self) -> None:
        self._guard = Lock()
        self._locks: dict[str, Lock] = {}
        self._pending: dict[str, deque[ValidationTask]] = defaultdict(deque)
        self._running: dict[str, str] = {}

    def enqueue(self, task: ValidationTask) -> int:
        key = task.queue_key()
        with self._guard:
            self._pending[key].append(task)
            return len(self._pending[key])

    def next_task(self, key: str) -> ValidationTask | None:
        with self._guard:
            queue = self._pending.get(key)
            if not queue:
                return None
            return queue.popleft()

    @contextmanager
    def acquire(
        self,
        task: ValidationTask | str,
        *,
        run_id: str | None = None,
        lock_root: Path | None = None,
    ) -> Iterator[str]:
        key = task if isinstance(task, str) else task.queue_key()
        active_run_id = run_id or (task.run_id if isinstance(task, ValidationTask) else key)
        with self._guard:
            lock = self._locks.setdefault(key, Lock())
        lock.acquire()
        lock_handle = None
        try:
            if lock_root is not None:
                lock_root.mkdir(parents=True, exist_ok=True)
                lock_path = lock_root / _lock_filename(key)
                lock_path.touch(exist_ok=True)
                lock_handle = lock_path.open("a+", encoding="utf-8")
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            with self._guard:
                self._running[key] = active_run_id
            yield key
        finally:
            with self._guard:
                self._running.pop(key, None)
            if lock_handle is not None:
                try:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                finally:
                    lock_handle.close()
            lock.release()

    def run_next(self, key: str, runner: Callable[[ValidationTask], T]) -> T | None:
        task = self.next_task(key)
        if task is None:
            return None
        with self.acquire(task):
            return runner(task)

    def status(self, key: str | None = None) -> dict[str, object]:
        with self._guard:
            keys = [key] if key else sorted(set(self._pending) | set(self._running))
            scoped: dict[str, object] = {}
            for item in keys:
                scoped[item] = {
                    "pending": len(self._pending.get(item, ())),
                    "running": self._running.get(item),
                }
            return scoped
