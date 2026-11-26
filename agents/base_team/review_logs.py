"""Keep long review-failure output out of the ledger.

When a review CLI fails, its exception text can be its whole session output
(megabytes). The full text goes to a per-user log file; the finding keeps a
short, capped ``review_error`` that ends with the log path, plus ``review_log``.

Log root: ``$BBH_LOG_DIR``, else ``$XDG_STATE_HOME/bug_bounty_harness/logs``,
else ``~/.local/state/bug_bounty_harness/logs``. Directories are created 0700
and files 0600, because review output can contain target data.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

LOG_DIR_ENV = "BBH_LOG_DIR"
APP_DIR = "bug_bounty_harness"
ENTRY_CAP = 500
SUMMARY_CAP = 2000
_REASON_CAP = 200
_COMPONENT_MAX = 80
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def log_root() -> Path:
    override = os.environ.get(LOG_DIR_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    state = os.environ.get("XDG_STATE_HOME", "").strip()
    base = Path(state).expanduser() if state else Path.home() / ".local" / "state"
    return base / APP_DIR / "logs"


def sanitize_component(value: Any) -> str:
    """One safe path component: no separators, no ``..``, no leading dot."""
    text = _UNSAFE.sub("_", str(value or "")).lstrip(".")[:_COMPONENT_MAX]
    return text if text.strip("._-") else "unknown"


def finding_log_id(finding: dict[str, Any]) -> str:
    for key in ("fid", "harness_fid"):
        value = str(finding.get(key) or "").strip()
        if value:
            return sanitize_component(value)
    basis = str(finding.get("identity") or finding.get("title") or "").strip()
    if not basis:
        return "unknown"
    return "h" + hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:12]


def encode_log_text(text: str) -> bytes:
    """Bytes written for ``text``; lone surrogates (valid in JSON strings) are kept, not replaced."""
    return text.encode("utf-8", "surrogatepass")


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _ensure_private_dir(path: Path) -> None:
    """Create ``path`` and any missing parents with mode 0700."""
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            continue
        os.chmod(directory, 0o700)
    if not path.is_dir():
        raise NotADirectoryError(str(path))


def write_log(text: str, *, category: str, program: Any, lane: Any, name: str) -> Path:
    """Atomically write ``text`` to a new 0600 file; never overwrite.

    Path: ``<root>/<category>/<program>/<lane>/<name>-<UTC>-<rand>.log``.
    """
    directory = log_root() / sanitize_component(category) / sanitize_component(program) / sanitize_component(lane)
    _ensure_private_dir(directory)
    data = encode_log_text(text)
    fd, temp_name = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".log")  # mkstemp: 0600
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        for _ in range(16):
            final = directory / f"{sanitize_component(name)}-{_utc_stamp()}-{secrets.token_hex(3)}.log"
            try:
                os.link(temp, final)  # fails if final exists: never overwrites
            except FileExistsError:
                continue
            return final
        raise FileExistsError("could not pick an unused log file name")
    finally:
        temp.unlink(missing_ok=True)


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def capped_summary(errors: Iterable[str], suffix: str) -> str:
    """Each error clipped to ENTRY_CAP; the whole value (with suffix) at most SUMMARY_CAP."""
    body = "; ".join(_clip(str(error), ENTRY_CAP) for error in errors)
    return _clip(body, SUMMARY_CAP - len(suffix)) + suffix


def _short_reason(exc: BaseException) -> str:
    return _clip(f"{type(exc).__name__}: {exc}".replace("\n", " "), _REASON_CAP)


def summarize_review_failure(
    errors: list[str],
    finding: dict[str, Any],
    *,
    program: Any = None,
    lane: Any = None,
) -> tuple[str, str | None]:
    """Log the full error text and return ``(capped review_error, log path or None)``.

    Never raises for a log-write failure: the summary then notes why the full
    log was not saved.
    """
    full_text = "; ".join(str(error) for error in errors)
    try:
        path = write_log(
            full_text,
            category="review",
            program=program or finding.get("program"),
            lane=lane or finding.get("lane"),
            name=finding_log_id(finding),
        )
    except Exception as exc:  # the review result must not depend on logging
        return capped_summary(errors, f" (full log not saved: {_short_reason(exc)})"), None
    return capped_summary(errors, f" (full log: {path})"), str(path)
