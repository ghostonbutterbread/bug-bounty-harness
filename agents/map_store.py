#!/usr/bin/env python3
"""URL-anchored surface observation store for bug bounty mapping.

Stores agent observations in a filesystem tree that mirrors the application URL
structure, indexed by ``map.jsonl`` for cross-surface queries.

Layout::

    recon/maps/
    ├── map.jsonl                     # Index: one JSONL line per observation
    ├── _app/index.md                 # App-wide overview
    ├── _app/{observation}/index.md   # App-wide observations (scope=app)
    ├── {surface}/
    │   ├── _surface/index.md         # Surface-wide overview
    │   ├── _surface/{observation}/index.md  # Surface-wide observations
    │   └── {url_path}/{observation}/index.md  # URL observations
    └── _crossref/
        └── {url_path}/index.md       # Auto-regenerated: all surfaces for this URL

CLI Usage::

    # Initialise
    python3 agents/map_store.py init --program canva --family web_bounty --lane web

    # Write an observation
    printf '%s\n' 'CSRF token `_csrf`, reflected XSS in `?redirect=`.' > /tmp/mapstore-body.md
    python3 agents/map_store.py write --program canva \\
        --url "https://app.com/login" --surface js \\
        --body-file /tmp/mapstore-body.md \\
        --tags "csrf,xss-reflected" --scope url

    # Query by URL
    python3 agents/map_store.py query --program canva \\
        --url "app.com/login"

    # Query by URL + surface filter
    python3 agents/map_store.py query --program canva \\
        --url "app.com/login" --surface xss

    # Archive a stale gadget/note after current testing proves it no longer works
    python3 agents/map_store.py update-status --program canva \\
        --path "xss/app.com_s_login/old-gadget/index.md" \\
        --status archived \\
        --reason "Retested current login flow twice; sink no longer renders."

    # Rebuild cross-reference views
    python3 agents/map_store.py rebuild-crossref --program canva
"""

from __future__ import annotations

import argparse
import fcntl
import json
import re
import shutil
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Reuse bounty_notes normalisation so URLs match across systems.
try:
    from agents.bounty_notes import normalize_url
except ImportError:
    def normalize_url(value: str) -> str:
        value = value.strip()
        if not value:
            return value
        parse_value = value if "://" in value else f"https://{value}"
        parsed = urlsplit(parse_value)
        host = parsed.netloc.lower()
        path = re.sub(r"/+", "/", parsed.path or "/")
        if path != "/":
            path = path.rstrip("/")
        query_pairs = sorted(
            (key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True)
        )
        query = "&".join(f"{key}={val}" if val else key for key, val in query_pairs)
        return urlunsplit((parsed.scheme.lower() or "https", host, path, query, ""))

from agents.storage_resolver import ensure_layout, resolve_storage  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAP_DIRNAME = "maps"
MAP_INDEX = "map.jsonl"
LOCK_FILE = ".mapstore.lock"
APP_SCOPE = "app"
SURFACE_SCOPE = "surface"
URL_SCOPE = "url"
VALID_SCOPES = {APP_SCOPE, SURFACE_SCOPE, URL_SCOPE}
ACTIVE_STATUS = "active"
CANDIDATE_STATUS = "candidate"
FAILED_STATUS = "failed"
NEEDS_RECHECK_STATUS = "needs_recheck"
STALE_STATUS = "stale"
ARCHIVED_STATUS = "archived"
VALID_STATUSES = {
    ACTIVE_STATUS,
    CANDIDATE_STATUS,
    FAILED_STATUS,
    NEEDS_RECHECK_STATUS,
    STALE_STATUS,
    ARCHIVED_STATUS,
}
CROSSREF_DIR = "_crossref"
APP_DIR = "_app"
SURFACE_INDEX_DIR = "_surface"
OBSERVATION_FILE = "index.md"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time_filter(value: str) -> datetime:
    """Parse an ISO/date/relative time filter into an aware UTC datetime."""
    value = value.strip()
    if not value:
        raise ValueError("time filter cannot be empty")

    relative = re.fullmatch(r"(\d+)([hdw])", value.lower())
    if relative:
        amount = int(relative.group(1))
        unit = relative.group(2)
        if unit == "h":
            delta = timedelta(hours=amount)
        elif unit == "d":
            delta = timedelta(days=amount)
        else:
            delta = timedelta(weeks=amount)
        return utc_now() - delta

    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        parsed = datetime.fromisoformat(value)
    else:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _entry_time(entry: dict) -> datetime | None:
    timestamp = str(entry.get("timestamp") or "").strip()
    if not timestamp:
        return None
    try:
        return parse_time_filter(timestamp)
    except ValueError:
        return None


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(text, encoding="utf-8")
    tmp_path.replace(path)


def slugify(value: str, *, fallback: str = "observation") -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = value.strip("-")
    return value or fallback


def observation_slug(
    *,
    surface: str,
    scope: str,
    title: str = "",
    run_id: str | None = None,
    tags: list[str] | None = None,
) -> str:
    """Build a stable readable slug for observation files."""
    descriptor = title or run_id or " ".join(tags or []) or "observation"
    pieces = [descriptor] if scope == URL_SCOPE else [surface, descriptor]
    if title and run_id:
        pieces.append(run_id)
    return slugify(" ".join(piece for piece in pieces if piece), fallback="observation")


def normalize_status(value: str | None, *, default: str = ACTIVE_STATUS) -> str:
    """Normalize a lifecycle status from CLI/index input."""
    status = slugify(value or default, fallback=default).replace("-", "_")
    aliases = {
        "fail": FAILED_STATUS,
        "failed_once": FAILED_STATUS,
        "recheck": NEEDS_RECHECK_STATUS,
        "needs-recheck": NEEDS_RECHECK_STATUS,
        "archive": ARCHIVED_STATUS,
    }
    status = aliases.get(status, status)
    if status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid status: {value!r}. Use one of: {', '.join(sorted(VALID_STATUSES))}"
        )
    return status


def _entry_status(entry: dict) -> str:
    try:
        return normalize_status(str(entry.get("status") or ACTIVE_STATUS))
    except ValueError:
        return ACTIVE_STATUS


def _format_status_note(*, timestamp: str, status: str, agent: str, reason: str) -> str:
    reason = reason.strip() or "No reason recorded."
    return (
        "\n\n## Lifecycle Update\n\n"
        f"- {timestamp}: status -> `{status}` by `{agent}`\n"
        f"  Reason: {reason}\n"
    )


# ---------------------------------------------------------------------------
# URL → filesystem path
# ---------------------------------------------------------------------------

# Characters that are invalid or problematic in filesystem paths.
_PATH_ESCAPE_TABLE = str.maketrans({
    "/":  "_s_",
    "\\": "_b_",
    ":":  "_c_",
    "*":  "_a_",
    "?":  "_q_",
    '"':  "_dq_",
    "<":  "_lt_",
    ">":  "_gt_",
    "|":  "_pi_",
    "#":  "_hash_",
})


def url_to_dirname(url: str) -> str:
    """Convert a URL into a safe filesystem directory name.

    ``https://app.com/login?next=/admin`` → ``app.com/login_q_next_s__admin``
    """
    if not url:
        return "_root"
    # Strip scheme
    cleaned = re.sub(r"^https?://", "", url)
    # Strip trailing slash for dir name
    cleaned = cleaned.rstrip("/")
    # Escape remaining special chars
    cleaned = cleaned.translate(_PATH_ESCAPE_TABLE)
    # Collapse multiple underscores
    cleaned = re.sub(r"_+", "_", cleaned)
    cleaned = cleaned.strip("_")
    return cleaned or "_root"


def _decode_dirname(dirname: str) -> str:
    """Reverse url_to_dirname for display (best-effort)."""
    reverse_table = {v: k for k, v in _PATH_ESCAPE_TABLE.items()}
    result = dirname
    for escaped, original in reverse_table.items():
        result = result.replace(escaped, original)
    return result


# ---------------------------------------------------------------------------
# MapStore
# ---------------------------------------------------------------------------


class MapStore:
    """Read/write surface observations indexed by URL and surface type."""

    def __init__(
        self,
        program: str,
        *,
        family: str = "web_bounty",
        lane: str = "web",
        root: str | None = None,
        create: bool = True,
    ) -> None:
        self._program = program
        self._family = family
        self._lane = lane
        self._layout = resolve_storage(
            program, family=family, lane=lane, root_override=root, create=create
        )
        if create:
            ensure_layout(self._layout)
        self._maps_root = self._layout.recon_root / MAP_DIRNAME

    # -- properties ----------------------------------------------------------

    @property
    def maps_root(self) -> Path:
        return self._maps_root

    @property
    def index_path(self) -> Path:
        return self._maps_root / MAP_INDEX

    @property
    def lock_path(self) -> Path:
        return self._maps_root / LOCK_FILE

    @property
    def program(self) -> str:
        return self._program

    # -- init ----------------------------------------------------------------

    @contextmanager
    def _locked(self):
        """Serialize MapStore writers across concurrent agent processes."""
        self._maps_root.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def init(self) -> Path:
        """Create the maps directory structure. Idempotent."""
        self._maps_root.mkdir(parents=True, exist_ok=True)
        with self._locked():
            # App-wide
            (self._maps_root / APP_DIR).mkdir(parents=True, exist_ok=True)
            app_index = self._maps_root / APP_DIR / OBSERVATION_FILE
            if not app_index.exists():
                _atomic_write_text(
                    app_index,
                    f"# App-Wide: {self._program}\n\n"
                    "Observations that apply to the entire application.\n",
                )
            # Index file
            if not self.index_path.exists():
                _atomic_write_text(self.index_path, "")
            # Crossref dir
            (self._maps_root / CROSSREF_DIR).mkdir(parents=True, exist_ok=True)
        return self._maps_root

    # -- index read/write ----------------------------------------------------

    def _read_index(self) -> list[dict]:
        if not self.index_path.exists():
            return []
        entries: list[dict] = []
        with self.index_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if isinstance(entry, dict):
                        entries.append(entry)
                except json.JSONDecodeError:
                    continue
        return entries

    def _write_index(self, entries: list[dict]) -> None:
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        content = "".join(json.dumps(entry, ensure_ascii=False) + "\n" for entry in entries)
        _atomic_write_text(self.index_path, content)

    def _upsert_entry(self, entry: dict) -> None:
        entries = self._read_index()
        # Replace existing entry with same path
        path_key = entry.get("path", "")
        entries = [e for e in entries if e.get("path") != path_key]
        entries.append(entry)
        # Sort newest first
        entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        self._write_index(entries)

    def _observation_dir(
        self,
        *,
        scope: str,
        surface: str,
        url: str = "",
        title: str = "",
        run_id: str | None = None,
        tags: list[str] | None = None,
    ) -> str:
        """Return a collision-free directory for an observation."""
        slug = observation_slug(
            surface=surface, scope=scope, title=title, run_id=run_id, tags=tags
        )
        if scope == APP_SCOPE:
            base = f"{APP_DIR}/{slug}"
        elif scope == SURFACE_SCOPE:
            base = f"{surface}/{SURFACE_INDEX_DIR}/{slug}"
        else:
            url_dir = url_to_dirname(url)
            base = f"{surface}/{url_dir}/{slug}"

        candidate = base
        suffix = 2
        while (self._maps_root / candidate / OBSERVATION_FILE).exists():
            candidate = f"{base}-{suffix}"
            suffix += 1
        return candidate

    def _pointer_heading(self, *, scope: str, surface: str, url: str = "") -> str:
        if scope == APP_SCOPE:
            return f"App-Wide: {self._program}"
        if scope == SURFACE_SCOPE:
            return f"Surface-Wide: {surface}"
        return f"Observations: {normalize_url(url) if url else surface}"

    def _refresh_pointer_index(self, directory: Path, heading: str) -> None:
        """Write a small index.md that points agents at child observations."""
        directory.mkdir(parents=True, exist_ok=True)
        status_by_path = {
            entry.get("path", ""): _entry_status(entry)
            for entry in self._read_index()
        }
        lines = [
            f"# {heading}",
            "",
            f"Generated: {iso_now()}",
            "",
            "## Observations",
        ]
        children = sorted(path for path in directory.iterdir() if path.is_dir())
        if not children:
            lines.append("")
            lines.append("(none yet)")
        for child in children:
            obs_file = child / OBSERVATION_FILE
            if not obs_file.exists():
                continue
            rel_path = obs_file.relative_to(self._maps_root).as_posix()
            if status_by_path.get(rel_path) == ARCHIVED_STATUS:
                continue
            title = child.name
            try:
                first_line = obs_file.read_text(encoding="utf-8").splitlines()[0]
                title = first_line.lstrip("# ").strip() or title
            except (IndexError, OSError, UnicodeDecodeError):
                pass
            lines.append(f"- [{title}]({child.name}/{OBSERVATION_FILE})")
        if len(lines) == 5:
            lines.append("")
            lines.append("(none yet)")
        _atomic_write_text(directory / OBSERVATION_FILE, "\n".join(lines).rstrip() + "\n")

    # -- write observation ---------------------------------------------------

    def write(
        self,
        *,
        url: str = "",
        surface: str,
        body: str,
        scope: str = URL_SCOPE,
        tags: list[str] | None = None,
        crossfamily: list[str] | None = None,
        agent: str = "ghost",
        run_id: str | None = None,
        title: str = "",
        status: str = ACTIVE_STATUS,
    ) -> Path:
        """Write a surface observation and index it.

        Args:
            url: Normalised URL (empty for app-wide or surface-wide).
            surface: Surface type (js, xss, api, auth, ssrf, etc.).
            body: Markdown observation content.
            scope: ``app``, ``surface``, or ``url``.
            tags: Lowercase tags for filtering and cross-relevance.
            crossfamily: List of ``family/program/lane`` strings this
                observation is relevant to outside its own family.
            agent: Agent name.
            run_id: Run identifier.
            title: Observation title for the markdown header and index.
            status: Lifecycle status for opportunistic memory hygiene.

        Returns:
            Path to the written observation file.
        """
        if scope not in VALID_SCOPES:
            raise ValueError(f"Invalid scope: {scope!r}. Use: {VALID_SCOPES}")

        tags = tags or []
        crossfamily = crossfamily or []
        status = normalize_status(status)

        with self._locked():
            return self._write_observation_unlocked(
                url=url,
                surface=surface,
                body=body,
                scope=scope,
                tags=tags,
                crossfamily=crossfamily,
                agent=agent,
                run_id=run_id,
                title=title,
                status=status,
            )

    def _write_observation_unlocked(
        self,
        *,
        url: str,
        surface: str,
        body: str,
        scope: str,
        tags: list[str],
        crossfamily: list[str],
        agent: str,
        run_id: str | None,
        title: str,
        status: str,
    ) -> Path:
        # Determine file path
        if scope == APP_SCOPE:
            rel_dir = self._observation_dir(
                scope=scope,
                surface=surface,
                title=title,
                run_id=run_id,
                tags=tags,
            )
        elif scope == SURFACE_SCOPE:
            rel_dir = self._observation_dir(
                scope=scope,
                surface=surface,
                title=title,
                run_id=run_id,
                tags=tags,
            )
        else:
            rel_dir = self._observation_dir(
                scope=scope,
                surface=surface,
                url=url,
                title=title,
                run_id=run_id,
                tags=tags,
            )

        obs_dir = self._maps_root / rel_dir
        obs_dir.mkdir(parents=True, exist_ok=True)
        obs_path = obs_dir / OBSERVATION_FILE
        timestamp = iso_now()

        # Build markdown content
        title_display = title or (f"{surface}/{url_to_dirname(url)}" if url else f"{surface}/{scope}")
        header = [
            f"# {title_display}",
            "",
            f"Surface: {surface}",
            f"Scope: {scope}",
            f"Status: {status}",
        ]
        if url:
            header.append(f"URL: {url}")
        if tags:
            header.append(f"Tags: {' '.join('#' + t for t in tags)}")
        header.extend([
            f"Agent: {agent}",
            f"Run: {run_id or 'manual'}",
            f"Updated: {timestamp}",
            "",
        ])

        _atomic_write_text(obs_path, "\n".join(header) + body.rstrip() + "\n")

        # Upsert index entry
        entry: dict[str, Any] = {
            "url": normalize_url(url) if url else "",
            "surface": slugify(surface),
            "scope": scope,
            "path": obs_path.relative_to(self._maps_root).as_posix(),
            "tags": sorted({slugify(t) for t in tags}),
            "crossfamily": sorted(set(crossfamily)),
            "timestamp": timestamp,
            "agent": agent,
            "run_id": run_id or "",
            "title": title_display,
            "status": status,
            "status_updated": timestamp,
            "status_agent": agent,
            "status_reason": "initial write",
        }
        self._upsert_entry(entry)
        self._refresh_pointer_index(
            obs_dir.parent,
            self._pointer_heading(scope=scope, surface=surface, url=url),
        )

        return obs_path

    # -- update observation lifecycle ---------------------------------------

    def update_status(
        self,
        *,
        path: str,
        status: str,
        reason: str,
        agent: str = "ghost",
    ) -> dict:
        """Update the lifecycle status for an existing observation.

        Status changes are evidence-backed annotations from agents that tried a
        gadget/note or saw current app behavior change. They do not delete the
        observation; archived entries remain queryable with explicit filters.
        """
        status = normalize_status(status)
        reason = reason.strip()
        if not reason:
            raise ValueError("status update reason is required")

        with self._locked():
            entries = self._read_index()
            match: dict | None = None
            for entry in entries:
                if entry.get("path") == path:
                    match = entry
                    break
            if match is None:
                raise ValueError(f"No MapStore entry found for path: {path}")

            obs_path = self._maps_root / path
            if not obs_path.exists():
                raise ValueError(f"Observation file is missing: {path}")

            timestamp = iso_now()
            match["status"] = status
            match["status_updated"] = timestamp
            match["status_agent"] = agent
            match["status_reason"] = reason
            history = match.get("status_history")
            if not isinstance(history, list):
                history = []
            history.append({
                "timestamp": timestamp,
                "status": status,
                "agent": agent,
                "reason": reason,
            })
            match["status_history"] = history
            entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
            self._write_index(entries)

            content = obs_path.read_text(encoding="utf-8")
            lines = content.splitlines()
            replaced = False
            for idx, line in enumerate(lines):
                if line.startswith("Status: "):
                    lines[idx] = f"Status: {status}"
                    replaced = True
                    break
            if not replaced:
                insert_at = 4 if len(lines) >= 4 else len(lines)
                lines.insert(insert_at, f"Status: {status}")
            content = "\n".join(lines).rstrip() + _format_status_note(
                timestamp=timestamp,
                status=status,
                agent=agent,
                reason=reason,
            )
            _atomic_write_text(obs_path, content.rstrip() + "\n")
            self._refresh_pointer_index(
                obs_path.parent.parent,
                self._pointer_heading(
                    scope=str(match.get("scope") or URL_SCOPE),
                    surface=str(match.get("surface") or ""),
                    url=str(match.get("url") or ""),
                ),
            )

            return dict(match)

    # -- query ---------------------------------------------------------------

    def query(
        self,
        *,
        url: str | None = None,
        surface: str | None = None,
        scope: str | None = None,
        tags: list[str] | None = None,
        statuses: list[str] | None = None,
        include_archived: bool = False,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
        cross_family: bool = False,
        cross_family_entries: list[dict] | None = None,
    ) -> list[dict]:
        """Query observations from the index.

        Args:
            url: Normalised URL to match (fuzzy: matches if the index entry
                URL contains this value, or vice versa).
            surface: Filter to this surface type. Also includes entries
                tagged ``{surface}-relevant`` from other surfaces.
            scope: Filter to ``app``, ``surface``, or ``url``.
            tags: Filter to entries that contain every listed tag.
            statuses: Filter to entries with any listed lifecycle status.
            include_archived: Include archived entries when no explicit status
                filter is provided.
            since: Include observations at or after this UTC timestamp.
            until: Include observations at or before this UTC timestamp.
            limit: Maximum number of observations to return after sorting.
            cross_family: When True, also searches other family maps
                that have ``crossfamily`` pointing to this one.
            cross_family_entries: Pre-fetched cross-family entries (used
                internally when the query tool gathers them in advance).

        Returns:
            List of matching index entries, newest first.
        """
        entries = self._read_index()
        if cross_family_entries:
            entries = entries + cross_family_entries
        results: list[dict] = []
        required_tags = {slugify(tag) for tag in tags or [] if tag}
        required_statuses = {
            normalize_status(status) for status in statuses or [] if status
        }

        if url:
            normalized = normalize_url(url)
            # Strip trailing slash for matching
            norm_no_slash = normalized.rstrip("/") if normalized != "/" else normalized

        for entry in entries:
            entry_url = entry.get("url", "")
            entry_surface = entry.get("surface", "")
            entry_scope = entry.get("scope", "")
            entry_tags = entry.get("tags", [])
            entry_status = _entry_status(entry)
            entry_time = _entry_time(entry)
            entry_tag_set = {slugify(tag) for tag in entry_tags}

            # --- URL matching -------------------------------------------------
            if url and entry_scope == URL_SCOPE:
                # Normalised fuzzy match
                e_norm = normalize_url(entry_url) if entry_url else ""
                e_no_slash = e_norm.rstrip("/") if e_norm != "/" else e_norm
                if norm_no_slash != e_no_slash:
                    continue
            elif url and entry_scope != URL_SCOPE:
                # App-wide and surface-wide always pass URL filter
                pass

            # --- Scope filtering ----------------------------------------------
            if scope and entry_scope != scope:
                continue

            # --- Timestamp filtering -----------------------------------------
            if since or until:
                if entry_time is None:
                    continue
                if since and entry_time < since:
                    continue
                if until and entry_time > until:
                    continue

            # --- Tag filtering ------------------------------------------------
            if required_tags and not required_tags.issubset(entry_tag_set):
                continue

            # --- Lifecycle status filtering ---------------------------------
            if required_statuses:
                if entry_status not in required_statuses:
                    continue
            elif entry_status == ARCHIVED_STATUS and not include_archived:
                continue

            # --- Surface filtering --------------------------------------------
            if surface:
                # Same surface → always include
                same_surface = entry_surface == surface
                # Cross-surface relevance: explicit tag or prefix match
                # "xss-relevant" or "xss-reflected" both match for surface="xss"
                cross_relevant = any(
                    tag == f"{surface}-relevant" or tag.startswith(f"{surface}-")
                    for tag in entry_tags
                )
                # App-wide entries always included
                app_wide = entry_scope == APP_SCOPE

                if not (same_surface or cross_relevant or app_wide):
                    continue

            results.append(entry)

        # Deduplicate by store-relative identity. Cross-family entries can have
        # the same relative path as local entries, so include their source.
        seen: set[tuple[str, str]] = set()
        deduped: list[dict] = []
        for entry in results:
            path = entry.get("path", "")
            source = entry.get("_crossfamily_source") or "local"
            identity = (source, path)
            if identity not in seen:
                seen.add(identity)
                deduped.append(entry)

        deduped.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        if limit is not None and limit >= 0:
            deduped = deduped[:limit]
        return deduped

    # -- read observation file ------------------------------------------------

    def read_obs(self, path: str) -> str | None:
        """Read an observation file by its relative path from map.jsonl."""
        full = self._maps_root / path
        if not full.exists():
            return None
        return full.read_text(encoding="utf-8")

    # -- rebuild crossref ----------------------------------------------------

    def rebuild_crossref(self, cross_family_entries: list[dict] | None = None) -> int:
        """Regenerate ``_crossref/`` aggregated views from ``map.jsonl``.

        Returns the number of crossref files written.
        """
        entries = self._read_index()
        if cross_family_entries:
            entries = entries + cross_family_entries
        entries = [
            entry for entry in entries
            if _entry_status(entry) != ARCHIVED_STATUS
        ]

        # Group by URL
        by_url: dict[str, list[dict]] = {}
        for entry in entries:
            entry_url = entry.get("url", "")
            if not entry_url:
                continue
            normalized = normalize_url(entry_url)
            by_url.setdefault(normalized, []).append(entry)

        crossref_root = self._maps_root / CROSSREF_DIR
        crossref_root.mkdir(parents=True, exist_ok=True)

        count = 0
        for url_val, url_entries in by_url.items():
            url_dir = url_to_dirname(url_val)
            out_dir = crossref_root / url_dir
            out_dir.mkdir(parents=True, exist_ok=True)

            # Group by surface
            by_surface: dict[str, list[dict]] = {}
            for entry in url_entries:
                surface = entry.get("surface", "unknown")
                by_surface.setdefault(surface, []).append(entry)

            lines = [
                f"# Observations: {url_val}",
                "",
                f"Generated: {iso_now()}",
                f"Surfaces: {', '.join(sorted(by_surface))}",
                "",
            ]

            # Include app-wide entries
            app_entries = [e for e in entries if e.get("scope") == APP_SCOPE]
            if app_entries:
                lines.append("## App-Wide")
                for entry in app_entries:
                    lines.append(
                        f"- [{entry.get('title', entry.get('path', ''))}]"
                        f"(../../{entry.get('path', '')}) "
                        f"`{entry.get('timestamp', '')}`"
                    )
                lines.append("")

            for surface_name in sorted(by_surface):
                lines.append(f"## {surface_name}")
                for entry in by_surface[surface_name]:
                    title = entry.get("title", entry.get("path", ""))
                    path = entry.get("path", "")
                    ts = entry.get("timestamp", "")
                    tags = " ".join(
                        f"`#{t}`" for t in entry.get("tags", [])
                    )
                    source_family = ""
                    if entry.get("crossfamily"):
                        source_family = (
                            f" [→]{' '.join(entry['crossfamily'])}"
                        )
                    lines.append(
                        f"- [{title}](../../{path}) {tags} `{ts}`{source_family}"
                    )
                lines.append("")

            (out_dir / OBSERVATION_FILE).write_text(
                "\n".join(lines).rstrip() + "\n", encoding="utf-8"
            )
            count += 1

        return count

    # -- cross-family resolution ---------------------------------------------

    def find_crossfamily_entries(
        self, surface: str | None = None
    ) -> list[dict]:
        """Search other family maps that point TO this family via crossfamily.

        This is used by the query tool to gather observations from other
        families (e.g., binaries → web_bounty).
        """
        results: list[dict] = []
        this_key = f"{self._family}/{self._program}/{self._lane}"

        # Only search if there are other families — for now, check common
        # sibling family roots under the shared base.
        shared_base = self._layout.base_root
        for family_name in ["web_bounty", "binaries"]:
            if family_name == self._family:
                continue
            family_root = Path(shared_base) / family_name / self._program
            if not family_root.exists():
                continue

            # Try each lane
            for lane_dir in family_root.iterdir():
                if not lane_dir.is_dir():
                    continue
                lane = lane_dir.name
                maps_index = lane_dir / "recon" / MAP_DIRNAME / MAP_INDEX
                if not maps_index.exists():
                    continue

                try:
                    with maps_index.open("r", encoding="utf-8") as fh:
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            cf = entry.get("crossfamily", [])
                            if this_key in cf:
                                # Tag with source family for display
                                entry["_crossfamily_source"] = (
                                    f"{family_name}/{lane}"
                                )
                                results.append(entry)
                except Exception:
                    continue

        if surface:
            results = [
                e for e in results
                if e.get("surface") == surface
                or f"{surface}-relevant" in e.get("tags", [])
                or e.get("scope") == APP_SCOPE
            ]

        return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--program", required=True)
        p.add_argument("--family", default="web_bounty")
        p.add_argument("--lane", default="web")
        p.add_argument("--root", default=None)

    # init
    init_p = sub.add_parser("init", help="Create maps directory structure")
    _add_common(init_p)

    # write
    write_p = sub.add_parser("write", help="Write a surface observation")
    _add_common(write_p)
    write_p.add_argument("--url", default="", help="Normalised URL (empty for app/surface-wide)")
    write_p.add_argument("--surface", required=True, help="Surface type: js, xss, auth, etc.")
    body_group = write_p.add_mutually_exclusive_group(required=True)
    body_group.add_argument("--body", help="Markdown observation content. Prefer --body-file or --body-stdin for content with shell metacharacters.")
    body_group.add_argument("--body-file", help="Read Markdown observation content from file")
    body_group.add_argument("--body-stdin", action="store_true", help="Read Markdown observation content from stdin")
    write_p.add_argument("--scope", default=URL_SCOPE, choices=sorted(VALID_SCOPES))
    write_p.add_argument("--tags", default="", help="Comma-separated tags")
    write_p.add_argument("--crossfamily", default="", help="Comma-separated family/program/lane refs")
    write_p.add_argument("--agent", default="ghost")
    write_p.add_argument("--run-id", default=None)
    write_p.add_argument("--title", default="")
    write_p.add_argument("--status", default=ACTIVE_STATUS, choices=sorted(VALID_STATUSES), help="Lifecycle status for this observation")

    # query
    query_p = sub.add_parser("query", help="Query observations by URL and/or surface")
    _add_common(query_p)
    query_p.add_argument("--url", default=None, help="URL to query")
    query_p.add_argument("--surface", default=None, help="Surface filter")
    query_p.add_argument("--scope", default=None, choices=sorted(VALID_SCOPES))
    query_p.add_argument("--tags", default="", help="Comma-separated required tags")
    query_p.add_argument("--status", default="", help="Comma-separated lifecycle statuses to include")
    query_p.add_argument("--include-archived", action="store_true", help="Include archived entries when no explicit --status filter is set")
    query_p.add_argument("--since", default=None, help="Only show observations since ISO time/date or relative value like 24h, 7d, 2w")
    query_p.add_argument("--until", default=None, help="Only show observations until ISO time/date or relative value like 24h, 7d, 2w")
    query_p.add_argument("--recent-days", type=int, default=None, help="Shortcut for --since now minus N days")
    query_p.add_argument("--limit", type=int, default=None, help="Maximum observations to show")
    query_p.add_argument("--cross-family", action="store_true", help="Include cross-family observations")
    query_p.add_argument("--json", action="store_true", help="Output as JSON")

    # update-status
    status_p = sub.add_parser("update-status", help="Update an observation lifecycle status")
    _add_common(status_p)
    status_p.add_argument("--path", required=True, help="MapStore-relative observation path from query output")
    status_p.add_argument("--status", required=True, choices=sorted(VALID_STATUSES))
    status_p.add_argument("--reason", required=True, help="Evidence-backed reason for the status change")
    status_p.add_argument("--agent", default="ghost")
    status_p.add_argument("--json", action="store_true", help="Output updated index entry as JSON")

    # rebuild-crossref
    xref_p = sub.add_parser("rebuild-crossref", help="Regenerate _crossref/ views")
    _add_common(xref_p)

    # migrate-workspace
    mig_p = sub.add_parser("migrate-workspace", help="Scan workdir for agent notes and migrate to map store")
    mig_p.add_argument("--source-dir", default="~/workdir/working", help="Source directory to scan (default: ~/workdir/working)")
    mig_p.add_argument("--program", default=None, help="Limit to specific program (auto-detected if omitted)")
    mig_p.add_argument("--family", default="web_bounty", help="Storage family")
    mig_p.add_argument("--lane", default="web", help="Storage lane")
    mig_p.add_argument("--root", default=None)
    mig_p.add_argument("--dry-run", action="store_true", help="Show what would happen without writing")
    mig_p.add_argument("--no-move", action="store_true", help="Don't move source files, just index them")

    # cleanup-profiles
    cln_p = sub.add_parser("cleanup-profiles", help="Remove chromium profiles from working directories")
    cln_p.add_argument("--program", required=True)
    cln_p.add_argument("--family", default="web_bounty")
    cln_p.add_argument("--lane", default="web")
    cln_p.add_argument("--root", default=None)
    cln_p.add_argument("--dry-run", action="store_true", help="Show what would be deleted without deleting")

    return parser


def _run_init(store: MapStore) -> int:
    root = store.init()
    print(str(root))
    return 0


def _run_write(store: MapStore, args: argparse.Namespace) -> int:
    body = args.body
    if args.body_file:
        body = Path(args.body_file).read_text(encoding="utf-8").strip()
    elif args.body_stdin:
        body = sys.stdin.read().strip()
    tags = [t.strip() for t in args.tags.split(",") if t.strip()]
    crossfamily = [c.strip() for c in args.crossfamily.split(",") if c.strip()]
    path = store.write(
        url=args.url,
        surface=args.surface,
        body=body,
        scope=args.scope,
        tags=tags,
        crossfamily=crossfamily,
        agent=args.agent,
        run_id=args.run_id,
        title=args.title,
        status=args.status,
    )
    print(str(path))
    return 0


def _run_query(store: MapStore, args: argparse.Namespace) -> int:
    cross_entries: list[dict] | None = None
    if args.cross_family:
        cross_entries = store.find_crossfamily_entries(surface=args.surface)

    since = None
    until = None
    if args.recent_days is not None:
        since = utc_now() - timedelta(days=args.recent_days)
    if args.since:
        since = parse_time_filter(args.since)
    if args.until:
        until = parse_time_filter(args.until)

    results = store.query(
        url=args.url,
        surface=args.surface,
        scope=args.scope,
        tags=[t.strip() for t in args.tags.split(",") if t.strip()],
        statuses=[s.strip() for s in args.status.split(",") if s.strip()],
        include_archived=args.include_archived,
        since=since,
        until=until,
        limit=args.limit,
        cross_family=args.cross_family,
        cross_family_entries=cross_entries,
    )

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        if not results:
            print("(no observations found)")
            return 0
        for entry in results:
            ts = entry.get("timestamp", "")
            surface_name = entry.get("surface", "")
            scope = entry.get("scope", "")
            url_val = entry.get("url", "") or "(app-wide)"
            title = entry.get("title", "")
            path = entry.get("path", "")
            tags = ", ".join(entry.get("tags", []))
            status = _entry_status(entry)
            cf_source = entry.get("_crossfamily_source", "")

            print(f"{ts} | {surface_name}/{scope} | {title}")
            print(f"  Status: {status}")
            print(f"  URL: {url_val}")
            print(f"  Path: {path}")
            if tags:
                print(f"  Tags: {tags}")
            if cf_source:
                print(f"  From: {cf_source} (cross-family)")
            print()

    return 0


def _run_update_status(store: MapStore, args: argparse.Namespace) -> int:
    entry = store.update_status(
        path=args.path,
        status=args.status,
        reason=args.reason,
        agent=args.agent,
    )
    if args.json:
        print(json.dumps(entry, indent=2, sort_keys=True))
    else:
        print(f"{entry.get('path')} -> {entry.get('status')}")
    return 0


def _run_rebuild_crossref(store: MapStore, args: argparse.Namespace) -> int:
    cross_entries = store.find_crossfamily_entries()
    count = store.rebuild_crossref(cross_family_entries=cross_entries)
    print(f"Regenerated {count} crossref views")
    return 0


# ---------------------------------------------------------------------------
# Migration helpers
# ---------------------------------------------------------------------------

_PROGRAM_MAP: dict[str, str | None] = {
    "canva": "canva", "flourish": "flourish", "portswigger": "portswigger",
    "juice": "juice-shop", "hacky": "hacky", "csv": "flourish",
    "tracking": "canva", "access": "canva", "idor": "canva",
    "ssrf": "canva", "dompurify": "canva", "human": None,
}

_SURFACE_FROM_DIR: dict[str, str] = {
    "api": "api", "xss": "xss", "ssrf": "ssrf", "js": "js",
    "javascript": "js", "sourcesink": "js", "auth": "auth",
    "idor": "idor", "subdomain": "recon", "brainstorm": "recon",
    "flow": "api", "integration": "api", "brand": "js",
    "geo": "recon", "invoice": "api", "partner": "recon",
    "tracking": "recon", "deepdive": "recon", "newsurface": "recon",
    "recovery": "auth", "egress": "recon", "magicmedia": "recon",
    "mcp": "recon", "csv": "api", "design": "api",
    "apps": "api", "fuzz": "fuzz", "controls": "js",
    "enum": "recon", "map": "recon", "tester": "api",
    "explore": "recon", "seeds": "recon", "active": "recon",
}

_URL_RE = re.compile(r"https?://[^\s)\]`\"<>]+")


def _parse_program(dirname: str) -> str | None:
    first = dirname.split("-")[0]
    return _PROGRAM_MAP.get(first)


def _infer_surface(dirname: str, _content: str = "") -> str:
    parts = dirname.split("-")
    for part in parts:
        if part in _SURFACE_FROM_DIR:
            return _SURFACE_FROM_DIR[part]
    return "recon"


def _extract_urls(text: str) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for match in _URL_RE.finditer(text):
        raw = match.group(0).rstrip(".;,:'\"")
        normalized = normalize_url(raw)
        if normalized and normalized not in seen:
            seen.add(normalized)
            urls.append(raw if "://" in raw else normalized)
    return urls


def _infer_tags(dirname: str, content: str, urls: list[str]) -> list[str]:
    tags: set[str] = set()
    # Keywords from directory name
    for part in dirname.split("-"):
        if part not in _PROGRAM_MAP and part not in _SURFACE_FROM_DIR and len(part) > 2:
            tags.add(slugify(part))
    # Vuln-class mentions in content
    lower = content.lower()
    if "xss" in lower:
        tags.add("xss-reflected" if "reflected" in lower else "xss")
    if "ssrf" in lower:
        tags.add("ssrf")
    if "idor" in lower:
        tags.add("idor")
    if "csrf" in lower:
        tags.add("csrf")
    if "csp" in lower:
        tags.add("csp")
    if "jwt" in lower or "bearer" in lower:
        tags.add("jwt")
    if "oauth" in lower:
        tags.add("oauth")
    if "rate" in lower and ("limit" in lower or "throttl" in lower):
        tags.add("rate-limit")
    return sorted(tags)


def _run_migrate_workspace(args: argparse.Namespace) -> int:
    source_dir = Path(args.source_dir).expanduser().resolve()
    if not source_dir.exists():
        raise SystemExit(f"Source directory does not exist: {source_dir}")

    migrated = 0
    skipped = 0
    moved = 0

    for subdir in sorted(source_dir.iterdir()):
        if not subdir.is_dir():
            continue
        notes_file = subdir / "notes.md"
        if not notes_file.exists():
            continue

        dirname = subdir.name
        program = args.program or _parse_program(dirname)
        if not program:
            print(f"SKIP {dirname}: cannot determine program")
            skipped += 1
            continue

        print(f"\n{'[DRY RUN] ' if args.dry_run else ''}MIGRATE {dirname} → program={program}")

        content = notes_file.read_text(encoding="utf-8")
        urls = _extract_urls(content)
        print(f"  URLs: {len(urls)}")
        for u in urls[:5]:
            print(f"    {u}")
        if len(urls) > 5:
            print(f"    ... and {len(urls) - 5} more")

        if args.dry_run:
            migrated += 1
            continue

        surface = _infer_surface(dirname, content)
        print(f"  Surface: {surface}")

        primary_url = urls[0] if urls else ""
        tags = _infer_tags(dirname, content, urls)
        # Add extracted hostnames as tags for cross-referencing
        for url in urls:
            try:
                host = urlsplit(url).netloc.lower()
                if host and host not in tags:
                    tags.append(slugify(host))
            except Exception:
                pass

        store = MapStore(
            program, family=args.family, lane=args.lane, root=args.root
        )
        store.init()

        store.write(
            url=primary_url,
            surface=surface,
            body=content,
            tags=tags,
            agent="migration",
            run_id=dirname,
            title=dirname,
        )
        print(f"  Wrote to map store")
        migrated += 1

        if not args.no_move:
            layout = store._layout
            dest = layout.working_root / "scratch" / dirname
            if not dest.exists():
                shutil.move(str(subdir), str(dest))
                print(f"  Moved → {dest}")
                moved += 1
            else:
                print(f"  SKIP move: destination exists {dest}")

    print(f"\nDone: {migrated} migrated, {skipped} skipped, {moved} moved")
    return 0


def _run_cleanup_profiles(args: argparse.Namespace) -> int:
    store = MapStore(
        args.program, family=args.family, lane=args.lane, root=args.root
    )
    working = store._layout.working_root
    profiles_dir = working / "chromium-profiles"

    if not profiles_dir.exists():
        print(f"No chromium-profiles found at {profiles_dir}")
        return 0

    size = sum(
        f.stat().st_size for f in profiles_dir.rglob("*") if f.is_file()
    )
    size_mb = size / (1024 * 1024)

    if args.dry_run:
        print(f"[DRY RUN] Would delete {profiles_dir} ({size_mb:.0f} MB)")
        return 0

    shutil.rmtree(profiles_dir)
    print(f"Deleted {profiles_dir} ({size_mb:.0f} MB)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Commands that don't need an upfront MapStore
    if args.command == "migrate-workspace":
        return _run_migrate_workspace(args)
    if args.command == "cleanup-profiles":
        return _run_cleanup_profiles(args)

    store = MapStore(
        args.program,
        family=args.family,
        lane=args.lane,
        root=args.root,
    )

    if args.command == "init":
        return _run_init(store)
    elif args.command == "write":
        return _run_write(store, args)
    elif args.command == "query":
        return _run_query(store, args)
    elif args.command == "update-status":
        return _run_update_status(store, args)
    elif args.command == "rebuild-crossref":
        return _run_rebuild_crossref(store, args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
