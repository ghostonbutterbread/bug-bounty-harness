#!/usr/bin/env python3
"""
url_ingest.py — SQLite-backed URL ingestor and review tracker.

Usage:
    python3 agents/url_ingest.py ingest   <program> [--source <file>] [--run-id <id>]
                                                 [--scope-filter auto] [--no-repull-scope]
    python3 agents/url_ingest.py status   <program> [--lane <lane>] [--url <url>]
    python3 agents/url_ingest.py mark     <program> --url <url> --lane <lane> --status <status> \
                                                 [--skill <skill>] [--test-family <family>] \
                                                 [--notes <notes>] [--evidence <path>]
    python3 agents/url_ingest.py history  <program> --url <url>
    python3 agents/url_ingest.py next     <program> --lane <lane> [--skill <skill>] \
                                                 [--test-family <family>] [--limit <n>]
    python3 agents/url_ingest.py search   <program> [--route-hash <hash>] [--param-hash <hash>] \
                                                 [--host <host>] [--limit <n>]
    python3 agents/url_ingest.py stats    <program>
    python3 agents/url_ingest.py init     <program>
"""

import sqlite3
import hashlib
import argparse
import json
import sys
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qsl, urlencode
from pathlib import Path
from contextlib import contextmanager

try:
    from scope_validator import ScopeValidator
except ModuleNotFoundError:
    from agents.scope_validator import ScopeValidator

SHARED_BASE = Path.home() / "Shared" / "web_bounty"

VALID_STATUSES = {"discovered", "surface_reviewed", "deep_reviewed", "validated_signal", "dismissed"}
VALID_LANES = {
    "recon",
    "xss",
    "sqli",
    "ssrf",
    "idor",
    "lfi",
    "access-control",
    "ssti",
    "open-redirect",
    "xxe",
    "race",
    "csrf",
}
DEFAULT_TEST_SKILL = "manual"
DEFAULT_TEST_FAMILY = "general-review"
PULLSCOPE_PLATFORMS = ("hackerone", "bugcrowd", "intigriti")
PARAM_PRESETS = {
    "xss": (
        "q",
        "query",
        "search",
        "keyword",
        "title",
        "name",
        "text",
        "message",
        "description",
        "html",
        "content",
        "utm_content",
    ),
    "ssrf": (
        "url",
        "uri",
        "redirect",
        "return",
        "next",
        "callback",
        "continue",
        "target",
        "image",
        "src",
        "link",
        "webhook",
        "domain",
        "host",
        "referrer",
        "loginredirect",
        "signupredirect",
    ),
    "lfi": (
        "file",
        "path",
        "template",
        "theme",
        "page",
        "view",
        "include",
        "include_page_ids",
        "load",
        "download",
        "asset",
        "folder",
        "dir",
    ),
    "opaque-state": (
        "ui",
        "adj",
        "layout",
        "layoutqueryid",
        "searchqueryid",
        "queryid",
        "design",
        "category",
        "filter",
        "type",
    ),
}


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """Return a normalized, lowercase, query-sorted canonical URL."""
    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception:
        return url.lower()
    scheme = parsed.scheme.lower() if parsed.scheme else "https"
    netloc = (parsed.netloc or "").lower()
    path = parsed.path if parsed.path else ""
    params = sorted(parse_qsl(parsed.query, keep_blank_values=True), key=lambda kv: kv[0])
    query = urlencode(params) if params else ""
    # Normalize path: if only "/" with no params, use "" to avoid "/?" artifact
    if path == "/" and not query:
        path = ""
    normalized = f"{scheme}://{netloc}{path}"
    if query:
        normalized += f"?{query}"
    return normalized


def url_hashes(url: str):
    """Return (url_hash, route_hash, param_hash) for a URL."""
    canonical = normalize_url(url)
    parsed = urlparse(canonical)
    path = parsed.path or "/"
    param_keys = sorted(parse_qsl(parsed.query, keep_blank_values=True), key=lambda kv: kv[0])
    param_keys_str = json.dumps([k for k, _ in param_keys])
    url_hash = hashlib.sha256(canonical.encode()).hexdigest()
    route_hash = hashlib.sha256(path.encode()).hexdigest()
    param_hash = hashlib.sha256(param_keys_str.encode()).hexdigest()
    return url_hash, route_hash, param_hash


def parse_host_from_url(url: str) -> str:
    """Extract host from URL."""
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def parse_path_from_url(url: str) -> str:
    """Extract path from URL."""
    try:
        return urlparse(url).path or "/"
    except Exception:
        return "/"


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db_path(program: str) -> Path:
    """Return the path to the SQLite DB for a given program."""
    db_dir = SHARED_BASE / program / "web" / "recon" / "url_index"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "url_index.sqlite"


def schema() -> str:
    """Return the SQL to create the URL index schema."""
    return """
    CREATE TABLE IF NOT EXISTS urls (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        canonical_url TEXT NOT NULL,
        url_hash      TEXT NOT NULL UNIQUE,
        route_hash    TEXT NOT NULL,
        param_hash    TEXT NOT NULL,
        host          TEXT,
        path          TEXT,
        param_keys    TEXT,
        source        TEXT,
        first_seen    TIMESTAMP NOT NULL,
        last_seen     TIMESTAMP NOT NULL
    );

    CREATE TABLE IF NOT EXISTS observations (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        url_id        INTEGER NOT NULL,
        lane          TEXT NOT NULL,
        status        TEXT NOT NULL,
        agent_id      TEXT,
        run_id        TEXT,
        evidence_path TEXT,
        notes         TEXT,
        created_at    TIMESTAMP NOT NULL,
        FOREIGN KEY (url_id) REFERENCES urls(id)
    );

    CREATE TABLE IF NOT EXISTS test_runs (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        url_id           INTEGER NOT NULL,
        lane             TEXT NOT NULL,
        skill            TEXT NOT NULL,
        test_family      TEXT NOT NULL,
        technique        TEXT,
        status           TEXT NOT NULL,
        depth            TEXT,
        agent_id         TEXT,
        run_id           TEXT,
        evidence_path    TEXT,
        request_variant  TEXT,
        response_summary TEXT,
        notes            TEXT,
        started_at       TIMESTAMP NOT NULL,
        completed_at     TIMESTAMP NOT NULL,
        FOREIGN KEY (url_id) REFERENCES urls(id)
    );

    CREATE TABLE IF NOT EXISTS imports (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        source_file   TEXT NOT NULL,
        program       TEXT,
        run_id        TEXT,
        urls_imported INTEGER,
        urls_read     INTEGER,
        urls_accepted INTEGER,
        urls_rejected INTEGER,
        scope_mode    TEXT,
        scope_source  TEXT,
        scope_note    TEXT,
        scoped_temp_path TEXT,
        rejected_temp_path TEXT,
        imported_at   TIMESTAMP NOT NULL
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_urls_hash       ON urls(url_hash);
    CREATE INDEX IF NOT EXISTS idx_urls_route_hash        ON urls(route_hash);
    CREATE INDEX IF NOT EXISTS idx_urls_param_hash        ON urls(param_hash);
    CREATE INDEX IF NOT EXISTS idx_urls_host              ON urls(host);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_obs_url_lane    ON observations(url_id, lane);
    CREATE INDEX IF NOT EXISTS idx_obs_status             ON observations(status);
    CREATE INDEX IF NOT EXISTS idx_obs_run_id             ON observations(run_id);
    CREATE INDEX IF NOT EXISTS idx_test_runs_url          ON test_runs(url_id);
    CREATE INDEX IF NOT EXISTS idx_test_runs_lane         ON test_runs(lane);
    CREATE INDEX IF NOT EXISTS idx_test_runs_skill        ON test_runs(skill);
    CREATE INDEX IF NOT EXISTS idx_test_runs_family       ON test_runs(test_family);
    CREATE INDEX IF NOT EXISTS idx_test_runs_run_id       ON test_runs(run_id);
    CREATE INDEX IF NOT EXISTS idx_test_runs_completed_at ON test_runs(completed_at);
    """


@contextmanager
def get_conn(program: str):
    """Context manager for a DB connection."""
    db_path = get_db_path(program)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


def init_db(program: str):
    """Create schema for a program if it doesn't exist."""
    db_path = get_db_path(program)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.executescript(schema())
    _migrate_import_columns(conn)
    conn.close()
    print(f"✓ Initialized DB at {db_path}")


def _migrate_import_columns(conn) -> None:
    """Add import metadata columns for existing URL index databases."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(imports)").fetchall()}
    columns = {
        "urls_read": "INTEGER",
        "urls_accepted": "INTEGER",
        "urls_rejected": "INTEGER",
        "scope_mode": "TEXT",
        "scope_source": "TEXT",
        "scope_note": "TEXT",
        "scoped_temp_path": "TEXT",
        "rejected_temp_path": "TEXT",
    }
    for name, sql_type in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE imports ADD COLUMN {name} {sql_type}")
    conn.commit()


def _read_url_lines(source_file: str | None) -> tuple[list[str], str]:
    """Read candidate URLs from a file or stdin and return non-empty, non-comment lines."""
    source_label = source_file or "stdin"
    lines: list[str] = []
    if source_file:
        if not os.path.isfile(source_file):
            raise FileNotFoundError(source_file)
        with open(source_file, encoding="utf-8", errors="ignore") as fh:
            raw_lines = fh
            for raw_url in raw_lines:
                raw_url = raw_url.strip()
                if raw_url and not raw_url.startswith("#"):
                    lines.append(raw_url)
    else:
        for raw_url in sys.stdin:
            raw_url = raw_url.strip()
            if raw_url and not raw_url.startswith("#"):
                lines.append(raw_url)
    return lines, source_label


def _scope_temp_path(program: str, run_id: str | None, suffix: str) -> Path:
    safe_program = re.sub(r"[^A-Za-z0-9._-]+", "_", program).strip("._-") or "program"
    safe_run = re.sub(r"[^A-Za-z0-9._-]+", "_", run_id or "manual").strip("._-") or "manual"
    return Path(tempfile.gettempdir()) / f"url-ingest-{safe_program}-{safe_run}-{suffix}.txt"


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


def _try_repull_scope(program: str) -> tuple[bool, str]:
    """Try public scope pulls across known platforms. Returns (success, note)."""
    script = Path(__file__).resolve().parent / "scope_puller.py"
    errors: list[str] = []
    for platform in PULLSCOPE_PLATFORMS:
        result = subprocess.run(
            [sys.executable, str(script), program, "--platform", platform],
            capture_output=True,
            text=True,
            timeout=90,
        )
        validator = ScopeValidator(program, strict=False)
        if result.returncode == 0 and not validator.is_empty():
            return True, f"pulled scope via {platform}"
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        errors.append(f"{platform}: {detail[-1] if detail else 'no scope entries'}")
    return False, "; ".join(errors)


def _prepare_scope_staging(
    program: str,
    urls: list[str],
    *,
    run_id: str | None,
    scope_filter: str,
    repull_scope: bool,
) -> dict:
    """Filter URLs through saved/pulled scope and write temp accepted/rejected files."""
    validator = ScopeValidator(program, strict=False)
    scope_source = "saved_scope"
    scope_note = validator.scope_summary()

    if validator.is_empty() and repull_scope:
        pulled, note = _try_repull_scope(program)
        validator = ScopeValidator(program, strict=False)
        scope_source = "pulled_scope" if pulled and not validator.is_empty() else "no_scope_after_pull"
        scope_note = note

    if scope_filter == "off":
        accepted = urls
        rejected: list[str] = []
        mode = "scope_filter_off"
    elif validator.is_empty():
        accepted = urls
        rejected = []
        mode = "no_saved_scope"
        if repull_scope:
            mode = "no_scope_after_pull"
    else:
        accepted, rejected = validator.partition(urls)
        mode = "saved_scope" if scope_source == "saved_scope" else "pulled_scope"

    scoped_path = _scope_temp_path(program, run_id, "scoped")
    rejected_path = _scope_temp_path(program, run_id, "rejected")
    _write_lines(scoped_path, accepted)
    _write_lines(rejected_path, rejected)
    return {
        "accepted": accepted,
        "rejected": rejected,
        "scope_mode": mode,
        "scope_source": scope_source,
        "scope_note": scope_note,
        "scoped_temp_path": str(scoped_path),
        "rejected_temp_path": str(rejected_path),
    }


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------

def ingest(
    program: str,
    source_file: str = None,
    run_id: str = None,
    *,
    scope_filter: str = "off",
    repull_scope: bool = True,
):
    """
    Ingest URLs from a source file (or stdin) into the DB.
    Deduplicates by url_hash.
    """
    init_db(program)

    try:
        raw_urls, source_label = _read_url_lines(source_file)
    except FileNotFoundError:
        print(f"ERROR: file not found: {source_file}", file=sys.stderr)
        return

    staging = _prepare_scope_staging(
        program,
        raw_urls,
        run_id=run_id,
        scope_filter=scope_filter,
        repull_scope=repull_scope,
    )
    urls = staging["accepted"]
    urls_read = len(raw_urls)
    urls_rejected = len(staging["rejected"])
    urls_inserted = 0
    now = datetime.now(timezone.utc).isoformat()

    with get_conn(program) as conn:
        source_for_rows = os.path.basename(source_file) if source_file else "stdin"
        for raw_url in urls:
            canonical = normalize_url(raw_url)
            uh, rh, ph = url_hashes(raw_url)
            host = parse_host_from_url(raw_url)
            path = parse_path_from_url(raw_url)
            parsed = urlparse(canonical)
            param_keys = json.dumps(sorted(k for k, _ in parse_qsl(parsed.query)))
            inserted = _upsert_url(
                conn, canonical, uh, rh, ph, host, path, param_keys, source_for_rows, now
            )
            urls_inserted += int(inserted)

        conn.execute(
            "INSERT INTO imports (source_file, program, run_id, urls_imported, urls_read, "
            "urls_accepted, urls_rejected, scope_mode, scope_source, scope_note, "
            "scoped_temp_path, rejected_temp_path, imported_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                source_label,
                program,
                run_id,
                urls_inserted,
                urls_read,
                len(urls),
                urls_rejected,
                staging["scope_mode"],
                staging["scope_source"],
                staging["scope_note"],
                staging["scoped_temp_path"],
                staging["rejected_temp_path"],
                now,
            ),
        )
        conn.commit()

    print(f"✓ Ingested {urls_inserted} URLs (read {urls_read}, accepted {len(urls)}, rejected {urls_rejected}) from {source_file or 'stdin'}")
    print(f"  scope_mode={staging['scope_mode']} scoped={staging['scoped_temp_path']} rejected={staging['rejected_temp_path']}")


def _upsert_url(conn, canonical, url_hash, route_hash, param_hash, host, path,
                param_keys, source, now):
    """Insert or update a URL record. Return True when a new URL is inserted."""
    existing = conn.execute(
        "SELECT id FROM urls WHERE url_hash = ?", (url_hash,)
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE urls SET last_seen = ?, source = ? WHERE id = ?",
            (now, source, existing["id"])
        )
        return False
    else:
        conn.execute(
            "INSERT INTO urls (canonical_url, url_hash, route_hash, param_hash, host, path, "
            "param_keys, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (canonical, url_hash, route_hash, param_hash, host, path, param_keys, source, now, now)
        )
        return True


def _ensure_url(conn, url: str, source: str, now: str) -> int:
    """Return a URL id, inserting a URL record when needed."""
    uh, _, _ = url_hashes(url)
    row = conn.execute("SELECT id FROM urls WHERE url_hash = ?", (uh,)).fetchone()
    if row:
        return row["id"]

    canonical = normalize_url(url)
    uh2, rh, ph = url_hashes(url)
    host = parse_host_from_url(url)
    path = parse_path_from_url(url)
    parsed = urlparse(canonical)
    param_keys = json.dumps(sorted(k for k, _ in parse_qsl(parsed.query)))
    conn.execute(
        "INSERT INTO urls (canonical_url, url_hash, route_hash, param_hash, host, path, "
        "param_keys, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (canonical, uh2, rh, ph, host, path, param_keys, source, now, now),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


# ---------------------------------------------------------------------------
# Status query
# ---------------------------------------------------------------------------

def query_status(program: str, lane: str = None, url: str = None,
                 route_hash: str = None, param_hash: str = None, host: str = None,
                 limit: int = 50):
    """
    Query URLs by optional filters and return their current status.
    If url is provided, return status for that exact URL.
    """
    with get_conn(program) as conn:
        base_select = """
            SELECT u.id, u.canonical_url, u.host, u.path, u.source, u.first_seen,
                   o.lane, o.status, o.notes, o.evidence_path, o.agent_id, o.run_id
            FROM urls u
            LEFT JOIN observations o ON u.id = o.url_id
        """
        conditions = []
        params = []

        if url:
            uh, _, _ = url_hashes(url)
            conditions.append("u.url_hash = ?")
            params.append(uh)
        elif route_hash:
            conditions.append("u.route_hash = ?")
            params.append(route_hash)
        elif param_hash:
            conditions.append("u.param_hash = ?")
            params.append(param_hash)
        elif host:
            conditions.append("u.host LIKE ?")
            params.append(f"%{host}%")
        else:
            # No filter = return recent
            pass

        if lane:
            conditions.append("(o.lane = ? OR o.lane IS NULL)")
            params.append(lane)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        query = f"{base_select} WHERE {where_clause} ORDER BY u.last_seen DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()

        if not rows:
            print("No results found.")
            return

        # Group by URL
        url_map = {}
        for row in rows:
            uid = row["id"]
            if uid not in url_map:
                url_map[uid] = {
                    "canonical_url": row["canonical_url"],
                    "host": row["host"],
                    "path": row["path"],
                    "source": row["source"],
                    "first_seen": row["first_seen"],
                    "observations": []
                }
            if row["lane"]:
                url_map[uid]["observations"].append({
                    "lane": row["lane"],
                    "status": row["status"],
                    "notes": row["notes"],
                    "evidence_path": row["evidence_path"],
                    "agent_id": row["agent_id"],
                    "run_id": row["run_id"]
                })

        for uid, info in url_map.items():
            print(f"\nURL: {info['canonical_url']}")
            print(f"  Host: {info['host']}  Path: {info['path']}")
            print(f"  Source: {info['source']}  First seen: {info['first_seen']}")
            if info["observations"]:
                for obs in info["observations"]:
                    print(f"  [{obs['lane']}] {obs['status']}  notes={obs['notes']}  "
                          f"evidence={obs['evidence_path']}")
            else:
                print("  Status: discovered (no observations yet)")


def query_history(program: str, url: str, limit: int = 50):
    """Print append-only test history for a URL."""
    with get_conn(program) as conn:
        uh, _, _ = url_hashes(url)
        row = conn.execute(
            "SELECT id, canonical_url, host, path FROM urls WHERE url_hash = ?", (uh,)
        ).fetchone()
        if not row:
            print("No URL found.")
            return

        print(f"\nURL: {row['canonical_url']}")
        print(f"  Host: {row['host']}  Path: {row['path']}")
        tests = conn.execute(
            """
            SELECT lane, skill, test_family, technique, status, depth, agent_id,
                   run_id, evidence_path, request_variant, response_summary, notes,
                   started_at, completed_at
            FROM test_runs
            WHERE url_id = ?
            ORDER BY completed_at DESC, id DESC
            LIMIT ?
            """,
            (row["id"], limit),
        ).fetchall()
        if not tests:
            print("  No test runs logged yet.")
            return
        for test in tests:
            print(
                f"  [{test['lane']}] {test['skill']}:{test['test_family']} "
                f"{test['status']} depth={test['depth']} run={test['run_id']}"
            )
            if test["technique"]:
                print(f"    technique={test['technique']}")
            if test["request_variant"]:
                print(f"    request={test['request_variant']}")
            if test["response_summary"]:
                print(f"    response={test['response_summary']}")
            if test["notes"]:
                print(f"    notes={test['notes']}")
            if test["evidence_path"]:
                print(f"    evidence={test['evidence_path']}")


def _param_filter_terms(param_preset: str | None, param_key_like: str | None) -> list[str]:
    """Return lowercase parameter-key terms for queue filtering."""
    terms: list[str] = []
    if param_preset:
        preset = PARAM_PRESETS.get(param_preset)
        if not preset:
            valid = ", ".join(sorted(PARAM_PRESETS))
            print(f"ERROR: unknown --param-preset {param_preset!r}. Valid: {valid}", file=sys.stderr)
            return []
        terms.extend(preset)
    if param_key_like:
        terms.extend(part.strip() for part in param_key_like.split(",") if part.strip())
    return [term.lower() for term in terms if term]


def query_next(program: str, lane: str, skill: str = None, test_family: str = None,
               host: str = None, limit: int = 50, param_preset: str = None,
               param_key_like: str = None, has_query: bool = False):
    """Print URLs that have not yet been tested for the requested lane/skill/family."""
    if not lane:
        print("ERROR: --lane is required for next", file=sys.stderr)
        return

    with get_conn(program) as conn:
        filters = ["u.id NOT IN (SELECT url_id FROM observations WHERE lane = ? AND status IN ('deep_reviewed', 'dismissed'))"]
        params = [lane]
        tested_filters = ["tr.url_id = u.id", "tr.lane = ?"]
        tested_params = [lane]
        if skill:
            tested_filters.append("tr.skill = ?")
            tested_params.append(skill)
        if test_family:
            tested_filters.append("tr.test_family = ?")
            tested_params.append(test_family)
        filters.append(f"NOT EXISTS (SELECT 1 FROM test_runs tr WHERE {' AND '.join(tested_filters)})")
        params.extend(tested_params)
        if host:
            filters.append("u.host LIKE ?")
            params.append(f"%{host}%")
        param_terms = _param_filter_terms(param_preset, param_key_like)
        if param_preset and not param_terms:
            return
        if has_query:
            filters.append("u.param_keys != '[]'")
        if param_terms:
            term_filters = []
            for term in param_terms:
                term_filters.append("LOWER(u.param_keys) LIKE ?")
                params.append(f"%{term}%")
            filters.append(f"({' OR '.join(term_filters)})")
        params.append(limit)
        rows = conn.execute(
            f"""
            SELECT u.canonical_url, u.host, u.path, u.source, u.first_seen
            FROM urls u
            WHERE {' AND '.join(filters)}
            ORDER BY u.last_seen DESC
            LIMIT ?
            """,
            params,
        ).fetchall()

    if not rows:
        print("No candidate URLs found.")
        return
    for row in rows:
        print(row["canonical_url"])


# ---------------------------------------------------------------------------
# Mark
# ---------------------------------------------------------------------------

def mark(program: str, url: str, lane: str, status: str,
         notes: str = None, evidence_path: str = None, agent_id: str = None,
         run_id: str = None, skill: str = None, test_family: str = None,
         technique: str = None, request_variant: str = None,
         response_summary: str = None, depth: str = None):
    """Record an append-only test run and update the latest per-lane URL summary."""
    if status not in VALID_STATUSES:
        print(f"ERROR: invalid status '{status}'. Valid: {VALID_STATUSES}", file=sys.stderr)
        return
    if lane not in VALID_LANES:
        print(f"NOTE: lane '{lane}' not in standard set {VALID_LANES}", file=sys.stderr)

    init_db(program)
    now = datetime.now(timezone.utc).isoformat()
    normalized_skill = str(skill or DEFAULT_TEST_SKILL).strip() or DEFAULT_TEST_SKILL
    normalized_family = str(test_family or DEFAULT_TEST_FAMILY).strip() or DEFAULT_TEST_FAMILY
    normalized_depth = str(depth or status).strip() or status

    with get_conn(program) as conn:
        before = conn.execute(
            "SELECT id FROM urls WHERE url_hash = ?", (url_hashes(url)[0],)
        ).fetchone()
        if not before:
            print(f"WARNING: URL not found in DB — ingested as new", file=sys.stderr)
        url_id = _ensure_url(conn, url, "mark-unknown", now)

        conn.execute(
            "INSERT INTO test_runs (url_id, lane, skill, test_family, technique, status, "
            "depth, notes, evidence_path, agent_id, run_id, request_variant, response_summary, "
            "started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                url_id,
                lane,
                normalized_skill,
                normalized_family,
                technique,
                status,
                normalized_depth,
                notes,
                evidence_path,
                agent_id,
                run_id,
                request_variant,
                response_summary,
                now,
                now,
            ),
        )

        # Upsert observation
        existing = conn.execute(
            "SELECT id FROM observations WHERE url_id = ? AND lane = ?",
            (url_id, lane)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE observations SET status=?, notes=?, evidence_path=?, "
                "agent_id=?, run_id=?, created_at=? WHERE id = ?",
                (status, notes, evidence_path, agent_id, run_id, now, existing["id"])
            )
            print(f"✓ Updated observation: {url} [{lane}] = {status}")
        else:
            conn.execute(
                "INSERT INTO observations (url_id, lane, status, notes, evidence_path, "
                "agent_id, run_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (url_id, lane, status, notes, evidence_path, agent_id, run_id, now)
            )
            print(f"✓ Recorded observation: {url} [{lane}] = {status}")
        conn.commit()


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def stats(program: str):
    """Print DB statistics for a program."""
    with get_conn(program) as conn:
        total = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
        print(f"\n=== URL Index: {program} ===")
        print(f"Total URLs: {total}")

        print("\nBy lane+status:")
        rows = conn.execute("""
            SELECT lane, status, COUNT(*) as cnt
            FROM observations
            GROUP BY lane, status
            ORDER BY lane, status
        """).fetchall()
        if rows:
            for row in rows:
                print(f"  [{row['lane']}] {row['status']}: {row['cnt']}")
        else:
            print("  (no observations yet)")

        print("\nBy skill+test family:")
        rows = conn.execute("""
            SELECT skill, test_family, status, COUNT(*) as cnt
            FROM test_runs
            GROUP BY skill, test_family, status
            ORDER BY skill, test_family, status
        """).fetchall()
        if rows:
            for row in rows:
                print(f"  {row['skill']}:{row['test_family']} [{row['status']}]: {row['cnt']}")
        else:
            print("  (no test runs yet)")

        print("\nBy source file:")
        rows = conn.execute("""
            SELECT source, COUNT(*) as cnt
            FROM (SELECT DISTINCT url_hash, source FROM urls)
            GROUP BY source ORDER BY cnt DESC LIMIT 20
        """).fetchall()
        for row in rows:
            print(f"  {row['source']}: {row['cnt']}")

        last_import = conn.execute(
            "SELECT imported_at, source_file, urls_imported, urls_read, urls_accepted, "
            "urls_rejected, scope_mode, scoped_temp_path, rejected_temp_path FROM imports "
            "ORDER BY imported_at DESC LIMIT 1"
        ).fetchone()
        if last_import:
            print(f"\nLast import: {last_import['imported_at']}  "
                  f"({last_import['urls_imported']} URLs from {last_import['source_file']})")
            print(
                f"  scope_mode={last_import['scope_mode']} "
                f"read={last_import['urls_read']} accepted={last_import['urls_accepted']} "
                f"rejected={last_import['urls_rejected']}"
            )
            if last_import["scoped_temp_path"]:
                print(f"  scoped_temp={last_import['scoped_temp_path']}")
            if last_import["rejected_temp_path"]:
                print(f"  rejected_temp={last_import['rejected_temp_path']}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="url-ingest — SQLite-backed URL ingestor and review tracker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("cmd", choices=["init", "ingest", "status", "mark", "history", "next", "search", "stats"],
                        help="Sub-command")
    parser.add_argument("program", help="Target program name")
    parser.add_argument("--source", "-s", help="Source file to ingest (default: stdin)")
    parser.add_argument("--run-id", help="Recon run ID to associate with this import")
    parser.add_argument(
        "--scope-filter",
        choices=["off", "auto"],
        default="off",
        help="For ingest: write /tmp scoped/rejected files and ingest only scoped URLs when scope exists.",
    )
    parser.add_argument(
        "--repull-scope",
        action="store_true",
        default=None,
        help="For ingest: if saved scope is missing, try public HackerOne/Bugcrowd/Intigriti scope pulls before fallback. Default when --scope-filter auto is used.",
    )
    parser.add_argument(
        "--no-repull-scope",
        action="store_false",
        dest="repull_scope",
        help="For ingest: do not try pulling scope when saved scope is missing.",
    )
    parser.add_argument("--lane", help="Lane to filter by (e.g. xss, ssrf)")
    parser.add_argument("--url", help="Exact URL to query")
    parser.add_argument("--route-hash", help="Route hash to search")
    parser.add_argument("--param-hash", help="Param hash to search")
    parser.add_argument("--host", help="Host substring to search")
    parser.add_argument("--limit", "-n", type=int, default=50, help="Max results (default: 50)")
    parser.add_argument(
        "--param-preset",
        choices=sorted(PARAM_PRESETS),
        help="For next: filter queue by parameter-key preset, e.g. xss, ssrf, lfi.",
    )
    parser.add_argument(
        "--param-key-like",
        help="For next: comma-separated parameter key substrings to match.",
    )
    parser.add_argument(
        "--has-query",
        action="store_true",
        help="For next: only return URLs with query parameters.",
    )
    parser.add_argument("--status", help=f"Status value: {sorted(VALID_STATUSES)}")
    parser.add_argument("--notes", help="Notes for observation")
    parser.add_argument("--evidence", help="Evidence path for observation")
    parser.add_argument("--agent-id", help="Agent ID that wrote this observation")
    parser.add_argument("--run-id-mark", dest="run_id", help="Run ID for observation")
    parser.add_argument("--skill", help="Skill or agent capability used, e.g. user-agent-fuzz")
    parser.add_argument("--test-family", help="Specific test family, e.g. header-behavior")
    parser.add_argument("--technique", help="Specific technique or payload family")
    parser.add_argument("--depth", help="Analysis depth override; defaults to --status")
    parser.add_argument("--request-variant", help="Short description of request mutation tested")
    parser.add_argument("--response-summary", help="Short result summary without sensitive data")

    args = parser.parse_args()

    cmd = args.cmd

    if cmd == "init":
        init_db(args.program)

    elif cmd == "ingest":
        repull_scope = args.repull_scope
        if repull_scope is None:
            repull_scope = args.scope_filter == "auto"
        ingest(
            args.program,
            source_file=args.source,
            run_id=args.run_id,
            scope_filter=args.scope_filter,
            repull_scope=repull_scope,
        )

    elif cmd == "status":
        query_status(args.program, lane=args.lane, url=args.url,
                     route_hash=args.route_hash, param_hash=args.param_hash,
                     host=args.host, limit=args.limit)

    elif cmd == "mark":
        if not args.url or not args.lane or not args.status:
            print("ERROR: --url, --lane, and --status are required for mark", file=sys.stderr)
            sys.exit(1)
        mark(args.program, url=args.url, lane=args.lane, status=args.status,
             notes=args.notes, evidence_path=args.evidence,
             agent_id=args.agent_id, run_id=args.run_id, skill=args.skill,
             test_family=args.test_family, technique=args.technique,
             request_variant=args.request_variant, response_summary=args.response_summary,
             depth=args.depth)

    elif cmd == "history":
        if not args.url:
            print("ERROR: --url is required for history", file=sys.stderr)
            sys.exit(1)
        query_history(args.program, url=args.url, limit=args.limit)

    elif cmd == "next":
        if not args.lane:
            print("ERROR: --lane is required for next", file=sys.stderr)
            sys.exit(1)
        query_next(args.program, lane=args.lane, skill=args.skill,
                   test_family=args.test_family, host=args.host, limit=args.limit,
                   param_preset=args.param_preset,
                   param_key_like=args.param_key_like,
                   has_query=args.has_query)

    elif cmd == "search":
        query_status(args.program, lane=args.lane, url=args.url,
                     route_hash=args.route_hash, param_hash=args.param_hash,
                     host=args.host, limit=args.limit)

    elif cmd == "stats":
        stats(args.program)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
