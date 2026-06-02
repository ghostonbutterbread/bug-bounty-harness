#!/usr/bin/env python3
"""
url_ingest.py — SQLite-backed URL ingestor and review tracker.

Usage:
    python3 agents/url_ingest.py ingest   <program> [--source <file>] [--run-id <id>]
    python3 agents/url_ingest.py status   <program> [--lane <lane>] [--url <url>]
    python3 agents/url_ingest.py mark     <program> --url <url> --lane <lane> --status <status> \
                                                 [--notes <notes>] [--evidence <path>]
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
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qsl, urlencode
from pathlib import Path
from contextlib import contextmanager

SHARED_BASE = Path.home() / "Shared" / "web_bounty"

VALID_STATUSES = {"discovered", "surface_reviewed", "deep_reviewed", "validated_signal", "dismissed"}
VALID_LANES = {"xss", "sqli", "ssrf", "idor", "access-control", "ssti", "open-redirect", "xxe", "race", "csrf"}


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

    CREATE TABLE IF NOT EXISTS imports (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        source_file   TEXT NOT NULL,
        program       TEXT,
        run_id        TEXT,
        urls_imported INTEGER,
        imported_at   TIMESTAMP NOT NULL
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_urls_hash       ON urls(url_hash);
    CREATE INDEX IF NOT EXISTS idx_urls_route_hash        ON urls(route_hash);
    CREATE INDEX IF NOT EXISTS idx_urls_param_hash        ON urls(param_hash);
    CREATE INDEX IF NOT EXISTS idx_urls_host              ON urls(host);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_obs_url_lane    ON observations(url_id, lane);
    CREATE INDEX IF NOT EXISTS idx_obs_status             ON observations(status);
    CREATE INDEX IF NOT EXISTS idx_obs_run_id             ON observations(run_id);
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
    conn.close()
    print(f"✓ Initialized DB at {db_path}")


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------

def ingest(program: str, source_file: str = None, run_id: str = None):
    """
    Ingest URLs from a source file (or stdin) into the DB.
    Deduplicates by url_hash.
    """
    init_db(program)

    urls_read = 0
    urls_inserted = 0
    now = datetime.now(timezone.utc).isoformat()

    with get_conn(program) as conn:
        # Ingest from a specific file
        if source_file:
            if not os.path.isfile(source_file):
                print(f"ERROR: file not found: {source_file}", file=sys.stderr)
                return
            with open(source_file) as fh:
                for raw_url in fh:
                    raw_url = raw_url.strip()
                    if not raw_url or raw_url.startswith("#"):
                        continue
                    canonical = normalize_url(raw_url)
                    uh, rh, ph = url_hashes(raw_url)
                    host = parse_host_from_url(raw_url)
                    path = parse_path_from_url(raw_url)
                    parsed = urlparse(canonical)
                    param_keys = json.dumps(sorted(k for k, _ in parse_qsl(parsed.query)))
                    _upsert_url(conn, canonical, uh, rh, ph, host, path, param_keys,
                                os.path.basename(source_file), now)
                    urls_read += 1
                    urls_inserted += 1

            # Log import
            conn.execute(
                "INSERT INTO imports (source_file, program, run_id, urls_imported, imported_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (source_file, program, run_id, urls_inserted, now)
            )
            conn.commit()

        # Ingest from stdin
        else:
            for raw_url in sys.stdin:
                raw_url = raw_url.strip()
                if not raw_url:
                    continue
                canonical = normalize_url(raw_url)
                uh, rh, ph = url_hashes(raw_url)
                host = parse_host_from_url(raw_url)
                path = parse_path_from_url(raw_url)
                parsed = urlparse(canonical)
                param_keys = json.dumps(sorted(k for k, _ in parse_qsl(parsed.query)))
                _upsert_url(conn, canonical, uh, rh, ph, host, path, param_keys, "stdin", now)
                urls_read += 1
                urls_inserted += 1

        print(f"✓ Ingested {urls_inserted} URLs (read {urls_read}) from {source_file or 'stdin'}")


def _upsert_url(conn, canonical, url_hash, route_hash, param_hash, host, path,
                param_keys, source, now):
    """Insert or update a URL record."""
    existing = conn.execute(
        "SELECT id FROM urls WHERE url_hash = ?", (url_hash,)
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE urls SET last_seen = ?, source = ? WHERE id = ?",
            (now, source, existing["id"])
        )
    else:
        conn.execute(
            "INSERT INTO urls (canonical_url, url_hash, route_hash, param_hash, host, path, "
            "param_keys, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (canonical, url_hash, route_hash, param_hash, host, path, param_keys, source, now, now)
        )


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


# ---------------------------------------------------------------------------
# Mark
# ---------------------------------------------------------------------------

def mark(program: str, url: str, lane: str, status: str,
         notes: str = None, evidence_path: str = None, agent_id: str = None,
         run_id: str = None):
    """Record an observation (analysis depth update) for a URL in a given lane."""
    if status not in VALID_STATUSES:
        print(f"ERROR: invalid status '{status}'. Valid: {VALID_STATUSES}", file=sys.stderr)
        return
    if lane not in VALID_LANES:
        print(f"NOTE: lane '{lane}' not in standard set {VALID_LANES}", file=sys.stderr)

    init_db(program)
    now = datetime.now(timezone.utc).isoformat()

    with get_conn(program) as conn:
        uh, _, _ = url_hashes(url)
        row = conn.execute("SELECT id FROM urls WHERE url_hash = ?", (uh,)).fetchone()
        if not row:
            print(f"WARNING: URL not found in DB — ingested as new", file=sys.stderr)
            canonical = normalize_url(url)
            uh2, rh, ph = url_hashes(url)
            host = parse_host_from_url(url)
            path = parse_path_from_url(url)
            parsed = urlparse(canonical)
            param_keys = json.dumps(sorted(k for k, _ in parse_qsl(parsed.query)))
            conn.execute(
                "INSERT INTO urls (canonical_url, url_hash, route_hash, param_hash, host, path, "
                "param_keys, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (canonical, uh2, rh, ph, host, path, param_keys, "mark-unknown", now, now)
            )
            url_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        else:
            url_id = row["id"]

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

        print("\nBy source file:")
        rows = conn.execute("""
            SELECT source, COUNT(*) as cnt
            FROM (SELECT DISTINCT url_hash, source FROM urls)
            GROUP BY source ORDER BY cnt DESC LIMIT 20
        """).fetchall()
        for row in rows:
            print(f"  {row['source']}: {row['cnt']}")

        last_import = conn.execute(
            "SELECT imported_at, source_file, urls_imported FROM imports "
            "ORDER BY imported_at DESC LIMIT 1"
        ).fetchone()
        if last_import:
            print(f"\nLast import: {last_import['imported_at']}  "
                  f"({last_import['urls_imported']} URLs from {last_import['source_file']})")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="url-ingest — SQLite-backed URL ingestor and review tracker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("cmd", choices=["init", "ingest", "status", "mark", "search", "stats"],
                        help="Sub-command")
    parser.add_argument("program", help="Target program name")
    parser.add_argument("--source", "-s", help="Source file to ingest (default: stdin)")
    parser.add_argument("--run-id", help="Recon run ID to associate with this import")
    parser.add_argument("--lane", help="Lane to filter by (e.g. xss, ssrf)")
    parser.add_argument("--url", help="Exact URL to query")
    parser.add_argument("--route-hash", help="Route hash to search")
    parser.add_argument("--param-hash", help="Param hash to search")
    parser.add_argument("--host", help="Host substring to search")
    parser.add_argument("--limit", "-n", type=int, default=50, help="Max results (default: 50)")
    parser.add_argument("--status", help=f"Status value: {sorted(VALID_STATUSES)}")
    parser.add_argument("--notes", help="Notes for observation")
    parser.add_argument("--evidence", help="Evidence path for observation")
    parser.add_argument("--agent-id", help="Agent ID that wrote this observation")
    parser.add_argument("--run-id-mark", dest="run_id", help="Run ID for observation")

    args = parser.parse_args()

    cmd = args.cmd

    if cmd == "init":
        init_db(args.program)

    elif cmd == "ingest":
        ingest(args.program, source_file=args.source, run_id=args.run_id)

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
             agent_id=args.agent_id, run_id=args.run_id)

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
