#!/usr/bin/env python3
"""Sanitized SQLite index for agent mitmproxy lanes."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl


DEFAULT_LANE_ROOT = Path("~/.local/state/ghost/mitm-lanes").expanduser()
DEFAULT_STORE = Path("~/.local/share/ghost/proxy-store/proxy_store.sqlite").expanduser()
DEFAULT_PROXY_HOST = "hoster"
DEFAULT_AGENT_PORT_MIN = 8081
DEFAULT_AGENT_PORT_MAX = 8090
SECRET_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-csrf-token",
    "x-xsrf-token",
    "x-api-key",
    "api-key",
    "apikey",
    "set-cookie",
}
NOISY_HOST_SUFFIXES = (
    "googleapis.com",
    "gstatic.com",
    "google.com",
    "clients2.google.com",
)


def scrub_user_site_for_mitmproxy() -> None:
    """Avoid user-site package shadowing for Ubuntu mitmproxy imports."""
    user_site = os.path.expanduser("~/.local/lib")
    sys.path[:] = [entry for entry in sys.path if not entry.startswith(user_site)]


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }
    for name, definition in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS lanes (
            lane TEXT PRIMARY KEY,
            program TEXT,
            task TEXT,
            account TEXT,
            profile_dir TEXT,
            proxy_server TEXT,
            flow_file TEXT,
            raw_dir TEXT,
            run_id TEXT,
            agent_id TEXT,
            runtime_host TEXT,
            proxy_host TEXT,
            proxy_port INTEGER,
            transport TEXT,
            account_label TEXT,
            browser_profile_id TEXT,
            session_source TEXT,
            first_indexed_at REAL,
            last_indexed_at REAL,
            request_count INTEGER DEFAULT 0,
            note TEXT
        );
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_uid TEXT NOT NULL UNIQUE,
            lane TEXT NOT NULL,
            program TEXT,
            task TEXT,
            run_id TEXT,
            agent_id TEXT,
            account_label TEXT,
            runtime_host TEXT,
            proxy_host TEXT,
            proxy_port INTEGER,
            transport TEXT,
            browser_profile_id TEXT,
            session_source TEXT,
            ts_start REAL,
            ts_end REAL,
            scheme TEXT,
            host TEXT,
            port INTEGER,
            method TEXT,
            path TEXT,
            path_key TEXT,
            url_no_query TEXT,
            query_names_json TEXT NOT NULL DEFAULT '[]',
            request_header_names_json TEXT NOT NULL DEFAULT '[]',
            response_header_names_json TEXT NOT NULL DEFAULT '[]',
            request_content_type TEXT,
            response_content_type TEXT,
            status_code INTEGER,
            response_size INTEGER,
            request_size INTEGER,
            has_authorization INTEGER DEFAULT 0,
            has_cookie INTEGER DEFAULT 0,
            has_sensitive_headers INTEGER DEFAULT 0,
            body_field_names_json TEXT NOT NULL DEFAULT '[]',
            tags_json TEXT NOT NULL DEFAULT '[]',
            raw_flow_file TEXT,
            indexed_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_requests_host_path ON requests(host, path_key);
        CREATE INDEX IF NOT EXISTS idx_requests_method ON requests(method);
        CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status_code);
        CREATE INDEX IF NOT EXISTS idx_requests_lane ON requests(lane);
        CREATE INDEX IF NOT EXISTS idx_requests_program ON requests(program);
        CREATE INDEX IF NOT EXISTS idx_requests_run ON requests(run_id);
        CREATE INDEX IF NOT EXISTS idx_requests_agent ON requests(agent_id);
        CREATE INDEX IF NOT EXISTS idx_requests_account ON requests(account_label);
        CREATE TABLE IF NOT EXISTS params (
            request_id INTEGER NOT NULL,
            location TEXT NOT NULL,
            name TEXT NOT NULL,
            UNIQUE(request_id, location, name),
            FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_params_name ON params(name);
        CREATE TABLE IF NOT EXISTS request_packets (
            request_id INTEGER PRIMARY KEY,
            flow_uid TEXT NOT NULL UNIQUE,
            method TEXT NOT NULL,
            scheme TEXT,
            host TEXT,
            port INTEGER,
            path TEXT,
            full_url TEXT,
            http_version TEXT,
            headers_json TEXT NOT NULL DEFAULT '[]',
            body BLOB NOT NULL DEFAULT X'',
            captured_at REAL,
            indexed_at REAL NOT NULL,
            FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS proxy_leases (
            lease_id TEXT PRIMARY KEY,
            lane TEXT NOT NULL UNIQUE,
            proxy_host TEXT NOT NULL,
            proxy_port INTEGER NOT NULL UNIQUE,
            proxy_server TEXT NOT NULL,
            agent_id TEXT,
            run_id TEXT,
            program TEXT,
            task TEXT,
            account_label TEXT,
            runtime_host TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            started_at REAL NOT NULL,
            expires_at REAL,
            updated_at REAL NOT NULL,
            note TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_proxy_leases_status ON proxy_leases(status);
        CREATE INDEX IF NOT EXISTS idx_proxy_leases_agent ON proxy_leases(agent_id);
        CREATE INDEX IF NOT EXISTS idx_proxy_leases_account ON proxy_leases(account_label);
        """
    )
    ensure_columns(
        conn,
        "lanes",
        {
            "run_id": "TEXT",
            "agent_id": "TEXT",
            "runtime_host": "TEXT",
            "proxy_host": "TEXT",
            "proxy_port": "INTEGER",
            "transport": "TEXT",
            "account_label": "TEXT",
            "browser_profile_id": "TEXT",
            "session_source": "TEXT",
        },
    )
    ensure_columns(
        conn,
        "requests",
        {
            "run_id": "TEXT",
            "agent_id": "TEXT",
            "account_label": "TEXT",
            "runtime_host": "TEXT",
            "proxy_host": "TEXT",
            "proxy_port": "INTEGER",
            "transport": "TEXT",
            "browser_profile_id": "TEXT",
            "session_source": "TEXT",
        },
    )
    conn.commit()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def unique_sorted(values: list[str]) -> list[str]:
    return sorted({value for value in values if value})


def path_key(path: str) -> str:
    path_only = path.split("?", 1)[0] or "/"
    return re.sub(r"/+", "/", path_only)


def header_names(headers: Any) -> list[str]:
    names = []
    for name, _value in headers.items(multi=True):
        names.append(str(name).lower())
    return unique_sorted(names)


def request_flags(headers: Any) -> dict[str, bool]:
    lower = {str(name).lower() for name, _value in headers.items(multi=True)}
    return {
        "has_authorization": "authorization" in lower,
        "has_cookie": "cookie" in lower,
        "has_sensitive_headers": bool(lower & SECRET_HEADER_NAMES),
    }


def query_names(request: Any) -> list[str]:
    try:
        return unique_sorted([str(name) for name, _value in request.query.items(multi=True)])
    except Exception:
        query = request.path.split("?", 1)[1] if "?" in request.path else ""
        return unique_sorted([name for name, _value in parse_qsl(query, keep_blank_values=True)])


def body_field_names(request: Any, max_bytes: int = 64_000) -> list[str]:
    content = request.raw_content or b""
    if not content or len(content) > max_bytes:
        return []
    ctype = (request.headers.get("content-type", "") or "").lower()
    try:
        if "application/json" in ctype:
            parsed = json.loads(content.decode("utf-8", errors="replace"))
            if isinstance(parsed, dict):
                return unique_sorted([str(key) for key in parsed.keys()])
            return []
        if "application/x-www-form-urlencoded" in ctype:
            return unique_sorted([name for name, _value in parse_qsl(content.decode("utf-8", errors="replace"))])
    except Exception:
        return []
    return []


def classify_tags(host: str, method: str, status_code: int | None, qnames: list[str], body_names: list[str]) -> list[str]:
    tags = []
    if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        tags.append("stateful-method")
    if status_code and status_code >= 400:
        tags.append("error-response")
    if qnames:
        tags.append("query-params")
    if body_names:
        tags.append("body-fields")
    if any(host == suffix or host.endswith(f".{suffix}") for suffix in NOISY_HOST_SUFFIXES):
        tags.append("browser-background")
    return tags


def flow_record(
    flow: Any,
    lane: str,
    program: str | None,
    task: str | None,
    flow_file: Path,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    request = getattr(flow, "request", None)
    if request is None:
        return None
    response = getattr(flow, "response", None)
    qnames = query_names(request)
    bnames = body_field_names(request)
    req_headers = header_names(request.headers)
    resp_headers = header_names(response.headers) if response else []
    flags = request_flags(request.headers)
    status_code = response.status_code if response else None
    host = str(request.host or "")
    method = str(request.method or "")
    url_no_query = request.pretty_url.split("?", 1)[0]
    safe_path = path_key(request.path)
    uid_source = f"{lane}|{getattr(flow, 'id', '')}|{method}|{request.pretty_url}|{request.timestamp_start}"
    metadata = metadata or {}
    return {
        "flow_uid": sha256_text(uid_source),
        "lane": lane,
        "program": program,
        "task": task,
        "run_id": metadata.get("run_id"),
        "agent_id": metadata.get("agent_id"),
        "account_label": metadata.get("account_label"),
        "runtime_host": metadata.get("runtime_host"),
        "proxy_host": metadata.get("proxy_host"),
        "proxy_port": metadata.get("proxy_port"),
        "transport": metadata.get("transport"),
        "browser_profile_id": metadata.get("browser_profile_id"),
        "session_source": metadata.get("session_source"),
        "ts_start": request.timestamp_start,
        "ts_end": response.timestamp_end if response else None,
        "scheme": request.scheme,
        "host": host,
        "port": request.port,
        "method": method,
        "path": safe_path,
        "path_key": safe_path,
        "url_no_query": url_no_query,
        "query_names_json": json_dumps(qnames),
        "request_header_names_json": json_dumps(req_headers),
        "response_header_names_json": json_dumps(resp_headers),
        "request_content_type": request.headers.get("content-type"),
        "response_content_type": response.headers.get("content-type") if response else None,
        "status_code": status_code,
        "response_size": len(response.raw_content or b"") if response else None,
        "request_size": len(request.raw_content or b""),
        "has_authorization": int(flags["has_authorization"]),
        "has_cookie": int(flags["has_cookie"]),
        "has_sensitive_headers": int(flags["has_sensitive_headers"]),
        "body_field_names_json": json_dumps(bnames),
        "tags_json": json_dumps(classify_tags(host, method, status_code, qnames, bnames)),
        "raw_flow_file": str(flow_file),
        "indexed_at": time.time(),
        "_query_names": qnames,
        "_body_field_names": bnames,
    }


def request_packet_record(flow: Any, flow_uid: str) -> dict[str, Any] | None:
    request = getattr(flow, "request", None)
    if request is None:
        return None
    headers = [
        {"name": str(name), "value": str(value)}
        for name, value in request.headers.items(multi=True)
    ]
    return {
        "flow_uid": flow_uid,
        "method": str(request.method or ""),
        "scheme": str(request.scheme or ""),
        "host": str(request.host or ""),
        "port": request.port,
        "path": str(request.path or ""),
        "full_url": str(request.pretty_url or ""),
        "http_version": str(getattr(request, "http_version", "") or ""),
        "headers_json": json_dumps(headers),
        "body": request.raw_content or b"",
        "captured_at": request.timestamp_start,
        "indexed_at": time.time(),
    }


def upsert_request(conn: sqlite3.Connection, record: dict[str, Any]) -> int:
    columns = [
        key for key in record.keys()
        if not key.startswith("_")
    ]
    placeholders = ",".join("?" for _ in columns)
    updates = ",".join(f"{column}=excluded.{column}" for column in columns if column != "flow_uid")
    conn.execute(
        f"""
        INSERT INTO requests ({",".join(columns)})
        VALUES ({placeholders})
        ON CONFLICT(flow_uid) DO UPDATE SET {updates}
        """,
        [record[column] for column in columns],
    )
    row = conn.execute("SELECT id FROM requests WHERE flow_uid=?", (record["flow_uid"],)).fetchone()
    request_id = int(row["id"])
    conn.execute("DELETE FROM params WHERE request_id=?", (request_id,))
    for name in record["_query_names"]:
        conn.execute(
            "INSERT OR IGNORE INTO params(request_id, location, name) VALUES (?, 'query', ?)",
            (request_id, name),
        )
    for name in record["_body_field_names"]:
        conn.execute(
            "INSERT OR IGNORE INTO params(request_id, location, name) VALUES (?, 'body', ?)",
            (request_id, name),
        )
    return request_id


def upsert_request_packet(conn: sqlite3.Connection, request_id: int, packet: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO request_packets(
            request_id, flow_uid, method, scheme, host, port, path, full_url,
            http_version, headers_json, body, captured_at, indexed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(flow_uid) DO UPDATE SET
          request_id=excluded.request_id,
          method=excluded.method,
          scheme=excluded.scheme,
          host=excluded.host,
          port=excluded.port,
          path=excluded.path,
          full_url=excluded.full_url,
          http_version=excluded.http_version,
          headers_json=excluded.headers_json,
          body=excluded.body,
          captured_at=excluded.captured_at,
          indexed_at=excluded.indexed_at
        """,
        (
            request_id,
            packet["flow_uid"],
            packet["method"],
            packet["scheme"],
            packet["host"],
            packet["port"],
            packet["path"],
            packet["full_url"],
            packet["http_version"],
            packet["headers_json"],
            packet["body"],
            packet["captured_at"],
            packet["indexed_at"],
        ),
    )


def read_lane_state(root: Path, lane: str) -> dict[str, Any]:
    path = root / lane / "state.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}


def metadata_from_args(args: argparse.Namespace, lane_state: dict[str, Any]) -> dict[str, Any]:
    proxy_server = getattr(args, "proxy_server", None) or lane_state.get("proxy_server")
    proxy_host = getattr(args, "proxy_host", None) or lane_state.get("proxy_host")
    proxy_port = getattr(args, "proxy_port", None) or lane_state.get("proxy_port")
    if proxy_server and (not proxy_host or proxy_port is None):
        match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:]+):(\d+)", str(proxy_server))
        if match:
            proxy_host = proxy_host or match.group(1)
            proxy_port = proxy_port if proxy_port is not None else int(match.group(2))
    return {
        "run_id": getattr(args, "run_id", None) or lane_state.get("run_id"),
        "agent_id": getattr(args, "agent_id", None) or lane_state.get("agent_id"),
        "account_label": (
            getattr(args, "account_label", None)
            or lane_state.get("account_label")
            or lane_state.get("account")
        ),
        "runtime_host": getattr(args, "runtime_host", None) or lane_state.get("runtime_host"),
        "proxy_host": proxy_host,
        "proxy_port": int(proxy_port) if proxy_port is not None else None,
        "transport": getattr(args, "transport", None) or lane_state.get("transport") or "browser",
        "browser_profile_id": (
            getattr(args, "browser_profile_id", None)
            or lane_state.get("browser_profile_id")
            or lane_state.get("profile_dir")
        ),
        "session_source": getattr(args, "session_source", None) or lane_state.get("session_source"),
        "proxy_server": proxy_server,
    }


def index_lane(args: argparse.Namespace) -> dict[str, Any]:
    scrub_user_site_for_mitmproxy()
    from mitmproxy.io import FlowReader

    root = Path(args.lane_root).expanduser()
    lane_state = read_lane_state(root, args.lane)
    flow_file = Path(args.flow_file or lane_state.get("flow_file", "")).expanduser()
    if not flow_file.exists():
        return {"status": "missing-flow-file", "flow_file": str(flow_file), "lane": args.lane}

    program = args.program or lane_state.get("program")
    task = args.task or lane_state.get("task")
    metadata = metadata_from_args(args, lane_state)
    db_path = Path(args.db).expanduser()
    indexed = 0
    skipped = 0
    with connect(db_path) as conn:
        init_db(conn)
        now = time.time()
        conn.execute(
            """
            INSERT INTO lanes(lane, program, task, account, profile_dir, proxy_server, flow_file, raw_dir, first_indexed_at, last_indexed_at, note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(lane) DO UPDATE SET
              program=excluded.program,
              task=excluded.task,
              account=excluded.account,
              profile_dir=excluded.profile_dir,
              proxy_server=excluded.proxy_server,
              flow_file=excluded.flow_file,
              raw_dir=excluded.raw_dir,
              last_indexed_at=excluded.last_indexed_at,
              note=excluded.note
            """,
            (
                args.lane,
                program,
                task,
                metadata.get("account_label"),
                lane_state.get("profile_dir"),
                metadata.get("proxy_server"),
                str(flow_file),
                str(flow_file.parent),
                now,
                now,
                args.note,
            ),
        )
        conn.execute(
            """
            UPDATE lanes
            SET run_id=?, agent_id=?, runtime_host=?, proxy_host=?, proxy_port=?,
                transport=?, account_label=?, browser_profile_id=?, session_source=?
            WHERE lane=?
            """,
            (
                metadata.get("run_id"),
                metadata.get("agent_id"),
                metadata.get("runtime_host"),
                metadata.get("proxy_host"),
                metadata.get("proxy_port"),
                metadata.get("transport"),
                metadata.get("account_label"),
                metadata.get("browser_profile_id"),
                metadata.get("session_source"),
                args.lane,
            ),
        )
        with flow_file.open("rb") as handle:
            reader = FlowReader(handle)
            for flow in reader.stream():
                record = flow_record(flow, args.lane, program, task, flow_file, metadata)
                if not record:
                    skipped += 1
                    continue
                request_id = upsert_request(conn, record)
                if args.store_full_requests:
                    packet = request_packet_record(flow, record["flow_uid"])
                    if packet:
                        upsert_request_packet(conn, request_id, packet)
                indexed += 1
        conn.execute(
            "UPDATE lanes SET request_count=(SELECT COUNT(*) FROM requests WHERE lane=?) WHERE lane=?",
            (args.lane, args.lane),
        )
        conn.commit()
    return {
        "status": "indexed",
        "lane": args.lane,
        "program": program,
        "task": task,
        "db": str(db_path),
        "flow_file": str(flow_file),
        "indexed": indexed,
        "skipped": skipped,
    }


def query_requests(args: argparse.Namespace) -> dict[str, Any]:
    db_path = Path(args.db).expanduser()
    if not db_path.exists():
        return {"status": "missing-db", "db": str(db_path), "rows": []}
    clauses = []
    values: list[Any] = []
    if args.program:
        clauses.append("program = ?")
        values.append(args.program)
    if args.lane:
        clauses.append("lane = ?")
        values.append(args.lane)
    if args.run_id:
        clauses.append("run_id = ?")
        values.append(args.run_id)
    if args.agent_id:
        clauses.append("agent_id = ?")
        values.append(args.agent_id)
    if args.account_label:
        clauses.append("account_label = ?")
        values.append(args.account_label)
    if args.host:
        clauses.append("host LIKE ?")
        values.append(args.host)
    if args.method:
        clauses.append("method = ?")
        values.append(args.method.upper())
    if args.path:
        clauses.append("path_key LIKE ?")
        values.append(args.path)
    if args.param:
        clauses.append("id IN (SELECT request_id FROM params WHERE name = ?)")
        values.append(args.param)
    if args.no_background:
        clauses.append("tags_json NOT LIKE ?")
        values.append("%browser-background%")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
        SELECT id, flow_uid, lane, program, task, method, scheme, host, port, path_key, status_code,
               response_content_type, response_size, has_authorization, has_cookie,
               run_id, agent_id, account_label, runtime_host, proxy_host, proxy_port,
               transport, browser_profile_id, session_source,
               query_names_json, body_field_names_json, tags_json, raw_flow_file
        FROM requests
        {where}
        ORDER BY ts_start DESC
        LIMIT ?
    """
    values.append(args.limit)
    with connect(db_path) as conn:
        rows = [dict(row) for row in conn.execute(sql, values).fetchall()]
    for row in rows:
        for key in ("query_names_json", "body_field_names_json", "tags_json"):
            row[key.removesuffix("_json")] = json.loads(row.pop(key))
    return {"status": "ok", "db": str(db_path), "count": len(rows), "rows": rows}


def lane_summary(args: argparse.Namespace) -> dict[str, Any]:
    db_path = Path(args.db).expanduser()
    if not db_path.exists():
        return {"status": "missing-db", "db": str(db_path), "lanes": []}
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT lane, program, task, run_id, agent_id, account_label, proxy_server,
                   proxy_host, proxy_port, transport, browser_profile_id, session_source,
                   flow_file, request_count, last_indexed_at
            FROM lanes
            ORDER BY last_indexed_at DESC
            LIMIT ?
            """,
            (args.limit,),
        ).fetchall()
    return {"status": "ok", "db": str(db_path), "lanes": [dict(row) for row in rows]}


def active_lease_where(now: float) -> str:
    return "status = 'active' AND (expires_at IS NULL OR expires_at > ?)"


def lease_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


def lease_acquire(args: argparse.Namespace) -> dict[str, Any]:
    db_path = Path(args.db).expanduser()
    now = time.time()
    expires_at = now + args.ttl_seconds if args.ttl_seconds else None
    proxy_host = args.proxy_host
    requested_ports = [args.port] if args.port else list(range(args.port_min, args.port_max + 1))
    with connect(db_path) as conn:
        init_db(conn)
        conn.execute("BEGIN IMMEDIATE")
        for port in requested_ports:
            active = conn.execute(
                f"SELECT * FROM proxy_leases WHERE proxy_port=? AND {active_lease_where(now)}",
                (port, now),
            ).fetchone()
            if active:
                continue
            lane = args.lane or f"{sanitize_lease_part(args.agent_id or 'agent')}-{int(now)}-{port}"
            lease_id = args.lease_id or lane
            existing = conn.execute(
                f"SELECT * FROM proxy_leases WHERE (lease_id=? OR lane=?) AND {active_lease_where(now)}",
                (lease_id, lane, now),
            ).fetchone()
            if existing:
                conn.rollback()
                return {"status": "lease-unavailable", "db": str(db_path), "lease": lease_row(existing)}
            proxy_server = args.proxy_server or f"http://{proxy_host}:{port}"
            conn.execute(
                """
                INSERT INTO proxy_leases(
                    lease_id, lane, proxy_host, proxy_port, proxy_server, agent_id,
                    run_id, program, task, account_label, runtime_host, status,
                    started_at, expires_at, updated_at, note
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
                """,
                (
                    lease_id,
                    lane,
                    proxy_host,
                    port,
                    proxy_server,
                    args.agent_id,
                    args.run_id,
                    args.program,
                    args.task,
                    args.account_label,
                    args.runtime_host,
                    now,
                    expires_at,
                    now,
                    args.note,
                ),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM proxy_leases WHERE lease_id=?", (lease_id,)).fetchone()
            return {"status": "leased", "db": str(db_path), "lease": lease_row(row)}
        conn.rollback()
    return {
        "status": "no-free-port",
        "db": str(db_path),
        "proxy_host": proxy_host,
        "port_min": args.port_min,
        "port_max": args.port_max,
    }


def lease_list(args: argparse.Namespace) -> dict[str, Any]:
    db_path = Path(args.db).expanduser()
    now = time.time()
    with connect(db_path) as conn:
        init_db(conn)
        clauses = []
        values: list[Any] = []
        if args.active:
            clauses.append(active_lease_where(now))
            values.append(now)
        if args.agent_id:
            clauses.append("agent_id = ?")
            values.append(args.agent_id)
        if args.account_label:
            clauses.append("account_label = ?")
            values.append(args.account_label)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = conn.execute(
            f"SELECT * FROM proxy_leases {where} ORDER BY started_at DESC LIMIT ?",
            (*values, args.limit),
        ).fetchall()
    return {"status": "ok", "db": str(db_path), "leases": [dict(row) for row in rows]}


def lease_release(args: argparse.Namespace) -> dict[str, Any]:
    db_path = Path(args.db).expanduser()
    selectors = []
    values: list[Any] = []
    if args.lease_id:
        selectors.append("lease_id = ?")
        values.append(args.lease_id)
    if args.lane:
        selectors.append("lane = ?")
        values.append(args.lane)
    if args.port:
        selectors.append("proxy_port = ?")
        values.append(args.port)
    if not selectors:
        return {"status": "missing-selector", "db": str(db_path)}
    where = " OR ".join(selectors)
    with connect(db_path) as conn:
        init_db(conn)
        rows = [dict(row) for row in conn.execute(f"SELECT * FROM proxy_leases WHERE {where}", values).fetchall()]
        conn.execute(f"DELETE FROM proxy_leases WHERE {where}", values)
        conn.commit()
    return {"status": "released", "db": str(db_path), "count": len(rows), "released": rows}


def sanitize_lease_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")
    return cleaned or "agent"


def export_request_packet(args: argparse.Namespace) -> dict[str, Any]:
    db_path = Path(args.db).expanduser()
    if not db_path.exists():
        return {"status": "missing-db", "db": str(db_path)}
    if not args.output and not args.allow_sensitive_stdout:
        return {
            "status": "missing-output",
            "db": str(db_path),
            "message": "Refusing to print a full request packet without --allow-sensitive-stdout.",
        }
    clauses = []
    values: list[Any] = []
    if args.id is not None:
        clauses.append("p.request_id = ?")
        values.append(args.id)
    if args.flow_uid:
        clauses.append("p.flow_uid = ?")
        values.append(args.flow_uid)
    if not clauses:
        return {"status": "missing-selector", "db": str(db_path)}
    with connect(db_path) as conn:
        row = conn.execute(
            f"""
            SELECT p.*, r.lane, r.program, r.task
            FROM request_packets p
            JOIN requests r ON r.id = p.request_id
            WHERE {' AND '.join(clauses)}
            LIMIT 1
            """,
            values,
        ).fetchone()
    if not row:
        return {"status": "not-found", "db": str(db_path)}
    packet = dict(row)
    body = packet.pop("body") or b""
    packet["headers"] = json.loads(packet.pop("headers_json"))
    packet["body_base64"] = base64.b64encode(body).decode("ascii")
    packet["body_size"] = len(body)
    packet["warning"] = "This packet may contain cookies, bearer tokens, CSRF tokens, API keys, or request body secrets. Do not paste it into prompts or chat."
    rendered = json.dumps(packet, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered)
        return {"status": "exported", "db": str(db_path), "output": str(output), "request_id": packet["request_id"]}
    print(rendered, end="")
    return {"status": "printed", "db": str(db_path), "request_id": packet["request_id"]}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Index, query, and export local mitmproxy lane data.")
    parser.add_argument("--db", default=str(DEFAULT_STORE), help="SQLite proxy store path.")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Initialize the proxy store.")
    init.set_defaults(func=lambda args: (init_db(connect(Path(args.db).expanduser())) or {"status": "initialized", "db": args.db}))

    index = sub.add_parser("index-lane", help="Index one mitmproxy lane flow file.")
    index.add_argument("--lane", required=True)
    index.add_argument("--lane-root", default=str(DEFAULT_LANE_ROOT))
    index.add_argument("--flow-file")
    index.add_argument("--program")
    index.add_argument("--task")
    index.add_argument("--run-id")
    index.add_argument("--agent-id")
    index.add_argument("--account-label")
    index.add_argument("--runtime-host")
    index.add_argument("--proxy-host")
    index.add_argument("--proxy-port", type=int)
    index.add_argument("--proxy-server")
    index.add_argument("--transport", default="browser")
    index.add_argument("--browser-profile-id")
    index.add_argument("--session-source")
    index.add_argument("--note")
    index.add_argument(
        "--no-full-requests",
        dest="store_full_requests",
        action="store_false",
        help="Only index sanitized metadata; do not store replay packets.",
    )
    index.set_defaults(func=index_lane, store_full_requests=True)

    query = sub.add_parser("query", help="Query sanitized request summaries.")
    query.add_argument("--program")
    query.add_argument("--lane")
    query.add_argument("--run-id")
    query.add_argument("--agent-id")
    query.add_argument("--account-label")
    query.add_argument("--host", help="SQL LIKE pattern, e.g. %.example.com")
    query.add_argument("--method")
    query.add_argument("--path", help="SQL LIKE pattern for path, e.g. /api/%")
    query.add_argument("--param")
    query.add_argument("--no-background", action="store_true")
    query.add_argument("--limit", type=int, default=25)
    query.set_defaults(func=query_requests)

    lanes = sub.add_parser("lanes", help="List indexed lanes.")
    lanes.add_argument("--limit", type=int, default=25)
    lanes.set_defaults(func=lane_summary)

    leases = sub.add_parser("leases", help="List active or historical proxy leases.")
    leases.add_argument("--active", action="store_true", help="Only show active, non-expired leases.")
    leases.add_argument("--agent-id")
    leases.add_argument("--account-label")
    leases.add_argument("--limit", type=int, default=25)
    leases.set_defaults(func=lease_list)

    acquire = sub.add_parser("lease-acquire", help="Acquire an active proxy lane lease.")
    acquire.add_argument("--lease-id")
    acquire.add_argument("--lane")
    acquire.add_argument("--proxy-host", default=DEFAULT_PROXY_HOST)
    acquire.add_argument("--proxy-server")
    acquire.add_argument("--port", type=int)
    acquire.add_argument("--port-min", type=int, default=DEFAULT_AGENT_PORT_MIN)
    acquire.add_argument("--port-max", type=int, default=DEFAULT_AGENT_PORT_MAX)
    acquire.add_argument("--agent-id")
    acquire.add_argument("--run-id")
    acquire.add_argument("--program")
    acquire.add_argument("--task")
    acquire.add_argument("--account-label")
    acquire.add_argument("--runtime-host")
    acquire.add_argument("--ttl-seconds", type=int, default=6 * 60 * 60)
    acquire.add_argument("--note")
    acquire.set_defaults(func=lease_acquire)

    release = sub.add_parser("lease-release", help="Release an active proxy lane lease.")
    selector = release.add_mutually_exclusive_group(required=True)
    selector.add_argument("--lease-id")
    selector.add_argument("--lane")
    selector.add_argument("--port", type=int)
    release.set_defaults(func=lease_release)

    export = sub.add_parser("export-request", help="Export one full captured request packet for local replay.")
    selector = export.add_mutually_exclusive_group(required=True)
    selector.add_argument("--id", type=int, help="Request id from the sanitized query output.")
    selector.add_argument("--flow-uid", help="Flow uid from the sanitized query output.")
    export.add_argument("--output", help="Write JSON packet to this local file.")
    export.add_argument(
        "--allow-sensitive-stdout",
        action="store_true",
        help="Explicitly allow printing the full request packet to stdout.",
    )
    export.set_defaults(func=export_request_packet)

    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = args.func(args)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{result.get('status')}: {result.get('db', '')}")
        if result.get("lease"):
            print(json.dumps(result["lease"], sort_keys=True))
        for row in result.get("rows", result.get("lanes", result.get("leases", []))):
            print(json.dumps(row, sort_keys=True))
    return 0 if result.get("status") not in {"missing-flow-file", "missing-db", "missing-output", "missing-selector", "not-found"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
