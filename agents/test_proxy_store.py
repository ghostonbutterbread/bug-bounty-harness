from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import stat
import subprocess
import sys
import types
from argparse import Namespace
from pathlib import Path

import pytest


def load_proxy_store():
    root = Path(__file__).resolve().parents[1]
    script = root / "skills" / "chromium-test" / "scripts" / "proxy_store.py"
    spec = importlib.util.spec_from_file_location("proxy_store", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_connect_creates_and_repairs_private_default_store(tmp_path, monkeypatch):
    module = load_proxy_store()
    db = tmp_path / "proxy-store" / "proxy.sqlite"
    monkeypatch.setattr(module, "DEFAULT_STORE", db)
    previous_umask = os.umask(0o022)
    try:
        with module.connect(db) as conn:
            module.init_db(conn)
        assert stat.S_IMODE(db.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(db.stat().st_mode) == 0o600

        os.chmod(db.parent, 0o755)
        os.chmod(db, 0o644)
        with module.connect(db) as conn:
            assert conn.execute("SELECT 1").fetchone()[0] == 1
        assert stat.S_IMODE(db.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(db.stat().st_mode) == 0o600
    finally:
        os.umask(previous_umask)


def test_connect_repairs_existing_sidecars_before_sqlite_opens(tmp_path, monkeypatch):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"
    with module.connect(db) as conn:
        module.init_db(conn)
    for suffix in ("-wal", "-shm"):
        Path(f"{db}{suffix}").write_bytes(b"fixture")
        os.chmod(f"{db}{suffix}", 0o644)
    original_connect = module.sqlite3.connect

    def checked_connect(path):
        assert all(stat.S_IMODE(Path(f"{db}{suffix}").stat().st_mode) == 0o600
                   for suffix in ("-wal", "-shm"))
        return original_connect(path)

    monkeypatch.setattr(module.sqlite3, "connect", checked_connect)
    with module.connect(db) as conn:
        assert conn.execute("SELECT 1").fetchone()[0] == 1


def test_connect_repairs_read_only_existing_sidecars(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"
    with module.connect(db) as conn:
        module.init_db(conn)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{db}{suffix}")
        sidecar.write_bytes(b"fixture")
        os.chmod(sidecar, 0o444)

    with module.connect(db, read_only=True) as conn:
        assert conn.execute("SELECT 1").fetchone()[0] == 1
    for suffix in ("-wal", "-shm"):
        assert stat.S_IMODE(Path(f"{db}{suffix}").stat().st_mode) == 0o400


def test_writable_connect_repairs_read_only_existing_sidecars(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"
    with module.connect(db) as conn:
        module.init_db(conn)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{db}{suffix}")
        sidecar.write_bytes(b"fixture")
        os.chmod(sidecar, 0o444)

    with module.connect(db) as conn:
        assert conn.execute("SELECT 1").fetchone()[0] == 1
    for suffix in ("-wal", "-shm"):
        assert stat.S_IMODE(Path(f"{db}{suffix}").stat().st_mode) == 0o600


def test_connect_keeps_sqlite_created_sidecars_private(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"
    previous_umask = os.umask(0o022)
    try:
        with module.connect(db) as conn:
            module.init_db(conn)
            conn.execute("INSERT INTO lanes(lane) VALUES ('fixture')")
            conn.commit()
            for suffix in ("-wal", "-shm"):
                sidecar = Path(f"{db}{suffix}")
                assert sidecar.exists()
                assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600
    finally:
        os.umask(previous_umask)


def test_connect_refuses_symlinked_default_directory_without_chmod(tmp_path, monkeypatch):
    module = load_proxy_store()
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    os.chmod(shared, 0o755)
    dedicated = tmp_path / "proxy-store"
    dedicated.symlink_to(shared, target_is_directory=True)
    db = dedicated / "proxy.sqlite"
    monkeypatch.setattr(module, "DEFAULT_STORE", db)

    with pytest.raises(OSError):
        module.connect(db)
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755
    assert not (shared / "proxy.sqlite").exists()


@pytest.mark.parametrize("mode", [0o770, 0o757])
def test_connect_rejects_attacker_writable_custom_parent(tmp_path, mode):
    module = load_proxy_store()
    parent = tmp_path / "shared"
    parent.mkdir()
    os.chmod(parent, mode)
    db = parent / "proxy.sqlite"

    with pytest.raises(OSError):
        module.connect(db)
    assert not db.exists()
    assert stat.S_IMODE(parent.stat().st_mode) == mode


def test_query_and_export_read_only_custom_database(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"
    with module.connect(db) as conn:
        module.init_db(conn)
        conn.execute("INSERT INTO requests(flow_uid,lane,indexed_at) VALUES ('f1','fixture',1)")
        request_id = conn.execute("SELECT id FROM requests").fetchone()[0]
        conn.execute("INSERT INTO request_packets(request_id,flow_uid,method,indexed_at) VALUES (?, 'f1', 'GET', 1)", (request_id,))
        conn.commit()
    os.chmod(db, 0o444)

    query = module.query_requests(Namespace(
        db=str(db), program=None, lane=None, run_id=None, agent_id=None,
        account_label=None, host=None, method=None, path=None, param=None,
        no_background=False, limit=10,
    ))
    export = module.export_request_packet(Namespace(
        db=str(db), id=request_id, flow_uid=None, output=str(tmp_path / "out.json"),
        allow_sensitive_stdout=False,
    ))
    assert query["count"] == 1
    assert export["status"] == "exported"
    assert stat.S_IMODE(db.stat().st_mode) == 0o400


def test_init_db_creates_core_tables(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"

    with module.connect(db) as conn:
        module.init_db(conn)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

    assert {"lanes", "requests", "params", "request_packets", "proxy_leases"}.issubset(tables)
    with module.connect(db) as conn:
        request_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(requests)").fetchall()
        }
    assert {"run_id", "agent_id", "account_label", "proxy_host", "proxy_port", "transport"}.issubset(
        request_columns
    )


def test_upsert_request_stores_only_sanitized_metadata(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"
    record = {
        "flow_uid": "flow-1",
        "lane": "lane-a",
        "program": "demo",
        "task": "smoke",
        "ts_start": 1.0,
        "ts_end": 2.0,
        "scheme": "https",
        "host": "example.com",
        "port": 443,
        "method": "POST",
        "path": "/api/item",
        "path_key": "/api/item",
        "url_no_query": "https://example.com/api/item",
        "query_names_json": module.json_dumps(["id", "token"]),
        "request_header_names_json": module.json_dumps(["authorization", "cookie", "content-type"]),
        "response_header_names_json": module.json_dumps(["content-type"]),
        "request_content_type": "application/json",
        "response_content_type": "application/json",
        "status_code": 200,
        "response_size": 42,
        "request_size": 20,
        "has_authorization": 1,
        "has_cookie": 1,
        "has_sensitive_headers": 1,
        "body_field_names_json": module.json_dumps(["name"]),
        "tags_json": module.json_dumps(["stateful-method"]),
        "raw_flow_file": "/tmp/flows.mitm",
        "indexed_at": 3.0,
        "_query_names": ["id", "token"],
        "_body_field_names": ["name"],
    }

    with module.connect(db) as conn:
        module.init_db(conn)
        module.upsert_request(conn, record)
        conn.commit()
        row = conn.execute("SELECT * FROM requests").fetchone()
        params = {
            item["name"]
            for item in conn.execute("SELECT name FROM params").fetchall()
        }

    dumped = " ".join(str(value) for value in dict(row).values())
    assert "secret-value" not in dumped
    assert "Bearer" not in dumped
    assert row["has_authorization"] == 1
    assert row["has_cookie"] == 1
    assert params == {"id", "name", "token"}


def test_full_request_packet_can_be_exported_to_file_without_query_leak(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"
    output = tmp_path / "packet.json"
    secret_cookie = "session=secret-value"

    with module.connect(db) as conn:
        module.init_db(conn)
        conn.execute(
            """
            INSERT INTO requests(flow_uid,lane,program,method,host,path_key,query_names_json,request_header_names_json,response_header_names_json,body_field_names_json,tags_json,indexed_at,has_cookie)
            VALUES ('f1','lane-a','demo','POST','example.com','/api/item','["id"]','["cookie"]','[]','["name"]','[]',1,1)
            """
        )
        request_id = conn.execute("SELECT id FROM requests").fetchone()["id"]
        module.upsert_request_packet(
            conn,
            request_id,
            {
                "flow_uid": "f1",
                "method": "POST",
                "scheme": "https",
                "host": "example.com",
                "port": 443,
                "path": "/api/item?id=123",
                "full_url": "https://example.com/api/item?id=123",
                "http_version": "HTTP/2.0",
                "headers_json": module.json_dumps([
                    {"name": "Cookie", "value": secret_cookie},
                    {"name": "Content-Type", "value": "application/json"},
                ]),
                "body": b'{"name":"private"}',
                "captured_at": 1.0,
                "indexed_at": 2.0,
            },
        )
        conn.commit()

    query_args = type(
        "Args",
        (),
        {
            "db": str(db),
            "program": "demo",
            "lane": None,
            "run_id": None,
            "agent_id": None,
            "account_label": None,
            "host": None,
            "method": "POST",
            "path": None,
            "param": None,
            "no_background": False,
            "limit": 10,
        },
    )()
    query_result = module.query_requests(query_args)
    dumped_query = str(query_result)
    assert secret_cookie not in dumped_query
    assert "private" not in dumped_query
    assert query_result["rows"][0]["id"] == request_id

    export_args = type(
        "Args",
        (),
        {
            "db": str(db),
            "id": request_id,
            "flow_uid": None,
            "output": str(output),
            "allow_sensitive_stdout": False,
        },
    )()
    export_result = module.export_request_packet(export_args)

    assert export_result["status"] == "exported"
    packet = output.read_text()
    assert secret_cookie in packet
    assert "eyJuYW1lIjoicHJpdmF0ZSJ9" in packet


def test_export_request_packet_refuses_stdout_without_explicit_flag(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"
    with module.connect(db) as conn:
        module.init_db(conn)

    args = type(
        "Args",
        (),
        {
            "db": str(db),
            "id": 1,
            "flow_uid": None,
            "output": None,
            "allow_sensitive_stdout": False,
        },
    )()

    result = module.export_request_packet(args)

    assert result["status"] == "missing-output"


def test_query_filters_method_and_param(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"
    with module.connect(db) as conn:
        module.init_db(conn)
        conn.execute(
            """
            INSERT INTO requests(flow_uid,lane,program,method,host,path_key,query_names_json,request_header_names_json,response_header_names_json,body_field_names_json,tags_json,indexed_at)
            VALUES ('f1','lane-a','demo','POST','example.com','/api/item','["id"]','[]','[]','[]','[]',1)
            """
        )
        request_id = conn.execute("SELECT id FROM requests").fetchone()["id"]
        conn.execute(
            "INSERT INTO params(request_id, location, name) VALUES (?, 'query', 'id')",
            (request_id,),
        )
        conn.commit()

    args = type(
        "Args",
        (),
        {
            "db": str(db),
            "program": "demo",
            "lane": None,
            "run_id": None,
            "agent_id": None,
            "account_label": None,
            "host": None,
            "method": "POST",
            "path": None,
            "param": "id",
            "no_background": False,
            "limit": 10,
        },
    )()
    result = module.query_requests(args)

    assert result["count"] == 1
    assert result["rows"][0]["path_key"] == "/api/item"


def test_lease_acquire_rejects_task_proxy_overflow_port(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"
    args = type("Args", (), {
        "db": str(db), "lease_id": None, "lane": None, "proxy_host": "hoster",
        "proxy_server": None, "port": 8091, "port_min": 8081, "port_max": 8090,
        "agent_id": "standalone", "run_id": "run", "program": "demo", "task": "test",
        "account_label": "fixture", "runtime_host": "hoster", "ttl_seconds": 3600,
        "note": None,
    })()

    result = module.lease_acquire(args)

    assert result["status"] == "task-port-reserved"
    assert result["proxy_port"] == 8091
    assert not db.exists()


def test_lease_acquire_rejects_task_proxy_overflow_at_cli(tmp_path):
    script = Path(__file__).resolve().parents[1] / "skills/chromium-test/scripts/proxy_store.py"
    db = tmp_path / "proxy.sqlite"

    result = subprocess.run(
        [sys.executable, str(script), "--db", str(db), "--json", "lease-acquire", "--port", "8091"],
        capture_output=True, text=True, check=False,
    )

    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "task-port-reserved"
    assert not db.exists()


def test_lease_acquire_skips_task_proxy_overflow_in_custom_range(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"
    args = type("Args", (), {
        "db": str(db), "lease_id": None, "lane": None, "proxy_host": "hoster",
        "proxy_server": None, "port": None, "port_min": 8091, "port_max": 8095,
        "agent_id": "standalone", "run_id": "run", "program": "demo", "task": "test",
        "account_label": "fixture", "runtime_host": "hoster", "ttl_seconds": 3600,
        "note": None,
    })()

    result = module.lease_acquire(args)

    assert result["status"] == "no-free-port"
    with module.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM proxy_leases").fetchone()[0] == 0


def test_lease_acquire_skips_active_port_and_release_frees_it(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"

    base_args = {
        "db": str(db),
        "lease_id": None,
        "lane": None,
        "proxy_host": "hoster",
        "proxy_server": None,
        "port": None,
        "port_min": 8081,
        "port_max": 8082,
        "agent_id": "agent-a",
        "run_id": "run-a",
        "program": "demo",
        "task": "xss",
        "account_label": "qa-user",
        "runtime_host": "openclaw",
        "ttl_seconds": 3600,
        "note": None,
    }

    first = module.lease_acquire(type("Args", (), base_args)())
    second = module.lease_acquire(type("Args", (), {**base_args, "agent_id": "agent-b", "run_id": "run-b"})())

    assert first["status"] == "leased"
    assert first["lease"]["proxy_port"] == 8081
    assert first["lease"]["proxy_server"] == "http://hoster:8081"
    assert second["status"] == "leased"
    assert second["lease"]["proxy_port"] == 8082

    release = module.lease_release(
        type(
            "Args",
            (),
            {
                "db": str(db),
                "lease_id": first["lease"]["lease_id"],
                "lane": None,
                "port": None,
                "mark_released": False,
            },
        )()
    )
    third = module.lease_acquire(type("Args", (), {**base_args, "agent_id": "agent-c", "run_id": "run-c"})())

    assert release["status"] == "released"
    assert release["count"] == 1
    assert third["status"] == "leased"
    assert third["lease"]["proxy_port"] == 8081


def test_query_filters_account_and_run_attribution(tmp_path):
    module = load_proxy_store()
    db = tmp_path / "proxy.sqlite"
    with module.connect(db) as conn:
        module.init_db(conn)
        conn.execute(
            """
            INSERT INTO requests(
                flow_uid,lane,program,task,run_id,agent_id,account_label,
                proxy_host,proxy_port,transport,method,host,path_key,
                query_names_json,request_header_names_json,response_header_names_json,
                body_field_names_json,tags_json,indexed_at
            )
            VALUES (
                'f1','lane-a','demo','idor','run-1','agent-1','qa-user',
                'hoster',8081,'browser','GET','example.com','/api/me',
                '[]','[]','[]','[]','[]',1
            )
            """
        )
        conn.execute(
            """
            INSERT INTO requests(
                flow_uid,lane,program,task,run_id,agent_id,account_label,
                proxy_host,proxy_port,transport,method,host,path_key,
                query_names_json,request_header_names_json,response_header_names_json,
                body_field_names_json,tags_json,indexed_at
            )
            VALUES (
                'f2','lane-b','demo','idor','run-2','agent-2','other-user',
                'hoster',8082,'browser','GET','example.com','/api/me',
                '[]','[]','[]','[]','[]',2
            )
            """
        )
        conn.commit()

    args = type(
        "Args",
        (),
        {
            "db": str(db),
            "program": "demo",
            "lane": None,
            "run_id": "run-1",
            "agent_id": None,
            "account_label": "qa-user",
            "host": None,
            "method": None,
            "path": None,
            "param": None,
            "no_background": False,
            "limit": 10,
        },
    )()
    result = module.query_requests(args)

    assert result["count"] == 1
    assert result["rows"][0]["run_id"] == "run-1"
    assert result["rows"][0]["account_label"] == "qa-user"
    assert result["rows"][0]["proxy_port"] == 8081


def test_index_lane_without_flow_path_returns_missing_file_before_open(monkeypatch, tmp_path):
    module = load_proxy_store()
    io = types.ModuleType("mitmproxy.io")
    setattr(io, "FlowReader", object)
    monkeypatch.setitem(sys.modules, "mitmproxy", types.ModuleType("mitmproxy"))
    monkeypatch.setitem(sys.modules, "mitmproxy.io", io)
    db = tmp_path / "proxy.sqlite"

    result = module.index_lane(Namespace(
        lane_root=str(tmp_path), lane="empty-lane", flow_file=None, db=str(db),
        program=None, task=None, note=None,
    ))

    assert result == {"status": "missing-flow-file", "flow_file": "", "lane": "empty-lane"}
    assert not db.exists()


def test_index_lane_with_directory_flow_path_returns_missing_file(monkeypatch, tmp_path):
    module = load_proxy_store()
    io = types.ModuleType("mitmproxy.io")
    setattr(io, "FlowReader", object)
    monkeypatch.setitem(sys.modules, "mitmproxy", types.ModuleType("mitmproxy"))
    monkeypatch.setitem(sys.modules, "mitmproxy.io", io)
    db = tmp_path / "proxy.sqlite"

    result = module.index_lane(Namespace(
        lane_root=str(tmp_path), lane="directory-lane", flow_file=str(tmp_path), db=str(db),
        program=None, task=None, note=None,
    ))

    assert result == {"status": "missing-flow-file", "flow_file": str(tmp_path), "lane": "directory-lane"}
    assert not db.exists()
