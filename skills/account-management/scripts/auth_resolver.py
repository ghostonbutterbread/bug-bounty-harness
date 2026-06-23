#!/usr/bin/env python3
"""Resolve owned account auth handoffs without exposing secret values."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any


DEFAULT_ROUTE_TABLE = Path(
    "/home/ryushe/projects/ai-policies/skills/proxy-routing-policy/data/proxy_routes.json"
)
DEFAULT_HOSTER_SSH_KEY = Path("/home/ryushe/.ssh/hoster")
AUTH_SEED_REF_PREFIXES = ("auth-seed:", "auth_seed:", "file:")
COOKIE_SPLIT_RE = re.compile(r";\s*")
AUTH_HEADER_ALLOWLIST = {
    "authorization",
    "x-csrf-token",
    "x-xsrf-token",
    "x-requested-with",
}
HEADER_PREFIX_ALLOWLIST = ("x-canva-",)
HEADER_DENYLIST = {
    "cookie",
    "host",
    "content-length",
    "x-pwnfox-color",
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "connection",
    "origin",
    "referer",
    "priority",
}
SAFE_ACCOUNT_FIELDS = (
    "alias",
    "email",
    "username",
    "user_id",
    "role",
    "tenant_id",
    "pwnfox_color",
    "credential_ref",
    "auth_seed_ref",
    "auth_refresh_source",
    "auth_refresh_hint",
    "auth_check_url",
    "auth_host_filter",
)


def shared_base() -> Path:
    return Path(os.environ.get("HARNESS_SHARED_BASE", "~/Shared/bounty_recon")).expanduser()


def inventory_path(program: str) -> Path:
    return shared_base() / program / "credentials" / "account_inventory.json"


def load_json_file(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"JSON file is invalid: {path}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"JSON file must contain an object: {path}")
    return data


def load_inventory(program: str) -> dict[str, Any]:
    return load_json_file(inventory_path(program))


def current_runtime(explicit: str | None = None) -> str:
    if explicit:
        return explicit.strip().lower()
    runtime = os.environ.get("GHOST_AGENT_RUNTIME")
    if runtime:
        return runtime.strip().lower()
    return socket.gethostname().strip().lower()


def route_table_path(explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    return DEFAULT_ROUTE_TABLE


def load_route_table(path: Path) -> dict[str, Any]:
    data = load_json_file(path)
    data.setdefault("default_lane", "agent")
    data.setdefault("runtimes", {})
    return data


def infer_ryushe_proxy_mode(runtime: str, route: dict[str, Any]) -> str:
    configured = route.get("ryushe_proxy_mode")
    if configured:
        return str(configured)
    if runtime == "hoster":
        return "direct"
    if runtime in {"openclaw", "ghostonbread"}:
        return "hoster-ssh"
    if runtime in {"ryushespc", "abommie"}:
        return "same-host-localhost"
    return "none"


def resolve_runtime_route(args: argparse.Namespace) -> dict[str, Any]:
    runtime = current_runtime(args.runtime)
    hostname = socket.gethostname().strip().lower()
    table_path = route_table_path(args.route_table)
    table = load_route_table(table_path)
    runtimes = table.get("runtimes") if isinstance(table.get("runtimes"), dict) else {}
    route = runtimes.get(runtime) if isinstance(runtimes.get(runtime), dict) else None
    matched_by = "runtime"
    if route is None and hostname in runtimes and isinstance(runtimes[hostname], dict):
        route = runtimes[hostname]
        matched_by = "hostname"
    if route is None:
        route = {}
        matched_by = "fallback"

    mode = infer_ryushe_proxy_mode(runtime, route)
    ryushe_endpoint = route.get("ryushe_proxy_mcp")
    if not ryushe_endpoint and mode == "direct":
        ryushe_endpoint = "http://ryushespc:3333/mcp"
    elif not ryushe_endpoint and mode == "same-host-localhost":
        ryushe_endpoint = "http://localhost:3333/mcp"

    return {
        "runtime": runtime,
        "hostname": hostname,
        "matched_by": matched_by,
        "route_table": str(table_path),
        "agent_lane": route.get("lane") or table.get("default_lane") or "agent",
        "agent_proxy_server": route.get("browser_proxy") or default_agent_proxy(runtime),
        "agent_mcp": route.get("caido_mcp"),
        "ryushe_proxy_mode": mode,
        "ryushe_proxy_endpoint": ryushe_endpoint,
        "can_query_ryushe_proxy": mode in {"direct", "hoster-ssh", "same-host-localhost"},
    }


def default_agent_proxy(runtime: str) -> str:
    if runtime in {"hoster", "ryushespc", "abommie"}:
        return "http://localhost:8080"
    return "http://hoster:8080"


def safe_account_record(account: dict[str, Any]) -> dict[str, Any]:
    safe = {key: account.get(key) for key in SAFE_ACCOUNT_FIELDS if account.get(key) is not None}
    ref = account.get("auth_seed_ref") or account.get("credential_ref")
    safe["credential_ref_type"] = credential_ref_type(ref)
    return safe


def credential_ref_type(ref: Any) -> str:
    if not ref:
        return "none"
    text = str(ref)
    if text.startswith(("auth-seed:", "auth_seed:")):
        return "auth-seed"
    if text.startswith("file:"):
        return "file"
    if text.startswith("bitwarden:"):
        return "bitwarden"
    if text.startswith("secret-store:"):
        return "secret-store"
    return "reference"


def resolve_account(inventory: dict[str, Any], selector: str | None, program: str) -> dict[str, Any]:
    if not selector:
        return {"status": "none", "inventory_path": str(inventory_path(program))}
    if not inventory:
        return {"status": "missing-inventory", "selector": selector, "inventory_path": str(inventory_path(program))}

    accounts = inventory.get("accounts")
    if not isinstance(accounts, list):
        accounts = []
    normalized = selector.lower()
    by_alias = {
        str(account.get("alias", "")).lower(): account
        for account in accounts
        if isinstance(account, dict) and account.get("alias")
    }
    if normalized in by_alias:
        return resolved_account(selector, "alias", by_alias[normalized], program)

    for account in accounts:
        if isinstance(account, dict) and str(account.get("pwnfox_color", "")).lower() == normalized:
            return resolved_account(selector, "pwnfox_color", account, program)

    lanes = inventory.get("pwnfox_lanes")
    if isinstance(lanes, list):
        for lane in lanes:
            if not isinstance(lane, dict):
                continue
            if str(lane.get("color", "")).lower() != normalized:
                continue
            alias = str(lane.get("account", "")).lower()
            if alias in by_alias:
                return resolved_account(selector, "pwnfox_lane", by_alias[alias], program)

    return {"status": "not-found", "selector": selector, "inventory_path": str(inventory_path(program))}


def resolved_account(selector: str, matched_by: str, account: dict[str, Any], program: str) -> dict[str, Any]:
    return {
        "status": "resolved",
        "selector": selector,
        "matched_by": matched_by,
        "inventory_path": str(inventory_path(program)),
        "account": account,
    }


def auth_seed_path(account: dict[str, Any] | None) -> Path | None:
    if not account:
        return None
    ref = account.get("auth_seed_ref") or account.get("credential_ref")
    if not ref:
        return None
    text = str(ref)
    for prefix in AUTH_SEED_REF_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    if not text.startswith(("/", "~")):
        return None
    return Path(text).expanduser()


def default_auth_seed_path(program: str, account: dict[str, Any], selector: str) -> Path:
    label = str(account.get("alias") or account.get("pwnfox_color") or selector)
    label = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-").lower() or "account"
    return shared_base() / program / "credentials" / "auth_seeds" / f"{label}.json"


def ensure_auth_seed_ref(program: str, account_alias: str | None, seed_path: Path) -> None:
    if not account_alias:
        return
    path = inventory_path(program)
    data = load_inventory(program)
    changed = False
    for account in data.get("accounts", []):
        if not isinstance(account, dict):
            continue
        if str(account.get("alias", "")) != account_alias:
            continue
        desired = f"auth-seed:{seed_path}"
        if account.get("auth_seed_ref") != desired:
            account["auth_seed_ref"] = desired
            changed = True
        break
    if not changed:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
        tmp_name = handle.name
    Path(tmp_name).replace(path)


def inspect_auth_seed(path: Path | None) -> dict[str, Any]:
    if not path:
        return {"status": "none"}
    if not path.exists():
        return {"status": "missing", "path": str(path)}
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        return {"status": "bad-permissions", "path": str(path), "mode": oct(mode)}
    data = load_json_file(path)
    return {
        "status": "available",
        "path": str(path),
        "mode": oct(mode),
        "cookie_count": len(data.get("cookies", [])) if isinstance(data.get("cookies"), list) else 0,
        "header_names": sorted(str(k) for k in data.get("headers", {}).keys())
        if isinstance(data.get("headers"), dict)
        else [],
        "safe_metadata": {
            key: data.get(key)
            for key in ("account_label", "session_source")
            if data.get(key) is not None
        },
    }


def load_auth_seed_values(path: Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    meta = inspect_auth_seed(path)
    if meta.get("status") != "available":
        return None
    return load_json_file(path)


def cookie_header(seed: dict[str, Any]) -> str | None:
    cookies = seed.get("cookies")
    if not isinstance(cookies, list):
        return None
    pairs = []
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        name = cookie.get("name")
        value = cookie.get("value")
        if name is None or value is None:
            continue
        pairs.append(f"{name}={value}")
    return "; ".join(pairs) if pairs else None


def run_auth_check(url: str | None, method: str, timeout: float, seed_path: Path | None) -> dict[str, Any]:
    if not url:
        return {"status": "skipped", "reason": "no-target-url"}
    seed = load_auth_seed_values(seed_path)
    if not seed:
        return {"status": "skipped", "reason": "no-usable-auth-seed", "url": url}

    headers = {}
    if isinstance(seed.get("headers"), dict):
        headers.update({str(k): str(v) for k, v in seed["headers"].items()})
    cookie = cookie_header(seed)
    if cookie and "Cookie" not in headers:
        headers["Cookie"] = cookie

    request = urllib.request.Request(url, method=method.upper(), headers=headers)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
    try:
        with opener.open(request, timeout=timeout) as response:
            code = int(response.status)
            return {
                "status": "passed" if 200 <= code < 400 else "failed",
                "url": url,
                "method": method.upper(),
                "status_code": code,
            }
    except urllib.error.HTTPError as exc:
        return {
            "status": "failed" if exc.code in {401, 403} else "error",
            "url": url,
            "method": method.upper(),
            "status_code": exc.code,
        }
    except Exception as exc:
        return {
            "status": "error",
            "url": url,
            "method": method.upper(),
            "error_type": exc.__class__.__name__,
        }


def auth_color(account: dict[str, Any], selector: str) -> str:
    hint = str(account.get("auth_refresh_hint") or "")
    if hint.lower().startswith("pwnfox:"):
        return hint.split(":", 1)[1].strip().lower()
    if account.get("pwnfox_color"):
        return str(account["pwnfox_color"]).strip().lower()
    return selector.strip().lower()


def host_filter_from_args(args: argparse.Namespace, account: dict[str, Any] | None) -> str | None:
    explicit = getattr(args, "host_filter", None)
    if explicit:
        return explicit
    if account and account.get("auth_host_filter"):
        return str(account["auth_host_filter"])
    url = getattr(args, "target_url", None) or (account or {}).get("auth_check_url")
    if url:
        parsed = urllib.parse.urlsplit(str(url))
        if parsed.hostname:
            return parsed.hostname
    return None


def build_pwnfox_httpql(color: str, host_filter: str | None = None, require_cookie: bool = False) -> str:
    clauses = [
        'req.raw.cont:"X-PwnFox-Color"',
        f'req.raw.cont:"{color}"',
    ]
    if host_filter:
        clauses.append(f'req.host.cont:"{host_filter}"')
    if require_cookie:
        clauses.append('req.raw.cont:"Cookie:"')
    return " AND ".join(clauses)


def mcp_call(endpoint: str, tool_name: str, arguments: dict[str, Any], timeout: float = 12.0) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8", errors="replace"))
    result = data.get("result") if isinstance(data, dict) else None
    if isinstance(result, dict) and result.get("isError"):
        text = ""
        content = result.get("content")
        if isinstance(content, list) and content and isinstance(content[0], dict):
            text = str(content[0].get("text", ""))
        raise RuntimeError(text or f"MCP tool {tool_name} returned an error")
    return data


def mcp_text_json(data: dict[str, Any]) -> dict[str, Any]:
    content = data.get("result", {}).get("content")
    if not isinstance(content, list) or not content or not isinstance(content[0], dict):
        raise RuntimeError("MCP response did not contain text content")
    text = content[0].get("text")
    if not isinstance(text, str):
        raise RuntimeError("MCP response text was not a string")
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise RuntimeError("MCP response text JSON was not an object")
    return parsed


def list_proxy_requests(endpoint: str, color: str, host_filter: str | None, limit: int) -> list[dict[str, Any]]:
    order = {"target": "req", "field": "created_at", "direction": "desc"}
    for require_cookie in (True, False):
        data = mcp_call(
            endpoint,
            "list_requests",
            {
                "filter": build_pwnfox_httpql(color, host_filter, require_cookie=require_cookie),
                "limit": limit,
                "order": order,
                "serialization": {"include_body": False, "max_text_body_chars": 0},
            },
        )
        parsed = mcp_text_json(data)
        items = parsed.get("items")
        if isinstance(items, list) and items:
            return [item for item in items if isinstance(item, dict)]
    return []


def first_header(headers: dict[str, Any], name: str) -> str | None:
    for key, value in headers.items():
        if str(key).lower() != name.lower():
            continue
        if isinstance(value, list):
            return "; ".join(str(part) for part in value if part is not None)
        return str(value)
    return None


def selected_headers(headers: dict[str, Any]) -> dict[str, str]:
    selected: dict[str, str] = {}
    for key, value in headers.items():
        lower = str(key).lower()
        if lower in HEADER_DENYLIST or lower.startswith("sec-"):
            continue
        if lower not in AUTH_HEADER_ALLOWLIST and not lower.startswith(HEADER_PREFIX_ALLOWLIST):
            continue
        if isinstance(value, list):
            text = ", ".join(str(part) for part in value if part is not None)
        else:
            text = str(value)
        if text:
            selected[str(key)] = text
    return selected


def parse_cookie_header(header: str | None, request_url: str | None, host: str | None) -> list[dict[str, Any]]:
    if not header:
        return []
    cookies: list[dict[str, Any]] = []
    for part in COOKIE_SPLIT_RE.split(header):
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if not name:
            continue
        cookie: dict[str, Any] = {
            "name": name,
            "value": value.strip(),
            "path": "/",
            "secure": True,
        }
        if request_url:
            cookie["url"] = request_url
        elif host:
            cookie["url"] = f"https://{host}/"
        cookies.append(cookie)
    return cookies


def seed_from_proxy_items(
    items: list[dict[str, Any]],
    account: dict[str, Any],
    color: str,
    program: str,
) -> dict[str, Any]:
    for item in items:
        request = item.get("request")
        if not isinstance(request, dict):
            continue
        headers = request.get("headers")
        if not isinstance(headers, dict):
            continue
        cookies = parse_cookie_header(first_header(headers, "Cookie"), request.get("url"), request.get("host"))
        selected = selected_headers(headers)
        if not cookies and not selected:
            continue
        return {
            "status": "found",
            "seed": {
                "account_label": account.get("alias"),
                "pwnfox_color": color,
                "program": program,
                "session_source": "ryushe-proxy",
                "source_request_id": request.get("id") or item.get("id"),
                "source_host": request.get("host"),
                "source_path": request.get("path"),
                "source_time": request.get("created_at") or item.get("time"),
                "cookies": cookies,
                "headers": selected,
            },
            "provenance": {
                "request_id": request.get("id") or item.get("id"),
                "host": request.get("host"),
                "path": request.get("path"),
                "time": request.get("created_at") or item.get("time"),
                "cookie_count": len(cookies),
                "header_names": sorted(selected.keys()),
            },
        }
    return {"status": "no-usable-auth-material", "items_seen": len(items)}


REMOTE_PROXY_QUERY_SCRIPT = r'''
import base64, json, re, sys, urllib.request
COOKIE_SPLIT_RE = re.compile(r";\s*")
AUTH_HEADER_ALLOWLIST = {"authorization", "x-csrf-token", "x-xsrf-token", "x-requested-with"}
HEADER_PREFIX_ALLOWLIST = ("x-canva-",)
HEADER_DENYLIST = {"cookie", "host", "content-length", "x-pwnfox-color", "user-agent", "accept", "accept-encoding", "accept-language", "connection", "origin", "referer", "priority"}
def mcp_call(endpoint, tool_name, arguments):
    payload = {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool_name,"arguments":arguments}}
    req = urllib.request.Request(endpoint, data=json.dumps(payload).encode(), headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream"})
    with urllib.request.urlopen(req, timeout=12) as response:
        data = json.loads(response.read().decode("utf-8", errors="replace"))
    result = data.get("result") if isinstance(data, dict) else None
    if isinstance(result, dict) and result.get("isError"):
        content = result.get("content")
        text = content[0].get("text", "") if isinstance(content, list) and content and isinstance(content[0], dict) else ""
        raise SystemExit(json.dumps({"status":"mcp-error","error":text[:500]}))
    return data
def text_json(data):
    content = data.get("result", {}).get("content")
    text = content[0].get("text") if isinstance(content, list) and content and isinstance(content[0], dict) else None
    return json.loads(text or "{}")
def filt(color, host_filter, require_cookie):
    clauses = ['req.raw.cont:"X-PwnFox-Color"', f'req.raw.cont:"{color}"']
    if host_filter:
        clauses.append(f'req.host.cont:"{host_filter}"')
    if require_cookie:
        clauses.append('req.raw.cont:"Cookie:"')
    return " AND ".join(clauses)
def first_header(headers, name):
    for key, value in headers.items():
        if str(key).lower() == name.lower():
            if isinstance(value, list):
                return "; ".join(str(part) for part in value if part is not None)
            return str(value)
    return None
def selected_headers(headers):
    selected = {}
    for key, value in headers.items():
        lower = str(key).lower()
        if lower in HEADER_DENYLIST or lower.startswith("sec-"):
            continue
        if lower not in AUTH_HEADER_ALLOWLIST and not lower.startswith(HEADER_PREFIX_ALLOWLIST):
            continue
        text = ", ".join(str(part) for part in value if part is not None) if isinstance(value, list) else str(value)
        if text:
            selected[str(key)] = text
    return selected
def parse_cookie_header(header, request_url, host):
    if not header:
        return []
    cookies = []
    for part in COOKIE_SPLIT_RE.split(header):
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if name:
            cookie = {"name": name, "value": value.strip(), "path": "/", "secure": True}
            cookie["url"] = request_url or (f"https://{host}/" if host else None)
            cookies.append({k:v for k,v in cookie.items() if v is not None})
    return cookies
def seed_from_items(items, account, color, program):
    for item in items:
        request = item.get("request") if isinstance(item, dict) else None
        headers = request.get("headers") if isinstance(request, dict) else None
        if not isinstance(headers, dict):
            continue
        cookies = parse_cookie_header(first_header(headers, "Cookie"), request.get("url"), request.get("host"))
        selected = selected_headers(headers)
        if cookies or selected:
            return {"status":"found","seed":{"account_label":account.get("alias"),"pwnfox_color":color,"program":program,"session_source":"ryushe-proxy","source_request_id":request.get("id") or item.get("id"),"source_host":request.get("host"),"source_path":request.get("path"),"source_time":request.get("created_at") or item.get("time"),"cookies":cookies,"headers":selected},"provenance":{"request_id":request.get("id") or item.get("id"),"host":request.get("host"),"path":request.get("path"),"time":request.get("created_at") or item.get("time"),"cookie_count":len(cookies),"header_names":sorted(selected.keys())}}
    return {"status":"no-usable-auth-material","items_seen":len(items)}
args = json.loads(base64.b64decode(sys.argv[1]).decode())
order = {"target":"req","field":"created_at","direction":"desc"}
items = []
for require_cookie in (True, False):
    data = mcp_call(args["endpoint"], "list_requests", {"filter":filt(args["color"], args.get("host_filter"), require_cookie), "limit":args.get("limit", 50), "order":order, "serialization":{"include_body":False,"max_text_body_chars":0}})
    parsed = text_json(data)
    items = [item for item in parsed.get("items", []) if isinstance(item, dict)]
    if items:
        break
print(json.dumps(seed_from_items(items, args["account"], args["color"], args["program"])))
'''


def query_proxy_seed(route: dict[str, Any], account: dict[str, Any], color: str, program: str, host_filter: str | None, limit: int) -> dict[str, Any]:
    mode = route.get("ryushe_proxy_mode")
    endpoint = route.get("ryushe_proxy_endpoint")
    payload = {
        "endpoint": endpoint,
        "account": safe_account_record(account),
        "color": color,
        "program": program,
        "host_filter": host_filter,
        "limit": limit,
    }
    if mode in {"direct", "same-host-localhost"}:
        if not endpoint:
            return {"status": "blocked", "reason": "missing-ryushe-proxy-endpoint"}
        items = list_proxy_requests(str(endpoint), color, host_filter, limit)
        return seed_from_proxy_items(items, account, color, program)
    if mode == "hoster-ssh":
        if not endpoint:
            endpoint = "http://ryushespc:3333/mcp"
            payload["endpoint"] = endpoint
        encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        command = [
            "ssh",
            "-i",
            str(DEFAULT_HOSTER_SSH_KEY),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ControlMaster=no",
            "-T",
            "ryushe@hoster",
            "python3",
            "-",
            encoded,
        ]
        proc = subprocess.run(
            command,
            input=REMOTE_PROXY_QUERY_SCRIPT,
            text=True,
            capture_output=True,
            timeout=35,
            check=False,
        )
        if proc.returncode != 0:
            return {
                "status": "ssh-error",
                "returncode": proc.returncode,
                "stderr": proc.stderr.strip()[-500:],
            }
        try:
            result = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {"status": "ssh-output-invalid"}
        if isinstance(result, dict):
            return result
        return {"status": "ssh-output-invalid"}
    return {"status": "blocked", "reason": "runtime-route-does-not-allow-ryushe-proxy", "ryushe_proxy_mode": mode}


def write_auth_seed(path: Path, seed: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(seed, handle, indent=2, sort_keys=True)
        handle.write("\n")
        tmp_name = handle.name
    os.chmod(tmp_name, 0o600)
    Path(tmp_name).replace(path)
    os.chmod(path, 0o600)


def refresh_from_ryushe_proxy(args: argparse.Namespace) -> dict[str, Any]:
    inventory = load_inventory(args.program)
    resolution = resolve_account(inventory, args.account, args.program)
    account = resolution.get("account") if resolution.get("status") == "resolved" else None
    route = resolve_runtime_route(args)
    if not account:
        return {
            "status": "unresolved-account",
            "program": args.program,
            "account_selector": args.account,
            "account_resolution": {
                key: resolution.get(key)
                for key in ("status", "selector", "matched_by", "inventory_path")
                if resolution.get(key) is not None
            },
            "runtime_route": route,
        }
    if account.get("auth_refresh_source") != "ryushe-proxy":
        return {
            "status": "not-permitted",
            "reason": "account-record-does-not-permit-ryushe-proxy",
            "account": safe_account_record(account),
            "runtime_route": route,
        }
    seed_path = auth_seed_path(account) or default_auth_seed_path(args.program, account, args.account)
    color = auth_color(account, args.account)
    host_filter = host_filter_from_args(args, account)
    query_result = query_proxy_seed(route, account, color, args.program, host_filter, args.limit)
    if query_result.get("status") != "found":
        return {
            "status": "no-matching-proxy-auth",
            "program": args.program,
            "account_selector": args.account,
            "account": safe_account_record(account),
            "runtime_route": route,
            "proxy_query": {k: v for k, v in query_result.items() if k != "seed"},
            "host_filter": host_filter,
            "safe_next": "use Bitwarden fallback or generate fresh traffic in the requested PwnFox color",
        }
    seed = query_result["seed"]
    write_auth_seed(seed_path, seed)
    ensure_auth_seed_ref(args.program, account.get("alias"), seed_path)
    return {
        "status": "refreshed",
        "program": args.program,
        "account_selector": args.account,
        "account": safe_account_record({**account, "auth_seed_ref": f"auth-seed:{seed_path}"}),
        "runtime_route": route,
        "auth_seed": inspect_auth_seed(seed_path),
        "proxy_provenance": query_result.get("provenance", {}),
        "host_filter": host_filter,
        "safe_next": "use auth_seed.path through chromium-test/proxy-curl and keep replay on the agent MITM lane",
    }


def proxy_refresh_plan(account: dict[str, Any] | None, route: dict[str, Any], auth_check: dict[str, Any]) -> dict[str, Any]:
    if not account:
        return {"status": "not-applicable", "reason": "no-resolved-account"}
    if auth_check.get("status") == "passed":
        return {"status": "not-needed", "reason": "auth-check-passed"}
    if account.get("auth_refresh_source") != "ryushe-proxy":
        return {
            "status": "not-permitted",
            "reason": "account-record-does-not-permit-ryushe-proxy",
            "auth_refresh_source": account.get("auth_refresh_source"),
        }

    mode = route.get("ryushe_proxy_mode")
    if mode == "direct":
        status = "needs-adapter"
        action = "query Ryushe-proxy directly from Hoster"
    elif mode == "hoster-ssh":
        status = "needs-adapter"
        action = "run one-shot Hoster SSH proxy lookup, then close SSH"
    elif mode == "same-host-localhost":
        status = "needs-adapter"
        action = "query same-host localhost Ryushe-proxy"
    else:
        return {
            "status": "blocked",
            "reason": "runtime-route-does-not-allow-ryushe-proxy",
            "ryushe_proxy_mode": mode,
        }
    return {
        "status": status,
        "action": action,
        "ryushe_proxy_mode": mode,
        "auth_refresh_hint": account.get("auth_refresh_hint"),
        "endpoint": route.get("ryushe_proxy_endpoint"),
        "note": "Run refresh-from-ryushe-proxy or resolve --refresh to write a locked-down auth seed.",
    }


def bitwarden_plan(account: dict[str, Any] | None, auth_check: dict[str, Any], proxy_plan: dict[str, Any]) -> dict[str, Any]:
    if not account:
        return {"status": "not-applicable"}
    if auth_check.get("status") == "passed":
        return {"status": "not-needed"}
    ref = account.get("credential_ref")
    ref_type = credential_ref_type(ref)
    if ref_type == "bitwarden":
        return {
            "status": "available",
            "credential_ref_type": "bitwarden",
            "next": "load bitwarden in resolver/broker context and create or refresh a locked-down auth seed",
        }
    if proxy_plan.get("status") in {"blocked", "not-permitted", "needs-adapter"}:
        return {
            "status": "fallback-possible-with-approval",
            "credential_ref_type": ref_type,
            "next": "use Bitwarden only if a matching item is recorded or Ryushe approves lookup",
        }
    return {"status": "not-needed"}


def resolve(args: argparse.Namespace) -> dict[str, Any]:
    inventory = load_inventory(args.program)
    resolution = resolve_account(inventory, args.account, args.program)
    account = resolution.get("account") if resolution.get("status") == "resolved" else None
    route = resolve_runtime_route(args)
    seed_path = auth_seed_path(account)
    seed = inspect_auth_seed(seed_path)
    target_url = args.target_url or (account or {}).get("auth_check_url")
    auth_check = run_auth_check(target_url, args.method, args.timeout, seed_path)
    proxy_plan = proxy_refresh_plan(account, route, auth_check)
    if seed.get("status") == "available" and auth_check.get("reason") == "no-target-url":
        proxy_plan = {"status": "not-needed", "reason": "stored-auth-seed-available"}
    refreshed = False
    if (
        getattr(args, "refresh", False)
        and account
        and auth_check.get("status") != "passed"
        and proxy_plan.get("status") == "needs-adapter"
    ):
        refresh_result = refresh_from_ryushe_proxy(args)
        if refresh_result.get("status") == "refreshed":
            seed_path = auth_seed_path({**account, "auth_seed_ref": refresh_result["account"].get("auth_seed_ref")})
            seed = inspect_auth_seed(seed_path)
            auth_check = run_auth_check(target_url, args.method, args.timeout, seed_path)
            proxy_plan = {"status": "completed", "provenance": refresh_result.get("proxy_provenance", {})}
            refreshed = True
        else:
            proxy_plan = {**proxy_plan, "refresh_attempt": refresh_result}
    bw_plan = bitwarden_plan(account, auth_check, proxy_plan)

    if auth_check.get("status") == "passed":
        status = "ready"
        auth_source = "stored-auth-seed"
    elif seed.get("status") == "available" and auth_check.get("reason") == "no-target-url":
        status = "ready"
        auth_source = seed.get("safe_metadata", {}).get("session_source") or "stored-auth-seed"
    elif refreshed and seed.get("status") == "available":
        status = "ready"
        auth_source = "ryushe-proxy-refresh"
    elif proxy_plan.get("status") == "needs-adapter":
        status = "needs-proxy-refresh-adapter"
        auth_source = "ryushe-proxy-refresh"
    elif bw_plan.get("status") in {"available", "fallback-possible-with-approval"}:
        status = "needs-bitwarden"
        auth_source = "bitwarden"
    elif resolution.get("status") != "resolved":
        status = "unresolved-account"
        auth_source = "none"
    else:
        status = "manual-needed"
        auth_source = "manual"

    result = {
        "status": status,
        "program": args.program,
        "account_selector": args.account,
        "account_resolution": {
            key: resolution.get(key)
            for key in ("status", "selector", "matched_by", "inventory_path")
            if resolution.get(key) is not None
        },
        "account": safe_account_record(account or {}),
        "auth_source": auth_source,
        "auth_seed": seed,
        "auth_check": auth_check,
        "runtime_route": route,
        "proxy_refresh": proxy_plan,
        "bitwarden": bw_plan,
        "safe_next": safe_next(status),
    }
    return result


def safe_next(status: str) -> str:
    if status == "ready":
        return "use auth_seed.path through chromium-test/proxy-curl and keep replay on the agent MITM lane"
    if status == "needs-proxy-refresh-adapter":
        return "wire the Ryushe-proxy extraction adapter, write refreshed values to auth_seed_ref, then retry resolve"
    if status == "needs-bitwarden":
        return "load Bitwarden in resolver context and create or refresh a locked-down auth seed; do not pass plaintext credentials to agents"
    if status == "unresolved-account":
        return "load account-management and register or select an owned account alias/color"
    return "ask Ryushe for manual auth refresh or a safe auth-check URL"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    route = sub.add_parser("route", help="Resolve current runtime route metadata.")
    route.add_argument("--runtime")
    route.add_argument("--route-table")
    route.set_defaults(func=lambda args: resolve_runtime_route(args))

    res = sub.add_parser("resolve", help="Resolve safe account auth handoff metadata.")
    res.add_argument("--program", required=True)
    res.add_argument("--account", required=True, help="Account alias or PwnFox color, such as blue.")
    res.add_argument("--target-url", help="Safe read-only URL for auth validation.")
    res.add_argument("--host-filter", help="Restrict Ryushe-proxy lookup to a host substring, such as canva.com.")
    res.add_argument("--method", default="GET", choices=("GET", "HEAD"))
    res.add_argument("--timeout", type=float, default=8.0)
    res.add_argument("--limit", type=int, default=80, help="Maximum proxy requests to inspect during refresh.")
    res.add_argument("--refresh", action="store_true", help="If stored auth is not ready, refresh from approved Ryushe-proxy source.")
    res.add_argument("--runtime")
    res.add_argument("--route-table")
    res.set_defaults(func=resolve)

    refresh = sub.add_parser("refresh-from-ryushe-proxy", help="Refresh one account/color auth seed from approved Ryushe-proxy traffic.")
    refresh.add_argument("--program", required=True)
    refresh.add_argument("--account", required=True, help="Account alias or PwnFox color, such as blue.")
    refresh.add_argument("--target-url", help="Safe URL used only to derive a host filter when --host-filter is omitted.")
    refresh.add_argument("--host-filter", help="Restrict Ryushe-proxy lookup to a host substring, such as canva.com.")
    refresh.add_argument("--limit", type=int, default=80, help="Maximum proxy requests to inspect.")
    refresh.add_argument("--runtime")
    refresh.add_argument("--route-table")
    refresh.set_defaults(func=refresh_from_ryushe_proxy)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = args.func(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
