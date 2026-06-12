#!/usr/bin/env python3
"""Launch an isolated Chromium/Chrome instance for scoped testing."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mitm_chromium_profile import DEFAULT_CA_CERT, DEFAULT_CERT_NAME, prepare_profile_ca


PORT_MIN = 9223
PORT_MAX = 9500
DEFAULT_ROUTE_TABLE = Path(
    "/home/ryushe/projects/ai-policies/skills/proxy-routing-policy/data/proxy_routes.json"
)
DEFAULT_HOSTER_CA_CERT = Path(
    "~/.local/state/ghost/mitm-lanes/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem"
).expanduser()
AUTH_SEED_REF_PREFIXES = ("auth-seed:", "auth_seed:", "file:")
CHROME_BINARIES = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
)


def sanitize_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")
    return slug or "default"


def listening_ports() -> set[int]:
    try:
        proc = subprocess.run(
            ["ss", "-ltn"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return set()

    ports: set[int] = set()
    for line in proc.stdout.splitlines():
        for match in re.finditer(r":(\d+)\s", line):
            ports.add(int(match.group(1)))
    return ports


def can_bind_localhost(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def iter_candidate_ports(requested: int | None) -> Iterable[int]:
    if requested is not None:
        yield requested
        return
    yield from range(PORT_MIN, PORT_MAX + 1)


def pick_port(requested: int | None = None) -> int:
    if requested is not None and not PORT_MIN <= requested <= PORT_MAX:
        raise SystemExit(f"--port must be in {PORT_MIN}-{PORT_MAX}")

    used = listening_ports()
    for port in iter_candidate_ports(requested):
        if port in used:
            continue
        if can_bind_localhost(port):
            return port

    if requested is not None:
        raise SystemExit(f"requested port {requested} is not available")
    raise SystemExit(f"no free port found in {PORT_MIN}-{PORT_MAX}")


def current_runtime() -> str:
    runtime = os.environ.get("GHOST_AGENT_RUNTIME")
    if runtime:
        return runtime.strip().lower()
    return socket.gethostname().strip().lower()


def load_runtime_route(runtime: str) -> dict[str, str]:
    allowed_route_keys = {"browser_proxy", "lane"}
    if DEFAULT_ROUTE_TABLE.exists():
        try:
            data = json.loads(DEFAULT_ROUTE_TABLE.read_text())
        except json.JSONDecodeError:
            data = {}
        runtimes = data.get("runtimes") if isinstance(data, dict) else None
        if isinstance(runtimes, dict):
            route = runtimes.get(runtime)
            if isinstance(route, dict):
                return {
                    str(k): str(v)
                    for k, v in route.items()
                    if v is not None and str(k) in allowed_route_keys
                }

    if runtime in {"hoster", "ryushespc", "abommie"}:
        return {
            "browser_proxy": "http://localhost:8080",
            "lane": "agent" if runtime == "hoster" else "ryushe",
        }
    return {
        "browser_proxy": "http://hoster:8080",
        "lane": "agent",
    }


def find_playwright_chromium_binary() -> str | None:
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception:
        return None

    try:
        with sync_playwright() as playwright:
            path = playwright.chromium.executable_path
    except Exception:
        return None

    if path and Path(path).exists():
        return str(path)
    return None


def find_chrome_binary(explicit: str | None = None) -> str:
    if explicit:
        path = shutil.which(explicit) if os.path.sep not in explicit else explicit
        if path and Path(path).exists():
            return str(path)
        raise SystemExit(f"Chrome binary not found: {explicit}")

    env_binary = os.environ.get("CHROMIUM_TEST_CHROME")
    if env_binary:
        return find_chrome_binary(env_binary)

    playwright_chromium = find_playwright_chromium_binary()
    if playwright_chromium:
        return playwright_chromium

    for binary in CHROME_BINARIES:
        path = shutil.which(binary)
        if path:
            return path
    raise SystemExit("No Chromium/Chrome binary found")


def default_profile_dir(program: str, account: str) -> Path:
    return (
        shared_base()
        / sanitize_slug(program)
        / "ghost"
        / "chromium-test"
        / "profiles"
        / sanitize_slug(account)
    )


def default_ephemeral_profile_dir(program: str, run_id: str | None) -> Path:
    label = sanitize_slug(run_id or f"run-{int(time.time())}")
    return (
        shared_base()
        / sanitize_slug(program)
        / "ghost"
        / "chromium-test"
        / "profiles"
        / "runs"
        / label
    )


def shared_base() -> Path:
    return Path(os.environ.get("HARNESS_SHARED_BASE", "~/Shared/bounty_recon")).expanduser()


def account_inventory_path(program: str) -> Path:
    return shared_base() / sanitize_slug(program) / "credentials" / "account_inventory.json"


def load_account_inventory(program: str) -> dict[str, Any]:
    path = account_inventory_path(program)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Account inventory is not valid JSON: {path}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"Account inventory must contain a JSON object: {path}")
    return data


def resolve_account_record(program: str, selector: str | None) -> dict[str, Any]:
    if not selector:
        return {"status": "none"}
    inventory = load_account_inventory(program)
    if not inventory:
        return {"status": "missing-inventory", "selector": selector}

    accounts = inventory.get("accounts", [])
    if not isinstance(accounts, list):
        accounts = []
    normalized = selector.lower()
    by_alias = {
        str(account.get("alias", "")).lower(): account
        for account in accounts
        if isinstance(account, dict) and account.get("alias")
    }

    if normalized in by_alias:
        return {
            "status": "resolved",
            "selector": selector,
            "matched_by": "alias",
            "account": by_alias[normalized],
            "inventory_path": str(account_inventory_path(program)),
        }
    for account in accounts:
        if not isinstance(account, dict):
            continue
        if str(account.get("pwnfox_color", "")).lower() == normalized:
            return {
                "status": "resolved",
                "selector": selector,
                "matched_by": "pwnfox_color",
                "account": account,
                "inventory_path": str(account_inventory_path(program)),
            }

    lanes = inventory.get("pwnfox_lanes", [])
    if isinstance(lanes, list):
        for lane in lanes:
            if not isinstance(lane, dict):
                continue
            if str(lane.get("color", "")).lower() == normalized:
                alias = str(lane.get("account", "")).lower()
                if alias in by_alias:
                    return {
                        "status": "resolved",
                        "selector": selector,
                        "matched_by": "pwnfox_lane",
                        "account": by_alias[alias],
                        "inventory_path": str(account_inventory_path(program)),
                    }
    return {"status": "not-found", "selector": selector, "inventory_path": str(account_inventory_path(program))}


def auth_seed_path_from_account(account: dict[str, Any] | None) -> Path | None:
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


def safe_account_resolution(resolution: dict[str, Any], auth_seed_file: Path | None) -> dict[str, Any]:
    if resolution.get("status") != "resolved":
        return {
            key: resolution.get(key)
            for key in ("status", "selector", "inventory_path")
            if resolution.get(key) is not None
        }
    account = resolution.get("account") or {}
    credential_ref = account.get("auth_seed_ref") or account.get("credential_ref")
    if credential_ref and str(credential_ref).startswith(("auth-seed:", "auth_seed:")):
        ref_type = "auth-seed"
    elif credential_ref and str(credential_ref).startswith("file:"):
        ref_type = "file"
    elif auth_seed_file:
        ref_type = "path"
    else:
        ref_type = "none"
    return {
        "status": "resolved",
        "selector": resolution.get("selector"),
        "matched_by": resolution.get("matched_by"),
        "inventory_path": resolution.get("inventory_path"),
        "account_alias": account.get("alias"),
        "pwnfox_color": account.get("pwnfox_color"),
        "role": account.get("role"),
        "auth_refresh_source": account.get("auth_refresh_source"),
        "auth_refresh_hint": account.get("auth_refresh_hint"),
        "credential_ref_type": ref_type,
        "auth_seed_file": str(auth_seed_file) if auth_seed_file else None,
    }


def cleanup_profile_dir(profile_dir: Path) -> dict[str, Any]:
    profile_dir = profile_dir.expanduser().resolve()
    if not profile_dir.exists():
        return {"status": "not-found", "profile_dir": str(profile_dir)}
    if profile_dir in {Path("/"), Path.home()}:
        return {"status": "refused", "profile_dir": str(profile_dir)}
    shutil.rmtree(profile_dir)
    return {"status": "deleted", "profile_dir": str(profile_dir)}


def auth_seed_metadata(path: str | None) -> dict[str, Any]:
    data = load_auth_seed(path)
    if data is None:
        return {"status": "none"}
    seed_path = Path(path).expanduser()
    mode = seed_path.stat().st_mode & 0o777
    safe_keys = ("account_label", "session_source", "created_at", "updated_at", "origin")
    safe = {key: str(data[key]) for key in safe_keys if data.get(key) is not None}
    return {
        "status": "loaded",
        "path": str(seed_path),
        "mode": oct(mode),
        "safe_metadata": safe,
        "secret_fields_present": sorted(
            key for key in data.keys()
            if key.lower() in {"cookies", "cookie", "authorization", "bearer", "token", "headers"}
        ),
        "cookie_count": len(data.get("cookies", [])) if isinstance(data.get("cookies"), list) else 0,
        "header_names": sorted(data.get("headers", {}).keys()) if isinstance(data.get("headers"), dict) else [],
    }


def load_auth_seed(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    seed_path = Path(path).expanduser()
    if not seed_path.exists():
        raise SystemExit(f"Auth seed file not found: {seed_path}")
    mode = seed_path.stat().st_mode & 0o777
    if mode & 0o077:
        raise SystemExit(f"Auth seed file must not be readable by group/other: {seed_path} mode={oct(mode)}")
    try:
        data = json.loads(seed_path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Auth seed file is not valid JSON: {seed_path}") from exc
    if not isinstance(data, dict):
        raise SystemExit("Auth seed file must contain a JSON object")
    return data


def resolve_auth_seed_file(args: argparse.Namespace) -> tuple[str | None, dict[str, Any]]:
    if args.auth_seed_file:
        return args.auth_seed_file, {
            "status": "explicit",
            "auth_seed_file": str(Path(args.auth_seed_file).expanduser()),
        }
    selector = args.account or args.account_label
    resolution = resolve_account_record(args.program, selector)
    account = resolution.get("account") if resolution.get("status") == "resolved" else None
    seed_path = auth_seed_path_from_account(account)
    return (str(seed_path) if seed_path else None), safe_account_resolution(resolution, seed_path)


def resolve_mitm_ca_cert(configured: str, proxy_server: str | None) -> Path:
    configured_path = Path(configured).expanduser()
    if (
        proxy_server
        and configured_path == DEFAULT_CA_CERT.expanduser()
        and re.search(r"^https?://hoster:8080/?$", proxy_server)
        and DEFAULT_HOSTER_CA_CERT.exists()
    ):
        return DEFAULT_HOSTER_CA_CERT
    return configured_path


def build_command(args: argparse.Namespace, port: int, profile_dir: Path) -> list[str]:
    chrome = find_chrome_binary(args.chrome_binary)
    command = [
        chrome,
        f"--remote-debugging-port={port}",
        "--remote-debugging-address=127.0.0.1",
        f"--remote-allow-origins={args.remote_allow_origins}",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-component-update",
        "--disable-sync",
        "--safebrowsing-disable-auto-update",
        "--new-window",
    ]

    proxy_server = args.proxy_server or os.environ.get("CHROMIUM_TEST_PROXY_SERVER")
    if proxy_server:
        command.append(f"--proxy-server={proxy_server}")
    if proxy_server and getattr(args, "ignore_certificate_errors", False):
        command.append("--ignore-certificate-errors")

    command.append(args.url or "about:blank")
    return command


def wait_for_cdp_page(port: int, timeout: float = 8.0) -> dict[str, Any] | None:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/json/list"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                targets = json.loads(response.read().decode("utf-8", errors="replace"))
        except Exception:
            time.sleep(0.2)
            continue
        if isinstance(targets, list):
            for target in targets:
                if target.get("type") == "page" and target.get("webSocketDebuggerUrl"):
                    return target
        time.sleep(0.2)
    return None


def cdp_call(ws: Any, method: str, params: dict[str, Any] | None = None, call_id: int = 1) -> dict[str, Any]:
    ws.send(json.dumps({"id": call_id, "method": method, "params": params or {}}))
    while True:
        message = json.loads(ws.recv())
        if message.get("id") == call_id:
            return message


def apply_auth_seed_via_cdp(port: int, target_url: str | None, seed: dict[str, Any] | None) -> dict[str, Any]:
    if not seed:
        return {"status": "none"}
    target = wait_for_cdp_page(port)
    if not target:
        return {"status": "missing-cdp-page"}
    try:
        import websocket  # type: ignore
    except Exception as exc:
        return {"status": "missing-websocket-client", "error": str(exc)}

    ws = websocket.create_connection(target["webSocketDebuggerUrl"], timeout=5)
    call_id = 1
    cookie_count = 0
    header_names: list[str] = []
    try:
        cdp_call(ws, "Network.enable", call_id=call_id)
        call_id += 1
        headers = seed.get("headers")
        if isinstance(headers, dict) and headers:
            clean_headers = {str(k): str(v) for k, v in headers.items()}
            cdp_call(ws, "Network.setExtraHTTPHeaders", {"headers": clean_headers}, call_id=call_id)
            call_id += 1
            header_names = sorted(clean_headers.keys())
        cookies = seed.get("cookies")
        if isinstance(cookies, list):
            for cookie in cookies:
                if not isinstance(cookie, dict) or not cookie.get("name"):
                    continue
                params = {
                    key: cookie[key]
                    for key in (
                        "name",
                        "value",
                        "url",
                        "domain",
                        "path",
                        "secure",
                        "httpOnly",
                        "sameSite",
                        "expires",
                    )
                    if key in cookie
                }
                if "url" not in params and "domain" not in params and target_url:
                    params["url"] = target_url
                response = cdp_call(ws, "Network.setCookie", params, call_id=call_id)
                call_id += 1
                if response.get("result", {}).get("success"):
                    cookie_count += 1
        navigated = False
        if target_url:
            cdp_call(ws, "Page.navigate", {"url": target_url}, call_id=call_id)
            navigated = True
        return {
            "status": "applied",
            "cookies_applied": cookie_count,
            "extra_header_names": header_names,
            "navigated": navigated,
        }
    finally:
        ws.close()


def parse_args() -> argparse.Namespace:
    if len(sys.argv) > 1 and sys.argv[1] == "cleanup-profile":
        parser = argparse.ArgumentParser(description="Delete a disposable Chromium profile directory.")
        parser.add_argument("cleanup_command")
        parser.add_argument("--profile-dir", required=True)
        parser.add_argument("--json", action="store_true")
        return parser.parse_args()

    parser = argparse.ArgumentParser(
        description="Launch an isolated Chromium/Chrome instance on a free CDP port."
    )
    parser.add_argument("program", help="Program or target slug.")
    parser.add_argument("task_arg", nargs="?", help="Requested test task label.")
    parser.add_argument("--task", dest="task_opt", help="Requested test task label.")
    parser.add_argument("--account", help="Override account/profile alias.")
    parser.add_argument("--url", help="Initial URL to open. Defaults to about:blank.")
    parser.add_argument("--port", type=int, help=f"CDP port in {PORT_MIN}-{PORT_MAX}.")
    parser.add_argument("--profile-dir", help="Override Chrome user-data-dir.")
    parser.add_argument("--run-id", help="Agent run id for ephemeral profile naming and proxy attribution.")
    parser.add_argument("--agent-id", help="Agent id for proxy attribution.")
    parser.add_argument("--account-label", help="Stable account label for proxy attribution.")
    parser.add_argument("--session-source", help="Auth/session source label for proxy attribution.")
    parser.add_argument(
        "--auth-seed-file",
        help=(
            "Locked-down JSON auth seed file. Must be owner-only readable; secret values are never printed. "
            "If omitted, --account/--account-label may resolve an auth seed from credentials/account_inventory.json."
        ),
    )
    parser.add_argument(
        "--ephemeral-profile",
        action="store_true",
        help="Create a fresh run-scoped browser profile and include a cleanup command in output.",
    )
    parser.add_argument(
        "--proxy-server",
        help="Actual browser HTTP/SOCKS proxy listener. Defaults to the runtime route table.",
    )
    parser.add_argument(
        "--proxy-cert-mode",
        choices=("auto", "import", "ignore", "none"),
        default=os.environ.get("CHROMIUM_TEST_PROXY_CERT_MODE", "auto"),
        help=(
            "How to handle proxy TLS interception. auto/import trust a CA in the profile; "
            "ignore adds --ignore-certificate-errors; none does neither."
        ),
    )
    parser.add_argument(
        "--mitm-ca-cert",
        default=os.environ.get("CHROMIUM_TEST_MITM_CA_CERT")
        or os.environ.get("MITMPROXY_CA_CERT")
        or str(DEFAULT_CA_CERT),
        help="CA certificate to import when --proxy-cert-mode is auto or import.",
    )
    parser.add_argument(
        "--mitm-cert-name",
        default=os.environ.get("CHROMIUM_TEST_MITM_CERT_NAME", DEFAULT_CERT_NAME),
        help="Certificate nickname for the Chromium profile NSS DB.",
    )
    parser.add_argument(
        "--remote-allow-origins",
        default=os.environ.get("CHROMIUM_TEST_REMOTE_ALLOW_ORIGINS", "*"),
        help="Value for Chromium --remote-allow-origins. Defaults to '*'.",
    )
    parser.add_argument("--chrome-binary", help="Override Chromium/Chrome executable.")
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Launch Chromium in headless mode for scripted smoke tests.",
    )
    parser.add_argument(
        "--isolated-home",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use a per-profile HOME so Chrome uses an isolated ~/.pki/nssdb trust store.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print launch plan only.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if getattr(args, "cleanup_command", None) == "cleanup-profile":
        result = cleanup_profile_dir(Path(args.profile_dir))
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"{result['status']}: {result['profile_dir']}")
        return 0 if result["status"] in {"deleted", "not-found"} else 2

    runtime = current_runtime()
    runtime_route = load_runtime_route(runtime)
    port = pick_port(args.port)
    task = args.task_opt or args.task_arg or "manual"
    resolved_auth_seed_file, account_resolution = resolve_auth_seed_file(args)
    auth_seed_data = load_auth_seed(resolved_auth_seed_file)
    auth_seed = auth_seed_metadata(resolved_auth_seed_file)
    if args.account_label:
        account = args.account_label
    elif auth_seed.get("safe_metadata", {}).get("account_label"):
        account = auth_seed["safe_metadata"]["account_label"]
    elif args.account:
        account = args.account
    else:
        account = f"{sanitize_slug(args.program)}-context"
    profile_dir_override = args.profile_dir
    profile_dir = (
        Path(profile_dir_override).expanduser()
        if profile_dir_override
        else default_ephemeral_profile_dir(args.program, args.run_id) if args.ephemeral_profile
        else default_profile_dir(args.program, account)
    )
    if not args.proxy_server:
        args.proxy_server = (
            os.environ.get("CHROMIUM_TEST_PROXY_SERVER")
            or runtime_route.get("browser_proxy")
        )
    mitm_ca_cert = resolve_mitm_ca_cert(args.mitm_ca_cert, args.proxy_server)
    if not args.dry_run:
        profile_dir.mkdir(parents=True, exist_ok=True)

    cert_status: dict[str, Any] = {"status": "not-needed"}
    args.ignore_certificate_errors = False
    home_dir = profile_dir / "home" if args.isolated_home else None
    if home_dir and not args.dry_run:
        home_dir.mkdir(parents=True, exist_ok=True)
    if args.proxy_server:
        if args.proxy_cert_mode in {"auto", "import"}:
            if args.dry_run:
                cert_status = {
                    "status": "dry-run",
                    "profile_dir": str(profile_dir),
                    "home_dir": str(home_dir) if home_dir else None,
                    "ca_cert": str(mitm_ca_cert),
                    "cert_name": args.mitm_cert_name,
                }
            else:
                try:
                    cert_status = prepare_profile_ca(
                        profile_dir,
                        mitm_ca_cert,
                        args.mitm_cert_name,
                        home_dir=home_dir,
                    )
                except RuntimeError as exc:
                    cert_status = {
                        "status": "import-error",
                        "profile_dir": str(profile_dir),
                        "home_dir": str(home_dir) if home_dir else None,
                        "ca_cert": str(mitm_ca_cert),
                        "cert_name": args.mitm_cert_name,
                        "error": str(exc),
                    }
            if cert_status.get("status") != "trusted":
                if args.proxy_cert_mode == "import" and not args.dry_run:
                    raise SystemExit(
                        "Could not import proxy CA into Chromium profile: "
                        f"{cert_status.get('status')}"
                    )
                if not args.dry_run:
                    args.ignore_certificate_errors = True
        elif args.proxy_cert_mode == "ignore":
            cert_status = {"status": "ignored-by-flag"}
            args.ignore_certificate_errors = True
        elif args.proxy_cert_mode == "none":
            cert_status = {"status": "disabled"}

    target_url = args.url
    if auth_seed_data and target_url:
        args.url = None
    command = build_command(args, port, profile_dir)
    args.url = target_url
    if args.headless and "--headless=new" not in command:
        command.insert(1, "--headless=new")
    result = {
        "program": args.program,
        "task": task,
        "account": account,
        "run_id": args.run_id,
        "agent_id": args.agent_id,
        "account_label": args.account_label or account,
        "session_source": args.session_source or auth_seed.get("safe_metadata", {}).get("session_source"),
        "account_resolution": account_resolution,
        "auth_seed": auth_seed,
        "port": port,
        "cdp_url": f"http://127.0.0.1:{port}",
        "cdp_version_url": f"http://127.0.0.1:{port}/json/version",
        "profile_dir": str(profile_dir),
        "profile_lifetime": "ephemeral" if args.ephemeral_profile else "persistent",
        "cleanup_command": (
            [
                sys.argv[0],
                "cleanup-profile",
                "--profile-dir",
                str(profile_dir),
                "--json",
            ]
            if args.ephemeral_profile
            else None
        ),
        "runtime": runtime,
        "runtime_route": runtime_route,
        "mitm_proxy": {
            "status": "configured" if args.proxy_server else "missing",
            "proxy_server": args.proxy_server,
            "source": "explicit/env/route",
        },
        "proxy_server": args.proxy_server or os.environ.get("CHROMIUM_TEST_PROXY_SERVER"),
        "proxy_cert_mode": args.proxy_cert_mode,
        "proxy_cert_status": cert_status,
        "auth_application": {"status": "dry-run" if auth_seed_data and args.dry_run else "none"},
        "command": command,
        "dry_run": args.dry_run,
    }

    if not args.dry_run:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, **({"HOME": str(home_dir)} if home_dir else {})},
            start_new_session=True,
        )
        time.sleep(1)
        result["pid"] = proc.pid
        result["auth_application"] = apply_auth_seed_via_cdp(port, target_url, auth_seed_data)

    if args.json or args.dry_run:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Started Chromium PID {result['pid']} on {result['cdp_url']}")
        print(f"Profile: {profile_dir}")
        if result["proxy_server"]:
            print(f"Browser proxy: {result['proxy_server']}")
            print(f"Proxy cert: {cert_status['status']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
