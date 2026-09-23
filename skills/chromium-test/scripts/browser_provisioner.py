#!/usr/bin/env python3
"""Node-local, resource-gated persistent Chromium provisioner.

Runs on the browser node. It leases an exact account profile, checks that
node's resources, and keeps each Chromium root inside a user-systemd unit.
It never prints CDP URLs, cookies, credentials, or auth-seed locations.
"""

from __future__ import annotations
import argparse, functools, hashlib, json, os, shutil, sqlite3, subprocess, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from browser_lifecycle import StartupDiagnostics, node_lock, owner_state, private_json, process_identity

LEASE = ROOT / "browser_profile_lease.py"
CHROMIUM = ROOT / "chromium_test.py"
STATE = Path(
    os.environ.get(
        "BROWSER_PROVISIONER_STATE",
        "~/.local/state/ghost/browser-profile-leases/browser_provisioner.sqlite",
    )
).expanduser()
DEFAULT_RAM_MIB, DEFAULT_SWAP_MIB, DEFAULT_IDLE = 2048, 512, 300
# Seconds to wait for the launcher to write its private record. Chromium must
# stand up a display and reach CDP first, which exceeds a few seconds on a
# loaded host; too small a value kills the unit before it can ever report.
LAUNCH_WAIT_SECONDS = float(os.environ.get("BROWSER_LAUNCH_WAIT_SECONDS", "45"))
MAX_TABS = 5


def emit(o, code=0):
    print(json.dumps(o, sort_keys=True))
    raise SystemExit(code)


def now():
    return time.time()


def slug(s):
    return (
        "".join(c.lower() if c.isalnum() or c in "._-" else "-" for c in s).strip(".-")
        or "unknown"
    )


def db():
    STATE.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(STATE)
    c.row_factory = sqlite3.Row
    c.execute(
        """CREATE TABLE IF NOT EXISTS browsers (lease_id TEXT PRIMARY KEY,browser_id TEXT UNIQUE NOT NULL,program TEXT NOT NULL,account TEXT NOT NULL,auth_domain TEXT NOT NULL DEFAULT 'legacy-global',agent_id TEXT NOT NULL,run_id TEXT NOT NULL,purpose TEXT NOT NULL,unit TEXT NOT NULL,profile_dir TEXT NOT NULL,launch_file TEXT NOT NULL,state TEXT NOT NULL,tab_count INTEGER NOT NULL DEFAULT 0,last_activity REAL NOT NULL,created REAL NOT NULL,updated REAL NOT NULL)"""
    )
    columns = {row["name"] for row in c.execute("pragma table_info(browsers)")}
    if "auth_domain" not in columns:
        c.execute(
            "alter table browsers add column auth_domain TEXT NOT NULL DEFAULT 'legacy-global'"
        )
    c.execute(
        "CREATE TABLE IF NOT EXISTS lifecycle (lease_id TEXT PRIMARY KEY, metadata TEXT NOT NULL)"
    )
    return c


def metadata(c, row):
    r = c.execute(
        "select metadata from lifecycle where lease_id=?", (row["lease_id"],)
    ).fetchone()
    return json.loads(r[0]) if r else {}


def save_metadata(c, lid, value):
    c.execute("insert or replace into lifecycle values (?,?)", (lid, json.dumps(value)))
    c.commit()


def reconcile_transfers(c):
    # Recover a process crash between the canonical lease transaction and the
    # manager projection. Never infer a new owner from a run label or idle time.
    database = STATE.parent / "browser_profile_leases.sqlite"
    if not database.exists():
        return
    for row in c.execute("select * from browsers where state='running'").fetchall():
        meta = metadata(c, row)
        pending = meta.get("pending_transfer")
        if not pending:
            continue
        with sqlite3.connect(database) as leases:
            leases.row_factory = sqlite3.Row
            active = leases.execute(
                "select * from browser_profile_leases where profile_dir=? and status='active'",
                (row["profile_dir"],),
            ).fetchone()
        if not active or active["lease_id"] == row["lease_id"]:
            continue
        info = record_info(row)
        if (
            active["owner_agent_id"] != pending["agent_id"]
            or active["owner_run_id"] != pending["run_id"]
            or active["cdp_url"] != info.get("cdp_url")
        ):
            continue
        c.execute(
            "update browsers set lease_id=?,agent_id=?,run_id=?,purpose=?,updated=? where lease_id=?",
            (
                active["lease_id"],
                active["owner_agent_id"],
                active["owner_run_id"],
                active["purpose"],
                now(),
                row["lease_id"],
            ),
        )
        save_metadata(c, active["lease_id"], pending["metadata"])


def serialized(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        with node_lock(STATE):
            reconcile_transfers(db())
            return function(*args, **kwargs)

    return wrapped


def meminfo():
    d = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        k, v = line.split(":", 1)
        d[k] = int(v.strip().split()[0]) // 1024
    return d.get("MemAvailable", 0), d.get("SwapFree", 0)


def admission(ram, swap):
    a, b = meminfo()
    return {
        "status": "admitted" if a >= ram and b >= swap else "rejected",
        "ram_available_mib": a,
        "swap_free_mib": b,
        "required_ram_available_mib": ram,
        "required_swap_free_mib": swap,
    }


def lease(args, *parts):
    manager = hashlib.sha256(str(STATE.resolve()).encode()).hexdigest()
    p = subprocess.run(
        [
            sys.executable,
            str(LEASE),
            "--state-dir",
            str(STATE.parent),
            "--json",
            *parts,
            *(
                ["--manager-id", manager]
                if parts[0] in ("acquire", "renew", "register-browser", "release")
                else []
            ),
        ],
        capture_output=True,
        text=True,
    )
    try:
        return json.loads(p.stdout)
    except Exception:
        return {"status": "lease-error", "detail": p.stderr.strip() or p.stdout.strip()}


def sysenv():
    e = os.environ.copy()
    e["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"
    e["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={e['XDG_RUNTIME_DIR']}/bus"
    return e


def unit_active(unit):
    p = subprocess.run(
        ["systemctl", "--user", "is-active", "--quiet", unit], env=sysenv()
    )
    return p.returncode == 0


def unit_identity(unit):
    result = subprocess.run(
        ["systemctl", "--user", "show", "--property=InvocationID", "--value", unit],
        capture_output=True,
        text=True,
        env=sysenv(),
    )
    return result.stdout.strip() if result.returncode == 0 else None


def stop_recorded(row):
    info = record_info(row)
    if unit_active(row["unit"]):
        expected = info.get("unit_invocation")
        if not expected or unit_identity(row["unit"]) != expected:
            return False
    stop_unit(row["unit"])
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if stopped(row):
            return True
        time.sleep(0.1)
    return False


def stop_unit(unit):
    subprocess.run(
        ["systemctl", "--user", "stop", unit],
        env=sysenv(),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["systemctl", "--user", "reset-failed", unit],
        env=sysenv(),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def safe(row):
    info = record_info(row)
    result = {key: row[key] for key in (
        "browser_id", "lease_id", "program", "account", "auth_domain", "state",
        "tab_count", "last_activity", "created", "updated",
    )}
    result.update(instance_id=row["browser_id"], pane_id=row["browser_id"],
                  instance_key=info.get("instance_key", ""),
                  account_color=info.get("account_color"),
                  driving_mode=info.get("driving_mode", "legacy"))
    activity = activity_snapshot(row) if row["state"] == "running" else None
    if activity and not activity.get("unavailable"):
        result["last_activity"] = activity["last_activity"]
    return result


def release_lease(lease_id, agent, disp="cancelled", health="healthy"):
    return lease(
        None,
        "release",
        "--lease-id",
        lease_id,
        "--agent-id",
        agent,
        "--disposition",
        disp,
        "--profile-health",
        health,
    )


def profile_path(program, account):
    return (
        Path(os.environ.get("HARNESS_BOUNTY_ARTIFACT_ROOT", "/mnt/bounty"))
        / slug(program)
        / "web"
        / "browser-profiles"
        / slug(account)
    )


def record_info(row):
    try:
        return json.loads(Path(row["launch_file"]).read_text())
    except (OSError, ValueError):
        return {}


def healthy(row):
    info = record_info(row)
    if not info.get("cdp_url") or not unit_active(row["unit"]):
        return False
    if owner_state(info.get("process_identity")) != "active":
        return False
    if not info.get("unit_invocation") or info["unit_invocation"] != unit_identity(
        row["unit"]
    ):
        return False
    import browser_profile_lease as profiles

    return profiles.local_cdp_version(info["cdp_url"])["status"] == "ready"


def stopped(row):
    info = record_info(row)
    if unit_active(row["unit"]):
        return False
    identity = info.get("process_identity")
    if row["state"] == "running" and not identity:
        return False
    if identity and owner_state(identity) != "terminal":
        return False
    if info.get("cdp_url"):
        import browser_profile_lease as profiles

        if profiles.local_cdp_version(info["cdp_url"])["status"] == "ready":
            return False
    return True


def stop_receipt(row):
    info = record_info(row)
    private_json(
        row["launch_file"],
        {key: info.get(key) for key in ("process_identity", "unit_invocation", "pid", "instance_key", "instance_selection", "instance_id", "pane_id", "account_color", "driving_mode")},
    )


def stale_singleton_lock(path, row):
    identity = record_info(row).get("process_identity")
    if not identity or owner_state(identity) != "terminal":
        return False
    try:
        return (
            path.is_symlink()
            and str(path.readlink()) == f"{identity['node']}-{identity['pid']}"
            and process_identity(identity["pid"]) is None
        )
    except (OSError, ValueError):
        return False


def retire(c, row, health="healthy"):
    if not stop_recorded(row):
        return False
    q = release_lease(row["lease_id"], row["agent_id"], health=health)
    if q.get("status") != "released":
        return False
    c.execute(
        "update browsers set state='stopped',updated=? where lease_id=?",
        (now(), row["lease_id"]),
    )
    c.commit()
    return True


def selected_browser(c, program, alias, domain, key):
    rows = c.execute(
        "SELECT * FROM browsers WHERE program=? AND account=? AND auth_domain=? ORDER BY created DESC",
        (slug(program), slug(alias), domain),
    ).fetchall()
    # Existing legacy manifests may use pre-domain paths. Do not migrate or
    # silently abandon them simply because the canonical path has changed.
    return next((row for row in rows if record_info(row).get("instance_key", "") == key), None)


def automatic_instance(c, args, alias, domain, *, allow_takeover=False, allow_migration=False):
    """Select under the node lock; acquisition/freeze still arbitrate ownership.

    Never copy a legacy profile or treat unobservable native use as idle.
    Explicit slots remain explicit; only manager-created auto slots are pooled.
    """
    import browser_profile_lease as profiles

    rows = c.execute(
        "SELECT * FROM browsers WHERE program=? AND account=? AND auth_domain=? ORDER BY created DESC",
        (slug(args.program), slug(alias), domain),
    ).fetchall()
    latest = {}
    for row in rows:
        latest.setdefault(record_info(row).get("instance_key", ""), row)
    legacy = latest.get("")
    if legacy:
        if legacy['agent_id'] == args.agent_id and legacy['run_id'] == args.run_id and legacy['state'] == 'running':
            return ""  # Preserve the authenticated legacy profile for its owner/next user.
        pooled_running = any(r['state'] == 'running' and
                             record_info(r).get('instance_selection') == 'automatic'
                             for k, r in latest.items() if k)
        if not allow_migration or (legacy['state'] == 'running' and not healthy(legacy)) or (
                legacy['state'] != 'running' and (not pooled_running or not stopped(legacy))):
            return ""
    # Historical leases and existing disk data are migration boundaries even
    # when no running browser is registered in this manager.
    lease_db = STATE.parent / "browser_profile_leases.sqlite"
    if lease_db.exists() and not legacy:
        with sqlite3.connect(f"file:{lease_db}?mode=ro", uri=True) as leases:
            columns = {r[1] for r in leases.execute("PRAGMA table_info(browser_profile_leases)")}
            if columns:
                key_filter = "AND COALESCE(instance_key, '')=''" if "instance_key" in columns else ""
                if leases.execute(
                    "SELECT 1 FROM browser_profile_leases WHERE program=? AND account_alias=? "
                    "AND (auth_domain=? OR auth_domain IS NULL) " + key_filter + " LIMIT 1",
                    (slug(args.program), slug(alias), domain),
                ).fetchone():
                    return ""
    legacy_paths = (
        profiles.profile_dir(args.program, domain, alias),
        profiles.profile_dir(args.program, profiles.DEFAULT_LEGACY_AUTH_DOMAIN, alias),
        profiles.profile_dir(args.program, domain, alias).parent.parent / slug(alias),
        profiles.shared_base() / profiles.program_key(args.program) / "ghost" / "chromium-test" / "profiles" / slug(alias),
    )
    if any(path.exists() for path in legacy_paths) and not legacy:
        return ""
    if legacy:
        manager = hashlib.sha256(str(STATE.resolve()).encode()).hexdigest()
        if (Path(legacy['profile_dir']) not in legacy_paths or
                not profiles.register_legacy_auto(lease_db, slug(args.program), slug(alias), domain,
                                                  legacy['profile_dir'], manager, legacy['lease_id'],
                                                  legacy['agent_id'], legacy['run_id'],
                                                  legacy_running=legacy['state'] == 'running')):
            return ""
    pooled = [(key, row) for key, row in latest.items()
              if record_info(row).get("instance_selection") == "automatic"]
    for key, row in pooled:
        if row["state"] == "running" and row["agent_id"] == args.agent_id and row["run_id"] == args.run_id:
            return key
    if allow_takeover:
        for key, row in pooled:
            if row["state"] == "running" and lifecycle_state(c, row) == "idle":
                return key  # start() must win the authoritative adapter freeze.
    for key, row in pooled:
        if row["state"] == "stopped":
            return key  # canonical lease health/policy remains authoritative.
    key = "auto-" + hashlib.sha256((args.agent_id + "\0" + args.run_id).encode()).hexdigest()[:24]
    # The original slot may now belong to an active transferee, or an explicit
    # caller may have used the same key. Never reacquire it by hash coincidence.
    return key if key not in latest else "auto-" + uuid.uuid4().hex


def account_policy(program, alias, domain):
    import browser_profile_lease as profiles
    path = STATE.parent / "browser_profile_leases.sqlite"
    if not path.exists():
        return False
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as leases:
        return profiles.single_browser_policy(leases, program, alias, domain)


def canonical_claim(row, instance, single):
    """Validate the manager projection before revoking any other owner's control.

    The canonical transaction still arbitrates acquisition/transfer. This check
    prevents evicting a stale projection or one of several grandfathered single
    policy browsers when doing so cannot admit this request.
    """
    import browser_profile_lease as profiles
    path = STATE.parent / "browser_profile_leases.sqlite"
    if not path.exists():
        return False
    with profiles.connect(path) as leases:
        active = leases.execute(
            "SELECT * FROM browser_profile_leases WHERE program=? AND account_alias=? "
            "AND (auth_domain=? OR auth_domain IS NULL) AND status='active' "
            "AND (expires_at>? OR manager_id IS NOT NULL OR cdp_url IS NOT NULL)",
            (row["program"], row["account"], row["auth_domain"], now()),
        ).fetchall()
    expected = {
        "lease_id": row["lease_id"], "owner_agent_id": row["agent_id"],
        "owner_run_id": row["run_id"], "profile_dir": row["profile_dir"],
        "instance_key": instance,
        "manager_id": hashlib.sha256(str(STATE.resolve()).encode()).hexdigest(),
    }
    matching = [lease for lease in active if all(lease[key] == value for key, value in expected.items())]
    conflicts = [lease for lease in active if lease["lease_id"] != row["lease_id"]
                 and (single or not instance or not lease["instance_key"] or lease["instance_key"] == instance)]
    return len(matching) == 1 and not conflicts


def select_display(c, args):
    """Reserve an unused display/loopback port while start holds the node lock."""
    if getattr(args, "headless", False) or getattr(args, "display_backend", None) == "default":
        return
    from kasmvnc_session import candidate_web_ports, can_bind_localhost, validate_display, KasmVNCSessionError

    used = set()
    used_ports = set()
    for row in c.execute("SELECT * FROM browsers WHERE state='running'").fetchall():
        session = record_info(row).get("kasmvnc", {})
        display = session.get("display")
        if display:
            used.add(display)
        if session.get("web_port"):
            used_ports.add(session["web_port"])
    requested = getattr(args, "kasmvnc_display", None)
    candidates = [validate_display(requested)] if requested is not None else range(20, 1000)
    for display in candidates:
        if (f":{display}" not in used and not Path(f"/tmp/.X11-unix/X{display}").exists()
                and not Path(f"/tmp/.X{display}-lock").exists()):
            for port in candidate_web_ports(getattr(args, "kasmvnc_web_port", None)):
                if port not in used_ports and can_bind_localhost(port):
                    args.kasmvnc_display = display
                    args.kasmvnc_web_port = port
                    return
            raise KasmVNCSessionError("no unused requested KasmVNC web port available")
    raise KasmVNCSessionError("no unused requested KasmVNC display available")


def activity_snapshot(row):
    info = record_info(row)
    if (not info.get("activity_tracking")
            or info.get("driving_mode") not in (None, "agent-driven")):
        return None
    from browser_control import activity_control
    try:
        return activity_control(info["control_socket"])
    except Exception:
        return {"unavailable": True}


def freeze_idle(row, seconds):
    from browser_control import activity_control
    try:
        return activity_control(record_info(row)["control_socket"], "freeze",
                                idle_seconds=seconds).get("frozen", False)
    except Exception:
        return False


def restore_failed_stop(row):
    # Do not thaw a half-stopped, replaced, or unidentifiable runtime. A healthy
    # exact original runtime can resume under its unchanged owner/generation.
    if not healthy(row):
        return False
    from browser_control import activity_control
    try:
        return activity_control(record_info(row)["control_socket"], "thaw").get("frozen") is False
    except Exception:
        return False


def cleanup_unused(c):
    stopped_ids = []
    for row in c.execute("SELECT * FROM browsers WHERE state='running'").fetchall():
        activity = activity_snapshot(row)
        if (not activity or activity.get("unavailable") or activity["idle_seconds"] < 7200
                or activity["inflight"] or activity["reserved_seconds"]):
            continue
        # Recheck AND freeze in the adapter's event loop, not a stale file snapshot.
        if freeze_idle(row, 7200):
            if retire(c, row):
                stopped_ids.append(row["browser_id"])
            else:
                meta = metadata(c, row)
                meta["control_restored"] = restore_failed_stop(row)
                meta["lifecycle_error"] = "idle-stop-not-verified"
                save_metadata(c, row["lease_id"], meta)
    return stopped_ids


def lifecycle_state(c, row):
    meta = metadata(c, row)
    activity = activity_snapshot(row)
    if activity is not None:
        if activity.get("unavailable"):
            return "activity-unavailable"
        if activity["inflight"] or activity["reserved_seconds"]:
            return "active"
        if owner_state(meta.get("owner")) == "terminal":
            return "terminal"
        return "idle" if activity["idle_seconds"] >= meta.get("idle_claim_seconds", DEFAULT_IDLE) else "active"
    owner = owner_state(meta.get("owner"))
    if meta.get("awaiting_until"):
        if owner == "active" and record_info(row).get("driving_mode") == "manual":
            return "active"
        return "expired-awaiting-input" if now() >= meta["awaiting_until"] else "active"
    return owner


def monitor_unit(bid):
    return "browser-owner-" + bid


def start_watcher(bid):
    command = [
        "systemd-run",
        "--user",
        "--collect",
        "--unit=" + monitor_unit(bid),
        "--property=Restart=on-failure",
    ]
    for key in (
        "BROWSER_PROVISIONER_STATE",
        "HARNESS_BOUNTY_ARTIFACT_ROOT",
        "HARNESS_SHARED_BASE",
    ):
        if key in os.environ:
            command.append("--setenv=" + key + "=" + os.environ[key])
    command += [
        "--",
        sys.executable,
        str(Path(__file__).resolve()),
        "watch",
        "--browser-id",
        bid,
    ]
    result = subprocess.run(command, capture_output=True, text=True, env=sysenv())
    if result.returncode or not unit_active(monitor_unit(bid)):
        raise RuntimeError("could not start browser lifecycle supervisor")


def maintain(args):
    with node_lock(STATE):
        c = db()
        reconcile_transfers(c)
        browser_id = getattr(args, "browser_id", None)
        rows = c.execute(
            "select * from browsers where state='running' AND (? IS NULL OR browser_id=?)",
            (browser_id, browser_id),
        ).fetchall()
        for row in rows:
            meta = metadata(c, row)
            state = lifecycle_state(c, row)
            if not unit_active(row["unit"]) and stopped(row):
                retire(c, row)
                continue
            if state == "activity-unavailable":
                meta["lifecycle_error"] = "activity-probe-unavailable"
                save_metadata(c, row["lease_id"], meta)
                continue
            if state in ("active", "idle"):
                q = lease(
                    None,
                    "renew",
                    "--lease-id",
                    row["lease_id"],
                    "--agent-id",
                    row["agent_id"],
                    "--ttl-seconds",
                    str(meta.get("ttl", 1800)),
                    "--work-state",
                    "awaiting-input" if meta.get("awaiting_until") else "active",
                )
                if q.get("status") != "renewed":
                    meta["lifecycle_error"] = "lease-renewal-rejected"
                    save_metadata(c, row["lease_id"], meta)
                    continue
                if meta.pop("lifecycle_error", None):
                    save_metadata(c, row["lease_id"], meta)
            elif state in ("terminal", "expired-awaiting-input"):
                if activity_snapshot(row) is not None and not freeze_idle(row, 0):
                    continue
                info = record_info(row)
                if (
                    meta.get("proxy_ownership") != "browser"
                    or info.get("kasmvnc")
                    or not any(flag.startswith("--headless") for flag in info.get("command", []))
                    or not info.get("activity_tracking")
                    or info.get("control_mode") != "pipe-fenced"
                ):
                    # The old task's proxy or non-revocable UI cannot safely
                    # remain attached merely to preserve a reconnect window.
                    if not retire(c, row):
                        meta["lifecycle_error"] = "terminal-cleanup-not-verified"
                        save_metadata(c, row["lease_id"], meta)
                    continue
                # Grace admits an immediate replacement without losing the browser. The
                # old control is revoked now, not only when another task arrives.
                if not meta.get("abandoned_at"):
                    info = record_info(row)
                    if info.get("control_mode") == "pipe-fenced":
                        from browser_control import rotate_control

                        try:
                            info.update(rotate_control(info["control_socket"]))
                            private_json(row["launch_file"], info)
                        except Exception:
                            meta["lifecycle_error"] = "control-fence-failed"
                            save_metadata(c, row["lease_id"], meta)
                            retire(c, row)
                            continue
                    meta["abandoned_at"] = now()
                    save_metadata(c, row["lease_id"], meta)
                if now() - meta["abandoned_at"] >= 30:
                    retire(c, row)
    return 0


def watch(args):
    while True:
        maintain(args)
        c = db()
        row = c.execute(
            "select * from browsers where browser_id=?", (args.browser_id,)
        ).fetchone()
        c.close()
        if not row or row["state"] != "running":
            return
        time.sleep(5)


@serialized
def start(args):
    owner = None
    if getattr(args, "owner_pid", None):
        owner = process_identity(args.owner_pid)
        if not owner:
            emit({"status": "owner-unavailable"}, 2)
    if getattr(args, "task_owned", False):
        if not owner and getattr(args, "driving_mode", None) == "manual":
            emit({"status": "owner-required", "reason": "native-input-untracked",
                  "next": "use agent-driven activity control or supply a task supervisor PID"}, 2)
        if args.program or args.account or args.auth_domain:
            emit({"status": "task-owned-conflicts-with-program"}, 2)
        args.program = "task-owned"
        args.account = (
            "task-"
            + hashlib.sha256((args.agent_id + "\0" + args.run_id).encode()).hexdigest()[
                :24
            ]
        )
        args.auth_domain = "task"
    c = db()
    sweep_rows(c, 14, True)
    import browser_profile_lease as profiles

    account, _ = (
        profiles.resolve_account(args.program, args.account)
        if not getattr(args, "task_owned", False)
        else ({"alias": args.account}, {})
    )
    alias = (account or {}).get("alias", args.account)
    if account is not None and not getattr(args, "task_owned", False) and not profiles.account_lease_eligible(account):
        emit({"status": "account-unavailable"}, 2)
    auth_domain = profiles.auth_domain_for(args, account)
    instance = profiles.instance_key(args)
    automatic = False
    if (account is not None and not instance and not getattr(args, "legacy_profile", False)
            and not getattr(args, "task_owned", False)):
        instance = automatic_instance(c, args, alias, auth_domain)
        automatic = bool(instance)
    row = selected_browser(c, args.program, alias, auth_domain, instance)
    if (row and row["state"] == "running"
            and row["agent_id"] == args.agent_id and row["run_id"] == args.run_id
            and getattr(args, "driving_mode", None) is not None
            and record_info(row).get("driving_mode") != args.driving_mode):
        emit({"status": "locked", "reason": "driving-mode-mismatch", **safe(row)}, 2)
    cleanup_unused(c)
    adm = admission(args.min_ram_available_mib, args.min_swap_free_mib)
    single = account_policy(args.program, alias, auth_domain)
    if (account is not None and not instance and not getattr(args, 'legacy_profile', False)
            and not getattr(args, 'task_owned', False)):
        instance = automatic_instance(c, args, alias, auth_domain,
                                      allow_migration=not single and adm['status'] == 'admitted')
        automatic = bool(instance)
    elif automatic:
        instance = automatic_instance(c, args, alias, auth_domain,
                                      allow_takeover=single or adm["status"] != "admitted")
    row = selected_browser(c, args.program, alias, auth_domain, instance)
    reusable = None
    retired = False
    if row and row["state"] == "running":
        state = lifecycle_state(c, row)
        same = row["agent_id"] == args.agent_id and row["run_id"] == args.run_id
        if (
            same
            and owner
            and state == "active"
            and metadata(c, row).get("owner") not in (None, owner)
        ):
            emit({"status": "locked", "reason": "owner-process-mismatch"}, 2)
        if (
            same
            and state not in ("terminal", "expired-awaiting-input")
            and healthy(row)
        ):
            info = record_info(row)
            if info.get("command"):
                was_headless = any(flag.startswith("--headless") for flag in info["command"])
                strict_kasm = getattr(args, "display_backend", None) == "kasmvnc" and not getattr(args, "headless", False)
                if (was_headless != bool(getattr(args, "headless", False))
                        or (strict_kasm and not info.get("kasmvnc"))):
                    emit({"status": "locked", "reason": "display-mode-mismatch", **safe(row)}, 2)
            activity = activity_snapshot(row)
            if activity and activity.get("frozen"):
                emit({"status": "recovery-blocked", "reason": "control-frozen", **safe(row)}, 2)
            meta = metadata(c, row)
            if owner and meta.get("owner") is None:
                meta["owner"] = owner
                save_metadata(c, row["lease_id"], meta)
            emit({"status": "already-running", **safe(row), "owner_state": state,
                  "watcher_healthy": unit_active(monitor_unit(row["browser_id"]))})
        if not same and state not in ("terminal", "expired-awaiting-input", "idle"):
            emit({"status": "queued" if automatic else "locked", "reason": "owner-" + state, **safe(row)}, 2)
        if not same and state == "idle":
            if instance and not single and adm["status"] == "admitted":
                emit({"status": "queued", "reason": "slot-owned", **safe(row)}, 2)
            if not canonical_claim(row, instance, single):
                emit({"status": "queued", "reason": "canonical-claim-conflict"}, 2)
        info = record_info(row)
        meta = metadata(c, row)
        threshold = meta.get("idle_claim_seconds", DEFAULT_IDLE) if state == "idle" else 0
        if (state == "idle" or activity_snapshot(row) is not None) and not freeze_idle(row, threshold):
            emit({"status": "queued" if automatic else "locked", "reason": "activity-changed", **safe(row)}, 2)
        # A task-scoped MITM lane belongs to its old task. Never relabel it. Only
        # an explicitly browser-owned fixed route can cross task ownership alive.
        compatible = (
            account is not None
            and profiles.account_lease_eligible(account)
            and meta.get("proxy_ownership") == "browser"
            and getattr(args, "proxy_ownership", "task") == "browser"
            and bool(args.proxy_server)
            and info.get("proxy_server") == args.proxy_server
            and info.get("proxy_cert_mode") == args.proxy_cert_mode
            and not info.get("kasmvnc")
            and info.get("activity_tracking")
            and any(flag.startswith("--headless") for flag in info.get("command", []))
            and getattr(args, "headless", False)
            and getattr(args, "driving_mode", None) != "manual"
        )
        if compatible and info.get("control_mode") == "pipe-fenced" and healthy(row):
            from browser_control import rotate_control

            try:
                rotated = rotate_control(info["control_socket"])
                if rotated.get("fenced"):
                    info.update(rotated)
                    private_json(row["launch_file"], info)
                    reusable = info
            except Exception:
                reusable = None
        if not reusable and not retire(c, row):
            restored = restore_failed_stop(row) if info.get("activity_tracking") else False
            emit({"status": "recovery-blocked", "reason": "stop-not-verified",
                  "control_restored": restored}, 2)
        retired = not reusable
    # Capacity is an admission gate, not a lease outcome. Do not acquire a profile
    # until this node can actually start Chromium: a no-capacity retry must leave
    # the next profile user with a healthy, available profile.
    if reusable:
        adm = {"status": "admitted", "reason": "no-new-process"}
    elif retired:
        adm = admission(args.min_ram_available_mib, args.min_swap_free_mib)
    if adm["status"] != "admitted":
        emit(
            {
                "status": "queued",
                "reason": "no-capacity",
                "retry_after_seconds": 30,
                "admission": adm,
                "retryable": not retired,
            },
            2,
        )
    if not reusable:
        from kasmvnc_session import KasmVNCSessionError
        try:
            select_display(c, args)
        except KasmVNCSessionError:
            emit({"status": "queued", "reason": "display-unavailable", "retry_after_seconds": 30,
                  "retryable": not retired}, 2)
    if reusable:
        manager = hashlib.sha256(str(STATE.resolve()).encode()).hexdigest()
        meta = metadata(c, row)
        meta["pending_transfer"] = {
            "agent_id": args.agent_id,
            "run_id": args.run_id,
            "metadata": {
                "owner": owner,
                "ttl": args.ttl_seconds,
                "idle_claim_seconds": getattr(args, "idle_seconds", DEFAULT_IDLE),
                "proxy_ownership": args.proxy_ownership,
            },
        }
        save_metadata(c, row["lease_id"], meta)
        got = profiles.transfer_managed_lease(
            STATE.parent / "browser_profile_leases.sqlite",
            row["lease_id"],
            manager,
            args.agent_id,
            args.run_id,
            args.purpose,
            args.ttl_seconds,
            reusable["cdp_url"],
            expected={"owner_agent_id": row["agent_id"], "owner_run_id": row["run_id"],
                      "profile_dir": row["profile_dir"], "instance_key": instance,
                      "program": slug(args.program), "account_alias": slug(alias),
                      "auth_domain": auth_domain},
        )
    else:
        got = lease(
            args,
            "acquire",
            args.program,
            args.account,
            *(["--auth-domain", args.auth_domain] if args.auth_domain else []),
            "--agent-id",
            args.agent_id,
            "--run-id",
            args.run_id,
            "--purpose",
            args.purpose,
            "--ttl-seconds",
            str(args.ttl_seconds),
            *(["--recover-profile"] if getattr(args, "recover_profile", False) else []),
            *(["--task-owned"] if getattr(args, "task_owned", False) else []),
            *(["--instance-key", instance] if instance else []),
        )
    if got.get("status") not in ("leased", "already-owned"):
        if reusable:
            # Rotation already revoked the old controller. No canonical transfer
            # committed: fence the new generation too and retain the old lease
            # for explicit recovery, without trying a second browser.
            meta = metadata(c, row)
            meta.pop("pending_transfer", None)
            meta["lifecycle_error"] = "canonical-transfer-rejected"
            save_metadata(c, row["lease_id"], meta)
            frozen = freeze_idle(row, 0)
            emit({"status": "recovery-blocked", "reason": "canonical-transfer-rejected",
                  "control_frozen": frozen}, 2)
        if automatic and got.get("status") == "locked":
            got = {**got, "status": "queued", "reason": "account-policy-locked", "retry_after_seconds": 30,
                   "retryable": not retired}
        emit(got, 2)
    lid = got["lease"]["lease_id"]
    resolved_domain = got["lease"].get("auth_domain", auth_domain)
    if reusable:
        t = now()
        c.execute(
            "update browsers set lease_id=?,agent_id=?,run_id=?,purpose=?,state=?,last_activity=?,updated=? where lease_id=?",
            (
                lid,
                args.agent_id,
                args.run_id,
                args.purpose,
                "running",
                t,
                t,
                row["lease_id"],
            ),
        )
        save_metadata(
            c,
            lid,
            {
                "owner": owner,
                "ttl": args.ttl_seconds,
                "idle_claim_seconds": getattr(args, "idle_seconds", DEFAULT_IDLE),
                "proxy_ownership": args.proxy_ownership,
            },
        )
        reg = lease(
            args,
            "register-browser",
            "--lease-id",
            lid,
            "--agent-id",
            args.agent_id,
            "--cdp-url",
            reusable["cdp_url"],
            "--service-unit",
            row["unit"],
        )
        if reg.get("status") != "registered":
            emit({"status": "recovery-blocked", "reason": "register-handoff"}, 2)
        emit(
            {
                "status": "reused",
                "fenced": True,
                "watcher_healthy": unit_active(monitor_unit(row["browser_id"])),
                **safe(
                    c.execute(
                        "select * from browsers where lease_id=?", (lid,)
                    ).fetchone()
                ),
            }
        )
    if row is None:
        row = selected_browser(c, args.program, got["lease"].get("account_alias", args.account), resolved_domain, instance)
    if (
        row
        and row["agent_id"] == args.agent_id
        and row["run_id"] == args.run_id
        and row["state"] == "running"
        and healthy(row)
    ):
        emit({"status": "already-running", **safe(row)})
    prof = Path(got["lease"]["profile_dir"])
    bid = str(uuid.uuid4())
    unit = "browser-" + bid
    diagnostics_dir = (STATE.parent / "startup" / bid
                       if os.environ.get("BROWSER_STARTUP_DIAGNOSTICS") == "1" else None)
    diagnostics = StartupDiagnostics("manager", diagnostics_dir)
    launch = STATE.parent / (bid + ".launch.json")
    launch.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(launch.parent, 0o700)
    # The unit stays foreground via sleep; Chromium remains inside its cgroup.
    cmd = [
        sys.executable,
        str(CHROMIUM),
        args.program,
        args.purpose,
        "--account",
        args.account,
        "--profile-dir",
        str(prof),
        "--run-id",
        args.run_id,
        "--agent-id",
        args.agent_id,
        "--account-label",
        args.account,
        "--proxy-cert-mode",
        args.proxy_cert_mode,
        "--driving-mode",
        getattr(args, "driving_mode", None) or "agent-driven",
        "--json",
    ]
    if getattr(args, "task_owned", False):
        cmd += ["--task-owned"]
    if getattr(args, "headless", False):
        cmd += ["--headless"]
    if args.proxy_server:
        cmd += ["--proxy-server", args.proxy_server]
    if args.mitm_ca_cert:
        cmd += ["--mitm-ca-cert", args.mitm_ca_cert]
    if args.url:
        cmd += ["--url", args.url]
    if args.display_backend:
        cmd += ["--display-backend", args.display_backend]
    if args.kasmvnc_display is not None:
        cmd += ["--kasmvnc-display", str(args.kasmvnc_display)]
    if args.kasmvnc_web_port is not None:
        cmd += ["--kasmvnc-web-port", str(args.kasmvnc_web_port)]
    cmd += ["--control-socket", str(STATE.parent / (bid + ".sock"))]
    shell = f"umask 077; BROWSER_PROVISIONER_UNIT={unit}.service {' '.join(__import__('shlex').quote(x) for x in cmd)} > {__import__('shlex').quote(str(launch))}; rc=$?; test $rc -eq 0 || exit $rc; exec sleep infinity"
    run = [
        "systemd-run",
        "--user",
        "--unit=" + unit,
        "--property=MemoryHigh=" + args.memory_high,
        "--property=MemoryMax=" + args.memory_max,
        "--property=CPUWeight=100",
        "--",
        "/bin/bash",
        "-lc",
        shell,
    ]
    # systemd user managers do not inherit the requesting shell environment.
    for key in (
        "BROWSER_PROVISIONER_STATE",
        "HARNESS_BOUNTY_ARTIFACT_ROOT",
        "HARNESS_SHARED_BASE",
        "CHROMIUM_TEST_CHROME",
        "DISPLAY",
        "XAUTHORITY",
    ):
        if key in os.environ:
            run.insert(2, "--setenv=" + key + "=" + os.environ[key])
    if diagnostics_dir:
        run.insert(2, "--setenv=BROWSER_STARTUP_RECEIPT_DIR=" + str(diagnostics_dir))
    with diagnostics.phase("dispatch"):
        p = subprocess.run(run, capture_output=True, text=True, env=sysenv())
    if p.returncode or not unit_active(unit):
        diagnostics.mark("dispatch", "failed", RuntimeError(), p.returncode)
        release_lease(lid, args.agent_id)
        emit({"status": "launch-failed", "detail": (p.stderr or p.stdout).strip()}, 2)
    diagnostics.mark("publication")
    deadline = time.time() + LAUNCH_WAIT_SECONDS
    while time.time() < deadline and (
        not launch.exists() or launch.stat().st_size == 0
    ):
        time.sleep(0.2)
    try:
        info = json.loads(launch.read_text())
    except Exception as exc:
        diagnostics.mark("publication", "failed",
                         TimeoutError() if isinstance(exc, FileNotFoundError)
                         or (isinstance(exc, json.JSONDecodeError) and not exc.doc) else exc)
        stop_unit(unit)
        release_lease(lid, args.agent_id)
        emit(
            {
                "status": "launch-failed",
                "detail": f"launcher did not produce a valid private record within {LAUNCH_WAIT_SECONDS:g}s (raise BROWSER_LAUNCH_WAIT_SECONDS if the host is slow)",
            },
            2,
        )
    diagnostics.mark("publication", "ready")
    diagnostics.mark("registration")
    reg = lease(
        args,
        "register-browser",
        "--lease-id",
        lid,
        "--agent-id",
        args.agent_id,
        "--cdp-url",
        info["cdp_url"],
        "--service-unit",
        unit,
    )
    if reg.get("status") != "registered":
        diagnostics.mark("registration", "failed", RuntimeError())
        stop_unit(unit)
        release_lease(lid, args.agent_id)
        emit(
            {"status": "launch-failed", "detail": "could not register owned browser"}, 2
        )
    diagnostics.mark("registration", "ready")
    info["process_identity"] = (
        process_identity(info["pid"]) if info.get("pid") else None
    )
    info["unit_invocation"] = unit_identity(unit)
    info["account_color"] = (account or {}).get("pwnfox_color")
    info["instance_key"] = instance
    info["instance_selection"] = "automatic" if automatic else "explicit" if instance else "legacy"
    info["instance_id"] = bid
    info["pane_id"] = bid
    private_json(launch, info)
    save_metadata(
        c,
        lid,
        {
            "owner": owner,
            "ttl": args.ttl_seconds,
            "idle_claim_seconds": getattr(args, "idle_seconds", DEFAULT_IDLE),
            "proxy_ownership": getattr(args, "proxy_ownership", "task"),
        },
    )
    t = now()
    c.execute("delete from browsers where lease_id=?", (lid,))
    c.execute(
        "insert into browsers values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            lid,
            bid,
            slug(args.program),
            slug(got["lease"].get("account_alias", args.account)),
            got["lease"].get("auth_domain", auth_domain),
            args.agent_id,
            args.run_id,
            args.purpose,
            unit,
            str(prof),
            str(launch),
            "running",
            0,
            t,
            t,
            t,
        ),
    )
    c.commit()
    out = c.execute("select * from browsers where lease_id=?", (lid,)).fetchone()
    try:
        start_watcher(bid)
    except RuntimeError:
        retire(c, out)
        emit(
            {"status": "launch-failed", "reason": "lifecycle-supervisor-unavailable"}, 2
        )
    emit(
        {
            "status": "started",
            **safe(out),
            "profile_lifetime": "persistent",
            "owner_state": lifecycle_state(c, out),
            "watcher_healthy": unit_active(monitor_unit(bid)),
        }
    )


@serialized
def touch(args):
    c = db()
    r = c.execute(
        "select * from browsers where lease_id=?", (args.lease_id,)
    ).fetchone()
    if not r or r["agent_id"] != args.agent_id or r["state"] != "running":
        emit({"status": "not-owner"}, 2)
    if lifecycle_state(c, r) in ("terminal", "expired-awaiting-input"):
        emit({"status": "owner-terminal"}, 2)
    if (
        args.work_state == "awaiting-input"
        and not 1 <= getattr(args, "awaiting_seconds", 1800) <= 3600
    ):
        emit({"status": "invalid-awaiting-bound"}, 2)
    activity = activity_snapshot(r)
    if activity is not None:
        meta = metadata(c, r)
        if activity.get("unavailable"):
            emit({"status": "activity-unavailable"}, 2)
        if meta.get("awaiting_until") and now() >= meta["awaiting_until"] and args.work_state == "awaiting-input":
            emit({"status": "reservation-expired"}, 2)
        from browser_control import activity_control
        try:
            activity_control(record_info(r)["control_socket"], "reserve",
                             seconds=getattr(args, "awaiting_seconds", 1800) if args.work_state == "awaiting-input" else 0)
        except Exception:
            emit({"status": "reservation-unavailable"}, 2)
    q = lease(
        args,
        "renew",
        "--lease-id",
        args.lease_id,
        "--agent-id",
        args.agent_id,
        "--ttl-seconds",
        str(args.ttl_seconds),
        "--work-state",
        args.work_state,
    )
    if q.get("status") != "renewed":
        emit(q, 2)
    meta = metadata(c, r)
    if args.work_state == "awaiting-input":
        meta.setdefault(
            "awaiting_until", now() + getattr(args, "awaiting_seconds", 1800)
        )
    else:
        meta.pop("awaiting_until", None)
    save_metadata(c, args.lease_id, meta)
    c.execute(
        "update browsers set last_activity=?,updated=? where lease_id=?",
        ((activity["last_activity"] if activity is not None else now()), now(), args.lease_id),
    )
    c.commit()
    emit(
        {
            "status": "touched",
            **safe(
                c.execute(
                    "select * from browsers where lease_id=?", (args.lease_id,)
                ).fetchone()
            ),
        }
    )


def status(args):
    c = db()
    r = c.execute(
        "select * from browsers where lease_id=?", (args.lease_id,)
    ).fetchone()
    if not r or r["agent_id"] != args.agent_id or r["state"] != "running":
        emit({"status": "not-owner"}, 2)
    running = r["state"] == "running" and unit_active(r["unit"])
    emit(
        {
            "status": "ok",
            **safe(r),
            "unit_active": running,
            "browser_healthy": healthy(r) if running else False,
            "owner_state": lifecycle_state(c, r),
            "max_tabs": MAX_TABS,
            "watcher_healthy": unit_active(monitor_unit(r["browser_id"])),
            "activity": activity_snapshot(r),
            "owner_process_state": owner_state(metadata(c, r).get("owner")),
            "lifecycle_error": metadata(c, r).get("lifecycle_error"),
        }
    )


def reap(args):
    maintain(args)
    with node_lock(STATE):
        stopped_ids = cleanup_unused(db())
    emit({"status": "ok", "idle_stopped": stopped_ids,
          "policy": "tracked-CDP-idle-7200s; legacy-conservative"})


@serialized
def release(args):
    c = db()
    r = c.execute(
        "select * from browsers where lease_id=?", (args.lease_id,)
    ).fetchone()
    if not r or r["agent_id"] != args.agent_id or r["state"] != "running":
        emit({"status": "not-owner"}, 2)
    if not stop_recorded(r):
        info = record_info(r)
        emit(
            {
                "status": "cleanup-incomplete",
                "unit_active": unit_active(r["unit"]),
                "same_invocation": info.get("unit_invocation")
                == unit_identity(r["unit"]),
                "root_state": owner_state(info.get("process_identity")),
            },
            2,
        )
    q = release_lease(
        args.lease_id, args.agent_id, args.disposition, args.profile_health
    )
    if q.get("status") != "released":
        emit(q, 2)
    stop_receipt(r)
    c.execute(
        "update browsers set state='stopped',updated=? where lease_id=?",
        (now(), args.lease_id),
    )
    c.commit()
    emit(
        {
            "status": "released",
            **safe(
                c.execute(
                    "select * from browsers where lease_id=?", (args.lease_id,)
                ).fetchone()
            ),
        }
    )


def managed_root():
    return Path(os.environ.get("HARNESS_BOUNTY_ARTIFACT_ROOT", "/mnt/bounty")).resolve()


def managed_profile(path):
    try:
        relative = Path(path).resolve().relative_to(managed_root())
    except ValueError:
        return False
    # Only manager-shaped legacy <program>/web/browser-profiles/<account> and
    # auth-domain-scoped <program>/web/browser-profiles/<domain>/<account> qualify.
    return (
        ((len(relative.parts) in (4, 5) and relative.parts[1:3] == ("web", "browser-profiles"))
         or (len(relative.parts) == 6 and relative.parts[1:3] == ("web", "browser-instances")))
        and all(part not in ("", ".", "..") for part in relative.parts)
    )


def sweep_rows(c, older_than_days, confirm):
    cutoff = now() - older_than_days * 86400
    removed = []
    skipped = []
    # The table is the explicit manager-created profile manifest: never discover arbitrary paths.
    for r in c.execute(
        "select * from browsers where state='stopped' and updated<?", (cutoff,)
    ).fetchall():
        p = Path(r["profile_dir"])
        lease_db = STATE.parent / "browser_profile_leases.sqlite"
        if lease_db.exists():
            with sqlite3.connect(lease_db) as leases:
                if leases.execute("SELECT 1 FROM sqlite_master WHERE name='browser_legacy_auto'").fetchone() and leases.execute(
                    "SELECT 1 FROM browser_legacy_auto WHERE profile_dir=?", (str(p),)
                ).fetchone():
                    skipped.append({"browser_id": r["browser_id"], "reason": "legacy-auth-retained"})
                    continue
        if not managed_profile(p):
            skipped.append(
                {"browser_id": r["browser_id"], "reason": "not-managed-profile"}
            )
            continue
        if unit_active(r["unit"]):
            skipped.append({"browser_id": r["browser_id"], "reason": "unit-active"})
            continue
        if os.path.lexists(p / "SingletonLock") and not stale_singleton_lock(
            p / "SingletonLock", r
        ):
            skipped.append(
                {"browser_id": r["browser_id"], "reason": "browser-profile-lock"}
            )
            continue
        lease_db = STATE.parent / "browser_profile_leases.sqlite"
        if lease_db.exists():
            with sqlite3.connect(lease_db) as leases:
                locked = leases.execute(
                    "select 1 from browser_profile_leases where profile_dir=? and status='active' limit 1",
                    (str(p),),
                ).fetchone()
            if locked:
                skipped.append(
                    {"browser_id": r["browser_id"], "reason": "profile-leased"}
                )
                continue
        others = c.execute(
            "select * from browsers where profile_dir=? and lease_id!=? and state NOT IN ('deleted','handed-off')",
            (str(p), r["lease_id"]),
        ).fetchall()
        if any(
            other["state"] != "stopped" or other["updated"] >= cutoff
            for other in others
        ):
            skipped.append({"browser_id": r["browser_id"], "reason": "profile-in-use"})
            continue
        if not stopped(r):
            skipped.append(
                {"browser_id": r["browser_id"], "reason": "browser-not-stopped"}
            )
            continue
        if not p.exists():
            skipped.append({"browser_id": r["browser_id"], "reason": "already-absent"})
            continue
        if not confirm:
            removed.append(
                {"browser_id": r["browser_id"], "profile_dir": str(p), "dry_run": True}
            )
            continue
        shutil.rmtree(p)
        c.execute(
            "update browsers set state='deleted',updated=? where lease_id=?",
            (now(), r["lease_id"]),
        )
        removed.append(
            {"browser_id": r["browser_id"], "profile_dir": str(p), "dry_run": False}
        )
    c.commit()
    return removed, skipped


@serialized
def sweep(args):
    removed, skipped = sweep_rows(db(), args.older_than_days, args.confirm)
    emit({"status": "ok", "removed": removed, "skipped": skipped})


def request(args):
    maintain(args)
    deadline = now() + args.wait_seconds
    delay = 30
    attempts = 0
    while True:
        cmd = [
            sys.executable,
            str(Path(__file__).resolve()),
            "start",
            *([args.program, args.account] if args.program and args.account else []),
            *(["--auth-domain", args.auth_domain] if args.auth_domain else []),
            "--agent-id",
            args.agent_id,
            "--run-id",
            args.run_id,
            "--purpose",
            args.purpose,
            "--ttl-seconds",
            str(args.ttl_seconds),
            "--idle-seconds",
            str(args.idle_seconds),
            "--min-ram-available-mib",
            str(args.min_ram_available_mib),
            "--min-swap-free-mib",
            str(args.min_swap_free_mib),
            "--memory-high",
            args.memory_high,
            "--memory-max",
            args.memory_max,
            "--proxy-cert-mode",
            args.proxy_cert_mode,
        ]
        if getattr(args, "task_owned", False):
            cmd += ["--task-owned"]
        if getattr(args, "headless", False):
            cmd += ["--headless"]
        if getattr(args, "driving_mode", None) is not None:
            cmd += ["--driving-mode", args.driving_mode]
        if getattr(args, "instance_key", None):
            cmd += ["--instance-key", args.instance_key]
        if getattr(args, "legacy_profile", False):
            cmd += ["--legacy-profile"]
        if getattr(args, "owner_pid", None):
            cmd += ["--owner-pid", str(args.owner_pid)]
        if getattr(args, "proxy_ownership", None):
            cmd += ["--proxy-ownership", args.proxy_ownership]
        if args.proxy_server:
            cmd += ["--proxy-server", args.proxy_server]
        if args.mitm_ca_cert:
            cmd += ["--mitm-ca-cert", args.mitm_ca_cert]
        if args.url:
            cmd += ["--url", args.url]
        if args.display_backend:
            cmd += ["--display-backend", args.display_backend]
        if args.kasmvnc_display is not None:
            cmd += ["--kasmvnc-display", str(args.kasmvnc_display)]
        if args.kasmvnc_web_port is not None:
            cmd += ["--kasmvnc-web-port", str(args.kasmvnc_web_port)]
        if getattr(args, "recover_profile", False):
            cmd += ["--recover-profile"]
        p = subprocess.run(cmd, capture_output=True, text=True)
        try:
            result = json.loads(p.stdout)
        except Exception:
            emit(
                {
                    "status": "launch-failed",
                    "detail": "provisioner returned invalid JSON",
                },
                2,
            )
        attempts += 1
        if result.get("status") != "queued" or result.get("retryable") is False:
            result.update(
                {
                    "attempts": attempts,
                    "waited_seconds": args.wait_seconds - max(0, deadline - now()),
                }
            )
            emit(result, p.returncode)
        remaining = deadline - now()
        if remaining <= 0:
            result.update(
                {
                    "status": "queued-timeout",
                    "attempts": attempts,
                    "waited_seconds": args.wait_seconds,
                    "next_retry_after_seconds": min(delay, 300),
                }
            )
            emit(result, 2)
        sleep_for = min(
            float(result.get("retry_after_seconds", delay)), delay, remaining
        )
        time.sleep(max(1, sleep_for))
        delay = min(delay * 2, 120)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("admission")
    a.add_argument("--min-ram-available-mib", type=int, default=DEFAULT_RAM_MIB)
    a.add_argument("--min-swap-free-mib", type=int, default=DEFAULT_SWAP_MIB)
    s = sub.add_parser("start")
    s.add_argument("program", nargs="?")
    s.add_argument("account", nargs="?")
    s.add_argument("--auth-domain")
    s.add_argument("--agent-id", required=True)
    s.add_argument("--run-id", required=True)
    s.add_argument("--purpose", required=True)
    s.add_argument("--url")
    s.add_argument("--ttl-seconds", type=int, default=1800)
    s.add_argument("--idle-seconds", type=int, default=DEFAULT_IDLE)
    s.add_argument("--min-ram-available-mib", type=int, default=DEFAULT_RAM_MIB)
    s.add_argument("--min-swap-free-mib", type=int, default=DEFAULT_SWAP_MIB)
    s.add_argument("--memory-high", default="1G")
    s.add_argument("--memory-max", default="2G")
    s.add_argument(
        "--proxy-cert-mode",
        choices=("auto", "import", "ignore", "none"),
        default="import",
    )
    s.add_argument("--proxy-server")
    s.add_argument("--mitm-ca-cert")
    s.add_argument("--display-backend", choices=("auto", "default", "kasmvnc"))
    s.add_argument("--kasmvnc-display", type=int)
    s.add_argument("--kasmvnc-web-port", type=int)
    s.add_argument(
        "--recover-profile",
        action="store_true",
        help="Lease an unavailable but eligible profile only to repair or re-authenticate it; release healthy before ordinary reuse.",
    )
    r0 = sub.add_parser("request")
    r0.add_argument("program", nargs="?")
    r0.add_argument("account", nargs="?")
    r0.add_argument("--auth-domain")
    r0.add_argument("--agent-id", required=True)
    r0.add_argument("--run-id", required=True)
    r0.add_argument("--purpose", required=True)
    r0.add_argument("--url")
    r0.add_argument("--ttl-seconds", type=int, default=1800)
    r0.add_argument("--idle-seconds", type=int, default=DEFAULT_IDLE)
    r0.add_argument("--wait-seconds", type=int, default=120)
    r0.add_argument("--min-ram-available-mib", type=int, default=DEFAULT_RAM_MIB)
    r0.add_argument("--min-swap-free-mib", type=int, default=DEFAULT_SWAP_MIB)
    r0.add_argument("--memory-high", default="1G")
    r0.add_argument("--memory-max", default="2G")
    r0.add_argument(
        "--proxy-cert-mode",
        choices=("auto", "import", "ignore", "none"),
        default="import",
    )
    r0.add_argument("--proxy-server")
    r0.add_argument("--mitm-ca-cert")
    r0.add_argument("--display-backend", choices=("auto", "default", "kasmvnc"))
    r0.add_argument("--kasmvnc-display", type=int)
    r0.add_argument("--kasmvnc-web-port", type=int)
    r0.add_argument(
        "--recover-profile",
        action="store_true",
        help="Lease an unavailable but eligible profile only to repair or re-authenticate it; release healthy before ordinary reuse.",
    )
    t = sub.add_parser("touch")
    t.add_argument("--lease-id", required=True)
    t.add_argument("--agent-id", required=True)
    t.add_argument("--ttl-seconds", type=int, default=1800)
    t.add_argument(
        "--work-state", choices=("active", "awaiting-input"), default="active"
    )
    q = sub.add_parser("status")
    q.add_argument("--lease-id", required=True)
    q.add_argument("--agent-id", required=True)
    r = sub.add_parser("reap-idle")
    r.add_argument("--idle-seconds", type=int, default=DEFAULT_IDLE)
    w = sub.add_parser("sweep-stale")
    w.add_argument("--older-than-days", type=int, default=14)
    w.add_argument("--confirm", action="store_true")
    x = sub.add_parser("release")
    x.add_argument("--lease-id", required=True)
    x.add_argument("--agent-id", required=True)
    x.add_argument(
        "--disposition", choices=("completed", "handoff", "cancelled"), required=True
    )
    x.add_argument(
        "--profile-health",
        choices=("healthy", "needs-refresh", "needs-cleanup", "unknown"),
        required=True,
    )
    for parser in (s, r0):
        parser.add_argument("--driving-mode", choices=("agent-driven", "manual"),
                            help="Fresh browsers default to agent-driven; omitted retries preserve existing mode. Explicit mismatches require release/restart.")
        parser.add_argument("--task-owned", action="store_true")
        selection = parser.add_mutually_exclusive_group()
        selection.add_argument("--instance-key", help="Explicit isolated profile slot; omitted automatically selects safe pool instances, preserving existing legacy profiles.")
        selection.add_argument("--legacy-profile", action="store_true", help="Keep legacy single-profile selection even for a fresh account/domain.")
        parser.add_argument(
            "--owner-pid",
            type=int,
            help="Long-lived task supervisor PID on this node, not this short-lived CLI.",
        )
        parser.add_argument(
            "--proxy-ownership", choices=("task", "browser"), default="task"
        )
        parser.add_argument("--headless", action="store_true")
    t.add_argument("--awaiting-seconds", type=int, default=1800)
    sub.add_parser("maintain")
    watcher = sub.add_parser("watch")
    watcher.add_argument("--browser-id", required=True)
    args = p.parse_args()
    if args.cmd in ("start", "request"):
        import browser_profile_lease as profiles
        try:
            profiles.instance_key(args)
        except ValueError as exc:
            p.error(str(exc))
        if not 1 <= args.idle_seconds < 7200:
            p.error("idle claim window must be between 1 and 7199 seconds")
        if args.ttl_seconds < 30:
            p.error("ttl must be at least 30 seconds")
        if not args.task_owned and (not args.program or not args.account):
            p.error("program and account required unless --task-owned")
    if args.cmd == "maintain":
        maintain(args)
    if args.cmd == "watch":
        watch(args)
    if args.cmd == "admission":
        emit(admission(args.min_ram_available_mib, args.min_swap_free_mib), 0)
    if args.cmd == "start":
        start(args)
    if args.cmd == "request":
        request(args)
    if args.cmd == "touch":
        touch(args)
    if args.cmd == "status":
        status(args)
    if args.cmd == "reap-idle":
        reap(args)
    if args.cmd == "sweep-stale":
        sweep(args)
    if args.cmd == "release":
        release(args)


if __name__ == "__main__":
    main()
