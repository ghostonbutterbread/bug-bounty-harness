#!/usr/bin/env python3
"""Idempotent, marker-scoped crontab lifecycle for BugBountyHarness.

Default installs are prepare-only. `--live` is explicit and still relies on the
orchestrator's existing scope, manual-review, rate, lock, and auth gates.
"""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARKER_PREFIX = "# BBH-SCHEDULE:"


def marker(program: str) -> str:
    return f"{MARKER_PREFIX}{program}"


def current_crontab() -> str:
    proc = subprocess.run(["crontab", "-l"], text=True, capture_output=True)
    if proc.returncode == 0:
        return proc.stdout
    if "no crontab" in proc.stderr.lower():
        return ""
    raise RuntimeError(proc.stderr.strip() or "could not read crontab")


def strip_entry(contents: str, program: str) -> str:
    lines = contents.splitlines()
    kept: list[str] = []
    skip_next = False
    for line in lines:
        if line.strip() == marker(program):
            skip_next = True
            continue
        if skip_next:
            skip_next = False
            continue
        kept.append(line)
    return "\n".join(kept).rstrip() + ("\n" if kept else "")


def render_entry(program: str, schedule: str, config_root: Path, *, live: bool) -> str:
    cron_dir = Path.home() / "Shared" / "web_bounty" / program / "web" / "recon" / "cron"
    log = cron_dir / "scheduler.log"
    lock = cron_dir / ".scheduler.lock"
    invocation = f"PYTHONPATH={ROOT} python3 {ROOT / 'agents' / 'cron_orchestrator.py'} run {program} --config-root {config_root}"
    if live:
        invocation += " --run"
    command = f"mkdir -p {cron_dir}; flock -n {lock} sh -lc 'cd {ROOT} && {invocation}' >> {log} 2>&1"
    return f"{marker(program)}\n{schedule} {command}\n"


def install(program: str, schedule: str, config_root: Path, *, live: bool) -> None:
    existing = current_crontab()
    updated = strip_entry(existing, program)
    if updated and not updated.endswith("\n"):
        updated += "\n"
    updated += render_entry(program, schedule, config_root, live=live)
    subprocess.run(["crontab", "-"], input=updated, text=True, check=True)


def remove(program: str) -> bool:
    existing = current_crontab()
    updated = strip_entry(existing, program)
    if updated == existing:
        return False
    subprocess.run(["crontab", "-"], input=updated, text=True, check=True)
    return True


def status(program: str) -> str:
    lines = current_crontab().splitlines()
    for index, line in enumerate(lines):
        if line.strip() == marker(program):
            return lines[index + 1] if index + 1 < len(lines) else "BROKEN_MARKER_NO_COMMAND"
    return "NOT_INSTALLED"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("install", "status", "remove"):
        item = sub.add_parser(name)
        item.add_argument("program")
    install_parser = sub.choices["install"]
    install_parser.add_argument("--schedule", default="0 2 * * *")
    install_parser.add_argument("--config-root", default=str(ROOT / "agents" / "config" / "cron"))
    install_parser.add_argument("--live", action="store_true", help="run scanner jobs; default remains prepare-only")
    args = parser.parse_args(argv)
    if args.command == "install":
        install(args.program, args.schedule, Path(args.config_root).resolve(), live=args.live)
        print(status(args.program))
    elif args.command == "status":
        print(status(args.program))
    else:
        print("REMOVED" if remove(args.program) else "NOT_INSTALLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
