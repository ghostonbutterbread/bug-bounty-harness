#!/usr/bin/env python3
"""Validate the selected target profile before forwarding to Bounty Core."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

from bounty_core.safety_incidents import main as provider_main
from bounty_core.storage import normalize_family, normalize_lane, normalize_program, resolve_storage

WEBHOOK_ENV = "DISCORD_SAFETY_WEBHOOK_URL"
_WEBHOOK_FILE = Path(".config/bounty-core/safety-webhook-url")
_WEBHOOK_PATTERN = re.compile(r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+\Z")
_MAX_WEBHOOK_BYTES = 4096


def _load_webhook_file() -> str | None:
    """Read only a regular, owner-private file; never include its data in errors."""
    try:
        path = Path.home() / _WEBHOOK_FILE
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_size > _MAX_WEBHOOK_BYTES):
                return None
            raw = os.read(fd, _MAX_WEBHOOK_BYTES + 1)
            if len(raw) > _MAX_WEBHOOK_BYTES:
                return None
            url = raw.decode("utf-8").removesuffix("\n")
            return url if _WEBHOOK_PATTERN.fullmatch(url) else None
        finally:
            os.close(fd)
    except (OSError, UnicodeError, RuntimeError):
        return None


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(
        description="Record or notify an agent-reported safety incident in the verified target lane",
        epilog="Pass record with incident fields or notify with an incident ID; --no-notify disables delivery for record.",
    )
    parser.add_argument("--program", required=True)
    parser.add_argument("--family", default="web_bounty")
    parser.add_argument("--lane", required=True)
    parser.add_argument("--profile", required=True, help="absolute path to context/target_profile.json")
    parser.add_argument("--root", help="optional explicit shared base; must match profile")
    args, remaining = parser.parse_known_args(argv)
    try:
        profile_path = Path(args.profile)
        if not profile_path.is_absolute() or profile_path.name != "target_profile.json":
            raise ValueError("profile path must be absolute and name target_profile.json")
        profile_path = profile_path.resolve(strict=True)
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        if not isinstance(profile, dict):
            raise ValueError("invalid profile")
        program = normalize_program(args.program)
        family = normalize_family(args.family)
        lane = normalize_lane(args.lane)
        if (profile.get("program"), profile.get("family"), profile.get("lane")) != (program, family, lane):
            raise ValueError("profile identity mismatch")
        canonical_value = profile.get("canonical_root")
        if not isinstance(canonical_value, str) or not Path(canonical_value).is_absolute():
            raise ValueError("invalid canonical root")
        canonical_root = Path(canonical_value).resolve(strict=False)
        if profile_path != canonical_root / "context" / "target_profile.json":
            raise ValueError("profile location mismatch")
        base_value = profile.get("base_root")
        if not isinstance(base_value, str) or not Path(base_value).is_absolute():
            raise ValueError("invalid profile base root")
        base_root = Path(base_value).resolve(strict=False)
        layout = resolve_storage(program, family=family, lane=lane, root_override=base_root)
        if layout.base_root != base_root or layout.lane_root != canonical_root:
            raise ValueError("canonical root mismatch")
        if args.root is not None:
            if not Path(args.root).is_absolute():
                raise ValueError("explicit root must be absolute")
            explicit = resolve_storage(program, family=family, lane=lane, root_override=args.root)
            if explicit.lane_root != canonical_root:
                raise ValueError("explicit root mismatch")
    except (OSError, ValueError, TypeError, IndexError):
        print("safety incident profile unavailable or inconsistent; no record or delivery attempted", file=sys.stderr)
        return 2
    # Only this CLI opts in. An explicit environment setting (even empty) wins;
    # --no-notify does not need to open a credential at all.
    if WEBHOOK_ENV not in os.environ and "--no-notify" not in remaining:
        url = _load_webhook_file()
        if url is None:
            print("safety incident webhook unavailable or insecure; notification not configured", file=sys.stderr)
        else:
            os.environ[WEBHOOK_ENV] = url
    return provider_main(["--program", program, "--family", family, "--lane", lane,
                          "--root", str(base_root), *remaining])


if __name__ == "__main__":
    raise SystemExit(main())
