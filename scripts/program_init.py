#!/usr/bin/env python3
"""Initialize canonical Shared and mounted-artifact lanes for a bounty program.

The initializer is deliberately idempotent: it creates missing directories and
front-door metadata but never removes or overwrites existing program state.
Scope is required by default; pass either ``--platform`` (to pull it) or
``--skip-scope`` (to record that the program needs a manual scope source).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# Direct execution sets sys.path to scripts/, not the harness root.
HARNESS_ROOT = Path(__file__).resolve().parents[1]
if str(HARNESS_ROOT) not in sys.path:
    sys.path.insert(0, str(HARNESS_ROOT))

from agents.scope_puller import canonical_program_slug, pull_scope
from agents.scope_seed_files import write_recon_seed_files
from agents.scope_manager import ScopeManager
from agents.storage_resolver import (
    BINARIES_FAMILY,
    WEB_FAMILY,
    ensure_layout,
    normalize_program,
    resolve_storage,
    write_context_files,
)

DEFAULT_ARTIFACT_ROOT = Path(os.environ.get("BOUNTY_ARTIFACT_ROOT", "/mnt/bounty"))
LANE_FAMILIES = {
    "web": WEB_FAMILY,
    "api": WEB_FAMILY,
    "apk": BINARIES_FAMILY,
    "exe": BINARIES_FAMILY,
    "mac": BINARIES_FAMILY,
}


def _mkdirs(paths: Iterable[Path], *, dry_run: bool) -> list[str]:
    created: list[str] = []
    for path in paths:
        if not path.exists():
            created.append(str(path))
            if not dry_run:
                path.mkdir(parents=True, exist_ok=True)
    return created


def _write_once(path: Path, text: str, *, dry_run: bool) -> bool:
    if path.exists():
        return False
    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return True


def _artifact_paths(program: str, lane: str, root: Path) -> list[Path]:
    program_root = root / program
    if lane in {"web", "api"}:
        surface = program_root / lane
        return [
            surface / "recon" / "fuzzing",
            surface / "recon" / "subdomains" / "runs",
            surface / "recon" / "javascript" / "urls",
            surface / "recon" / "javascript" / "downloads" / "by-host",
            surface / "recon" / "javascript" / "downloads" / "by-sha256",
            surface / "recon" / "javascript" / "sourcemaps",
            surface / "recon" / "javascript" / "chunks",
            surface / "recon" / "javascript" / "indexes",
            surface / "recon" / "javascript" / "runs",
            surface / "recon" / "pages",
            surface / "recon" / "api",
            surface / "screenshots" / "admin",
            surface / "screenshots" / "auth",
            surface / "screenshots" / "billing",
            surface / "screenshots" / "settings",
            surface / "screenshots" / "unknown",
            surface / "screenshots" / "runs",
            surface / "proxy" / "flows",
            surface / "proxy" / "har",
            surface / "proxy" / "runs",
            surface / "videos",
            surface / "browser-profiles",
            surface / "cdp-traces",
            surface / "reports-heavy",
        ]
    surface = program_root / lane
    return [
        surface / "static" / "decompile",
        surface / "static" / "jadx" / "runs",
        surface / "static" / "apktool",
        surface / "dynamic" / "traces",
        surface / "dynamic" / "frida",
        surface / "dynamic" / "screenshots",
        surface / "runs",
        surface / "reports-heavy",
    ]


def _shared_lane_paths(layout) -> list[Path]:
    paths = [
        layout.recon_root / "_meta",
        layout.recon_root / "_batches",
        layout.recon_root / "_runs",
        layout.recon_root / "_archive",
        layout.recon_root / "_scratch",
        layout.lane_root / "findings",
        layout.lane_root / "scripts",
    ]
    return [path for path in paths if path is not None]


def _read_scope(program: str) -> tuple[set[str], set[str]]:
    scope = ScopeManager(program)
    return scope.domains, scope.urls


def initialize_program(
    program: str,
    *,
    lanes: list[str],
    shared_root: Path,
    artifact_root: Path,
    platform: str | None,
    skip_scope: bool,
    dry_run: bool,
) -> dict[str, object]:
    slug = canonical_program_slug(program) if platform else normalize_program(program)
    if platform and skip_scope:
        raise ValueError("--platform and --skip-scope cannot be used together")
    if not platform and not skip_scope:
        raise ValueError("scope is required: provide --platform or explicitly use --skip-scope")

    if platform and not dry_run:
        pull_scope(program, platform)

    scope_state = "skipped" if skip_scope else ("pulled" if platform else "unknown")
    domains, urls = _read_scope(slug) if not dry_run else (set(), set())
    created: list[str] = []
    shared_lanes: dict[str, str] = {}

    for lane in lanes:
        layout = resolve_storage(
            slug,
            family=LANE_FAMILIES[lane],
            lane=lane,
            root_override=shared_root,
            create=False,
        )
        if not dry_run:
            ensure_layout(layout)
            write_context_files(layout)
        created.extend(_mkdirs(_shared_lane_paths(layout), dry_run=dry_run))
        shared_lanes[lane] = str(layout.lane_root)

        if lane in {"web", "api"} and not dry_run:
            seeds = write_recon_seed_files(layout.recon_root, domains, urls)
        else:
            seeds = {"urls": 0, "wildcards": 0}
        created.extend(_mkdirs(_artifact_paths(slug, lane, artifact_root), dry_run=dry_run))

        manifest = {
            "program": slug,
            "lane": lane,
            "scope_state": scope_state,
            "scope_domains": len(domains),
            "scope_urls": len(urls),
            "recon_seeds": seeds,
            "artifact_root": str(artifact_root / slug / lane),
            "initialized_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        manifest_path = layout.recon_root / "_meta" / "program-init.json"
        if _write_once(manifest_path, json.dumps(manifest, indent=2) + "\n", dry_run=dry_run):
            created.append(str(manifest_path))
        artifact_map = layout.recon_root / "artifact-map.md"
        if _write_once(
            artifact_map,
            f"# {slug} {lane} artifact map\n\n"
            f"Heavy non-secret artifacts: `{artifact_root / slug / lane}`\n\n"
            "Update machine-readable per-artifact maps when a persistent corpus is created.\n",
            dry_run=dry_run,
        ):
            created.append(str(artifact_map))

    return {
        "program": slug,
        "lanes": shared_lanes,
        "artifact_root": str(artifact_root / slug),
        "scope_state": scope_state,
        "scope_domains": len(domains),
        "scope_urls": len(urls),
        "created": created,
        "dry_run": dry_run,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program", help="Program slug or platform handle")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--platform", choices=["hackerone", "bugcrowd", "intigriti"], help="Pull published scope from this platform")
    scope.add_argument("--skip-scope", action="store_true", help="Initialize only and record that a manual scope source is still required")
    parser.add_argument("--lane", dest="lanes", choices=sorted(LANE_FAMILIES), action="append", help="Initialize a surface lane (repeatable; defaults to web)")
    parser.add_argument("--shared-root", type=Path, default=Path.home() / "Shared", help="Shared base root (default: ~/Shared)")
    parser.add_argument("--artifact-root", type=Path, default=DEFAULT_ARTIFACT_ROOT, help="Mounted non-secret artifact root (default: /mnt/bounty)")
    parser.add_argument("--dry-run", action="store_true", help="Show the initialization plan without creating files")
    parser.add_argument("--json", action="store_true", help="Print the result as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = initialize_program(
            args.program,
            lanes=args.lanes or ["web"],
            shared_root=args.shared_root.expanduser(),
            artifact_root=args.artifact_root.expanduser(),
            platform=args.platform,
            skip_scope=args.skip_scope,
            dry_run=args.dry_run,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}")
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Initialized {result['program']} ({result['scope_state']})")
        for lane, path in result["lanes"].items():
            print(f"  Shared {lane}: {path}")
        print(f"  Mounted artifacts: {result['artifact_root']}")
        print(f"  Created: {len(result['created'])} path(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
