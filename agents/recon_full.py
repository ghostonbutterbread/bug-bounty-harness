#!/usr/bin/env python3
"""Write a bounded, plan-only full-recon orchestration receipt."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_AGENT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _AGENT_DIR.parent
for candidate in (str(_REPO_ROOT), str(_AGENT_DIR)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from agents.recon.full import FullReconConfig, build_plan, write_plan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program")
    parser.add_argument("--target", required=True, help="Saved-scope origin or target label; owning lanes revalidate before traffic.")
    parser.add_argument("--mode", choices=["auto", "full", "delta", "map-only"], default="auto")
    parser.add_argument("--baseline-manifest", help="Comparable completed baseline receipt, when known.")
    parser.add_argument("--auth", dest="auth_alias", help="Approved owned-account alias; never a raw credential.")
    parser.add_argument("--include-proxy-history", action="store_true")
    parser.add_argument("--family", default="web_bounty")
    parser.add_argument("--lane", default="web")
    parser.add_argument("--root", help="Shared storage root override.")
    parser.add_argument("--run-id")
    parser.add_argument("--dry-run", action="store_true", help="Print the lane plan without writing a receipt.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = FullReconConfig(
        program=args.program,
        target=args.target,
        requested_mode=args.mode,
        baseline_manifest=args.baseline_manifest,
        auth_alias=args.auth_alias,
        include_proxy_history=args.include_proxy_history,
        family=args.family,
        lane=args.lane,
        root=args.root,
        run_id=args.run_id,
    )
    if args.dry_run:
        print(json.dumps(build_plan(config), indent=2, sort_keys=True))
    else:
        print(write_plan(config))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
