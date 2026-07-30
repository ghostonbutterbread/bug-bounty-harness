#!/usr/bin/env python3
"""Standalone recon aggregate mirror command."""

from __future__ import annotations

import argparse
from pathlib import Path

from agents.recon import bus


def mirror_aggregates(program: str) -> dict[str, object]:
    """Copy aggregate files into legacy compatibility locations."""
    root = bus.aggregate_root(program)
    base = bus.recon_root(program)
    mirrored: dict[str, str] = {}
    skipped: list[str] = []

    with bus.program_lock(root):
        for source_name, destinations in bus.MIRRORS.items():
            source = root / source_name
            if not source.exists():
                skipped.append(source_name)
                continue
            for relative in destinations:
                destination = base / relative
                bus.sync_generated_mirror(source, destination)
                mirrored[relative] = str(destination)

    return {
        "program": program,
        "mirrors": mirrored,
        "skipped": skipped,
        "status": "ok",
    }


def verify_aggregates(program: str) -> dict[str, object]:
    """Check derived mirrors byte-for-byte without rewriting them."""
    root = bus.aggregate_root(program)
    base = bus.recon_root(program)
    drift: list[dict[str, str]] = []
    checked: list[str] = []
    with bus.program_lock(root):
        for source_name, destinations in bus.MIRRORS.items():
            source = root / source_name
            for relative in destinations:
                destination = base / relative
                checked.append(relative)
                if not source.exists():
                    if destination.exists():
                        drift.append({"mirror": relative, "reason": "stale_source_missing"})
                    continue
                if not destination.exists():
                    drift.append({"mirror": relative, "reason": "missing"})
                elif source.read_bytes() != destination.read_bytes():
                    drift.append({"mirror": relative, "reason": "content_mismatch"})
                elif destination.stat().st_mode & 0o222:
                    drift.append({"mirror": relative, "reason": "writable"})
    return {
        "program": program,
        "checked": checked,
        "drift": drift,
        "status": "ok" if not drift else "drift",
        "exit_code": 0 if not drift else 1,
    }


def mirror(args: argparse.Namespace) -> dict[str, object]:
    """CLI adapter that honors the shared-base override used by recon bus."""
    original_shared_base = bus.SHARED_BASE
    if args.shared_base:
        bus.SHARED_BASE = Path(args.shared_base).expanduser()
    try:
        return mirror_aggregates(args.program)
    finally:
        bus.SHARED_BASE = original_shared_base


def verify(args: argparse.Namespace) -> dict[str, object]:
    original_shared_base = bus.SHARED_BASE
    if args.shared_base:
        bus.SHARED_BASE = Path(args.shared_base).expanduser()
    try:
        return verify_aggregates(args.program)
    finally:
        bus.SHARED_BASE = original_shared_base
