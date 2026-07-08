#!/usr/bin/env python3
"""Standalone recon aggregate mirror command."""

from __future__ import annotations

import argparse
import shutil
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
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                mirrored[relative] = str(destination)

    return {
        "program": program,
        "mirrors": mirrored,
        "skipped": skipped,
        "status": "ok",
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
