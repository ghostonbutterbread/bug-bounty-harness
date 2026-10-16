"""Read-only, lane-scoped verification of Coverage evidence pointers.

No Attempt payload or MapStore body is copied into Coverage. Legacy untyped
references stay usable but cannot be proven absent without run provenance.
"""
from __future__ import annotations

import json
from pathlib import PurePosixPath

from agents.map_store import MapStore
from agents.storage_resolver import resolve_storage


def verify_references(program: str, *, family: str, lane: str, root_override: str | None,
                      refs: list[str]) -> list[dict[str, str]]:
    layout = resolve_storage(program, family=family, lane=lane,
                             root_override=root_override, create=False)
    maps = MapStore(program, family=family, lane=lane, root=root_override, create=False)
    indexed_paths: set[str] | None = None
    map_index_complete = True
    results = []
    for ref in refs:
        status = "unverified"
        if ref.startswith("attempt:"):
            parts = ref.split(":", 2)
            if len(parts) == 3 and parts[1] not in {"", ".", ".."} and not any(
                separator in parts[1] for separator in ("/", "\\")
            ) and parts[2]:
                path = layout.lane_root / "attempts" / "_runs" / parts[1] / "attempts.jsonl"
                status = "missing"
                if path.is_file():
                    with path.open(encoding="utf-8") as handle:
                        for line in handle:
                            try:
                                row = json.loads(line)
                            except json.JSONDecodeError:
                                status = "unverified"  # incomplete/corrupt stream cannot prove absence
                                continue
                            if not isinstance(row, dict):
                                status = "unverified"  # non-object line is an incomplete/corrupt stream
                                continue
                            if row.get("attempt_id") == parts[2]:
                                status = "resolved"
                                break
        elif ref.startswith("map:"):
            relative = ref[4:]
            path = PurePosixPath(relative)
            if relative and not path.is_absolute() and ".." not in path.parts and "\\" not in relative:
                if indexed_paths is None:
                    indexed_paths = set()
                    if maps.index_path.is_file():
                        with maps.index_path.open(encoding="utf-8") as handle:
                            for line in handle:
                                try:
                                    entry = json.loads(line)
                                except json.JSONDecodeError:
                                    map_index_complete = False
                                    continue
                                if isinstance(entry, dict) and isinstance(entry.get("path"), str):
                                    indexed_paths.add(entry["path"])
                                else:
                                    map_index_complete = False
                if relative in indexed_paths and (maps.maps_root / relative).is_file():
                    status = "resolved"
                elif map_index_complete:
                    status = "missing"
        results.append({"ref": ref, "status": status})
    return results
