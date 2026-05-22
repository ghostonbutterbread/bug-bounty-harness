#!/usr/bin/env python3
"""Real-time Ghost ledger coordination for hunting agents."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.coverage_store import CoverageStore
from agents.ledger import ledger_add, ledger_check, ledger_get, ledger_list, ledger_path
from agents.snapshot_identity import get_snapshot_identity
from agents.storage_resolver import resolve_storage

DEFAULT_AGENT = os.environ.get("ME_AGENT") or "codex"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _default_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _normalize_program(program: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(program or "").strip())
    if not cleaned:
        raise ValueError("program is required")
    return cleaned


def _normalize_relpath(value: str) -> str:
    relpath = str(value or "").strip().replace("\\", "/")
    while relpath.startswith("./"):
        relpath = relpath[2:]
    return relpath


def _normalize_class_name(value: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        raise ValueError("class name is required")
    return text


def _slugify_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()) or "unknown"


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _root_override(args: argparse.Namespace) -> str | Path | None:
    return getattr(args, "root_override", None)


def _ghost_root(
    program: str,
    lane: str = "apk",
    family: str = "binaries",
    *,
    root_override: str | Path | None = None,
) -> Path:
    layout = resolve_storage(
        _normalize_program(program),
        family=family,
        lane=lane,
        root_override=root_override,
        create=True,
    )
    return layout.ledgers_root


def _coverage_root(
    program: str,
    lane: str = "apk",
    family: str = "binaries",
    *,
    root_override: str | Path | None = None,
) -> Path:
    return _ghost_root(program, lane=lane, family=family, root_override=root_override)


def _coverage_path(
    program: str,
    lane: str = "apk",
    family: str = "binaries",
    *,
    root_override: str | Path | None = None,
) -> Path:
    return _coverage_root(program, lane=lane, family=family, root_override=root_override) / "coverage.json"


def _shared_brain_index_path(
    program: str,
    lane: str = "apk",
    family: str = "binaries",
    *,
    root_override: str | Path | None = None,
) -> Path:
    return _ghost_root(program, lane=lane, family=family, root_override=root_override) / "shared_brain" / "index.json"


def _default_coverage(program: str) -> dict[str, Any]:
    return {
        "version": 1,
        "program": _normalize_program(program),
        "created_at": _utc_now(),
        "updated_at": _utc_now(),
        "snapshots": {},
    }


def _read_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default
    if not isinstance(data, dict):
        return default
    return data


def next_fid(findings: list[dict[str, Any]], prefix: str = "D") -> str:
    normalized_prefix = (prefix or "D").strip().upper() or "D"
    max_value = 0
    for finding in findings:
        fid = str(finding.get("fid", "")).strip().upper()
        if not fid.startswith(normalized_prefix):
            continue
        suffix = fid[len(normalized_prefix) :]
        if suffix.isdigit():
            max_value = max(max_value, int(suffix))
    return f"{normalized_prefix}{max_value + 1:02d}"


def _load_shared_brain_candidates(
    program: str,
    lane: str = "apk",
    family: str = "binaries",
    *,
    root_override: str | Path | None = None,
) -> dict[str, list[str]]:
    path = _shared_brain_index_path(
        program,
        lane=lane,
        family=family,
        root_override=root_override,
    )
    payload = _read_json(path, {})
    files = payload.get("files", {})
    if not isinstance(files, dict):
        return {}

    classes: dict[str, set[str]] = {}
    for relpath, metadata in files.items():
        if not isinstance(metadata, dict):
            continue
        normalized_path = _normalize_relpath(str(relpath))
        if not normalized_path:
            continue

        signals = metadata.get("signals", {})
        if not isinstance(signals, dict):
            continue

        hinted_classes: set[str] = set()

        class_scores = signals.get("class_scores", {})
        if isinstance(class_scores, dict):
            for class_name, score in class_scores.items():
                if _safe_int(score) > 0:
                    hinted_classes.add(_normalize_class_name(str(class_name)))

        sinks = signals.get("sinks", [])
        if isinstance(sinks, list):
            for sink in sinks:
                if not isinstance(sink, dict):
                    continue
                class_hints = sink.get("class_hints", [])
                if not isinstance(class_hints, list):
                    continue
                for class_name in class_hints:
                    text = str(class_name or "").strip()
                    if text:
                        hinted_classes.add(_normalize_class_name(text))

        for class_name in hinted_classes:
            classes.setdefault(class_name, set()).add(normalized_path)

    return {class_name: sorted(paths) for class_name, paths in sorted(classes.items())}


def _load_coverage_payload(
    program: str,
    lane: str = "apk",
    family: str = "binaries",
    *,
    root_override: str | Path | None = None,
) -> dict[str, Any]:
    return _read_json(
        _coverage_path(program, lane=lane, family=family, root_override=root_override),
        _default_coverage(program),
    )


def _examined_files(payload: dict[str, Any], class_name: str, snapshot_id: str | None = None) -> set[str]:
    snapshots = payload.get("snapshots", {})
    if not isinstance(snapshots, dict):
        return set()

    if snapshot_id:
        snapshot_items = [(snapshot_id, snapshots.get(snapshot_id))]
    else:
        snapshot_items = list(snapshots.items())

    examined: set[str] = set()
    normalized_class = _normalize_class_name(class_name)
    for _, snapshot_payload in snapshot_items:
        if not isinstance(snapshot_payload, dict):
            continue
        classes = snapshot_payload.get("classes", {})
        if not isinstance(classes, dict):
            continue
        class_bucket = classes.get(normalized_class, {})
        if not isinstance(class_bucket, dict):
            continue
        files = class_bucket.get("files", {})
        if not isinstance(files, dict):
            continue
        for relpath in files:
            normalized = _normalize_relpath(str(relpath))
            if normalized:
                examined.add(normalized)
    return examined


def _resolve_target_root(
    program: str,
    lane: str = "apk",
    family: str = "binaries",
    *,
    root_override: str | Path | None = None,
) -> Path:
    index_path = _shared_brain_index_path(
        program,
        lane=lane,
        family=family,
        root_override=root_override,
    )
    payload = _read_json(index_path, {})
    target_root = Path(str(payload.get("target_root") or "")).expanduser()
    if str(target_root).strip():
        return target_root.resolve(strict=False)

    explicit = str(os.environ.get("SNAPSHOT_TARGET_ROOT") or "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve(strict=False)

    return Path.cwd().resolve(strict=False)


def _resolve_snapshot(
    program: str,
    version_label: str | None,
    *,
    lane: str = "apk",
    family: str = "binaries",
    root_override: str | Path | None = None,
) -> dict[str, Any]:
    return get_snapshot_identity(
        _resolve_target_root(program, lane=lane, family=family, root_override=root_override),
        version_label=version_label,
    )


def cmd_check(args: argparse.Namespace) -> int:
    root_override = _root_override(args)
    exists, fid = ledger_check(
        args.program,
        _normalize_relpath(args.file),
        _normalize_class_name(args.class_name),
        lane=args.lane,
        family=args.family,
        root_override=root_override,
    )
    if not exists or not fid:
        print(json.dumps({"exists": False}))
        return 0

    finding = ledger_get(
        args.program,
        fid,
        lane=args.lane,
        family=args.family,
        root_override=root_override,
    )
    if args.snapshot:
        sightings = []
        if isinstance(finding, dict):
            sightings = finding.get("sightings", [])
        if not any(
            str(item.get("snapshot_id") or "") == str(args.snapshot)
            for item in sightings
            if isinstance(item, dict)
        ):
            print(json.dumps({"exists": False}))
            return 0

    print(
        json.dumps(
            {
                "exists": True,
                "fid": fid,
                "finding": finding,
            },
            indent=2,
        )
    )
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    root_override = _root_override(args)
    snapshot = _resolve_snapshot(
        args.program,
        args.version_label,
        lane=args.lane,
        family=args.family,
        root_override=root_override,
    )
    finding = {
        "type": args.type,
        "class_name": _normalize_class_name(args.class_name),
        "file": _normalize_relpath(args.file),
        "severity": str(args.severity).strip().upper(),
        "review_tier": "PENDING_REVIEW",
        "status": "active",
        "agent": args.agent,
        "fid_prefix": args.fid_prefix,
    }
    is_new_fid, fid = ledger_add(
        args.program,
        finding,
        str(snapshot.get("snapshot_id") or ""),
        str(snapshot.get("version_label") or ""),
        _default_run_id(),
        args.agent,
        lane=args.lane,
        family=args.family,
        root_override=root_override,
    )
    entry = ledger_get(
        args.program,
        str(fid or ""),
        lane=args.lane,
        family=args.family,
        root_override=root_override,
    )
    print(
        json.dumps(
            {
                "added": bool(is_new_fid),
                "duplicate": not bool(is_new_fid),
                "snapshot_id": snapshot.get("snapshot_id"),
                "version_label": snapshot.get("version_label"),
                "finding": entry,
            },
            indent=2,
        )
    )
    return 0


def cmd_cover(args: argparse.Namespace) -> int:
    root_override = _root_override(args)
    class_name = _normalize_class_name(args.class_name)
    snapshot = _resolve_snapshot(
        args.program,
        args.version_label,
        lane=args.lane,
        family=args.family,
        root_override=root_override,
    )
    target_root = _resolve_target_root(
        args.program,
        lane=args.lane,
        family=args.family,
        root_override=root_override,
    )
    store = CoverageStore(
        args.program,
        target_root,
        lane=args.lane,
        family=args.family,
        root_override=root_override,
    )
    store.mark_examined(
        vuln_class=class_name,
        files=[_normalize_relpath(args.file)],
        method=args.agent,
        status="done",
        run_id=_default_run_id(),
        snapshot_id=str(snapshot.get("snapshot_id") or ""),
        version_label=str(snapshot.get("version_label") or ""),
    )
    candidates = _load_shared_brain_candidates(
        args.program,
        lane=args.lane,
        family=args.family,
        root_override=root_override,
    ).get(class_name, [])
    uncovered = len(store.get_unexplored(class_name, candidates))

    print(
        json.dumps(
            {
                "covered": True,
                "program": _normalize_program(args.program),
                "class_name": class_name,
                "file": _normalize_relpath(args.file),
                "remaining_unexplored": uncovered,
                "coverage_path": str(store.path),
            },
            indent=2,
        )
    )
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    root_override = _root_override(args)
    findings = ledger_list(
        args.program,
        snapshot_id=args.snapshot,
        version_label=args.version_label,
        lane=args.lane,
        family=args.family,
        root_override=root_override,
    )

    print(
        json.dumps(
            {
                "program": _normalize_program(args.program),
                "ledger_path": str(
                    ledger_path(args.program, lane=args.lane, family=args.family, root_override=root_override)
                ),
                "findings": findings,
            },
            indent=2,
        )
    )
    return 0


def cmd_unexplored(args: argparse.Namespace) -> int:
    root_override = _root_override(args)
    all_candidates = _load_shared_brain_candidates(
        args.program,
        lane=args.lane,
        family=args.family,
        root_override=root_override,
    )
    if args.class_name:
        requested = _normalize_class_name(args.class_name)
        class_names = [requested]
    else:
        class_names = sorted(all_candidates)

    classes: dict[str, dict[str, Any]] = {}
    for class_name in class_names:
        candidates = all_candidates.get(class_name, [])
        coverage = _load_coverage_payload(
            args.program,
            lane=args.lane,
            family=args.family,
            root_override=root_override,
        )
        snapshot = _resolve_snapshot(
            args.program,
            args.version_label,
            lane=args.lane,
            family=args.family,
            root_override=root_override,
        )
        examined = sorted(_examined_files(coverage, class_name, snapshot_id=str(snapshot.get("snapshot_id") or "")))
        unexplored = [candidate for candidate in candidates if candidate not in set(examined)]
        classes[class_name] = {
            "candidate_count": len(candidates),
            "examined_count": len(examined),
            "unexplored_count": len(unexplored),
            "unexplored": unexplored,
            "coverage_path": str(
                _coverage_path(args.program, lane=args.lane, family=args.family, root_override=root_override)
            ),
        }

    response: dict[str, Any] = {
        "program": _normalize_program(args.program),
        "shared_brain_path": str(
            _shared_brain_index_path(args.program, lane=args.lane, family=args.family, root_override=root_override)
        ),
        "classes": classes,
    }
    if not _shared_brain_index_path(
        args.program,
        lane=args.lane,
        family=args.family,
        root_override=root_override,
    ).exists():
        response["warning"] = "shared_brain index not found; no candidate surfaces available"

    print(json.dumps(response, indent=2))
    return 0


def _add_common_arguments(
    parser: argparse.ArgumentParser,
    *,
    include_file: bool = True,
    include_class: bool = True,
    include_root: bool = True,
) -> None:
    parser.add_argument("--program", required=True)
    parser.add_argument("--family", default="binaries", help="Storage family, e.g. binaries or web_bounty.")
    parser.add_argument("--lane", default="apk", help="Storage lane, e.g. apk, exe, mac, web, api.")
    if include_root:
        parser.add_argument("--root", dest="root_override", help="Explicit local canonical root override.")
    if include_file:
        parser.add_argument("--file", required=True)
    if include_class:
        parser.add_argument("--class", "--class-name", dest="class_name", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ghost ledger coordination")
    subparsers = parser.add_subparsers(dest="command")

    check_parser = subparsers.add_parser("check", help="Check if a finding already exists")
    _add_common_arguments(check_parser)
    check_parser.add_argument("--snapshot")
    check_parser.set_defaults(func=cmd_check)

    add_parser = subparsers.add_parser("add", help="Add a finding to the ledger")
    _add_common_arguments(add_parser)
    add_parser.add_argument("--type", required=True)
    add_parser.add_argument("--severity", required=True)
    add_parser.add_argument("--agent", default=DEFAULT_AGENT)
    add_parser.add_argument("--fid-prefix", default="D")
    add_parser.add_argument("--version", dest="version_label")
    add_parser.set_defaults(func=cmd_add)

    cover_parser = subparsers.add_parser("cover", help="Mark a file/class surface as explored")
    _add_common_arguments(cover_parser)
    cover_parser.add_argument("--agent", default=DEFAULT_AGENT)
    cover_parser.add_argument("--version", dest="version_label")
    cover_parser.set_defaults(func=cmd_cover)

    list_parser = subparsers.add_parser("list", help="List current findings")
    _add_common_arguments(list_parser, include_file=False, include_class=False)
    list_parser.add_argument("--snapshot")
    list_parser.add_argument("--version", dest="version_label")
    list_parser.set_defaults(func=cmd_list)

    unexplored_parser = subparsers.add_parser("unexplored", help="List unexplored surfaces by class")
    _add_common_arguments(unexplored_parser, include_file=False, include_class=False, include_root=False)
    unexplored_parser.add_argument("--class", "--class-name", dest="class_name")
    unexplored_parser.set_defaults(func=cmd_unexplored)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help(sys.stderr)
        return 1
    try:
        return int(args.func(args) or 0)
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
