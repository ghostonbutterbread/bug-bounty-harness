#!/usr/bin/env python3
"""Real-time Ghost ledger coordination for hunting agents."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


LEDGER_VERSION = 1
DEFAULT_AGENT = os.environ.get("ME_AGENT") or "codex"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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


def _ghost_root(program: str) -> Path:
    return Path.home() / "Shared" / "bounty_recon" / _normalize_program(program) / "ghost"


def ledger_path(program: str) -> Path:
    return _ghost_root(program) / "ledger.json"


def _ledger_lock_path(program: str) -> Path:
    return _ghost_root(program) / "ledger.lock"


def _coverage_root(program: str) -> Path:
    return _ghost_root(program) / "surface_registry_source"


def _coverage_path(program: str, class_name: str) -> Path:
    return _coverage_root(program) / f"{_slugify_filename(class_name)}.json"


def _coverage_lock_path(program: str, class_name: str) -> Path:
    return _coverage_root(program) / f"{_slugify_filename(class_name)}.lock"


def _shared_brain_index_path(program: str) -> Path:
    return _ghost_root(program) / "shared_brain" / "index.json"


def _default_ledger(program: str) -> dict[str, Any]:
    return {
        "version": LEDGER_VERSION,
        "program": _normalize_program(program),
        "findings": [],
    }


def _default_coverage(program: str, class_name: str) -> dict[str, Any]:
    timestamp = _utc_now()
    return {
        "program": _normalize_program(program),
        "vuln_class": _normalize_class_name(class_name),
        "target_type": "source",
        "created_at": timestamp,
        "last_run": timestamp,
        "runs": 0,
        "examined": {},
        "unexplored": [],
        "findings": [],
        "notes": "",
    }


@contextmanager
def _locked_json(path: Path, lock_path: Path, default_factory, *, exclusive: bool) -> Iterator[dict[str, Any]]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.touch(exist_ok=True)
    mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH

    with lock_path.open("a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), mode)
        try:
            payload = _read_json(path, default_factory())
            yield payload
            if exclusive:
                _write_json_atomic(path, payload)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


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


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")
        temp_path = Path(handle.name)
    temp_path.replace(path)


def _finding_key(file_ref: str, class_name: str) -> tuple[str, str]:
    return (_normalize_relpath(file_ref), _normalize_class_name(class_name))


def _find_existing_finding(findings: list[dict[str, Any]], file_ref: str, class_name: str) -> dict[str, Any] | None:
    target_file, target_class = _finding_key(file_ref, class_name)
    for finding in findings:
        finding_file = _normalize_relpath(str(finding.get("file", "")))
        finding_class = _normalize_class_name(str(finding.get("class_name", "")) or "unknown")
        if (finding_file, finding_class) == (target_file, target_class):
            return finding
    return None


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


def _load_shared_brain_candidates(program: str) -> dict[str, list[str]]:
    path = _shared_brain_index_path(program)
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


def _load_coverage_payload(program: str, class_name: str) -> dict[str, Any]:
    return _read_json(_coverage_path(program, class_name), _default_coverage(program, class_name))


def _examined_files(payload: dict[str, Any]) -> set[str]:
    examined = payload.get("examined", {})
    if not isinstance(examined, dict):
        return set()
    return {_normalize_relpath(str(relpath)) for relpath in examined if _normalize_relpath(str(relpath))}


def _refresh_unexplored(payload: dict[str, Any], candidates: list[str]) -> None:
    examined = _examined_files(payload)
    payload["unexplored"] = [candidate for candidate in candidates if candidate not in examined]


def cmd_check(args: argparse.Namespace) -> int:
    with _locked_json(
        ledger_path(args.program),
        _ledger_lock_path(args.program),
        lambda: _default_ledger(args.program),
        exclusive=False,
    ) as ledger:
        existing = _find_existing_finding(ledger.get("findings", []), args.file, args.class_name)

    if existing is None:
        print(json.dumps({"exists": False}))
        return 0

    print(
        json.dumps(
            {
                "exists": True,
                "fid": str(existing.get("fid") or ""),
                "finding": existing,
            },
            indent=2,
        )
    )
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    with _locked_json(
        ledger_path(args.program),
        _ledger_lock_path(args.program),
        lambda: _default_ledger(args.program),
        exclusive=True,
    ) as ledger:
        findings = ledger.setdefault("findings", [])
        if not isinstance(findings, list):
            findings = []
            ledger["findings"] = findings

        existing = _find_existing_finding(findings, args.file, args.class_name)
        if existing is not None:
            print(json.dumps({"added": False, "duplicate": True, "finding": existing}, indent=2))
            return 0

        finding = {
            "fid": next_fid(findings, prefix=args.fid_prefix),
            "type": args.type,
            "class_name": _normalize_class_name(args.class_name),
            "file": _normalize_relpath(args.file),
            "severity": str(args.severity).strip().upper(),
            "review_tier": "PENDING_REVIEW",
            "added_at": _utc_now(),
            "agent": args.agent,
        }
        findings.append(finding)
        print(json.dumps({"added": True, "finding": finding}, indent=2))
    return 0


def cmd_cover(args: argparse.Namespace) -> int:
    class_name = _normalize_class_name(args.class_name)
    candidates = _load_shared_brain_candidates(args.program).get(class_name, [])
    coverage_file = _coverage_path(args.program, class_name)
    coverage_lock = _coverage_lock_path(args.program, class_name)
    timestamp = _utc_now()

    with _locked_json(
        coverage_file,
        coverage_lock,
        lambda: _default_coverage(args.program, class_name),
        exclusive=True,
    ) as payload:
        payload["program"] = _normalize_program(args.program)
        payload["vuln_class"] = class_name
        payload["target_type"] = "source"
        payload["last_run"] = timestamp
        payload["runs"] = _safe_int(payload.get("runs")) + 1

        examined = payload.setdefault("examined", {})
        if not isinstance(examined, dict):
            examined = {}
            payload["examined"] = examined

        relpath = _normalize_relpath(args.file)
        examined[relpath] = {
            "checked_at": timestamp,
            "method": args.agent,
            "sinks_found": [],
            "notes": "",
        }
        _refresh_unexplored(payload, candidates)
        uncovered = len(payload.get("unexplored", []))

    print(
        json.dumps(
            {
                "covered": True,
                "program": _normalize_program(args.program),
                "class_name": class_name,
                "file": _normalize_relpath(args.file),
                "remaining_unexplored": uncovered,
                "coverage_path": str(coverage_file),
            },
            indent=2,
        )
    )
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    with _locked_json(
        ledger_path(args.program),
        _ledger_lock_path(args.program),
        lambda: _default_ledger(args.program),
        exclusive=False,
    ) as ledger:
        findings = ledger.get("findings", [])
        if not isinstance(findings, list):
            findings = []

    print(
        json.dumps(
            {
                "program": _normalize_program(args.program),
                "ledger_path": str(ledger_path(args.program)),
                "findings": findings,
            },
            indent=2,
        )
    )
    return 0


def cmd_unexplored(args: argparse.Namespace) -> int:
    all_candidates = _load_shared_brain_candidates(args.program)
    if args.class_name:
        requested = _normalize_class_name(args.class_name)
        class_names = [requested]
    else:
        class_names = sorted(all_candidates)

    classes: dict[str, dict[str, Any]] = {}
    for class_name in class_names:
        candidates = all_candidates.get(class_name, [])
        coverage = _load_coverage_payload(args.program, class_name)
        examined = sorted(_examined_files(coverage))
        unexplored = [candidate for candidate in candidates if candidate not in set(examined)]
        classes[class_name] = {
            "candidate_count": len(candidates),
            "examined_count": len(examined),
            "unexplored_count": len(unexplored),
            "unexplored": unexplored,
            "coverage_path": str(_coverage_path(args.program, class_name)),
        }

    response: dict[str, Any] = {
        "program": _normalize_program(args.program),
        "shared_brain_path": str(_shared_brain_index_path(args.program)),
        "classes": classes,
    }
    if not _shared_brain_index_path(args.program).exists():
        response["warning"] = "shared_brain index not found; no candidate surfaces available"

    print(json.dumps(response, indent=2))
    return 0


def _add_common_arguments(parser: argparse.ArgumentParser, *, include_file: bool = True, include_class: bool = True) -> None:
    parser.add_argument("--program", required=True)
    if include_file:
        parser.add_argument("--file", required=True)
    if include_class:
        parser.add_argument("--class", "--class-name", dest="class_name", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ghost ledger coordination")
    subparsers = parser.add_subparsers(dest="command")

    check_parser = subparsers.add_parser("check", help="Check if a finding already exists")
    _add_common_arguments(check_parser)
    check_parser.set_defaults(func=cmd_check)

    add_parser = subparsers.add_parser("add", help="Add a finding to the ledger")
    _add_common_arguments(add_parser)
    add_parser.add_argument("--type", required=True)
    add_parser.add_argument("--severity", required=True)
    add_parser.add_argument("--agent", default=DEFAULT_AGENT)
    add_parser.add_argument("--fid-prefix", default="D")
    add_parser.set_defaults(func=cmd_add)

    cover_parser = subparsers.add_parser("cover", help="Mark a file/class surface as explored")
    _add_common_arguments(cover_parser)
    cover_parser.add_argument("--agent", default=DEFAULT_AGENT)
    cover_parser.set_defaults(func=cmd_cover)

    list_parser = subparsers.add_parser("list", help="List current findings")
    _add_common_arguments(list_parser, include_file=False, include_class=False)
    list_parser.set_defaults(func=cmd_list)

    unexplored_parser = subparsers.add_parser("unexplored", help="List unexplored surfaces by class")
    _add_common_arguments(unexplored_parser, include_file=False, include_class=False)
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
