#!/usr/bin/env python3
"""One-shot watcher for promoting completed recon run manifests."""

from __future__ import annotations

import argparse
import importlib
import inspect
import json
import subprocess
import sys
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


DONE_STATUSES = {"done", "ok", "completed", "success"}

PromoteFunc = Callable[..., dict[str, Any]]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def is_recon_bus_run_manifest(path: Path) -> bool:
    parts = path.parts
    return any(left == "aggregated" and right == "runs" for left, right in zip(parts, parts[1:]))


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("manifest root must be an object")
    return data


def is_promotable_manifest(path: Path, manifest: dict[str, Any]) -> bool:
    if is_recon_bus_run_manifest(path):
        return False
    status = str(manifest.get("status", "")).strip().lower()
    if status not in DONE_STATUSES:
        return False
    return manifest.get("promoted") is not True


def iter_manifest_paths(root: Path) -> Iterable[Path]:
    if root.is_file() and root.name == "manifest.json":
        yield root
        return
    if not root.exists():
        return
    yield from sorted(root.rglob("manifest.json"))


def _coerce_path_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, (str, Path)):
        return [str(value)]
    if isinstance(value, dict):
        paths: list[str] = []
        for item in value.values():
            paths.extend(_coerce_path_list(item))
        return paths
    if isinstance(value, Iterable):
        return [str(item) for item in value if item]
    return []


def _promotion_counts(result: dict[str, Any]) -> dict[str, Any]:
    for key in ("promoted_counts", "counts"):
        value = result.get(key)
        if isinstance(value, dict):
            return dict(value)
    appends = result.get("appends")
    if isinstance(appends, dict):
        counts: dict[str, Any] = {}
        for kind, append_result in appends.items():
            if not isinstance(append_result, dict):
                continue
            kind_counts = {
                key: value
                for key, value in append_result.items()
                if isinstance(value, dict) and key not in {"mirrors"}
            }
            if kind_counts:
                counts[str(kind)] = kind_counts
        return counts
    counts: dict[str, Any] = {}
    for key in ("urls", "alive", "params", "hosts", "js", "dirs"):
        value = result.get(key)
        if isinstance(value, dict):
            counts[key] = dict(value)
    return counts


def _promotion_paths(result: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for key in ("promoted_paths_touched", "paths_touched", "touched_paths", "promoted_paths", "indexed"):
        paths.extend(_coerce_path_list(result.get(key)))
    appends = result.get("appends")
    if isinstance(appends, dict):
        for append_result in appends.values():
            if not isinstance(append_result, dict):
                continue
            for key in ("manifest", "incoming", "indexed", "mirrors"):
                paths.extend(_coerce_path_list(append_result.get(key)))
    return sorted(dict.fromkeys(paths))


def mark_promoted(manifest_path: Path, manifest: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    updated = dict(manifest)
    updated["promoted"] = True
    updated["promoted_at"] = utc_now()
    updated["promoted_counts"] = _promotion_counts(result)
    updated["promoted_paths_touched"] = _promotion_paths(result)
    updated["promotion_result"] = result
    manifest_path.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return updated


def default_promote_run(
    *,
    program: str,
    run_root: Path,
    shared_base: Path | None = None,
    no_index: bool = False,
) -> dict[str, Any]:
    """Call the promote-run implementation when present, otherwise its CLI."""
    try:
        module = importlib.import_module("agents.recon.promote_run")
    except ModuleNotFoundError as exc:
        if exc.name != "agents.recon.promote_run":
            raise
    else:
        promote = getattr(module, "promote_run", None) or getattr(module, "promote", None)
        if promote is None:
            raise RuntimeError("agents.recon.promote_run has no promote_run/promote callable")
        signature = inspect.signature(promote)
        if len(signature.parameters) == 1:
            result = promote(
                argparse.Namespace(
                    program=program,
                    run_root=str(run_root),
                    shared_base=str(shared_base) if shared_base is not None else None,
                    no_index=no_index,
                )
            )
        else:
            result = promote(program=program, run_root=run_root, shared_base=shared_base, no_index=no_index)
        return result if isinstance(result, dict) else {"result": result}

    script = Path(__file__).resolve().parents[2] / "scripts" / "recon_bus.py"
    command = [sys.executable, str(script), "promote-run", program, "--run-root", str(run_root)]
    if shared_base is not None:
        command.extend(["--shared-base", str(shared_base)])
    if no_index:
        command.append("--no-index")
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise RuntimeError(f"promote-run failed for {run_root}: {message[-1000:]}")
    stdout = completed.stdout.strip()
    if not stdout:
        return {"status": "ok"}
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        return {"status": "ok", "stdout": stdout}
    return parsed if isinstance(parsed, dict) else {"result": parsed}


def watch_runs(args: argparse.Namespace, *, promote_func: PromoteFunc | None = None) -> dict[str, Any]:
    root = Path(args.root).expanduser()
    shared_base = Path(args.shared_base).expanduser() if args.shared_base else None
    promote = promote_func or default_promote_run
    summary: dict[str, Any] = {
        "program": args.program,
        "root": str(root),
        "dry_run": bool(args.dry_run),
        "scanned": 0,
        "promotable": 0,
        "promoted": 0,
        "skipped": [],
        "failed": [],
        "updated_manifests": [],
    }

    for manifest_path in iter_manifest_paths(root):
        summary["scanned"] += 1
        try:
            manifest = load_manifest(manifest_path)
        except Exception as exc:
            summary["skipped"].append({"manifest": str(manifest_path), "reason": f"invalid-manifest: {exc}"})
            continue
        if not is_promotable_manifest(manifest_path, manifest):
            summary["skipped"].append({"manifest": str(manifest_path), "reason": "not-promotable"})
            continue

        summary["promotable"] += 1
        run_root = manifest_path.parent
        if args.dry_run:
            summary["skipped"].append({"manifest": str(manifest_path), "reason": "dry-run", "run_root": str(run_root)})
            continue

        try:
            result = promote(
                program=args.program,
                run_root=run_root,
                shared_base=shared_base,
                no_index=bool(args.no_index),
            )
        except Exception as exc:
            summary["failed"].append({"manifest": str(manifest_path), "run_root": str(run_root), "error": str(exc)})
            continue

        updated = mark_promoted(manifest_path, manifest, result if isinstance(result, dict) else {"result": result})
        summary["promoted"] += 1
        summary["updated_manifests"].append(
            {
                "manifest": str(manifest_path),
                "run_root": str(run_root),
                "promoted_at": updated["promoted_at"],
                "promoted_counts": updated["promoted_counts"],
                "promoted_paths_touched": updated["promoted_paths_touched"],
            }
        )

    return summary


def add_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("watch-runs", help="Promote completed recon run manifests once per invocation.")
    parser.add_argument("program")
    parser.add_argument("--root", required=True, help="Recon tool run root or recon root to scan.")
    parser.add_argument("--shared-base", help="Override Shared web_bounty root for promote-run.")
    parser.add_argument("--dry-run", action="store_true", help="List promotable manifests without promoting or writing.")
    parser.add_argument("--no-index", action="store_true", help="Pass through to promote-run to skip index writes.")
    parser.set_defaults(func=watch_runs)
    return parser
