#!/usr/bin/env python3
"""Promote normalized artifacts from a completed recon tool run."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from agents.recon import bus


DIRECTORY_NAMES = ("normalized", "parsed")

FILENAME_KIND_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("params_raw", "params"), "param"),
    (("jsfiles", "js_urls", "javascript"), "js"),
    (("alive", "httpx", "live"), "alive"),
    (("wild", "hosts", "host", "subdomains", "subdomain"), "host"),
    (("dirs", "directories", "paths"), "dir"),
    (("urls", "url"), "url"),
)


def is_params_view(path: Path) -> bool:
    return path.name.lower() == "params.txt"


def is_params_raw(path: Path) -> bool:
    return path.name.lower() == "params_raw.txt"


def classify_path(path: Path) -> str | None:
    """Return the recon bus aggregate kind implied by a known output filename."""
    stem = path.stem.lower()
    for markers, kind in FILENAME_KIND_RULES:
        if any(marker in stem for marker in markers):
            return kind
    return None


def _dedupe_paths(paths: Iterable[Path]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen or not path.is_file():
            continue
        seen.add(resolved)
        out.append(path)
    return out


def _direct_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.iterdir() if path.is_file())


def _under_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _resolve_manifest_path(value: str, run_root: Path) -> Path | None:
    text = str(value or "").strip()
    if not text:
        return None
    candidate = Path(text).expanduser()
    if not candidate.is_absolute():
        candidate = run_root / candidate
    if candidate.is_file() and _under_root(candidate, run_root):
        return candidate
    return None


def _manifest_path_values(value: object, *, key_hint: str = "") -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            hint = f"{key_hint}.{key}" if key_hint else str(key)
            yield from _manifest_path_values(child, key_hint=hint)
        return
    if isinstance(value, list):
        for child in value:
            yield from _manifest_path_values(child, key_hint=key_hint)
        return
    if not isinstance(value, str):
        return

    lowered = key_hint.lower()
    if any(marker in lowered for marker in ("output", "file", "path", "artifact", "normalized", "parsed")):
        yield value


def manifest_declared_files(run_root: Path) -> list[Path]:
    manifest = run_root / "manifest.json"
    if not manifest.is_file():
        return []
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    paths = []
    for value in _manifest_path_values(payload):
        path = _resolve_manifest_path(value, run_root)
        if path is not None:
            paths.append(path)
    return _dedupe_paths(paths)


def discover_candidate_files(run_root: Path) -> dict[str, list[Path]]:
    files: list[Path] = []
    files.extend(_direct_files(run_root))
    for name in DIRECTORY_NAMES:
        files.extend(_direct_files(run_root / name))
    files.extend(manifest_declared_files(run_root))

    grouped: dict[str, list[Path]] = defaultdict(list)
    for path in _dedupe_paths(files):
        kind = classify_path(path)
        if kind:
            grouped[kind].append(path)
    if any(is_params_raw(path) for path in grouped.get("param", [])):
        grouped["param"] = [path for path in grouped["param"] if not is_params_view(path)]
    return {kind: sorted(paths) for kind, paths in sorted(grouped.items())}


def append_kind(
    *,
    program: str,
    kind: str,
    files: list[Path],
    run_root: Path,
    shared_base: str | None,
    no_index: bool,
) -> dict[str, object]:
    append_args = argparse.Namespace(
        program=program,
        kind=kind,
        value=[],
        input=[str(path) for path in files],
        stdin=False,
        run_id=f"promote-{bus.safe_slug(run_root.name)}-{kind}",
        liveness="unknown",
        httpx_bin=None,
        uro_bin=None,
        shared_base=shared_base,
        no_index=no_index,
    )
    return bus.append(append_args)


def promote_run(args: argparse.Namespace) -> dict[str, object]:
    run_root = Path(args.run_root).expanduser()
    if not run_root.is_dir():
        raise SystemExit(f"--run-root is not a directory: {run_root}")

    discovered = discover_candidate_files(run_root)
    appends: dict[str, dict[str, object]] = {}
    for kind, files in discovered.items():
        appends[kind] = append_kind(
            program=args.program,
            kind=kind,
            files=files,
            run_root=run_root,
            shared_base=args.shared_base,
            no_index=args.no_index,
        )

    return {
        "program": args.program,
        "run_root": str(run_root),
        "discovered": {kind: [str(path) for path in files] for kind, files in discovered.items()},
        "appends": appends,
        "status": "ok",
    }
