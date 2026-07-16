#!/usr/bin/env python3
"""Promote normalized artifacts from a completed recon tool run."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from agents.recon import bus


DIRECTORY_NAMES = ("normalized", "parsed", "raw")
PORT_MARKERS = ("naabu", "ports", "port")

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
    if any(marker in stem for marker in PORT_MARKERS):
        return "port"
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


def normalize_host_port(host: object, port_value: object) -> tuple[str, int] | None:
    host_text = str(host or "").strip().lower()
    if "://" in host_text:
        parsed = urlparse(host_text)
        host_text = (parsed.hostname or "").lower()
        if port_value is None:
            port_value = parsed.port
    if isinstance(port_value, str) and "/" in port_value:
        port_value = port_value.split("/", 1)[0]
    try:
        port = int(port_value)
    except (TypeError, ValueError):
        return None
    if not host_text or port < 1 or port > 65535:
        return None
    return host_text, port


def parse_port_line(line: str) -> tuple[str, int] | None:
    value = str(line or "").strip()
    if not value:
        return None
    if value.startswith("{"):
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            return None
        host = payload.get("host") or payload.get("ip") or payload.get("url")
        port_value = payload.get("port")
        if port_value is None and isinstance(payload.get("ports"), list) and payload["ports"]:
            port_value = payload["ports"][0]
        return normalize_host_port(host, port_value)
    if "://" in value:
        parsed = urlparse(value)
        return normalize_host_port(parsed.hostname, parsed.port)
    if ":" in value:
        host, port_value = value.rsplit(":", 1)
        return normalize_host_port(host, port_value)
    return None


def _read_port_records(files: Iterable[Path], program: str, run_root: Path) -> tuple[list[dict[str, object]], list[str]]:
    seen: set[tuple[str, int]] = set()
    rows: list[dict[str, object]] = []
    lines: list[str] = []
    for path in files:
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            parsed = parse_port_line(raw)
            if not parsed:
                continue
            host, port = parsed
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "program": program,
                    "host": host,
                    "port": port,
                    "source": "promote-run",
                    "source_file": str(path),
                    "run_root": str(run_root),
                }
            )
            lines.append(f"{host}:{port}")
    rows.sort(key=lambda row: (str(row["host"]), int(row["port"])))
    lines = [f"{row['host']}:{row['port']}" for row in rows]
    return rows, lines


def _append_jsonl(path: Path, rows: Iterable[dict[str, object]]) -> dict[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_keys: set[tuple[str, int]] = set()
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            parsed = normalize_host_port(payload.get("host") or payload.get("ip") or payload.get("url"), payload.get("port"))
            if parsed:
                existing_keys.add(parsed)
    new_rows = []
    for row in rows:
        parsed = normalize_host_port(row.get("host"), row.get("port"))
        if not parsed or parsed in existing_keys:
            continue
        existing_keys.add(parsed)
        new_rows.append(row)
    if new_rows:
        with path.open("a", encoding="utf-8") as handle:
            for row in new_rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    return {"read": len(list(rows)) if not isinstance(rows, list) else len(rows), "new": len(new_rows)}


def _append_lines(path: Path, lines: Iterable[str]) -> dict[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = set(bus.read_file_lines(path))
    new_lines = [line for line in lines if line not in existing]
    if new_lines:
        with path.open("a", encoding="utf-8") as handle:
            for line in new_lines:
                handle.write(line + "\n")
    return {"read": len(list(lines)) if not isinstance(lines, list) else len(lines), "new": len(new_lines)}


def promote_ports(
    *,
    program: str,
    files: list[Path],
    run_root: Path,
    shared_base: str | None,
) -> dict[str, object]:
    original_shared_base = bus.SHARED_BASE
    if shared_base:
        bus.SHARED_BASE = Path(shared_base).expanduser()
    try:
        rows, lines = _read_port_records(files, program, run_root)
        services_root = bus.recon_root(program) / "services"
        services_jsonl = services_root / "ports.jsonl"
        services_txt = services_root / "ports.txt"
        services_append_jsonl = _append_jsonl(services_jsonl, rows)
        services_append_txt = _append_lines(services_txt, lines)
        aggregate_root = bus.aggregate_root(program)
        aggregate_jsonl = aggregate_root / "ports.jsonl"
        aggregate_txt = aggregate_root / "ports.txt"
        aggregate_append_jsonl = _append_jsonl(aggregate_jsonl, rows)
        aggregate_append_txt = _append_lines(aggregate_txt, lines)
        return {
            "files": [str(path) for path in files],
            "normalized_count": len(rows),
            "services_ports_jsonl": str(services_jsonl),
            "services_ports_txt": str(services_txt),
            "aggregated_ports_jsonl": str(aggregate_jsonl),
            "aggregated_ports_txt": str(aggregate_txt),
            "append": {
                "services_ports_jsonl": services_append_jsonl,
                "services_ports_txt": services_append_txt,
                "aggregated_ports_jsonl": aggregate_append_jsonl,
                "aggregated_ports_txt": aggregate_append_txt,
            },
        }
    finally:
        bus.SHARED_BASE = original_shared_base


def promote_run(args: argparse.Namespace) -> dict[str, object]:
    run_root = Path(args.run_root).expanduser()
    if not run_root.is_dir():
        raise SystemExit(f"--run-root is not a directory: {run_root}")

    discovered = discover_candidate_files(run_root)
    appends: dict[str, dict[str, object]] = {}
    for kind, files in discovered.items():
        if kind == "port":
            continue
        appends[kind] = append_kind(
            program=args.program,
            kind=kind,
            files=files,
            run_root=run_root,
            shared_base=args.shared_base,
            no_index=args.no_index,
        )
    services = None
    if discovered.get("port"):
        services = promote_ports(
            program=args.program,
            files=discovered["port"],
            run_root=run_root,
            shared_base=args.shared_base,
        )

    return {
        "program": args.program,
        "run_root": str(run_root),
        "discovered": {kind: [str(path) for path in files] for kind, files in discovered.items()},
        "appends": appends,
        "services": services,
        "status": "ok",
    }
