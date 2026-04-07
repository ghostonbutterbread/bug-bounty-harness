"""Persistent, incremental repository index for zero-day team agents."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Iterable

from agents.sink_detector import SinkDetector


LOGGER = logging.getLogger(__name__)

INDEX_FILENAME = "index.json"
INDEX_VERSION = 1
MAX_FILE_SIZE = 2 * 1024 * 1024
MAX_CONTEXT_WORDS = 850
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    "out",
}
TEXT_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".css",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".mjs",
    ".cjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}
LANGUAGE_BY_SUFFIX = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".css": "css",
    ".go": "go",
    ".h": "c-header",
    ".hpp": "cpp-header",
    ".html": "html",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".json": "json",
    ".kt": "kotlin",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".sh": "shell",
    ".sql": "sql",
    ".swift": "swift",
    ".toml": "toml",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".txt": "text",
    ".vue": "vue",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
}

FRAMEWORK_SIGNATURES: dict[str, list[str]] = {
    "electron": [
        r"BrowserWindow",
        r"contextBridge\.exposeInMainWorld",
        r"ipcMain\.",
        r"ipcRenderer\.",
        r"webContents\.",
        r"\[browserwindow\]",
    ],
    "node": [
        r"\"engines\":\"",
        r"require\s*\(",
        r"module\.exports",
        r"\"type\":\"module\"",
    ],
    "python": [
        r"#!/usr/bin/env python",
        r"import\s+(flask|fastapi|django|requests|httpx)",
        r"requirements\.txt",
        r"setup\.py",
        r"pyproject\.toml",
    ],
}

ENTRY_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bnew\s+BrowserWindow\s*\(", re.IGNORECASE), "browser-window"),
    (re.compile(r"\bcontextBridge\.exposeInMainWorld\s*\(", re.IGNORECASE), "context-bridge"),
    (re.compile(r"\bipcMain\.(handle|on)\s*\(", re.IGNORECASE), "ipc-main-handler"),
    (re.compile(r"\bipcRenderer\.(invoke|send|on)\s*\(", re.IGNORECASE), "ipc-renderer-call"),
    (
        re.compile(r"\b(app|router)\.(get|post|put|delete|patch|all)\s*\(", re.IGNORECASE),
        "http-route",
    ),
    (
        re.compile(r"\b(process\.argv|sys\.argv|argparse\.ArgumentParser)\b", re.IGNORECASE),
        "cli-args",
    ),
    (
        re.compile(r"\b(process\.env|os\.environ|getenv)\b", re.IGNORECASE),
        "environment-read",
    ),
)

TRUST_BOUNDARY_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bcontextBridge\.exposeInMainWorld\s*\(", re.IGNORECASE), "context-bridge"),
    (re.compile(r"\bipcMain\.(handle|on)\s*\(", re.IGNORECASE), "ipc-main"),
    (re.compile(r"\bipcRenderer\.(invoke|send|on)\s*\(", re.IGNORECASE), "ipc-renderer"),
    (
        re.compile(r"\b(postMessage|addEventListener\s*\(\s*['\"]message['\"])", re.IGNORECASE),
        "postmessage",
    ),
    (
        re.compile(r"\b(fetch|axios\.|requests\.(get|post|put|request)|httpx\.)", re.IGNORECASE),
        "network",
    ),
    (
        re.compile(
            r"\b(fs\.(readFile|writeFile|createReadStream|createWriteStream|copyFile|mkdir)"
            r"|open\s*\(|Path\s*\(|path\.(join|resolve|normalize))",
            re.IGNORECASE,
        ),
        "filesystem",
    ),
    (re.compile(r"\b(localStorage|sessionStorage|document\.cookie)\b", re.IGNORECASE), "storage"),
    (re.compile(r"\b(process\.env|os\.environ|getenv)\b", re.IGNORECASE), "environment"),
)

SEVERITY_WEIGHTS = {"critical": 5, "high": 4, "medium": 2, "low": 1}

SINK_PATTERNS: dict[str, list[tuple[re.Pattern[str], str, str, list[str]]]] = {
    "dom-sink": [
        (re.compile(r"\.innerHTML\s*=", re.IGNORECASE), "innerHTML", "high", ["dom-xss"]),
        (re.compile(r"\.outerHTML\s*=", re.IGNORECASE), "outerHTML", "high", ["dom-xss"]),
        (re.compile(r"document\.write\s*\(", re.IGNORECASE), "document.write", "high", ["dom-xss"]),
        (re.compile(r"eval\s*\(", re.IGNORECASE), "eval", "critical", ["dom-xss", "exec-sink-reachability"]),
        (re.compile(r"Function\s*\(", re.IGNORECASE), "Function", "critical", ["dom-xss", "exec-sink-reachability"]),
    ],
    "file-ops": [
        (
            re.compile(r"fs\.(readFile|readFileSync|createReadStream)", re.IGNORECASE),
            "fs-read",
            "medium",
            ["path-traversal", "idor"],
        ),
        (
            re.compile(r"fs\.(writeFile|writeFileSync|createWriteStream|copyFile|mkdir)", re.IGNORECASE),
            "fs-write",
            "high",
            ["path-traversal", "idor"],
        ),
    ],
    "os-exec": [
        (
            re.compile(r"child_process\.(exec|execFile|spawn|fork)", re.IGNORECASE),
            "child_process.exec",
            "critical",
            ["exec-sink-reachability"],
        ),
        (
            re.compile(r"subprocess\.(Popen|run|call|check_output)", re.IGNORECASE),
            "subprocess",
            "critical",
            ["exec-sink-reachability"],
        ),
        (
            re.compile(r"os\.system\s*\(|\bpopen\s*\(", re.IGNORECASE),
            "os.system",
            "critical",
            ["exec-sink-reachability"],
        ),
    ],
    "network": [
        (re.compile(r"\bfetch\s*\(", re.IGNORECASE), "fetch", "high", ["ssrf"]),
        (re.compile(r"\baxios\.", re.IGNORECASE), "axios", "high", ["ssrf"]),
        (
            re.compile(r"requests\.(get|post|put|request)", re.IGNORECASE),
            "requests",
            "high",
            ["ssrf"],
        ),
    ],
    "deserialization": [
        (
            re.compile(r"pickle\.loads?|pickle\.load", re.IGNORECASE),
            "pickle",
            "critical",
            ["unsafe-deserialization"],
        ),
        (re.compile(r"yaml\.load\s*\(", re.IGNORECASE), "yaml.load", "high", ["unsafe-deserialization"]),
        (re.compile(r"marshal\.loads?", re.IGNORECASE), "marshal", "critical", ["unsafe-deserialization"]),
    ],
    "ipc": [
        (
            re.compile(r"contextBridge\.exposeInMainWorld", re.IGNORECASE),
            "contextBridge",
            "high",
            ["ipc-trust-boundary"],
        ),
        (
            re.compile(r"ipcRenderer\.(invoke|send|on)", re.IGNORECASE),
            "ipcRenderer",
            "high",
            ["ipc-trust-boundary"],
        ),
        (
            re.compile(r"ipcMain\.(handle|on)", re.IGNORECASE),
            "ipcMain",
            "high",
            ["ipc-trust-boundary"],
        ),
    ],
    "prototype-pollution": [
        (
            re.compile(r"Object\.assign\s*\(", re.IGNORECASE),
            "Object.assign",
            "medium",
            ["prototype-pollution"],
        ),
        (
            re.compile(r"\bmerge\s*\(|deepMerge|deepAssign", re.IGNORECASE),
            "deep-merge",
            "medium",
            ["prototype-pollution"],
        ),
    ],
    "native-module": [
        (
            re.compile(r"require\s*\(\s*['\"]better-sqlite3", re.IGNORECASE),
            "better-sqlite3",
            "high",
            ["native-module-abuse"],
        ),
        (
            re.compile(r"require\s*\(\s*['\"]keytar", re.IGNORECASE),
            "keytar",
            "critical",
            ["native-module-abuse"],
        ),
        (
            re.compile(r"require\s*\(\s*['\"]node-pty", re.IGNORECASE),
            "node-pty",
            "critical",
            ["native-module-abuse"],
        ),
        (
            re.compile(r"process\.dlopen\b", re.IGNORECASE),
            "process.dlopen",
            "critical",
            ["native-module-abuse"],
        ),
    ],
    "memory-ops": [
        (
            re.compile(r"\b(memcpy|memmove|strcpy|strcat|sprintf|vsprintf)\b", re.IGNORECASE),
            "native-memory-op",
            "critical",
            ["memory-unsafe-parser"],
        ),
        (
            re.compile(r"\bfrom_raw_parts|get_unchecked|copy_nonoverlapping\b", re.IGNORECASE),
            "rust-unsafe-op",
            "critical",
            ["memory-unsafe-parser"],
        ),
    ],
    "browser-config": [
        (
            re.compile(r"nodeIntegration\s*:\s*true", re.IGNORECASE),
            "nodeIntegration:true",
            "critical",
            ["node-integration"],
        ),
        (
            re.compile(r"contextIsolation\s*:\s*false", re.IGNORECASE),
            "contextIsolation:false",
            "critical",
            ["node-integration"],
        ),
    ],
}

SINK_NAME_TO_HINTS = {
    "innerHTML": ("innerHTML", "high", ["dom-xss"]),
    "outerHTML": ("outerHTML", "high", ["dom-xss"]),
    "document.write": ("document.write", "high", ["dom-xss"]),
    "document.writeln": ("document.write", "high", ["dom-xss"]),
    "eval()": ("eval", "critical", ["dom-xss", "exec-sink-reachability"]),
    "setTimeout(string)": ("setTimeout", "medium", ["dom-xss"]),
    "setInterval(string)": ("setInterval", "medium", ["dom-xss"]),
    "Function()": ("Function", "critical", ["dom-xss", "exec-sink-reachability"]),
    "new Function()": ("Function", "critical", ["dom-xss", "exec-sink-reachability"]),
    "execScript": ("execScript", "critical", ["dom-xss", "exec-sink-reachability"]),
    "insertAdjacentHTML": ("insertAdjacentHTML", "high", ["dom-xss"]),
    ".jquery.html()": ("jquery.html", "medium", ["dom-xss"]),
    "dangerouslySetInnerHTML": ("dangerouslySetInnerHTML", "high", ["dom-xss"]),
    "v-html": ("v-html", "medium", ["dom-xss"]),
    "ng-bind-html": ("ng-bind-html", "medium", ["dom-xss"]),
    "render": ("render", "low", ["dom-xss"]),
    "rerender": ("rerender", "low", ["dom-xss"]),
}


@dataclass
class RepoIndex:
    """Persistent target-wide repository index."""

    version: int = INDEX_VERSION
    target_root: str = ""
    target_id: str = ""
    generated_at: str = ""
    git_head: str | None = None
    manifest_hash: str = ""
    frameworks: list[dict[str, Any]] = field(default_factory=list)
    files: dict[str, dict[str, Any]] = field(default_factory=dict)
    inventories: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RepoIndex":
        """Deserialize a RepoIndex from JSON-backed data."""
        return cls(
            version=int(payload.get("version", INDEX_VERSION)),
            target_root=str(payload.get("target_root", "")).strip(),
            target_id=str(payload.get("target_id", "")).strip(),
            generated_at=str(payload.get("generated_at", "")).strip(),
            git_head=payload.get("git_head"),
            manifest_hash=str(payload.get("manifest_hash", "")).strip(),
            frameworks=list(payload.get("frameworks") or []),
            files=dict(payload.get("files") or {}),
            inventories=dict(payload.get("inventories") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return asdict(self)


def build_index(target_path: str | Path, program: str) -> RepoIndex:
    """Full index build. Walk files, scan signals, and aggregate inventories."""
    target_root = _resolve_target_root(target_path)
    manifest = _build_manifest(target_root)
    files: dict[str, dict[str, Any]] = {}

    for relpath in sorted(manifest):
        abs_path = target_root / relpath
        file_record = _index_file(abs_path, relpath)
        if file_record is not None:
            files[relpath] = file_record

    index = RepoIndex(
        version=INDEX_VERSION,
        target_root=str(target_root),
        target_id=_target_id_for(target_root),
        generated_at=_timestamp_iso(),
        git_head=_git_head_for(target_root),
        manifest_hash=_manifest_hash(manifest),
        frameworks=_detect_frameworks(files),
        files=files,
        inventories=_aggregate_inventories(files),
    )
    return index


def update_index(target_path: str | Path, existing: RepoIndex) -> RepoIndex:
    """Incrementally refresh an existing index based on current file metadata."""
    target_root = _resolve_target_root(target_path)
    manifest = _build_manifest(target_root)
    manifest_hash = _manifest_hash(manifest)
    git_head = _git_head_for(target_root)
    target_id = _target_id_for(target_root)

    if existing.target_id and existing.target_id != target_id:
        return build_index(target_root, program="ignored")

    if existing.manifest_hash == manifest_hash and existing.git_head == git_head:
        existing.generated_at = _timestamp_iso()
        return existing

    current_files: dict[str, dict[str, Any]] = {}
    changed_paths: set[str] = set()
    removed_paths = set(existing.files) - set(manifest)

    for relpath, metadata in manifest.items():
        cached = existing.files.get(relpath)
        if cached and _same_file_metadata(cached, metadata):
            current_files[relpath] = cached
            continue
        changed_paths.add(relpath)
        indexed = _index_file(target_root / relpath, relpath)
        if indexed is not None:
            current_files[relpath] = indexed

    if removed_paths:
        LOGGER.info("shared_brain removed %d file(s)", len(removed_paths))

    updated = RepoIndex(
        version=INDEX_VERSION,
        target_root=str(target_root),
        target_id=target_id,
        generated_at=_timestamp_iso(),
        git_head=git_head,
        manifest_hash=manifest_hash,
        frameworks=_detect_frameworks(current_files),
        files=current_files,
        inventories=_aggregate_inventories(current_files),
    )
    if changed_paths:
        LOGGER.info("shared_brain re-indexed %d changed file(s)", len(changed_paths))
    return updated


def load_index(program: str) -> RepoIndex | None:
    """Load an existing index from disk if present and valid."""
    path = _index_path(program)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.warning("shared_brain load failed for %s: %s", path, exc)
        return None
    if not isinstance(payload, dict):
        LOGGER.warning("shared_brain payload in %s is not an object", path)
        return None
    try:
        index = RepoIndex.from_dict(payload)
    except Exception as exc:
        LOGGER.warning("shared_brain decode failed for %s: %s", path, exc)
        return None
    if index.version != INDEX_VERSION:
        LOGGER.info("shared_brain version mismatch in %s; ignoring cached index", path)
        return None
    return index


def save_index(index: RepoIndex, program: str) -> None:
    """Persist an index under the program's shared brain directory."""
    path = _index_path(program)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(index.to_dict(), indent=2, sort_keys=True)
    path.write_text(payload + "\n", encoding="utf-8")


def get_class_context(index: RepoIndex, vuln_class: str) -> str:
    """Return compact generic repository context for one vulnerability class."""
    frameworks = [str(item.get("name", "")).strip() for item in index.frameworks if item.get("name")]
    files_by_score = sorted(
        index.files.items(),
        key=lambda item: (
            -int(item[1].get("signals", {}).get("class_scores", {}).get(vuln_class, 0)),
            -len(item[1].get("roles", []) or []),
            item[0],
        ),
    )
    top_files = []
    for relpath, data in files_by_score:
        score = int(data.get("signals", {}).get("class_scores", {}).get(vuln_class, 0))
        roles = ", ".join(data.get("roles") or [])
        if score <= 0 and not roles:
            continue
        top_files.append((relpath, data, score))
        if len(top_files) >= 6:
            break

    sinks = [
        item
        for item in index.inventories.get("sinks", [])
        if vuln_class in list(item.get("class_hints") or [])
    ][:10]
    boundaries = _candidate_boundaries(index, vuln_class)[:8]
    entries = _candidate_entries(index, vuln_class)[:6]

    lines = ["Repository inventory:"]
    if frameworks:
        lines.append(f"- Frameworks: {', '.join(frameworks)}")
    else:
        lines.append("- Frameworks: none confidently detected")

    if top_files:
        lines.append("- Files with recorded signals:")
        for relpath, data, score in top_files:
            roles = ", ".join(data.get("roles") or []) or "none"
            lines.append(f"  - {relpath} | roles={roles} | signal_score={score}")

    if boundaries:
        lines.append("- Trust boundaries observed:")
        for item in boundaries:
            lines.append(f"  - {item['file']}:{item['line']} | {item['kind']} | {item['text']}")

    if sinks:
        lines.append("- Sink inventory:")
        for item in sinks:
            lines.append(f"  - {item['file']}:{item['line']} | {item['kind']} | {item['text']}")

    if entries:
        lines.append("- Entry points and interfaces:")
        for item in entries:
            lines.append(f"  - {item['file']}:{item['line']} | {item['kind']} | {item['text']}")

    if not top_files and not boundaries and not sinks and not entries:
        lines.append("- No class-tagged signals recorded in the shared index.")

    return _truncate_context(lines, max_words=MAX_CONTEXT_WORDS)


def get_diverse_entry_points(index: RepoIndex, vuln_class: str, count: int = 3) -> list[dict[str, Any]]:
    """Return diverse entry points for a vulnerability class.

    Returns 'count' entry points from DIFFERENT files/kinds to ensure
    agents don't all start from the same position. Prefers entry points
    that have roles like 'entry-point', 'ipc-renderer-call', 'network'.
    """
    if count <= 0:
        return []

    entries = _candidate_entries(index, vuln_class)
    if not entries:
        return []

    scored: list[tuple[int, str, dict[str, Any]]] = []
    for entry in entries:
        kind = str(entry.get("kind", ""))
        file_path = str(entry.get("file", ""))

        priority = 0
        if kind in ("ipc-renderer-call", "context-bridge", "network", "cli-args"):
            priority = 3
        elif kind in ("ipc-main-handler", "ipc-renderer"):
            priority = 2
        elif "entry-point" in entry.get("roles", []):
            priority = 4
        else:
            priority = 1

        # Boost priority by class score so each class gets entry points
        # from files that actually matter for that class
        if file_path in index.files:
            class_score = index.files[file_path].get("signals", {}).get("class_scores", {}).get(vuln_class, 0)
            priority += class_score // 20  # scale: score of 80-100 adds +4

        scored.append((priority, file_path, entry))

    scored.sort(key=lambda item: (-item[0], item[1]))

    chosen: list[dict[str, Any]] = []
    chosen_files: set[str] = set()
    for _, file_path, entry in scored:
        if file_path in chosen_files:
            continue
        chosen.append(entry)
        chosen_files.add(file_path)
        if len(chosen) >= count:
            break

    return chosen


def _resolve_target_root(target_path: str | Path) -> Path:
    target_root = Path(target_path).expanduser().resolve()
    if not target_root.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_root}")
    if not target_root.is_dir():
        raise NotADirectoryError(f"Target path is not a directory: {target_root}")
    return target_root


def _timestamp_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _target_id_for(target_root: Path) -> str:
    return hashlib.sha1(str(target_root).encode("utf-8")).hexdigest()


def _index_path(program: str) -> Path:
    return (
        Path.home()
        / "Shared"
        / "bounty_recon"
        / str(program).strip()
        / "ghost"
        / "shared_brain"
        / INDEX_FILENAME
    )


def _git_head_for(target_root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(target_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    head = result.stdout.strip()
    return head or None


def _build_manifest(target_root: Path) -> dict[str, dict[str, int]]:
    manifest: dict[str, dict[str, int]] = {}
    for abs_path in _iter_indexable_files(target_root):
        try:
            stat_result = abs_path.stat()
        except OSError:
            continue
        relpath = abs_path.relative_to(target_root).as_posix()
        manifest[relpath] = {"size": int(stat_result.st_size), "mtime_ns": int(stat_result.st_mtime_ns)}
    return manifest


def _manifest_hash(manifest: dict[str, dict[str, int]]) -> str:
    digest = hashlib.sha256()
    for relpath in sorted(manifest):
        meta = manifest[relpath]
        digest.update(f"{relpath}\0{meta['size']}\0{meta['mtime_ns']}\n".encode("utf-8"))
    return digest.hexdigest()


def _iter_indexable_files(target_root: Path) -> Iterable[Path]:
    for root, dirnames, filenames in os.walk(target_root, topdown=True):
        dirnames[:] = [dirname for dirname in dirnames if dirname not in SKIP_DIRS]
        root_path = Path(root)
        for filename in filenames:
            abs_path = root_path / filename
            try:
                stat_result = abs_path.stat()
            except OSError:
                continue
            if stat_result.st_size > MAX_FILE_SIZE:
                continue
            if _looks_textual(abs_path):
                yield abs_path


def _looks_textual(path: Path) -> bool:
    if path.name in {"Dockerfile", "Makefile", "requirements.txt", "setup.py", "pyproject.toml", "package.json"}:
        return True
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    try:
        sample = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\x00" not in sample


def _index_file(abs_path: Path, relpath: str) -> dict[str, Any] | None:
    try:
        stat_result = abs_path.stat()
        content = abs_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    lang = _detect_language(abs_path, content)
    sha1 = hashlib.sha1(content.encode("utf-8", errors="replace")).hexdigest()
    entries = _scan_lines(content, ENTRY_PATTERNS)
    trust_boundaries = _scan_lines(content, TRUST_BOUNDARY_PATTERNS)
    sinks, class_scores = _scan_sinks(content)
    roles = _derive_roles(relpath, content, entries, trust_boundaries, sinks)

    return {
        "lang": lang,
        "size": int(stat_result.st_size),
        "mtime_ns": int(stat_result.st_mtime_ns),
        "sha1": sha1,
        "roles": roles,
        "signals": {
            "entries": entries,
            "trust_boundaries": trust_boundaries,
            "sinks": sinks,
            "class_scores": class_scores,
        },
    }


def _detect_language(path: Path, content: str) -> str:
    suffix = path.suffix.lower()
    if suffix in LANGUAGE_BY_SUFFIX:
        return LANGUAGE_BY_SUFFIX[suffix]
    if path.name == "Dockerfile":
        return "dockerfile"
    if content.startswith("#!/usr/bin/env python"):
        return "python"
    if content.startswith("#!/usr/bin/env node"):
        return "javascript"
    return "text"


def _scan_lines(content: str, patterns: Iterable[tuple[re.Pattern[str], str]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        for pattern, kind in patterns:
            if pattern.search(raw_line):
                results.append({"line": line_number, "kind": kind, "text": line[:220]})
    return _dedupe_signal_rows(results)


def _scan_sinks(content: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    sinks: list[dict[str, Any]] = []
    class_scores: dict[str, int] = {}
    seen: set[tuple[int, str]] = set()

    detector = SinkDetector()
    for sink in detector.find_sinks(content):
        sink_key = (sink.line, sink.name)
        if sink_key in seen:
            continue
        seen.add(sink_key)
        normalized_name, severity, class_hints = _sink_hints_for_name(sink.name)
        sinks.append(
            {
                "line": sink.line,
                "kind": normalized_name,
                "text": sink.snippet[:220],
                "class_hints": class_hints,
            }
        )
        for class_hint in class_hints:
            class_scores[class_hint] = class_scores.get(class_hint, 0) + SEVERITY_WEIGHTS.get(severity, 1)

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        for pattern_group in SINK_PATTERNS.values():
            for pattern, kind, severity, class_hints in pattern_group:
                if not pattern.search(raw_line):
                    continue
                sink_key = (line_number, kind)
                if sink_key in seen:
                    continue
                seen.add(sink_key)
                sinks.append(
                    {
                        "line": line_number,
                        "kind": kind,
                        "text": stripped[:220],
                        "class_hints": list(class_hints),
                    }
                )
                for class_hint in class_hints:
                    class_scores[class_hint] = class_scores.get(class_hint, 0) + SEVERITY_WEIGHTS.get(severity, 1)

    _apply_signal_scores(class_scores, sinks)
    return sorted(sinks, key=lambda item: (int(item["line"]), str(item["kind"]))), class_scores


def _sink_hints_for_name(sink_name: str) -> tuple[str, str, list[str]]:
    mapped = SINK_NAME_TO_HINTS.get(sink_name)
    if mapped is None:
        return sink_name, "medium", []
    kind, severity, class_hints = mapped
    return kind, severity, list(class_hints)


def _apply_signal_scores(class_scores: dict[str, int], sinks: list[dict[str, Any]]) -> None:
    kinds = {str(item.get("kind", "")) for item in sinks}
    if "contextBridge" in kinds or "ipcMain" in kinds or "ipcRenderer" in kinds:
        class_scores["ipc-trust-boundary"] = class_scores.get("ipc-trust-boundary", 0) + 2
    if "nodeIntegration:true" in kinds or "contextIsolation:false" in kinds:
        class_scores["node-integration"] = class_scores.get("node-integration", 0) + 5
    if "native-memory-op" in kinds or "rust-unsafe-op" in kinds:
        class_scores["memory-unsafe-parser"] = class_scores.get("memory-unsafe-parser", 0) + 4


def _derive_roles(
    relpath: str,
    content: str,
    entries: list[dict[str, Any]],
    trust_boundaries: list[dict[str, Any]],
    sinks: list[dict[str, Any]],
) -> list[str]:
    roles: set[str] = set()
    lower_relpath = relpath.lower()
    if any(marker in lower_relpath for marker in ("preload", "bridge")) or re.search(
        r"contextBridge\.exposeInMainWorld", content, re.IGNORECASE
    ):
        roles.add("electron-preload")
    if any(marker in lower_relpath for marker in ("main.", "/main/", "electron-main")) or re.search(
        r"BrowserWindow|app\.whenReady|webContents\.", content, re.IGNORECASE
    ):
        roles.add("electron-main")
    if re.search(r"\b(ipcMain|ipcRenderer)\.", content, re.IGNORECASE):
        roles.add("ipc")
    if trust_boundaries:
        roles.add("trust-boundary")
    if entries:
        roles.add("entry-point")
    if any("nodeIntegration:true" == item.get("kind") or "contextIsolation:false" == item.get("kind") for item in sinks):
        roles.add("electron-main")
    return sorted(roles)


def _aggregate_inventories(files: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    inventories = {"entries": [], "trust_boundaries": [], "sinks": []}
    for relpath, data in files.items():
        signals = data.get("signals", {})
        for key in ("entries", "trust_boundaries", "sinks"):
            for item in signals.get(key, []) or []:
                row = {"file": relpath, **item}
                inventories[key].append(row)
    for key in inventories:
        inventories[key] = sorted(
            inventories[key],
            key=lambda item: (str(item.get("file", "")), int(item.get("line", 0)), str(item.get("kind", ""))),
        )
    return inventories


def _detect_frameworks(files: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    frameworks: list[dict[str, Any]] = []
    names = set()
    if any(
        any(role in {"electron-main", "electron-preload"} for role in data.get("roles", []))
        for data in files.values()
    ):
        names.add("electron")
    if any(
        data.get("lang") in {"javascript", "typescript"}
        or relpath.endswith("package.json")
        for relpath, data in files.items()
    ):
        names.add("node")
    if any(
        data.get("lang") == "python"
        or relpath.endswith(("requirements.txt", "setup.py", "pyproject.toml"))
        for relpath, data in files.items()
    ):
        names.add("python")

    for name in sorted(names):
        evidence = _framework_evidence(name, files)
        frameworks.append({"name": name, "count": len(evidence), "files": evidence[:5]})
    return frameworks


def _framework_evidence(name: str, files: dict[str, dict[str, Any]]) -> list[str]:
    evidence: list[str] = []
    for relpath, data in sorted(files.items()):
        content_signals = data.get("signals", {})
        roles = set(data.get("roles") or [])
        lang = str(data.get("lang", ""))
        if name == "electron" and (
            {"electron-main", "electron-preload"} & roles
            or any(item.get("kind") in {"context-bridge", "ipc-main", "ipc-renderer"} for item in content_signals.get("trust_boundaries", []))
        ):
            evidence.append(relpath)
        elif name == "node" and (lang in {"javascript", "typescript"} or relpath.endswith("package.json")):
            evidence.append(relpath)
        elif name == "python" and (lang == "python" or relpath.endswith(("requirements.txt", "setup.py", "pyproject.toml"))):
            evidence.append(relpath)
    return evidence


def _candidate_boundaries(index: RepoIndex, vuln_class: str) -> list[dict[str, Any]]:
    boundaries = index.inventories.get("trust_boundaries", [])
    if vuln_class == "ipc-trust-boundary":
        preferred = {"context-bridge", "ipc-main", "ipc-renderer"}
        matches = [item for item in boundaries if item.get("kind") in preferred]
        if matches:
            return matches
    if vuln_class == "ssrf":
        matches = [item for item in boundaries if item.get("kind") == "network"]
        if matches:
            return matches
    if vuln_class in {"path-traversal", "native-module-abuse"}:
        matches = [item for item in boundaries if item.get("kind") == "filesystem"]
        if matches:
            return matches
    return boundaries


def _candidate_entries(index: RepoIndex, vuln_class: str) -> list[dict[str, Any]]:
    entries = index.inventories.get("entries", [])
    if vuln_class == "ipc-trust-boundary":
        preferred = {"context-bridge", "ipc-main-handler", "ipc-renderer-call"}
        matches = [item for item in entries if item.get("kind") in preferred]
        if matches:
            return matches
    if vuln_class == "node-integration":
        matches = [item for item in entries if item.get("kind") == "browser-window"]
        if matches:
            return matches
    if vuln_class == "ssrf":
        matches = [item for item in entries if item.get("kind") == "http-route"]
        if matches:
            return matches
    return entries


def _truncate_context(lines: list[str], max_words: int) -> str:
    output: list[str] = []
    words = 0
    for line in lines:
        line_words = len(line.split())
        if output and words + line_words > max_words:
            output.append("- Context truncated to keep prompt compact.")
            break
        output.append(line)
        words += line_words
    return "\n".join(output)


def _same_file_metadata(cached: dict[str, Any], metadata: dict[str, int]) -> bool:
    return (
        int(cached.get("size", 0)) == int(metadata.get("size", 0))
        and int(cached.get("mtime_ns", 0)) == int(metadata.get("mtime_ns", 0))
    )


def _dedupe_signal_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    for row in rows:
        key = (int(row.get("line", 0)), str(row.get("kind", "")), str(row.get("text", "")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped
