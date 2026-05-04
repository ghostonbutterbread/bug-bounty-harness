"""Static Application Mapper / RCE Spec Forge MVP.

This module is intentionally standalone: it maps local source trees, writes
inspectable AppMap artifacts, and forges a parser-compatible brainstorm spec.
It does not invoke zero_day_team or add runtime integration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

_AGENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _AGENT_DIR.parent
if _PROJECT_ROOT.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _PROJECT_ROOT.as_posix())

from agents.brainstorm_spec import parse_brainstorm_spec


SCAN_EXTENSIONS = {
    ".cjs",
    ".env",
    ".ini",
    ".js",
    ".json",
    ".jsx",
    ".mjs",
    ".py",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}
SPECIAL_FILENAMES = {
    ".env",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "coverage",
    "node_modules",
    "venv",
}


@dataclass(frozen=True)
class PatternSpec:
    name: str
    regex: re.Pattern[str]
    role: str
    family: str
    description: str
    trust_level: str
    attacker_control: str
    confidence: float


@dataclass(frozen=True)
class TargetDetection:
    detected_kind: str
    frameworks: tuple[str, ...] = ()
    manifests: tuple[str, ...] = ()
    entrypoints: tuple[dict[str, Any], ...] = ()
    confidence_bonus: float = 0.0


@dataclass(frozen=True)
class TargetPack:
    """Framework or language adapter that emits normalized AppMap evidence."""

    key: str
    aliases: tuple[str, ...]
    file_extensions: tuple[str, ...]
    manifest_names: tuple[str, ...]
    detect: Callable[[Path, dict[str, int]], TargetDetection | None]
    source_patterns_for_file: Callable[[Path], tuple[PatternSpec, ...]]
    boundary_patterns_for_file: Callable[[Path], tuple[PatternSpec, ...]] = lambda _path: ()


@dataclass(frozen=True)
class VulnerabilityPack:
    key: str
    sink_patterns_for_file: Callable[[Path], tuple[PatternSpec, ...]]
    transform_patterns_for_file: Callable[[Path], tuple[PatternSpec, ...]]
    build_flows: Callable[
        [list[dict[str, Any]]],
        tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]],
    ]
    render_spec: Callable[[MapResult, str], str]


@dataclass
class TargetProfile:
    program: str
    target_path: str
    target_kind: str
    detected_kinds: list[str]
    languages: dict[str, int]
    frameworks: list[str]
    manifests: list[str]
    entrypoints: list[dict[str, Any]]
    confidence: float


@dataclass
class MapResult:
    profile: TargetProfile
    focus: str = "rce"
    surfaces: list[dict[str, Any]] = field(default_factory=list)
    flows: list[dict[str, Any]] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    rejected_candidates: list[dict[str, Any]] = field(default_factory=list)


TARGET_PACKS: dict[str, TargetPack] = {}
VULNERABILITY_PACKS: dict[str, VulnerabilityPack] = {}


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


JS_SOURCE_PATTERNS = [
    PatternSpec(
        "node-project-config-load",
        _compile(r"\b(fs\.(readFileSync|readFile)|JSON\.parse|yaml\.load|dotenv\.config|cosmiconfig|configstore)\b|\brc\s*\("),
        "source",
        "config",
        "local project or workspace configuration is loaded",
        "project-controlled",
        "medium",
        0.72,
    ),
    PatternSpec(
        "node-cli-args",
        _compile(r"\b(process\.argv|commander\.|yargs\.|app\.commandLine)\b|\bminimist\s*\("),
        "source",
        "cli",
        "command line arguments influence application behavior",
        "user-controlled",
        "medium",
        0.68,
    ),
    PatternSpec(
        "node-remote-config",
        _compile(r"\b(fetch\(|axios\.|request\(|got\().{0,80}(config|metadata|template|script|feature|update)"),
        "source",
        "network-config",
        "network response appears to feed config, templates, scripts, or update metadata",
        "remote-controlled",
        "medium",
        0.7,
    ),
]

ELECTRON_SOURCE_PATTERNS = [
    PatternSpec(
        "electron-ipc-message",
        _compile(r"\b(ipcMain\.(handle|on)|ipcRenderer\.(send|invoke)|contextBridge\.exposeInMainWorld)\b"),
        "source",
        "ipc",
        "renderer IPC or preload bridge message crosses process boundary",
        "lower-trust-renderer",
        "high",
        0.82,
    ),
    PatternSpec(
        "electron-deeplink-or-protocol",
        _compile(r"\b(setAsDefaultProtocolClient|protocol\.register\w*Protocol|open-url)\b"),
        "source",
        "deeplink",
        "deep link or custom protocol can introduce external input",
        "external",
        "medium",
        0.76,
    ),
]

PY_SOURCE_PATTERNS = [
    PatternSpec(
        "python-project-config-load",
        _compile(r"\b(json\.load|json\.loads|yaml\.load|yaml\.safe_load|tomllib\.load|configparser\.|dotenv\.load_dotenv|open\().{0,120}(config|settings|\.ya?ml|\.json|\.toml|\.ini)"),
        "source",
        "config",
        "local project or workspace configuration is loaded",
        "project-controlled",
        "medium",
        0.72,
    ),
    PatternSpec(
        "python-cli-args",
        _compile(r"\b(argparse\.|click\.|typer\.|sys\.argv)\b"),
        "source",
        "cli",
        "command line arguments influence application behavior",
        "user-controlled",
        "medium",
        0.68,
    ),
    PatternSpec(
        "python-remote-config",
        _compile(r"\b(requests\.(get|post)|httpx\.|urllib\.request).{0,100}(config|metadata|template|script|feature|update)"),
        "source",
        "network-config",
        "network response appears to feed config, templates, scripts, or update metadata",
        "remote-controlled",
        "medium",
        0.7,
    ),
]

GENERIC_BOUNDARY_PATTERNS = [
    PatternSpec(
        "cwd-or-project-boundary",
        _compile(r"\b(workspace|project|import(ed)? project|settings|config)\b|\b(process\.cwd|os\.getcwd)\s*\("),
        "boundary",
        "project-boundary",
        "data crosses from project/workspace storage into application logic",
        "project-controlled",
        "medium",
        0.65,
    ),
    PatternSpec(
        "remote-to-local-boundary",
        _compile(r"\b(axios\.|requests\.(get|post)|httpx\.|download|update|sync)\b|\b(fetch|request)\s*\("),
        "boundary",
        "remote-boundary",
        "remote or synchronized data crosses into local processing",
        "remote-controlled",
        "medium",
        0.66,
    ),
]

ELECTRON_BOUNDARY_PATTERNS = [
    PatternSpec(
        "renderer-to-main-boundary",
        _compile(r"\b(ipcMain\.(handle|on)|contextBridge\.exposeInMainWorld|preload|BrowserWindow)\b"),
        "boundary",
        "electron-boundary",
        "lower-trust renderer or preload flow reaches privileged Electron code",
        "lower-trust-renderer",
        "high",
        0.85,
    ),
]

TRANSFORM_PATTERNS = [
    PatternSpec(
        "path-or-module-resolution",
        _compile(r"\b(path\.(join|resolve|normalize)|require\.resolve|importlib\.import_module|sys\.path)\b"),
        "transform",
        "resolution",
        "path or module resolution may rewrite attacker-influenced values",
        "mixed",
        "medium",
        0.55,
    ),
    PatternSpec(
        "template-or-env-expansion",
        _compile(r"\b(template|render|Handlebars|Mustache|nunjucks|ejs|jinja|expandvars|substitute|interpolate|env)\b"),
        "transform",
        "expansion",
        "template or environment expansion may turn data into executable syntax",
        "mixed",
        "medium",
        0.58,
    ),
    PatternSpec(
        "merge-or-deserialize",
        _compile(r"\b(Object\.assign|merge|defaultsDeep|yaml\.load|pickle\.load|pickle\.loads|loads\(|deserialize)\b"),
        "transform",
        "deserialization",
        "merge or deserialization can preserve attacker-controlled objects",
        "mixed",
        "medium",
        0.62,
    ),
]

JS_SINK_PATTERNS = [
    PatternSpec(
        "node-process-exec",
        _compile(r"\b(child_process\.(exec|execFile|spawn|fork)|exec\(|execFile\(|spawn\(|shelljs\.|execa\()"),
        "sink",
        "process-exec",
        "Node process execution sink",
        "privileged-local",
        "unknown",
        0.92,
    ),
    PatternSpec(
        "node-dynamic-code",
        _compile(r"\b(eval\(|new Function\(|Function\(|vm\.(runIn|Script)|setTimeout\([^,]+,|setInterval\([^,]+,)"),
        "sink",
        "dynamic-code",
        "JavaScript dynamic code execution sink",
        "privileged-local",
        "unknown",
        0.9,
    ),
    PatternSpec(
        "node-dynamic-module",
        _compile(r"\b(require\([^'\"`]|import\(|require\.resolve\()"),
        "sink",
        "dynamic-module",
        "dynamic module resolution or import sink",
        "privileged-local",
        "unknown",
        0.76,
    ),
]

PY_SINK_PATTERNS = [
    PatternSpec(
        "python-process-exec",
        _compile(r"\b(subprocess\.(run|Popen|call|check_call|check_output)|os\.system|os\.popen)\b"),
        "sink",
        "process-exec",
        "Python process execution sink",
        "privileged-local",
        "unknown",
        0.92,
    ),
    PatternSpec(
        "python-dynamic-code",
        _compile(r"\b(eval\(|exec\(|compile\()"),
        "sink",
        "dynamic-code",
        "Python dynamic code execution sink",
        "privileged-local",
        "unknown",
        0.9,
    ),
    PatternSpec(
        "python-unsafe-deserialization",
        _compile(r"\b(pickle\.load|pickle\.loads|yaml\.load\()"),
        "sink",
        "unsafe-deserialization",
        "unsafe Python deserialization sink",
        "privileged-local",
        "unknown",
        0.84,
    ),
]


MAX_AGENT_KEY_LEN = 64
MAX_CHAIN_LINE_SPAN = 40

JS_STATIC_PROCESS_LITERAL_RE = _compile(
    r"\b(?:child_process\.)?(?:exec|execFile|spawn|fork)\s*\(\s*(['\"`])(?:\\.|(?!\1).)*\1\s*(?:[,)]|$)"
)
PY_STATIC_PROCESS_LITERAL_RE = _compile(
    r"\b(?:subprocess\.(?:run|Popen|call|check_call|check_output)|os\.(?:system|popen))\s*\(\s*(?:[rub]{0,2})?(['\"])(?:\\.|(?!\1).)*\1\s*(?:[,)]|$)"
)
CONFIG_FILE_SOURCE_PATTERN = PatternSpec(
    "manifest-or-config-file",
    _compile(r".+"),
    "source",
    "config-file",
    "configuration or manifest file present in source tree",
    "project-controlled",
    "medium",
    0.52,
)
IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
LINKAGE_STOPWORDS = {
    "JSON",
    "Popen",
    "Parser",
    "String",
    "argparse",
    "async",
    "await",
    "child_process",
    "configparser",
    "const",
    "def",
    "exec",
    "execFile",
    "false",
    "fork",
    "from",
    "function",
    "get",
    "handle",
    "if",
    "import",
    "ipcMain",
    "json",
    "let",
    "open",
    "os",
    "parse",
    "path",
    "process",
    "read",
    "readFile",
    "readFileSync",
    "require",
    "return",
    "run",
    "shell",
    "spawn",
    "subprocess",
    "true",
    "var",
    "with",
}


def register_target_pack(pack: TargetPack) -> None:
    """Register a target/framework pack without changing core mapping code."""

    if not pack.key:
        raise ValueError("target pack key must not be empty")
    TARGET_PACKS[pack.key] = pack


def register_vulnerability_pack(pack: VulnerabilityPack) -> None:
    if not pack.key:
        raise ValueError("vulnerability pack key must not be empty")
    VULNERABILITY_PACKS[pack.key] = pack


def _all_scan_extensions() -> set[str]:
    extensions = set(SCAN_EXTENSIONS)
    for pack in TARGET_PACKS.values():
        extensions.update(ext.lower() for ext in pack.file_extensions)
    return extensions


def _all_special_filenames() -> set[str]:
    filenames = set(SPECIAL_FILENAMES)
    for pack in TARGET_PACKS.values():
        filenames.update(pack.manifest_names)
    return filenames


def _js_like(path: Path) -> bool:
    return path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


def _config_like(path: Path) -> bool:
    return path.suffix.lower() in {".json", ".yaml", ".yml", ".toml", ".ini", ".env"} or path.name in _all_special_filenames()


def _node_source_patterns(path: Path) -> tuple[PatternSpec, ...]:
    if not _js_like(path):
        return ()
    return tuple(JS_SOURCE_PATTERNS)


def _electron_source_patterns(path: Path) -> tuple[PatternSpec, ...]:
    if not _js_like(path):
        return ()
    return tuple(ELECTRON_SOURCE_PATTERNS)


def _python_source_patterns(path: Path) -> tuple[PatternSpec, ...]:
    return tuple(PY_SOURCE_PATTERNS) if path.suffix.lower() == ".py" else ()


def _config_source_patterns(path: Path) -> tuple[PatternSpec, ...]:
    return (CONFIG_FILE_SOURCE_PATTERN,) if _config_like(path) else ()


def _generic_boundary_patterns(path: Path) -> tuple[PatternSpec, ...]:
    if _js_like(path) or path.suffix.lower() == ".py":
        return tuple(GENERIC_BOUNDARY_PATTERNS)
    return ()


def _electron_boundary_patterns(path: Path) -> tuple[PatternSpec, ...]:
    if not _js_like(path):
        return ()
    return tuple(ELECTRON_BOUNDARY_PATTERNS)


def _rce_sink_patterns(path: Path) -> tuple[PatternSpec, ...]:
    if _js_like(path):
        return tuple(JS_SINK_PATTERNS)
    if path.suffix.lower() == ".py":
        return tuple(PY_SINK_PATTERNS)
    return ()


def _rce_transform_patterns(path: Path) -> tuple[PatternSpec, ...]:
    if _js_like(path) or path.suffix.lower() == ".py":
        return tuple(TRANSFORM_PATTERNS)
    return ()


def _active_target_packs(profile: TargetProfile | None) -> list[TargetPack]:
    if profile is None:
        return list(TARGET_PACKS.values())
    active: list[TargetPack] = []
    target_kind = profile.target_kind
    detected = set(profile.detected_kinds)
    for pack in TARGET_PACKS.values():
        if (
            pack.key == "config"
            or pack.key in detected
            or target_kind == pack.key
            or target_kind in pack.aliases
        ):
            active.append(pack)
    return active


def _detect_node_target(target_path: Path, languages: dict[str, int]) -> TargetDetection | None:
    package_json = target_path / "package.json"
    manifests: list[str] = []
    frameworks: set[str] = set()
    entrypoints: list[dict[str, Any]] = []

    if package_json.is_file():
        manifests.append("package.json")
        try:
            package = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            package = {}
        deps = {
            **(package.get("dependencies") if isinstance(package.get("dependencies"), dict) else {}),
            **(package.get("devDependencies") if isinstance(package.get("devDependencies"), dict) else {}),
        }
        if any(name in deps for name in ("express", "fastify", "koa", "next")):
            frameworks.add("node-web")
        if package.get("main"):
            entrypoints.append({"kind": "node-main", "path": str(package["main"])})
        scripts = package.get("scripts")
        if isinstance(scripts, dict):
            for name, command in sorted(scripts.items()):
                if name in {"start", "dev", "serve", "main"}:
                    entrypoints.append({"kind": "npm-script", "name": name, "command": str(command)})

    if not package_json.is_file() and not languages.get("javascript"):
        return None
    return TargetDetection(
        detected_kind="node",
        frameworks=tuple(sorted(frameworks)),
        manifests=tuple(manifests),
        entrypoints=tuple(entrypoints),
        confidence_bonus=0.08 if package_json.is_file() else 0.0,
    )


def _detect_electron_target(target_path: Path, _languages: dict[str, int]) -> TargetDetection | None:
    package_json = target_path / "package.json"
    has_electron = False
    entrypoints: list[dict[str, Any]] = []

    if package_json.is_file():
        try:
            package = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            package = {}
        deps = {
            **(package.get("dependencies") if isinstance(package.get("dependencies"), dict) else {}),
            **(package.get("devDependencies") if isinstance(package.get("devDependencies"), dict) else {}),
        }
        has_electron = "electron" in deps

    for path in iter_source_files(target_path):
        if not _js_like(path):
            continue
        try:
            line_sample = path.read_text(encoding="utf-8", errors="ignore")[:12000]
        except OSError:
            line_sample = ""
        if (
            "from 'electron'" in line_sample
            or 'from "electron"' in line_sample
            or "require('electron')" in line_sample
            or 'require("electron")' in line_sample
        ):
            has_electron = True
            rel = path.relative_to(target_path).as_posix()
            if "preload" in path.name.lower():
                entrypoints.append({"kind": "electron-preload", "path": rel})
            if "ipcMain" in line_sample or "app.whenReady" in line_sample:
                entrypoints.append({"kind": "electron-main", "path": rel})

    if not has_electron:
        return None
    return TargetDetection(
        detected_kind="electron",
        frameworks=("electron",),
        entrypoints=tuple(entrypoints),
        confidence_bonus=0.12,
    )


def _detect_python_target(target_path: Path, languages: dict[str, int]) -> TargetDetection | None:
    manifests = [manifest for manifest in ("pyproject.toml", "requirements.txt", "setup.py") if (target_path / manifest).is_file()]
    entrypoints: list[dict[str, Any]] = []
    if not languages.get("python") and not manifests:
        return None
    for path in iter_source_files(target_path):
        if path.suffix.lower() != ".py":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            text = ""
        if '__name__ == "__main__"' in text or "__name__ == '__main__'" in text:
            entrypoints.append({"kind": "python-main", "path": path.relative_to(target_path).as_posix()})
    return TargetDetection(
        detected_kind="python",
        frameworks=("python",) if manifests else (),
        manifests=tuple(manifests),
        entrypoints=tuple(entrypoints),
        confidence_bonus=0.08 if manifests else 0.0,
    )


def _register_builtin_packs() -> None:
    register_target_pack(
        TargetPack(
            key="electron",
            aliases=("electron", "electron-exe"),
            file_extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
            manifest_names=("package.json",),
            detect=_detect_electron_target,
            source_patterns_for_file=_electron_source_patterns,
            boundary_patterns_for_file=_electron_boundary_patterns,
        )
    )
    register_target_pack(
        TargetPack(
            key="node",
            aliases=("node", "javascript", "node-web"),
            file_extensions=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
            manifest_names=("package.json",),
            detect=_detect_node_target,
            source_patterns_for_file=_node_source_patterns,
            boundary_patterns_for_file=_generic_boundary_patterns,
        )
    )
    register_target_pack(
        TargetPack(
            key="python",
            aliases=("python", "py"),
            file_extensions=(".py",),
            manifest_names=("pyproject.toml", "requirements.txt", "setup.py"),
            detect=_detect_python_target,
            source_patterns_for_file=_python_source_patterns,
            boundary_patterns_for_file=_generic_boundary_patterns,
        )
    )
    register_target_pack(
        TargetPack(
            key="config",
            aliases=("config", "manifest"),
            file_extensions=(".json", ".yaml", ".yml", ".toml", ".ini", ".env"),
            manifest_names=tuple(SPECIAL_FILENAMES),
            detect=lambda _target_path, _languages: None,
            source_patterns_for_file=_config_source_patterns,
        )
    )
    register_vulnerability_pack(
        VulnerabilityPack(
            key="rce",
            sink_patterns_for_file=_rce_sink_patterns,
            transform_patterns_for_file=_rce_transform_patterns,
            build_flows=build_rce_flows,
            render_spec=lambda result, run_id: render_rce_spec(result, run_id=run_id),
        )
    )


def sanitize_key(value: str, *, fallback: str = "target") -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", value.strip().lower()).strip("-_")
    return slug or fallback


def iter_source_files(root: Path, *, max_file_bytes: int = 8_000_000) -> Iterable[Path]:
    scan_extensions = _all_scan_extensions()
    special_filenames = _all_special_filenames()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name not in special_filenames and path.suffix.lower() not in scan_extensions:
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        yield path


def classify_target(program: str, target_path: Path, target_kind: str = "auto") -> TargetProfile:
    languages: dict[str, int] = {}
    frameworks: set[str] = set()
    manifests: list[str] = []
    entrypoints: list[dict[str, Any]] = []

    for path in iter_source_files(target_path):
        suffix = path.suffix.lower()
        if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            languages["javascript"] = languages.get("javascript", 0) + 1
        elif suffix == ".py":
            languages["python"] = languages.get("python", 0) + 1
        elif suffix in {".json", ".yaml", ".yml", ".toml", ".ini", ".env"}:
            languages["config"] = languages.get("config", 0) + 1

    detected_kinds: list[str] = []
    confidence_bonus = 0.0
    for pack in TARGET_PACKS.values():
        detection = pack.detect(target_path, languages)
        if detection is None:
            continue
        if detection.detected_kind not in detected_kinds:
            detected_kinds.append(detection.detected_kind)
        frameworks.update(detection.frameworks)
        manifests.extend(manifest for manifest in detection.manifests if manifest not in manifests)
        entrypoints.extend(detection.entrypoints)
        confidence_bonus += detection.confidence_bonus
    if not detected_kinds:
        detected_kinds.append("source-tree")

    resolved_kind = target_kind if target_kind != "auto" else detected_kinds[0]
    confidence = 0.9 if target_kind != "auto" else min(0.95, 0.55 + (0.12 * len(detected_kinds)) + (0.08 * len(frameworks)) + confidence_bonus)
    return TargetProfile(
        program=program,
        target_path=str(target_path.resolve(strict=False)),
        target_kind=resolved_kind,
        detected_kinds=detected_kinds,
        languages=dict(sorted(languages.items())),
        frameworks=sorted(frameworks),
        manifests=sorted(manifests),
        entrypoints=entrypoints[:30],
        confidence=round(confidence, 2),
    )


def scan_surfaces(target_path: Path, *, focus: str = "rce", target_profile: TargetProfile | None = None) -> list[dict[str, Any]]:
    surfaces: list[dict[str, Any]] = []
    counters: dict[str, int] = {}
    vuln_pack = VULNERABILITY_PACKS[focus]
    target_packs = _active_target_packs(target_profile)

    for path in iter_source_files(target_path):
        patterns: list[PatternSpec] = []
        for pack in target_packs:
            patterns.extend(pack.source_patterns_for_file(path))
            patterns.extend(pack.boundary_patterns_for_file(path))
        patterns.extend(vuln_pack.transform_patterns_for_file(path))
        patterns.extend(vuln_pack.sink_patterns_for_file(path))
        if not patterns:
            continue

        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        rel = path.relative_to(target_path).as_posix()
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            for spec in patterns:
                if not spec.regex.search(stripped):
                    continue
                counters[spec.role] = counters.get(spec.role, 0) + 1
                surface_id = f"{spec.role[:1].upper()}{counters[spec.role]:04d}"
                surfaces.append(
                    {
                        "id": surface_id,
                        "role": spec.role,
                        "kind": spec.family,
                        "name": spec.name,
                        "description": spec.description,
                        "file": rel,
                        "line": line_no,
                        "snippet": stripped[:240],
                        "trust_level": spec.trust_level,
                        "attacker_control": spec.attacker_control,
                        "confidence": spec.confidence,
                    }
                )
    return surfaces


def build_rce_flows(surfaces: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    by_file: dict[str, list[dict[str, Any]]] = {}
    for surface in surfaces:
        by_file.setdefault(str(surface["file"]), []).append(surface)

    flows: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    flow_index = 1
    candidate_index = 1
    rejected_index = 1

    for file_name, file_surfaces in sorted(by_file.items()):
        sources = [item for item in file_surfaces if item["role"] == "source"]
        boundaries = [item for item in file_surfaces if item["role"] == "boundary"]
        transforms = [item for item in file_surfaces if item["role"] == "transform"]
        sinks = [item for item in file_surfaces if item["role"] == "sink"]

        if sinks and (not sources or not boundaries):
            rejected.append(
                {
                    "id": f"R{rejected_index:04d}",
                    "file": file_name,
                    "sink_ids": [sink["id"] for sink in sinks],
                    "reason": "sink evidence lacks same-file attacker-controlled source and trust boundary",
                }
            )
            rejected_index += 1
        if sources and not sinks:
            rejected.append(
                {
                    "id": f"R{rejected_index:04d}",
                    "file": file_name,
                    "source_ids": [source["id"] for source in sources],
                    "reason": "source or boundary evidence lacks same-file RCE sink",
                }
            )
            rejected_index += 1

        if not sources or not boundaries or not sinks:
            continue

        eligible_sinks = [sink for sink in sinks if not _is_static_literal_process_sink(sink)]
        if sinks and not eligible_sinks:
            rejected.append(
                {
                    "id": f"R{rejected_index:04d}",
                    "file": file_name,
                    "sink_ids": [sink["id"] for sink in sinks],
                    "reason": "sink evidence is an obvious static literal command",
                }
            )
            rejected_index += 1
            continue

        chain = _best_ordered_chain(sources, boundaries, transforms, eligible_sinks)
        if chain is None:
            rejected.append(
                {
                    "id": f"R{rejected_index:04d}",
                    "file": file_name,
                    "source_ids": [source["id"] for source in sources],
                    "boundary_ids": [boundary["id"] for boundary in boundaries],
                    "sink_ids": [sink["id"] for sink in eligible_sinks],
                    "reason": "same-file evidence lacks ordered proximate or linked source-to-sink chain",
                }
            )
            rejected_index += 1
            continue

        source, boundary, transform, sink, score = chain
        flow_id = f"F{flow_index:04d}"
        candidate_id = f"C{candidate_index:04d}"
        flow_index += 1
        candidate_index += 1

        chain_parts = [
            f"{source['kind']} source at {source['file']}:{source['line']}",
            f"{boundary['kind']} boundary",
        ]
        if transform:
            chain_parts.append(f"{transform['kind']} transform")
        chain_parts.append(f"{sink['kind']} sink at {sink['file']}:{sink['line']}")
        flow = {
            "id": flow_id,
            "source_id": source["id"],
            "boundary_id": boundary["id"],
            "transform_id": transform["id"] if transform else None,
            "sink_id": sink["id"],
            "file": file_name,
            "chain": chain_parts,
            "confidence": score,
        }
        flows.append(flow)
        candidates.append(
            {
                "id": candidate_id,
                "flow_id": flow_id,
                "surface_id": source["id"],
                "source": source,
                "boundary": boundary,
                "transform": transform,
                "sink": sink,
                "score": score,
                "priority": "high" if score >= 0.78 else "medium",
                "question": (
                    "Can attacker-controlled input at the mapped source influence "
                    f"the {sink['kind']} sink across the {boundary['kind']} boundary?"
                ),
            }
        )

    candidates.sort(key=lambda item: (-float(item["score"]), str(item["id"])))
    return flows, candidates, rejected


def _best_surface(items: list[dict[str, Any]]) -> dict[str, Any]:
    return sorted(items, key=lambda item: (-float(item["confidence"]), int(item["line"]), str(item["id"])))[0]


def _best_ordered_chain(
    sources: list[dict[str, Any]],
    boundaries: list[dict[str, Any]],
    transforms: list[dict[str, Any]],
    sinks: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None, dict[str, Any], float] | None:
    viable: list[tuple[float, int, str, dict[str, Any], dict[str, Any], dict[str, Any] | None, dict[str, Any]]] = []
    for source in sources:
        for boundary in boundaries:
            for sink in sinks:
                if int(source["line"]) >= int(sink["line"]):
                    continue
                if int(boundary["line"]) > int(sink["line"]):
                    continue
                transform = _best_transform_between(transforms, source, sink)
                if not _has_proximity_or_linkage(source, boundary, transform, sink):
                    continue
                score = _candidate_score(source, boundary, sink, transform)
                span = int(sink["line"]) - min(int(source["line"]), int(boundary["line"]))
                viable.append((score, -span, str(sink["id"]), source, boundary, transform, sink))
    if not viable:
        return None
    score, _neg_span, _sink_id, source, boundary, transform, sink = sorted(
        viable,
        key=lambda item: (-item[0], -item[1], item[2]),
    )[0]
    return source, boundary, transform, sink, score


def _best_transform_between(
    transforms: list[dict[str, Any]],
    source: dict[str, Any],
    sink: dict[str, Any],
) -> dict[str, Any] | None:
    between = [
        transform
        for transform in transforms
        if int(source["line"]) <= int(transform["line"]) <= int(sink["line"])
    ]
    return _best_surface(between) if between else None


def _has_proximity_or_linkage(
    source: dict[str, Any],
    boundary: dict[str, Any],
    transform: dict[str, Any] | None,
    sink: dict[str, Any],
) -> bool:
    chain_surfaces = [source, boundary, sink]
    if transform is not None:
        chain_surfaces.append(transform)
    line_span = max(int(item["line"]) for item in chain_surfaces) - min(
        int(item["line"]) for item in chain_surfaces
    )
    if line_span <= MAX_CHAIN_LINE_SPAN:
        return True

    sink_tokens = _linkage_tokens(str(sink.get("snippet", "")))
    upstream_tokens: set[str] = set()
    for item in (source, boundary, transform):
        if item is not None:
            upstream_tokens.update(_linkage_tokens(str(item.get("snippet", ""))))
    return bool(sink_tokens & upstream_tokens)


def _linkage_tokens(snippet: str) -> set[str]:
    tokens = {
        token
        for token in IDENTIFIER_RE.findall(snippet)
        if len(token) >= 3 and token not in LINKAGE_STOPWORDS
    }
    dotted = {
        match
        for match in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\b", snippet)
        if match not in LINKAGE_STOPWORDS
    }
    return tokens | dotted


def _is_static_literal_process_sink(sink: dict[str, Any]) -> bool:
    if sink.get("kind") != "process-exec":
        return False
    snippet = str(sink.get("snippet", ""))
    return bool(JS_STATIC_PROCESS_LITERAL_RE.search(snippet) or PY_STATIC_PROCESS_LITERAL_RE.search(snippet))


def _candidate_score(
    source: dict[str, Any],
    boundary: dict[str, Any],
    sink: dict[str, Any],
    transform: dict[str, Any] | None,
) -> float:
    base = (
        float(source["confidence"]) * 0.3
        + float(boundary["confidence"]) * 0.25
        + float(sink["confidence"]) * 0.35
        + (float(transform["confidence"]) if transform else 0.5) * 0.1
    )
    if source["kind"] == "ipc" and sink["kind"] in {"process-exec", "dynamic-code"}:
        base += 0.05
    if source["kind"] in {"config", "config-file"} and sink["kind"] == "process-exec":
        base += 0.04
    return round(min(base, 0.98), 2)


def map_application(program: str, target_path: Path, *, target_kind: str = "auto", focus: str = "rce") -> MapResult:
    profile = classify_target(program, target_path, target_kind=target_kind)
    vuln_pack = VULNERABILITY_PACKS[focus]
    surfaces = scan_surfaces(target_path, focus=focus, target_profile=profile)
    flows, candidates, rejected = vuln_pack.build_flows(surfaces)
    return MapResult(
        profile=profile,
        focus=focus,
        surfaces=surfaces,
        flows=flows,
        candidates=candidates,
        rejected_candidates=rejected,
    )


def default_output_root(program: str) -> Path:
    return Path.home() / "Shared" / "appmap" / sanitize_key(program) / "static"


def write_artifacts(
    result: MapResult,
    *,
    output_root: Path,
    run_id: str,
    write_specs: bool,
) -> dict[str, Path]:
    run_root = output_root.expanduser().resolve(strict=False) / "appmap" / run_id
    generated_specs = run_root / "generated_specs"
    run_root.mkdir(parents=True, exist_ok=True)
    generated_specs.mkdir(parents=True, exist_ok=True)

    paths = {
        "run_root": run_root,
        "target_profile": run_root / "target_profile.json",
        "architecture": run_root / "architecture.md",
        "surfaces": run_root / "surfaces.jsonl",
        "flows": run_root / "flows.jsonl",
        "candidates": run_root / "candidates.jsonl",
        "rejected_candidates": run_root / "rejected_candidates.jsonl",
        "summary": run_root / "appmap_summary.md",
    }

    paths["target_profile"].write_text(
        json.dumps(result.profile.__dict__, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    paths["architecture"].write_text(render_architecture(result), encoding="utf-8")
    _write_jsonl(paths["surfaces"], result.surfaces)
    _write_jsonl(paths["flows"], result.flows)
    _write_jsonl(paths["candidates"], result.candidates)
    _write_jsonl(paths["rejected_candidates"], result.rejected_candidates)

    if write_specs and result.candidates:
        focus_slug = sanitize_key(result.focus, fallback="focus")
        spec_path = generated_specs / f"{focus_slug}-spec.md"
        rendered = VULNERABILITY_PACKS[result.focus].render_spec(result, run_id)
        spec_path.write_text(rendered, encoding="utf-8")
        parse_brainstorm_spec(spec_path)
        paths["spec"] = spec_path
        paths[f"{focus_slug.replace('-', '_')}_spec"] = spec_path
        if result.focus == "rce":
            paths["rce_spec"] = spec_path

    paths["summary"].write_text(render_summary(result, paths, run_id=run_id), encoding="utf-8")
    return paths


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def render_architecture(result: MapResult) -> str:
    profile = result.profile
    lines = [
        f"# AppMap Architecture: {profile.program}",
        "",
        f"- Target kind: {profile.target_kind}",
        f"- Detected kinds: {', '.join(profile.detected_kinds)}",
        f"- Languages: {json.dumps(profile.languages, sort_keys=True)}",
        f"- Frameworks: {', '.join(profile.frameworks) if profile.frameworks else 'none detected'}",
        f"- Manifests: {', '.join(profile.manifests) if profile.manifests else 'none detected'}",
        f"- Entry points: {len(profile.entrypoints)}",
        f"- Focus: {result.focus}",
        f"- {result.focus.upper()} surfaces: {len(result.surfaces)}",
        f"- {result.focus.upper()} flows: {len(result.flows)}",
        f"- {result.focus.upper()} candidates: {len(result.candidates)}",
        "",
        "## Entrypoints",
        "",
    ]
    if profile.entrypoints:
        lines.extend(f"- `{json.dumps(entry, sort_keys=True)}`" for entry in profile.entrypoints[:20])
    else:
        lines.append("- No explicit entrypoints detected.")
    lines.extend(["", f"## High-Signal {result.focus.upper()} Candidates", ""])
    if result.candidates:
        for candidate in result.candidates[:10]:
            lines.append(
                "- "
                f"{candidate['id']} / {candidate['flow_id']}: "
                f"{candidate['source']['file']}:{candidate['source']['line']} -> "
                f"{candidate['sink']['file']}:{candidate['sink']['line']} "
                f"({candidate['sink']['kind']}, score {candidate['score']})"
            )
    else:
        lines.append("- No candidate met the source + boundary + sink threshold.")
    return "\n".join(lines).rstrip() + "\n"


def render_rce_spec(result: MapResult, *, run_id: str, max_hypotheses: int = 5) -> str:
    program_slug = sanitize_key(result.profile.program)
    created = datetime.now(timezone.utc).date().isoformat()
    candidates = result.candidates[:max_hypotheses]
    primitives: list[str] = []
    hypotheses: list[str] = []

    for index, candidate in enumerate(candidates, start=1):
        primitive_id = f"P{index:03d}"
        hypothesis_id = f"H{index:03d}"
        source = candidate["source"]
        boundary = candidate["boundary"]
        transform = candidate.get("transform")
        sink = candidate["sink"]
        agent_key = _stable_agent_key(program_slug, candidate)
        primitives.append(
            "\n".join(
                [
                    f"### {primitive_id} - {sink['kind']} reachable from {source['kind']} evidence",
                    f"- Source: {source['description']}",
                    f"- Impact: attacker-influenced data may reach {sink['description']}",
                    f"- Evidence: appmap-{candidate['id']}",
                    "- Status: active",
                ]
            )
        )
        transform_text = f" -> {transform['kind']} transform" if transform else ""
        focus_files = _focus_files_for_candidate(candidate)
        title = f"{_title_case(source['kind'])} input may influence {_title_case(sink['kind'])}"
        notes = (
            f"AppMap run {run_id}; candidate {candidate['id']}; flow {candidate['flow_id']}; "
            f"source file {source['file']}:{source['line']}; sink file {sink['file']}:{sink['line']}. "
            f"Boundary evidence {boundary['file']}:{boundary['line']}. "
            "Use appmap artifacts for exact snippets before testing."
        )
        hypotheses.append(
            "\n".join(
                [
                    f"### {hypothesis_id} - {title}",
                    candidate["question"],
                    f"- Status: untested",
                    f"- Priority: {candidate['priority']}",
                    f"- Surface: appmap-{candidate['surface_id']}-{source['kind']}",
                    f"- Entry point: {source['description']} ({source['trust_level']})",
                    (
                        f"- Expected chain: {source['kind']} source -> "
                        f"{boundary['kind']} boundary{transform_text} -> {sink['kind']} sink"
                    ),
                    "- Suggested agents:",
                    f"  - {agent_key}",
                    "- Focus files:",
                    *[f"  - {glob}" for glob in focus_files],
                    "- Tags: rce, appmap, static, " + source["kind"] + ", " + sink["kind"],
                    "- Evidence:",
                    f"  - appmap-{candidate['id']}",
                    f"  - surface-{candidate['surface_id']}",
                    f"  - flow-{candidate['flow_id']}",
                    f"- Notes: {notes}",
                ]
            )
        )

    mental_model = _mental_model(result)
    return (
        f"# Brainstorm Spec: {result.profile.program} AppMap RCE\n\n"
        "## Metadata\n"
        f"- Program: {program_slug}\n"
        "- Family: appmap\n"
        "- Lane: static\n"
        f"- Target kind: {result.profile.target_kind}\n"
        "- Target path: .\n"
        f"- Created: {created}\n"
        "- Status: active\n"
        f"- AppMap run id: {run_id}\n\n"
        "## Target mental model\n"
        f"{mental_model}\n\n"
        "## Impact primitives\n"
        + "\n\n".join(primitives)
        + "\n\n"
        "## Hypotheses\n"
        + "\n\n".join(hypotheses)
        + "\n\n"
        "## Coverage log\n"
        "| Hypothesis | Agent | Status | Result | Linked FIDs | Run ID | Notes |\n"
        "|---|---|---|---|---|---|---|\n"
    )


def _stable_agent_key(program_slug: str, candidate: dict[str, Any]) -> str:
    source = candidate["source"]
    sink = candidate["sink"]
    canonical = (
        f"{program_slug}:{candidate['id']}:{source['kind']}:{source['file']}:{source['line']}:"
        f"{sink['kind']}:{sink['file']}:{sink['line']}"
    )
    digest = hashlib.sha1(canonical.encode()).hexdigest()[:10]
    source_kind = sanitize_key(str(source["kind"]))
    sink_kind = sanitize_key(str(sink["kind"]))
    tail = sanitize_key(f"appmap-rce-{source_kind}-{sink_kind}-{digest}")
    if len(tail) > MAX_AGENT_KEY_LEN:
        tail = f"appmap-rce-{digest}"
    program_part = sanitize_key(program_slug)
    prefix_budget = MAX_AGENT_KEY_LEN - len(tail) - 1
    if prefix_budget > 0 and program_part:
        program_part = program_part[:prefix_budget].strip("-_")
        if program_part:
            return f"{program_part}-{tail}"
    return tail[:MAX_AGENT_KEY_LEN].strip("-_") or f"appmap-rce-{digest}"


def _focus_files_for_candidate(candidate: dict[str, Any]) -> list[str]:
    files = {
        str(candidate["source"]["file"]),
        str(candidate["boundary"]["file"]),
        str(candidate["sink"]["file"]),
    }
    if candidate.get("transform"):
        files.add(str(candidate["transform"]["file"]))
    return sorted(files)[:8] or ["."]


def _title_case(value: str) -> str:
    return " ".join(part.capitalize() for part in re.split(r"[-_]+", value) if part)


def _mental_model(result: MapResult) -> str:
    profile = result.profile
    kinds = ", ".join(profile.detected_kinds)
    frameworks = ", ".join(profile.frameworks) if profile.frameworks else "no named framework"
    return (
        f"Static AppMap classified this target as {profile.target_kind} "
        f"({kinds}) with {frameworks}. The {result.focus} mapper found "
        f"{len(result.surfaces)} source/boundary/transform/sink surfaces and "
        f"{len(result.candidates)} candidate chain(s) that preserve AppMap IDs "
        "for traceability."
    )


def render_summary(result: MapResult, paths: dict[str, Path], *, run_id: str) -> str:
    lines = [
        f"# AppMap Summary: {result.profile.program}",
        "",
        f"- Run ID: {run_id}",
        f"- Target path: `{result.profile.target_path}`",
        f"- Output root: `{paths['run_root']}`",
        f"- Surfaces: {len(result.surfaces)}",
        f"- Flows: {len(result.flows)}",
        f"- Candidates: {len(result.candidates)}",
        f"- Rejected candidates: {len(result.rejected_candidates)}",
    ]
    if "spec" in paths:
        focus_label = result.focus.upper()
        lines.extend(
            [
                f"- Generated {focus_label} spec: `{paths['spec']}`",
                "",
                "Suggested run command:",
                "",
                "```bash",
                f"python3 agents/zero_day_team.py {sanitize_key(result.profile.program)} {result.profile.target_path} --brainstorm-spec {paths['spec']} --brainstorm-only",
                "```",
            ]
        )
    else:
        lines.append(f"- Generated {result.focus.upper()} spec: none; no candidate met the MVP threshold.")
    return "\n".join(lines).rstrip() + "\n"


_register_builtin_packs()


def _target_kind_arg(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise argparse.ArgumentTypeError("target kind must not be empty")
    return normalized


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Static Application Mapper / RCE Spec Forge MVP.")
    parser.add_argument("program", help="Program name used in generated artifacts.")
    parser.add_argument("target_path", help="Local source tree, Electron app source, or extracted code path.")
    parser.add_argument("--target-kind", default="auto", type=_target_kind_arg, help="Target kind hint; defaults to auto.")
    parser.add_argument("--focus", default="rce", choices=sorted(VULNERABILITY_PACKS), help="Vulnerability focus for Phase 2.")
    parser.add_argument("--write-specs", action="store_true", help="Write and validate generated brainstorm specs.")
    parser.add_argument("--output-root", help="Output root. Defaults to ~/Shared/appmap/<program>/static.")
    parser.add_argument("--run-id", help="Deterministic run id override for tests or repeatable workflows.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target_path = Path(args.target_path).expanduser().resolve(strict=False)
    if not target_path.exists() or not target_path.is_dir():
        raise SystemExit(f"target_path must be an existing directory: {target_path}")

    run_id = args.run_id or f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{int(time.time())}"
    output_root = Path(args.output_root).expanduser() if args.output_root else default_output_root(args.program)
    result = map_application(args.program, target_path, target_kind=args.target_kind, focus=args.focus)
    paths = write_artifacts(result, output_root=output_root, run_id=run_id, write_specs=args.write_specs)
    print(f"[appmap] output: {paths['run_root']}")
    print(f"[appmap] surfaces={len(result.surfaces)} flows={len(result.flows)} candidates={len(result.candidates)}")
    if "spec" in paths:
        print(f"[appmap] generated spec: {paths['spec']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
