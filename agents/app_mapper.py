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
import shutil
import shlex
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

_AGENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _AGENT_DIR.parent
if _PROJECT_ROOT.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _PROJECT_ROOT.as_posix())

from agents.brainstorm_spec import (
    coverage_event_matches_assignment,
    hypothesis_to_agent_intents,
    parse_brainstorm_spec,
    read_coverage_jsonl,
)
from agents.storage_resolver import resolve_storage


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
    research: dict[str, Any] | None = None


@dataclass(frozen=True)
class PromotionResult:
    brainstorm_root: Path
    promotion_root: Path
    spec_paths: list[Path]
    context_paths: list[Path]
    manifest_path: Path


@dataclass(frozen=True)
class PromotedHandoff:
    brainstorm_root: Path
    promotion_root: Path
    spec_path: Path
    run_id: str
    focus: str
    source: str
    context_count: int


@dataclass(frozen=True)
class HandoffValidationResult:
    spec_path: Path
    counts: dict[str, int]
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass(frozen=True)
class ResearchRequest:
    program: str
    focus: str
    target_kind: str
    provider_key: str = "local-seed"
    research_online: bool = False
    seed_paths: tuple[Path, ...] = ()
    source_urls: tuple[str, ...] = ()


class ResearchProvider:
    """Opt-in research provider interface.

    Providers must declare whether they are network-capable. Network-capable
    providers may only run when --research-online is set and the user selected
    that provider explicitly; seed-only providers must never perform network I/O.
    """

    key = "base"
    network_capable = False

    def collect(self, request: ResearchRequest) -> dict[str, Any]:
        raise NotImplementedError


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
MAX_GENERATED_HYPOTHESES = 5
MAX_RESEARCH_SUMMARIES_PER_CANDIDATE = 3
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

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
        patterns: list[tuple[PatternSpec, tuple[str, ...]]] = []
        for pack in target_packs:
            for spec in pack.source_patterns_for_file(path):
                patterns.append((spec, _surface_target_pack_keys(spec, pack.key)))
            for spec in pack.boundary_patterns_for_file(path):
                patterns.append((spec, _surface_target_pack_keys(spec, pack.key)))
        patterns.extend((spec, ()) for spec in vuln_pack.transform_patterns_for_file(path))
        patterns.extend((spec, ()) for spec in vuln_pack.sink_patterns_for_file(path))
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
            for spec, target_pack_keys in patterns:
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
                        "target_pack_keys": list(target_pack_keys),
                    }
                )
    return surfaces


def _surface_target_pack_keys(spec: PatternSpec, emitting_pack_key: str) -> tuple[str, ...]:
    keys = {emitting_pack_key}
    if spec.family in TARGET_PACKS:
        keys.add(spec.family)
    return tuple(sorted(keys))


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


def canonical_output_root(
    *,
    family: str,
    program: str,
    lane: str,
    shared_root: Path | None = None,
) -> Path:
    """Return the canonical lane root used for durable AppMap data."""

    storage = resolve_storage(
        program,
        family=family,
        lane=lane,
        root_override=shared_root,
        create=False,
    )
    return storage.lane_root


def resolve_output_root(
    program: str,
    *,
    output_mode: str = "standalone",
    output_root: Path | None = None,
    family: str | None = None,
    lane: str | None = None,
    shared_root: Path | None = None,
) -> Path:
    if output_mode == "standalone":
        return output_root.expanduser() if output_root is not None else default_output_root(program)
    if output_mode != "canonical":
        raise ValueError("output_mode must be 'standalone' or 'canonical'")
    if output_root is not None:
        raise ValueError("--output-root is standalone-only; use --shared-root with --output-mode canonical")
    if not family or not lane:
        raise ValueError("--output-mode canonical requires --family and --lane")
    return canonical_output_root(family=family, program=program, lane=lane, shared_root=shared_root)


def write_artifacts(
    result: MapResult,
    *,
    output_root: Path,
    run_id: str,
    write_specs: bool,
    output_mode: str = "standalone",
) -> dict[str, Path]:
    safe_run_id = validate_run_id(run_id)
    appmap_root = output_root.expanduser().resolve(strict=False) / "appmap"
    run_root = appmap_root / safe_run_id
    if not run_root.resolve(strict=False).is_relative_to(appmap_root):
        raise ValueError(f"run_id {run_id!r} resolves outside output root")
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
        "manifest": run_root / "manifest.json",
        "index": appmap_root / "index.jsonl",
        "summary": run_root / "appmap_summary.md",
    }
    if result.research is not None:
        research_root = run_root / "research"
        paths.update(
            {
                "research": research_root,
                "research_manifest": research_root / "research_manifest.json",
                "research_sources": research_root / "sources.jsonl",
                "research_technique_packs": research_root / "technique_packs.jsonl",
            }
        )

    paths["target_profile"].write_text(
        json.dumps(result.profile.__dict__, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    paths["architecture"].write_text(render_architecture(result), encoding="utf-8")
    _write_jsonl(paths["surfaces"], result.surfaces)
    _write_jsonl(paths["flows"], result.flows)
    _write_jsonl(paths["candidates"], result.candidates)
    _write_jsonl(paths["rejected_candidates"], result.rejected_candidates)
    if result.research is not None:
        _write_research_artifacts(result.research, paths)

    if write_specs and result.candidates:
        focus_slug = sanitize_key(result.focus, fallback="focus")
        spec_path = generated_specs / f"{focus_slug}-spec.md"
        rendered = VULNERABILITY_PACKS[result.focus].render_spec(result, safe_run_id)
        rendered = _with_appmap_run_root_metadata(rendered, run_root)
        spec_path.write_text(rendered, encoding="utf-8")
        spec = parse_brainstorm_spec(spec_path)
        paths["spec"] = spec_path
        paths[f"{focus_slug.replace('-', '_')}_spec"] = spec_path
        if result.focus == "rce":
            paths["rce_spec"] = spec_path
        context_paths = write_agent_contexts(
            result,
            run_root=run_root,
            run_id=safe_run_id,
            spec_path=spec_path,
            parsed_spec=spec,
        )
        if context_paths:
            paths["agent_contexts"] = run_root / "agent_contexts"
            for index, context_path in enumerate(context_paths, start=1):
                stem_parts = context_path.stem.split("-", 2)
                if len(stem_parts) >= 2:
                    hypothesis_id, candidate_id = stem_parts[0].lower(), stem_parts[1].lower()
                    paths.setdefault(f"agent_context_{candidate_id}", context_path)
                    paths[f"agent_context_{hypothesis_id}_{candidate_id}_{index}"] = context_path

    manifest = render_run_manifest(result, paths, run_id=safe_run_id, output_mode=output_mode)
    paths["manifest"].write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _append_run_index(paths["index"], manifest)
    paths["summary"].write_text(render_summary(result, paths, run_id=safe_run_id), encoding="utf-8")
    return paths


def promote_appmap_handoff(
    paths: dict[str, Path],
    *,
    brainstorm_root: Path,
    run_id: str,
    spec_name: str | None = None,
    overwrite: bool = False,
    promotion_layout: str = "flat",
) -> PromotionResult:
    """Copy generated specs and context packets into a brainstorm handoff area.

    Promotion is intentionally narrow: only generated specs and agent context
    packets move into brainstorm space. Raw surfaces, flows, and candidates stay
    in the originating AppMap run root.
    """

    if "spec" not in paths:
        raise ValueError("cannot promote AppMap handoff without a generated spec")
    if promotion_layout not in {"flat", "category"}:
        raise ValueError("promotion_layout must be 'flat' or 'category'")
    safe_run_id = validate_run_id(run_id)
    run_root = paths["run_root"]
    brainstorm_base = brainstorm_root.expanduser()
    _reject_symlink_components(brainstorm_base, label="destination")
    destination_root = brainstorm_base.resolve(strict=False)

    source_specs = sorted({path for key, path in paths.items() if key == "spec" or key.endswith("_spec")})
    focus_slug = _promotion_focus_slug(paths, source_specs)
    if promotion_layout == "category":
        promotion_root = destination_root / f"appmap-{safe_run_id}" / focus_slug
    else:
        promotion_root = destination_root / f"appmap-{safe_run_id}-{focus_slug}"
    _ensure_destination_inside(promotion_root, destination_root)

    copy_pairs: list[tuple[Path, Path]] = []
    for source_spec in source_specs:
        destination_name = spec_name or source_spec.name
        destination_spec = promotion_root / _safe_relative_filename(destination_name)
        copy_pairs.append((source_spec, destination_spec))

    contexts_dir = paths.get("agent_contexts")
    if contexts_dir:
        _reject_symlink_components(contexts_dir, label="source")
    if contexts_dir and contexts_dir.is_dir():
        promoted_context_root = promotion_root / "agent_contexts"
        for source_context in sorted(path for path in contexts_dir.iterdir() if path.suffix == ".json"):
            destination_context = promoted_context_root / source_context.name
            copy_pairs.append((source_context, destination_context))

    manifest_path = destination_root / "appmap_promotions.jsonl"
    _preflight_promotion_copy(copy_pairs, promotion_root=promotion_root, overwrite=overwrite)
    _preflight_manifest_path(manifest_path, destination_root)
    for source, destination in copy_pairs:
        _copy_file_safely(source, destination, overwrite=overwrite)

    promoted_specs = [
        destination
        for source, destination in copy_pairs
        if source in source_specs
    ]
    promoted_contexts = [
        destination
        for source, destination in copy_pairs
        if source not in source_specs
    ]

    promotion_record = {
        "schema_version": 1,
        "promoted_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "appmap_run_id": safe_run_id,
        "appmap_run_root": str(run_root),
        "source_specs": [_relative_to(path, run_root) for path in source_specs],
        "promotion_layout": promotion_layout,
        "promotion_root": _relative_to(promotion_root, destination_root),
        "focus": focus_slug,
        "promoted_specs": [_relative_to(path, promotion_root) for path in promoted_specs],
        "promoted_contexts": [_relative_to(path, promotion_root) for path in promoted_contexts],
        "source_manifest": _relative_to(paths["manifest"], run_root) if "manifest" in paths else None,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(promotion_record, sort_keys=True) + "\n")

    return PromotionResult(
        brainstorm_root=destination_root,
        promotion_root=promotion_root,
        spec_paths=promoted_specs,
        context_paths=promoted_contexts,
        manifest_path=manifest_path,
    )


def list_promoted_handoffs(brainstorm_root: Path) -> list[PromotedHandoff]:
    """Discover promoted AppMap specs from the promotion ledger and per-run dirs."""

    root = brainstorm_root.expanduser().resolve(strict=False)
    handoffs: dict[Path, PromotedHandoff] = {}
    manifest_category_roots: set[Path] = set()
    manifest_path = root / "appmap_promotions.jsonl"
    if manifest_path.is_file():
        for record in _read_jsonl_objects(manifest_path):
            promotion_root = _resolve_manifest_promotion_root(root, record.get("promotion_root"))
            if promotion_root is None:
                continue
            if record.get("promotion_layout") == "category":
                manifest_category_roots.add(promotion_root)
            run_id = str(record.get("appmap_run_id") or "")
            focus_hint = str(record.get("focus") or "").strip()
            for spec_rel in record.get("promoted_specs") or []:
                spec_path = _resolve_manifest_promoted_spec(promotion_root, spec_rel)
                if spec_path is None:
                    continue
                handoff = _promoted_handoff_from_spec(
                    root,
                    promotion_root,
                    spec_path,
                    source="manifest",
                    run_id_hint=run_id,
                    focus_hint=focus_hint,
                )
                if handoff is not None:
                    handoffs[spec_path] = handoff

    if root.is_dir():
        for promotion_root in _iter_promoted_spec_roots(root, category_roots=manifest_category_roots):
            if promotion_root.is_symlink() or _has_symlink_component(promotion_root):
                continue
            resolved_promotion_root = promotion_root.resolve(strict=False)
            if not _path_is_within(resolved_promotion_root, root):
                continue
            for spec_path in sorted(promotion_root.glob("*.md")):
                if spec_path.is_symlink() or _has_symlink_component(spec_path):
                    continue
                resolved_spec = spec_path.resolve(strict=False)
                if not _path_is_within(resolved_spec, resolved_promotion_root):
                    continue
                existing = handoffs.get(resolved_spec)
                if existing is not None:
                    handoffs[resolved_spec] = PromotedHandoff(
                        brainstorm_root=existing.brainstorm_root,
                        promotion_root=existing.promotion_root,
                        spec_path=existing.spec_path,
                        run_id=existing.run_id,
                        focus=existing.focus,
                        source="manifest,directory",
                        context_count=existing.context_count,
                    )
                    continue
                handoff = _promoted_handoff_from_spec(
                    root,
                    resolved_promotion_root,
                    resolved_spec,
                    source="directory",
                )
                if handoff is not None:
                    handoffs[resolved_spec] = handoff
    return sorted(handoffs.values(), key=lambda item: (item.run_id, str(item.spec_path)))


APPMAP_STATUS_COVERED_EVENTS = {"agent_completed_no_finding", "agent_duplicate_only", "review_promoted"}
APPMAP_STATUS_ATTENTION_EVENTS = {"agent_timeout", "agent_crashed", "agent_invalid_output", "review_rejected"}
APPMAP_STATUS_RAW_EVENTS = {"agent_completed_with_raw_findings"}
APPMAP_STATUS_TERMINAL_EVENTS = APPMAP_STATUS_COVERED_EVENTS | APPMAP_STATUS_ATTENTION_EVENTS | APPMAP_STATUS_RAW_EVENTS


def _normalized_status_path(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        return raw
    return str(Path(raw).expanduser().resolve(strict=False))


def _coverage_events_for_spec(coverage_path: Path, spec_path: Path) -> list[dict[str, Any]]:
    normalized_spec = _normalized_status_path(spec_path)
    return [
        event
        for event in read_coverage_jsonl(coverage_path)
        if _normalized_status_path(event.get("source_spec_path") or event.get("brainstorm_spec")) == normalized_spec
    ]


def _event_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        event_name = str(event.get("event") or "").strip()
        if event_name:
            counts[event_name] = counts.get(event_name, 0) + 1
    return counts


def _assignment_identities_for_status(spec_path: Path) -> list[dict[str, str]]:
    try:
        spec = _strict_parse_promoted_spec(spec_path)
    except Exception:
        return []
    appmap_run_id = str(getattr(spec, "metadata", {}).get("AppMap run id") or "").strip()
    identities: list[dict[str, str]] = []
    for hypothesis in getattr(spec, "hypotheses", []):
        if getattr(hypothesis, "status", "") == "retired":
            continue
        evidence_refs = [str(item) for item in getattr(hypothesis, "evidence", [])]
        candidate_refs = sorted(set(_appmap_candidate_refs(evidence_refs)))
        if len(candidate_refs) != 1:
            continue
        try:
            intents = hypothesis_to_agent_intents(spec, hypothesis)
        except Exception:
            continue
        for intent in intents:
            identities.append(
                {
                    "source_spec_path": _normalized_status_path(spec_path),
                    "hypothesis_id": str(getattr(intent, "hypothesis_id", hypothesis.id)),
                    "agent_key": str(getattr(intent, "agent_key", "")),
                    "candidate_id": candidate_refs[0],
                    "appmap_context_packet": "",
                    "appmap_run_id": appmap_run_id,
                    "snapshot_id": "",
                    "snapshot_version": "",
                }
            )
    return identities


def _latest_assignment_event(identity: dict[str, str], events: list[dict[str, Any]]) -> str:
    latest = ""
    tracked_events = APPMAP_STATUS_TERMINAL_EVENTS | {"agent_queued", "agent_spawned"}
    for event in events:
        event_name = str(event.get("event") or "").strip()
        if event_name not in tracked_events:
            continue
        if coverage_event_matches_assignment(event, identity):
            latest = event_name
    return latest


def _assignment_status_counts(identities: list[dict[str, str]], events: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"covered": 0, "review": 0, "attention": 0, "running": 0, "pending": 0}
    for identity in identities:
        latest = _latest_assignment_event(identity, events)
        if not latest:
            counts["pending"] += 1
        elif latest in APPMAP_STATUS_COVERED_EVENTS:
            counts["covered"] += 1
        elif latest in APPMAP_STATUS_RAW_EVENTS:
            counts["review"] += 1
        elif latest in APPMAP_STATUS_ATTENTION_EVENTS:
            counts["attention"] += 1
        elif latest in {"agent_queued", "agent_spawned"}:
            counts["running"] += 1
        else:
            counts["pending"] += 1
    return counts


def _campaign_spec_status(
    validation: HandoffValidationResult,
    counts: dict[str, int],
    assignment_counts: dict[str, int],
) -> str:
    if not validation.ok:
        return "blocked"
    if assignment_counts.get("attention", 0):
        return "attention"
    if assignment_counts.get("review", 0):
        return "review"
    expected = int(validation.counts.get("appmap_intents") or 0)
    if expected and assignment_counts.get("covered", 0) >= expected:
        return "complete"
    if assignment_counts.get("running", 0):
        return "running"
    return "ready"


def campaign_status(brainstorm_root: Path) -> dict[str, Any]:
    root = brainstorm_root.expanduser().resolve(strict=False)
    coverage_path = root / "coverage.jsonl"
    handoffs = list_promoted_handoffs(root)
    specs: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    for handoff in handoffs:
        validation = validate_promoted_handoff(handoff.spec_path)
        events = _coverage_events_for_spec(coverage_path, handoff.spec_path)
        counts = _event_counts(events)
        assignment_counts = _assignment_status_counts(_assignment_identities_for_status(handoff.spec_path), events)
        status = _campaign_spec_status(validation, counts, assignment_counts)
        status_counts[status] = status_counts.get(status, 0) + 1
        specs.append(
            {
                "status": status,
                "run_id": handoff.run_id,
                "focus": handoff.focus,
                "spec": str(handoff.spec_path),
                "source": handoff.source,
                "contexts": handoff.context_count,
                "validation_ok": validation.ok,
                "validation_errors": list(validation.errors),
                "counts": dict(validation.counts),
                "coverage_events": counts,
                "assignments": assignment_counts,
            }
        )
    return {
        "brainstorm_root": str(root),
        "coverage": str(coverage_path),
        "handoff_count": len(handoffs),
        "status_counts": status_counts,
        "specs": specs,
    }


def validate_promoted_handoff(spec_path: Path) -> HandoffValidationResult:
    """Validate AppMap-linked handoff packets without writing runtime artifacts."""

    errors: list[str] = []
    counts = {
        "hypotheses": 0,
        "appmap_hypotheses": 0,
        "appmap_intents": 0,
        "packets": 0,
    }
    try:
        resolved_spec = _resolve_direct_promoted_spec(spec_path)
    except Exception as exc:
        return HandoffValidationResult(spec_path.expanduser().resolve(strict=False), counts, [str(exc)])
    try:
        spec = _strict_parse_promoted_spec(resolved_spec)
    except Exception as exc:
        return HandoffValidationResult(resolved_spec, counts, [f"strict brainstorm spec parse failed: {exc}"])

    counts["hypotheses"] = len(getattr(spec, "hypotheses", []))
    spec_run_id = str(getattr(spec, "metadata", {}).get("AppMap run id") or "").strip()
    spec_run_root = str(getattr(spec, "metadata", {}).get("AppMap run root") or "").strip()
    if not spec_run_id:
        errors.append("spec metadata is missing AppMap run id")
    if not spec_run_root:
        errors.append("spec metadata is missing AppMap run root")

    contexts_dir = resolved_spec.parent / "agent_contexts"
    for hypothesis in getattr(spec, "hypotheses", []):
        evidence_refs = [str(item) for item in getattr(hypothesis, "evidence", [])]
        candidate_refs = _appmap_candidate_refs(evidence_refs)
        context_refs = _appmap_context_refs(evidence_refs)
        if not candidate_refs and not context_refs:
            continue
        counts["appmap_hypotheses"] += 1
        candidate_id = _validate_hypothesis_candidate_refs(hypothesis.id, candidate_refs, errors)
        if candidate_id is None:
            continue
        try:
            intents = hypothesis_to_agent_intents(spec, hypothesis)
        except Exception as exc:
            errors.append(f"{hypothesis.id}: failed to enumerate brainstorm intents: {exc}")
            continue
        for intent in intents:
            counts["appmap_intents"] += 1
            packet_path = _resolve_sibling_context_packet(
                contexts_dir,
                hypothesis_id=str(getattr(intent, "hypothesis_id", hypothesis.id)),
                candidate_id=candidate_id,
                agent_key=str(getattr(intent, "agent_key", "")),
                errors=errors,
            )
            _validate_context_ref_for_intent(
                intent,
                candidate_id=candidate_id,
                context_refs=context_refs,
                errors=errors,
            )
            if packet_path is None:
                continue
            packet = _load_context_packet(packet_path, errors)
            if packet is None:
                continue
            counts["packets"] += 1
            _validate_context_packet(
                packet,
                packet_path=packet_path,
                intent=intent,
                candidate_id=candidate_id,
                spec_run_id=spec_run_id,
                spec_run_root=spec_run_root,
                errors=errors,
            )
    if counts["appmap_hypotheses"] == 0:
        errors.append("promoted AppMap handoff contains zero AppMap hypotheses")
    if counts["appmap_intents"] == 0:
        errors.append("promoted AppMap handoff contains zero AppMap agent intents")
    if counts["packets"] == 0:
        errors.append("promoted AppMap handoff contains zero AppMap context packets")
    return HandoffValidationResult(resolved_spec, counts, errors)


def plan_promoted_handoff_command(
    spec_path: Path,
    *,
    selected_hypothesis: str | None = None,
) -> str:
    """Return the explicit existing runtime command for a promoted AppMap spec."""

    resolved_spec = _resolve_direct_promoted_spec(spec_path)
    try:
        spec = _strict_parse_promoted_spec(resolved_spec)
    except Exception as exc:
        raise ValueError(f"strict brainstorm spec parse failed: {exc}") from exc
    if selected_hypothesis:
        matching_hypothesis = next(
            (hypothesis for hypothesis in getattr(spec, "hypotheses", []) if hypothesis.id == selected_hypothesis),
            None,
        )
        if matching_hypothesis is None or matching_hypothesis.status == "retired":
            raise ValueError(f"brainstorm hypothesis {selected_hypothesis!r} was not found or is retired")
        _validate_selected_hypothesis_for_plan(spec, matching_hypothesis, resolved_spec)
    else:
        active_hypotheses = [
            hypothesis
            for hypothesis in getattr(spec, "hypotheses", [])
            if getattr(hypothesis, "status", "") != "retired"
        ]
        if not active_hypotheses:
            raise ValueError("promoted AppMap handoff has no active hypotheses to plan")
        for hypothesis in active_hypotheses:
            _validate_selected_hypothesis_for_plan(spec, hypothesis, resolved_spec)
    metadata = getattr(spec, "metadata", {})
    program = str(metadata.get("Program") or "").strip() or "program"
    target_path = str(metadata.get("Target path") or "").strip() or "."
    run_root = str(metadata.get("AppMap run root") or "").strip()
    if run_root:
        manifest_path = Path(run_root).expanduser() / "manifest.json"
        if manifest_path.is_file():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                manifest = {}
            if isinstance(manifest, dict) and str(manifest.get("target_path") or "").strip():
                target_path = str(manifest["target_path"])

    command = [
        "python3",
        "agents/zero_day_team.py",
        program,
        target_path,
        "--brainstorm-spec",
        str(resolved_spec),
        "--brainstorm-only",
    ]
    if selected_hypothesis:
        command.extend(["--brainstorm-hypothesis", selected_hypothesis])
    return shlex.join(command)


def _resolve_direct_promoted_spec(spec_path: Path) -> Path:
    raw_path = spec_path.expanduser()
    if raw_path.is_symlink() or _has_symlink_component(raw_path):
        raise ValueError(f"promoted AppMap spec path must not be a symlink or contain symlink components: {raw_path}")
    resolved = raw_path.resolve(strict=False)
    if not resolved.is_file():
        raise FileNotFoundError(f"promoted AppMap spec does not exist or is not a regular file: {raw_path}")
    return resolved


def validate_run_id(run_id: str) -> str:
    safe = str(run_id or "").strip()
    if not safe or safe in {".", ".."} or not RUN_ID_RE.fullmatch(safe):
        raise ValueError(
            "run_id must be 1-128 ASCII letters, digits, dots, underscores, or hyphens; "
            "it must start with a letter or digit and must not contain path separators"
        )
    return safe


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _read_jsonl_objects(path: Path) -> Iterable[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            yield payload


class LocalSeedResearchProvider(ResearchProvider):
    """Deterministic provider backed by local seed files only."""

    key = "local-seed"

    def collect(self, request: ResearchRequest) -> dict[str, Any]:
        sources, technique_packs, errors = _collect_seed_research(request)
        cache_key = _json_digest(
            {
                "provider": self.key,
                "program": request.program,
                "focus": request.focus,
                "target_kind": request.target_kind,
                "seed_paths": [str(path.expanduser().resolve(strict=False)) for path in request.seed_paths],
                "sources": sources,
                "technique_packs": technique_packs,
            }
        )
        return {
            "manifest": _research_manifest(
                request,
                provider_key=self.key,
                cache_key=cache_key,
                network_access=False,
                network_policy="local seed provider only; no network I/O",
                sources=sources,
                technique_packs=technique_packs,
                errors=errors,
                fetched=[],
            ),
            "sources": sources,
            "technique_packs": technique_packs,
        }


class WebFetchResearchProvider(ResearchProvider):
    """Conservative HTTPS-only fetcher for operator-supplied source URLs."""

    key = "web-fetch"
    network_capable = True
    max_source_urls = 10
    max_bytes = 256 * 1024
    timeout_seconds = 5.0

    def __init__(
        self,
        *,
        opener: Callable[..., Any] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._opener = opener or _non_redirecting_urlopen
        self._now = now or (lambda: datetime.now(timezone.utc))

    def collect(self, request: ResearchRequest) -> dict[str, Any]:
        if not request.research_online:
            raise ValueError("--research-provider web-fetch requires --research-online")
        if not request.source_urls:
            raise ValueError("--research-provider web-fetch requires at least one --research-source-url")
        if len(request.source_urls) > self.max_source_urls:
            raise ValueError(f"--research-source-url accepts at most {self.max_source_urls} URLs")

        sources, technique_packs, errors = _collect_seed_research(request)
        known_source_ids = {source["id"] for source in sources}
        known_technique_ids = {technique["id"] for technique in technique_packs}
        fetched: list[dict[str, Any]] = []

        for url in request.source_urls:
            fetch_record, source, metadata = self._fetch_source(url, len(sources) + 1)
            fetched.append(fetch_record)
            if source is None:
                if fetch_record.get("error"):
                    errors.append(f"{url}: {fetch_record['error']}")
                continue

            raw_source_id = str(source.get("id") or source.get("source_id") or "").strip()
            if source["id"] in known_source_ids:
                source["id"] = _stable_research_id(
                    "",
                    prefix="W",
                    index=len(sources) + 1,
                    payload=source,
                    known_ids=known_source_ids,
                )
                source["citation"] = f"[{source['id']}]"
            known_source_ids.add(source["id"])
            sources.append(source)

            if metadata is None:
                continue
            for metadata_error in metadata.get("errors", []):
                errors.append(str(metadata_error))

            aliases: dict[str, str] = {}
            if raw_source_id:
                aliases[raw_source_id] = source["id"]
            seed_source_ids = [source["id"]]
            for metadata_source in metadata.get("sources", []):
                normalized_source = _normalize_research_source(
                    metadata_source,
                    seed_path=None,
                    index=len(sources) + 1,
                    known_ids=known_source_ids,
                    default_url=str(metadata_source.get("url") or url),
                    default_source_type="web-source-metadata",
                    metadata_origin=url,
                )
                metadata_raw_id = str(metadata_source.get("id") or metadata_source.get("source_id") or "").strip()
                if metadata_raw_id:
                    aliases[metadata_raw_id] = normalized_source["id"]
                known_source_ids.add(normalized_source["id"])
                seed_source_ids.append(normalized_source["id"])
                sources.append(normalized_source)

            for technique in metadata.get("technique_packs", []):
                normalized_technique = _normalize_technique_pack(
                    technique,
                    request=request,
                    seed_path=Path(url),
                    index=len(technique_packs) + 1,
                    source_aliases=aliases,
                    seed_source_ids=seed_source_ids,
                    known_source_ids=known_source_ids,
                    known_technique_ids=known_technique_ids,
                    errors=errors,
                )
                known_technique_ids.add(normalized_technique["id"])
                technique_packs.append(normalized_technique)

        sources.sort(key=lambda item: item["id"])
        technique_packs.sort(key=lambda item: item["id"])
        cache_key = _json_digest(
            {
                "provider": self.key,
                "program": request.program,
                "focus": request.focus,
                "target_kind": request.target_kind,
                "seed_paths": [str(path.expanduser().resolve(strict=False)) for path in request.seed_paths],
                "source_urls": list(request.source_urls),
                "fetched": _stable_research_cache_value(fetched),
                "sources": _stable_research_cache_value(sources),
                "technique_packs": _stable_research_cache_value(technique_packs),
            }
        )
        return {
            "manifest": _research_manifest(
                request,
                provider_key=self.key,
                cache_key=cache_key,
                network_access=True,
                network_policy=(
                    "HTTPS-only fetch of explicit --research-source-url values; no search, crawling, "
                    f"or target probing; max_bytes={self.max_bytes}; timeout_seconds={self.timeout_seconds:g}"
                ),
                sources=sources,
                technique_packs=technique_packs,
                errors=errors,
                fetched=fetched,
            ),
            "sources": sources,
            "technique_packs": technique_packs,
        }

    def _fetch_source(self, raw_url: str, index: int) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
        url = raw_url.strip()
        fetched_at = self._now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        fetch_record: dict[str, Any] = {
            "url": url,
            "requested_at": fetched_at,
            "status": "not_fetched",
            "network_access": True,
            "max_bytes": self.max_bytes,
            "timeout_seconds": self.timeout_seconds,
        }
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            fetch_record["status"] = "rejected"
            fetch_record["error"] = "research-source-url must be an absolute https URL"
            return fetch_record, None, None

        request = urllib.request.Request(url, headers={"User-Agent": "AppMapResearch/1.0"})
        try:
            with self._opener(request, timeout=self.timeout_seconds) as response:
                final_url = str(getattr(response, "url", "") or getattr(response, "geturl", lambda: url)())
                status_code = int(getattr(response, "status", 0) or getattr(response, "code", 0) or response.getcode())
                headers = getattr(response, "headers", None)
                if 300 <= status_code < 400:
                    location = _header_value(headers, "Location")
                    fetch_record.update(
                        {
                            "status": "redirect_rejected",
                            "http_status": status_code,
                            "location": location,
                            "error": _redirect_rejected_error(location),
                        }
                    )
                    return fetch_record, None, None
                if final_url and final_url != url:
                    fetch_record["status"] = "redirect_rejected"
                    fetch_record["final_url"] = final_url
                    fetch_record["error"] = _redirect_rejected_error(final_url)
                    return fetch_record, None, None
                if urllib.parse.urlsplit(final_url or url).scheme.lower() != "https":
                    fetch_record["status"] = "rejected"
                    fetch_record["final_url"] = final_url
                    fetch_record["error"] = "redirected to non-https URL"
                    return fetch_record, None, None
                content_type = _header_value(headers, "Content-Type")
                data = response.read(self.max_bytes + 1)
        except urllib.error.HTTPError as exc:
            if 300 <= int(exc.code) < 400:
                location = _header_value(getattr(exc, "headers", None), "Location")
                fetch_record.update(
                    {
                        "status": "redirect_rejected",
                        "http_status": exc.code,
                        "location": location,
                        "error": _redirect_rejected_error(location),
                    }
                )
                return fetch_record, None, None
            fetch_record.update(
                {
                    "status": "http_error",
                    "http_status": exc.code,
                    "error": str(exc.reason or exc),
                }
            )
            return fetch_record, None, None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            fetch_record.update({"status": "error", "error": str(exc)})
            return fetch_record, None, None

        truncated = len(data) > self.max_bytes
        if truncated:
            data = data[: self.max_bytes]
        digest = hashlib.sha256(data).hexdigest()
        text = _decode_web_bytes(data, content_type)
        title = _extract_web_title(text) or urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1] or url
        summary = _summarize_web_text(text, content_type)
        fetch_record.update(
            {
                "status": "ok_truncated" if truncated else "ok",
                "http_status": status_code,
                "final_url": final_url,
                "content_type": content_type,
                "bytes_read": len(data),
                "truncated": truncated,
                "content_sha256": digest,
            }
        )
        if truncated:
            fetch_record["error"] = f"response truncated after {self.max_bytes} bytes"

        source_id = _stable_research_id(
            "",
            prefix="W",
            index=index,
            payload={"url": url, "content_sha256": digest},
            known_ids=set(),
        )
        source = {
            "id": source_id,
            "title": _compact_text(title, 180),
            "url": _compact_text(final_url or url, 500),
            "source_type": "web-fetch",
            "retrieved_at": fetched_at,
            "local_path": "",
            "summary": _compact_text(summary, 1200),
            "content_sha256": digest,
            "citation": f"[{source_id}]",
            "network_access": True,
            "http_status": status_code,
            "content_type": _compact_text(content_type, 120),
            "content_bytes": len(data),
        }
        metadata = _web_research_metadata(text, content_type, url)
        return fetch_record, source, metadata


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


_NON_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)
_VOLATILE_RESEARCH_CACHE_FIELDS = {"requested_at", "retrieved_at", "fetched_at", "generated_at"}


def _non_redirecting_urlopen(request: urllib.request.Request, *, timeout: float) -> Any:
    return _NON_REDIRECT_OPENER.open(request, timeout=timeout)


def _redirect_rejected_error(location: str) -> str:
    if location:
        return f"redirect rejected; Location: {location}"
    return "redirect rejected; Location header missing"


def _stable_research_cache_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _stable_research_cache_value(item)
            for key, item in value.items()
            if str(key) not in _VOLATILE_RESEARCH_CACHE_FIELDS
        }
    if isinstance(value, list):
        return [_stable_research_cache_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_stable_research_cache_value(item) for item in value)
    return value


def _collect_seed_research(request: ResearchRequest) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    sources: list[dict[str, Any]] = []
    technique_packs: list[dict[str, Any]] = []
    errors: list[str] = []
    known_source_ids: set[str] = set()
    known_technique_ids: set[str] = set()

    for seed_path in request.seed_paths:
        seed = _load_research_seed(seed_path, errors)
        aliases: dict[str, str] = {}
        seed_sources: list[str] = []
        for source in seed.get("sources", []):
            normalized = _normalize_research_source(
                source,
                seed_path=seed_path,
                index=len(sources) + 1,
                known_ids=known_source_ids,
            )
            raw_id = str(source.get("id") or source.get("source_id") or "").strip()
            if raw_id:
                aliases[raw_id] = normalized["id"]
            known_source_ids.add(normalized["id"])
            seed_sources.append(normalized["id"])
            sources.append(normalized)
        for technique in seed.get("technique_packs", []):
            technique_packs.append(
                _normalize_technique_pack(
                    technique,
                    request=request,
                    seed_path=seed_path,
                    index=len(technique_packs) + 1,
                    source_aliases=aliases,
                    seed_source_ids=seed_sources,
                    known_source_ids=known_source_ids,
                    known_technique_ids=known_technique_ids,
                    errors=errors,
                )
            )
            known_technique_ids.add(technique_packs[-1]["id"])

    sources.sort(key=lambda item: item["id"])
    technique_packs.sort(key=lambda item: item["id"])
    return sources, technique_packs, errors


def _research_manifest(
    request: ResearchRequest,
    *,
    provider_key: str,
    cache_key: str,
    network_access: bool,
    network_policy: str,
    sources: list[dict[str, Any]],
    technique_packs: list[dict[str, Any]],
    errors: list[str],
    fetched: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "enabled": bool(request.research_online or request.seed_paths or request.source_urls),
        "provider": provider_key,
        "cache_key": cache_key,
        "cache_policy": "research artifacts are the offline cache for reproducible reuse",
        "online_requested": bool(request.research_online),
        "network_access": network_access,
        "network_policy": network_policy,
        "program": request.program,
        "focus": request.focus,
        "target_kind": request.target_kind,
        "seed_paths": [str(path.expanduser().resolve(strict=False)) for path in request.seed_paths],
        "source_urls": list(request.source_urls),
        "fetched": fetched,
        "counts": {
            "sources": len(sources),
            "technique_packs": len(technique_packs),
            "errors": len(errors),
        },
        "errors": errors,
    }


RESEARCH_PROVIDERS: dict[str, type[ResearchProvider]] = {
    LocalSeedResearchProvider.key: LocalSeedResearchProvider,
    WebFetchResearchProvider.key: WebFetchResearchProvider,
}


def _build_research_provider(name: str) -> ResearchProvider:
    try:
        provider_cls = RESEARCH_PROVIDERS[name]
    except KeyError as exc:
        choices = ", ".join(sorted(RESEARCH_PROVIDERS))
        raise ValueError(f"unknown research provider {name!r}; expected one of: {choices}") from exc
    return provider_cls()


def _normalized_research_source_urls(source_urls: Iterable[str]) -> tuple[str, ...]:
    return tuple(str(url).strip() for url in source_urls if str(url).strip())


def _validate_research_options(
    *,
    research_online: bool,
    provider: ResearchProvider,
    source_urls: Iterable[str],
) -> tuple[str, ...]:
    urls = _normalized_research_source_urls(source_urls)
    max_source_urls = int(getattr(provider, "max_source_urls", WebFetchResearchProvider.max_source_urls))
    if len(urls) > max_source_urls:
        raise ValueError(f"--research-source-url accepts at most {max_source_urls} URLs")
    if urls and not provider.network_capable:
        raise ValueError("--research-source-url requires --research-provider web-fetch")
    if provider.network_capable and not research_online:
        raise ValueError(f"--research-provider {provider.key} requires --research-online")
    if provider.key == WebFetchResearchProvider.key and research_online and not urls:
        raise ValueError("--research-provider web-fetch requires at least one --research-source-url")
    return urls


def _header_value(headers: Any, name: str) -> str:
    if headers is None:
        return ""
    getter = getattr(headers, "get", None)
    if callable(getter):
        value = getter(name) or getter(name.lower()) or getter(name.title())
        return str(value or "")
    return ""


def _decode_web_bytes(data: bytes, content_type: str) -> str:
    charset = ""
    match = re.search(r"charset=([\w.\-]+)", content_type or "", re.IGNORECASE)
    if match:
        charset = match.group(1)
    for encoding in (charset, "utf-8", "latin-1"):
        if not encoding:
            continue
        try:
            return data.decode(encoding, errors="replace")
        except LookupError:
            continue
    return data.decode("utf-8", errors="replace")


def _extract_web_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return _html_text(match.group(1))


def _summarize_web_text(text: str, content_type: str) -> str:
    if "html" in (content_type or "").lower() or re.search(r"<html\b|<body\b|<p\b", text, re.IGNORECASE):
        text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
        text = _html_text(text)
    return _compact_text(text, 900)


def _html_text(text: str) -> str:
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = (
        text.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )
    return _compact_text(text, 1200)


def _web_research_metadata(text: str, content_type: str, url: str) -> dict[str, Any] | None:
    lower_type = (content_type or "").lower()
    path = urllib.parse.urlsplit(url).path.lower()
    if "json" not in lower_type and not path.endswith((".json", ".jsonl")):
        return None
    errors: list[str] = []
    metadata = _load_research_payload_text(text, origin=url, errors=errors, jsonl=path.endswith(".jsonl"))
    if errors:
        metadata["errors"] = errors
    return metadata


def generate_research_artifacts(
    result: MapResult,
    *,
    research_online: bool = False,
    seed_paths: Iterable[Path] = (),
    source_urls: Iterable[str] = (),
    research_provider: str = "local-seed",
    provider: ResearchProvider | None = None,
) -> dict[str, Any] | None:
    seeds = tuple(path.expanduser() for path in seed_paths)
    provider = provider or _build_research_provider(research_provider)
    urls = _validate_research_options(
        research_online=research_online,
        provider=provider,
        source_urls=source_urls,
    )
    if not research_online and not seeds and not urls:
        return None
    return provider.collect(
        ResearchRequest(
            program=result.profile.program,
            focus=result.focus,
            target_kind=result.profile.target_kind,
            provider_key=provider.key,
            research_online=research_online,
            seed_paths=seeds,
            source_urls=urls,
        )
    )


def _load_research_seed(seed_path: Path, errors: list[str]) -> dict[str, list[dict[str, Any]]]:
    path = seed_path.expanduser()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"{path}: failed to read seed: {exc}")
        return {"sources": [], "technique_packs": []}
    stripped = text.strip()
    if not stripped:
        return {"sources": [], "technique_packs": []}

    payload: Any
    try:
        if path.suffix.lower() == ".jsonl":
            payload = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    payload.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    errors.append(f"{path}: line {line_number}: invalid JSON: {exc.msg}")
        else:
            payload = json.loads(stripped)
    except json.JSONDecodeError:
        source = {
            "title": path.name,
            "source_type": "local-text-seed",
            "local_path": str(path.resolve(strict=False)),
            "summary": _compact_text(stripped, 900),
        }
        return {"sources": [source], "technique_packs": []}

    return _research_payload_sections(payload, origin=str(path), errors=errors)


def _load_research_payload_text(
    text: str,
    *,
    origin: str,
    errors: list[str],
    jsonl: bool,
) -> dict[str, list[dict[str, Any]]]:
    stripped = text.strip()
    if not stripped:
        return {"sources": [], "technique_packs": []}
    try:
        if jsonl:
            payload: Any = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    payload.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    errors.append(f"{origin}: line {line_number}: invalid JSON: {exc.msg}")
        else:
            payload = json.loads(stripped)
    except json.JSONDecodeError as exc:
        errors.append(f"{origin}: invalid JSON research metadata: {exc.msg}")
        return {"sources": [], "technique_packs": []}
    return _research_payload_sections(payload, origin=origin, errors=errors)


def _research_payload_sections(payload: Any, *, origin: str, errors: list[str]) -> dict[str, list[dict[str, Any]]]:
    sources: list[dict[str, Any]] = []
    technique_packs: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        sources.extend(_dict_rows(payload.get("sources")))
        technique_packs.extend(
            _dict_rows(
                payload.get("technique_packs")
                if payload.get("technique_packs") is not None
                else payload.get("techniques")
            )
        )
        if str(payload.get("type") or "").strip() in {"source", "technique", "technique_pack"}:
            rows = _research_payload_sections([payload], origin=origin, errors=errors)
            sources.extend(rows["sources"])
            technique_packs.extend(rows["technique_packs"])
    elif isinstance(payload, list):
        for row in payload:
            if not isinstance(row, dict):
                continue
            row_type = str(row.get("type") or row.get("record_type") or "").strip()
            if row_type == "source":
                sources.append(row)
            elif row_type in {"technique", "technique_pack"}:
                technique_packs.append(row)
            elif "summary" in row and ("target_pack_keys" in row or "vulnerability_pack" in row):
                technique_packs.append(row)
            elif "url" in row or "title" in row:
                sources.append(row)
    else:
        errors.append(f"{origin}: unsupported research seed JSON root")
    return {"sources": sources, "technique_packs": technique_packs}


def _dict_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _normalize_research_source(
    source: dict[str, Any],
    *,
    seed_path: Path | None,
    index: int,
    known_ids: set[str],
    default_url: str = "",
    default_source_type: str = "seed",
    metadata_origin: str = "",
) -> dict[str, Any]:
    raw_id = str(source.get("id") or source.get("source_id") or "").strip()
    source_id = _stable_research_id(raw_id, prefix="S", index=index, payload=source, known_ids=known_ids)
    fallback_title = seed_path.name if seed_path is not None else default_url or source_id
    local_path = str(source.get("local_path") or "")
    if not local_path and seed_path is not None:
        local_path = str(seed_path.resolve(strict=False))
    return {
        "id": source_id,
        "title": _compact_text(str(source.get("title") or source.get("name") or fallback_title), 180),
        "url": _compact_text(str(source.get("url") or source.get("link") or default_url), 500),
        "source_type": _compact_text(str(source.get("source_type") or source.get("type") or default_source_type), 80),
        "retrieved_at": _compact_text(str(source.get("retrieved_at") or source.get("published_at") or ""), 80),
        "local_path": _compact_text(local_path, 500),
        "summary": _compact_text(str(source.get("summary") or source.get("description") or ""), 1200),
        "content_sha256": _json_digest(source),
        "citation": f"[{source_id}]",
        "metadata_origin": _compact_text(metadata_origin, 500),
    }


def _normalize_technique_pack(
    technique: dict[str, Any],
    *,
    request: ResearchRequest,
    seed_path: Path,
    index: int,
    source_aliases: dict[str, str],
    seed_source_ids: list[str],
    known_source_ids: set[str],
    known_technique_ids: set[str],
    errors: list[str],
) -> dict[str, Any]:
    raw_id = str(technique.get("id") or technique.get("key") or technique.get("technique_id") or "").strip()
    technique_id = _stable_research_id(raw_id, prefix="T", index=index, payload=technique, known_ids=known_technique_ids)
    source_ids: list[str] = []
    requested_source_ids = _string_list(technique.get("source_ids") or technique.get("sources"))
    for item in requested_source_ids:
        raw_source_id = str(item).strip()
        if not raw_source_id:
            continue
        resolved_source_id = source_aliases.get(raw_source_id) or sanitize_key(raw_source_id, fallback="")
        if resolved_source_id in known_source_ids:
            source_ids.append(resolved_source_id)
        else:
            errors.append(f"{seed_path}: technique {technique_id} references unknown source id {raw_source_id!r}")
    if not requested_source_ids:
        source_ids = list(seed_source_ids)
    source_ids = sorted(dict.fromkeys(source_ids))
    return {
        "id": technique_id,
        "title": _compact_text(str(technique.get("title") or technique.get("name") or technique_id), 180),
        "summary": _compact_text(str(technique.get("summary") or technique.get("description") or ""), 1400),
        "vulnerability_pack": _compact_text(str(technique.get("vulnerability_pack") or technique.get("focus") or request.focus), 80),
        "target_pack_keys": _string_list(technique.get("target_pack_keys") or technique.get("target_packs")),
        "applicable_surface_kinds": _string_list(
            technique.get("applicable_surface_kinds") or technique.get("surface_kinds")
        ),
        "applies_to_all": _bool_value(technique.get("applies_to_all")),
        "guidance": [_compact_text(item, 500) for item in _string_list(technique.get("guidance") or technique.get("steps"))],
        "source_ids": source_ids,
        "citations": [f"[{source_id}]" for source_id in source_ids],
        "seed_path": str(seed_path.resolve(strict=False)),
        "content_sha256": _json_digest(technique),
    }


def _stable_research_id(
    value: str,
    *,
    prefix: str,
    index: int,
    payload: dict[str, Any],
    known_ids: set[str],
) -> str:
    cleaned = sanitize_key(value, fallback="")
    if cleaned:
        candidate = cleaned[:80]
    else:
        digest = _json_digest(payload)[:10]
        candidate = f"{prefix}{index:04d}-{digest}"
    while candidate in known_ids:
        candidate = f"{candidate}-{_json_digest({'id': candidate, 'index': index})[:6]}"
    return candidate


def _json_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list | tuple | set):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _compact_text(value: str, limit: int) -> str:
    compacted = re.sub(r"\s+", " ", str(value or "")).strip()
    return compacted[:limit]


def _strict_parse_promoted_spec(spec_path: Path) -> Any:
    return parse_brainstorm_spec(spec_path, validate_paths=True)


def _resolve_manifest_promotion_root(root: Path, value: Any) -> Path | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    candidate = Path(raw).expanduser()
    if any(part in {"", ".", ".."} for part in candidate.parts):
        return None
    raw_path = candidate if candidate.is_absolute() else root / candidate
    resolved = raw_path.resolve(strict=False)
    if not _path_is_within(resolved, root):
        return None
    if raw_path.is_symlink() or _has_symlink_component(raw_path):
        return None
    if not resolved.is_dir():
        return None
    return resolved


def _resolve_manifest_promoted_spec(promotion_root: Path, value: Any) -> Path | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    candidate = Path(raw).expanduser()
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        return None
    raw_path = promotion_root / candidate
    resolved = raw_path.resolve(strict=False)
    if not _path_is_within(resolved, promotion_root):
        return None
    if raw_path.is_symlink() or _has_symlink_component(raw_path):
        return None
    if not resolved.is_file():
        return None
    return resolved


def _path_is_within(path: Path, root: Path) -> bool:
    resolved_root = root.resolve(strict=False)
    resolved_path = path.resolve(strict=False)
    return resolved_path == resolved_root or resolved_path.is_relative_to(resolved_root)


def _has_symlink_component(path: Path) -> bool:
    expanded = path.expanduser()
    current = Path(expanded.anchor) if expanded.is_absolute() else Path.cwd()
    parts = expanded.parts[1:] if expanded.is_absolute() else expanded.parts
    for part in parts:
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def _promoted_handoff_from_spec(
    brainstorm_root: Path,
    promotion_root: Path,
    spec_path: Path,
    *,
    source: str,
    run_id_hint: str = "",
    focus_hint: str = "",
) -> PromotedHandoff | None:
    try:
        spec = _strict_parse_promoted_spec(spec_path)
        metadata: dict[str, Any] = getattr(spec, "metadata", {})
    except Exception:
        return None
    run_id = str(metadata.get("AppMap run id") or run_id_hint or "").strip()
    focus = sanitize_key(focus_hint, fallback="") if focus_hint else ""
    if not focus:
        focus = _handoff_focus_from_spec(spec_path, promotion_root, run_id=run_id)
    contexts_dir = spec_path.parent / "agent_contexts"
    context_count = (
        len([path for path in contexts_dir.glob("*.json") if path.is_file() and not path.is_symlink()])
        if contexts_dir.is_dir() and not contexts_dir.is_symlink()
        else 0
    )
    return PromotedHandoff(
        brainstorm_root=brainstorm_root,
        promotion_root=promotion_root,
        spec_path=spec_path,
        run_id=run_id,
        focus=focus,
        source=source,
        context_count=context_count,
    )


def _handoff_focus_from_spec(spec_path: Path, promotion_root: Path, *, run_id: str = "") -> str:
    stem = spec_path.stem
    if stem.endswith("-spec"):
        return stem[:-5] or "focus"
    if stem == "spec":
        parent = promotion_root.parent
        if re.fullmatch(r"appmap-[A-Za-z0-9][A-Za-z0-9._-]{0,127}", parent.name):
            return sanitize_key(promotion_root.name, fallback="focus")
        safe_run_id = sanitize_key(run_id, fallback="")
        flat_prefix = f"appmap-{safe_run_id}-" if safe_run_id else ""
        if flat_prefix and promotion_root.name.startswith(flat_prefix):
            return sanitize_key(promotion_root.name[len(flat_prefix):], fallback="focus")
    match = re.match(r"appmap-[^-]+-(?P<focus>.+)", promotion_root.name)
    if match:
        return match.group("focus")
    return stem or "focus"


def _iter_promoted_spec_roots(root: Path, *, category_roots: set[Path]) -> Iterable[Path]:
    for appmap_root in sorted(path for path in root.glob("appmap-*") if path.is_dir() and not path.is_symlink()):
        if _has_symlink_component(appmap_root):
            continue
        resolved_appmap_root = appmap_root.resolve(strict=False)
        if not _path_is_within(resolved_appmap_root, root):
            continue
        yield appmap_root
        for focus_root in sorted(category_roots, key=lambda path: (str(path).casefold(), str(path))):
            if focus_root.parent != resolved_appmap_root:
                continue
            if focus_root.is_symlink() or _has_symlink_component(focus_root):
                continue
            resolved_focus_root = focus_root.resolve(strict=False)
            if not _path_is_within(resolved_focus_root, resolved_appmap_root):
                continue
            yield resolved_focus_root


def _appmap_candidate_refs(evidence_refs: list[str]) -> list[str]:
    return [
        match.group(1)
        for evidence in evidence_refs
        for match in re.finditer(r"\bappmap-(C\d{4})\b", evidence)
    ]


def _appmap_context_refs(evidence_refs: list[str]) -> list[tuple[str, str, str]]:
    return [
        match.groups()
        for evidence in evidence_refs
        for match in re.finditer(r"\bappmap-context:([^:\s]+):(C\d{4}):([^\s]+)\b", evidence)
    ]


def _validate_hypothesis_candidate_refs(
    hypothesis_id: str,
    candidate_refs: list[str],
    errors: list[str],
) -> str | None:
    unique_candidate_refs = sorted(set(candidate_refs))
    if not candidate_refs:
        errors.append(f"{hypothesis_id}: missing appmap-C#### candidate evidence")
        return None
    if len(candidate_refs) != len(unique_candidate_refs):
        errors.append(f"{hypothesis_id}: duplicate appmap-C#### candidate evidence")
        return None
    if len(unique_candidate_refs) != 1:
        errors.append(f"{hypothesis_id}: aggregates multiple AppMap candidates: {', '.join(unique_candidate_refs)}")
        return None
    return unique_candidate_refs[0]


def _validate_selected_hypothesis_for_plan(spec: Any, hypothesis: Any, resolved_spec: Path) -> None:
    errors: list[str] = []
    evidence_refs = [str(item) for item in getattr(hypothesis, "evidence", [])]
    candidate_refs = _appmap_candidate_refs(evidence_refs)
    context_refs = _appmap_context_refs(evidence_refs)
    hypothesis_id = str(getattr(hypothesis, "id", ""))
    if not candidate_refs and not context_refs:
        raise ValueError(f"brainstorm hypothesis {hypothesis_id!r} is not an AppMap-linked hypothesis")

    candidate_id = _validate_hypothesis_candidate_refs(hypothesis_id, candidate_refs, errors)
    if candidate_id is not None:
        try:
            intents = hypothesis_to_agent_intents(spec, hypothesis)
        except Exception as exc:
            errors.append(f"{hypothesis_id}: failed to enumerate brainstorm intents: {exc}")
            intents = []
        metadata = getattr(spec, "metadata", {})
        spec_run_id = str(metadata.get("AppMap run id") or "").strip()
        spec_run_root = str(metadata.get("AppMap run root") or "").strip()
        contexts_dir = resolved_spec.parent / "agent_contexts"
        for intent in intents:
            packet_path = _resolve_sibling_context_packet(
                contexts_dir,
                hypothesis_id=str(getattr(intent, "hypothesis_id", hypothesis_id)),
                candidate_id=candidate_id,
                agent_key=str(getattr(intent, "agent_key", "")),
                errors=errors,
            )
            _validate_context_ref_for_intent(
                intent,
                candidate_id=candidate_id,
                context_refs=context_refs,
                errors=errors,
            )
            if packet_path is None:
                continue
            packet = _load_context_packet(packet_path, errors)
            if packet is None:
                continue
            _validate_context_packet(
                packet,
                packet_path=packet_path,
                intent=intent,
                candidate_id=candidate_id,
                spec_run_id=spec_run_id,
                spec_run_root=spec_run_root,
                errors=errors,
            )
    if errors:
        raise ValueError(
            f"brainstorm hypothesis {hypothesis_id!r} is not a valid AppMap handoff selection: "
            + "; ".join(errors)
        )


def _resolve_sibling_context_packet(
    contexts_dir: Path,
    *,
    hypothesis_id: str,
    candidate_id: str,
    agent_key: str,
    errors: list[str],
) -> Path | None:
    safe_agent_key = sanitize_key(agent_key, fallback="agent")
    if contexts_dir.is_symlink() or _has_symlink_component(contexts_dir):
        errors.append(
            f"{hypothesis_id}/{agent_key}: sibling agent_contexts directory must not be symlinked: {contexts_dir}"
        )
        return None
    resolved_contexts_dir = contexts_dir.resolve(strict=False)
    if not resolved_contexts_dir.is_dir():
        matches: list[Path] = []
    else:
        expected = contexts_dir / f"{hypothesis_id}-{candidate_id}-{safe_agent_key}.json"
        if expected.exists() or expected.is_symlink():
            matches = [expected]
        else:
            matches = sorted(contexts_dir.glob(f"*-{candidate_id}-{safe_agent_key}.json"))
    if len(matches) != 1:
        errors.append(
            f"{hypothesis_id}/{agent_key}: expected exactly one sibling AppMap context packet "
            f"for {candidate_id} under {contexts_dir}; found {len(matches)}"
        )
        return None
    packet_path = matches[0]
    if packet_path.is_symlink():
        errors.append(f"{packet_path}: AppMap context packet must not be a symlink")
        return None
    if _has_symlink_component(packet_path):
        errors.append(f"{packet_path}: AppMap context packet path must not include symlink components")
        return None
    resolved_packet = packet_path.resolve(strict=False)
    if not _path_is_within(resolved_packet, resolved_contexts_dir):
        errors.append(f"{packet_path}: resolved AppMap context packet escapes sibling agent_contexts")
        return None
    if not resolved_packet.is_file():
        errors.append(f"{packet_path}: AppMap context packet must be a regular file")
        return None
    return packet_path


def _validate_context_ref_for_intent(
    intent: Any,
    *,
    candidate_id: str,
    context_refs: list[tuple[str, str, str]],
    errors: list[str],
) -> None:
    hypothesis_id = str(getattr(intent, "hypothesis_id", ""))
    agent_key = str(getattr(intent, "agent_key", ""))
    matches = [
        ref
        for ref in context_refs
        if ref[0] == hypothesis_id and ref[1] == candidate_id and ref[2] == agent_key
    ]
    if len(matches) != 1:
        errors.append(
            f"{hypothesis_id}/{agent_key}: expected exactly one matching appmap-context evidence ref "
            f"for {candidate_id}; found {len(matches)}"
        )


def _load_context_packet(path: Path, errors: list[str]) -> dict[str, Any] | None:
    if path.is_symlink():
        errors.append(f"{path}: AppMap context packet must not be a symlink")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{path}: invalid JSON context packet: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"{path}: context packet must be a JSON object")
        return None
    return payload


def _validate_context_packet(
    packet: dict[str, Any],
    *,
    packet_path: Path,
    intent: Any,
    candidate_id: str,
    spec_run_id: str,
    spec_run_root: str,
    errors: list[str],
) -> None:
    hypothesis_id = str(getattr(intent, "hypothesis_id", ""))
    agent_key = str(getattr(intent, "agent_key", ""))
    linkage = packet.get("hypothesis_linkage") if isinstance(packet.get("hypothesis_linkage"), dict) else {}
    packet_candidate = packet.get("candidate") if isinstance(packet.get("candidate"), dict) else {}
    packet_run_id = str(packet.get("run_id") or "").strip()
    packet_run_root = str(packet.get("appmap_run_root") or "").strip()
    packet_candidate_id = str(packet_candidate.get("id") or "").strip()

    if spec_run_id and packet_run_id != spec_run_id:
        errors.append(f"{packet_path}: run_id {packet_run_id!r} does not match spec AppMap run id {spec_run_id!r}")
    if spec_run_root and packet_run_root != spec_run_root:
        errors.append(f"{packet_path}: appmap_run_root does not match spec AppMap run root")
    if packet_candidate_id != candidate_id:
        errors.append(f"{packet_path}: candidate.id {packet_candidate_id!r} does not match {candidate_id!r}")
    if str(linkage.get("hypothesis_id") or "") != hypothesis_id:
        errors.append(f"{packet_path}: hypothesis_linkage.hypothesis_id does not match {hypothesis_id!r}")
    if str(linkage.get("candidate_id") or "") != candidate_id:
        errors.append(f"{packet_path}: hypothesis_linkage.candidate_id does not match {candidate_id!r}")
    if str(linkage.get("agent_key") or "") != agent_key:
        errors.append(f"{packet_path}: hypothesis_linkage.agent_key does not match {agent_key!r}")
    if "spec_file" not in linkage:
        errors.append(f"{packet_path}: hypothesis_linkage.spec_file is missing")


def _copy_file_safely(source: Path, destination: Path, *, overwrite: bool) -> None:
    promotion_root = destination.parent.parent if destination.parent.name == "agent_contexts" else destination.parent
    _preflight_promotion_copy(
        [(source, destination)],
        promotion_root=promotion_root,
        overwrite=overwrite,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination, follow_symlinks=False)


def _promotion_focus_slug(paths: dict[str, Path], source_specs: list[Path]) -> str:
    manifest_path = paths.get("manifest")
    if manifest_path and manifest_path.is_file() and not manifest_path.is_symlink():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            manifest = {}
        focus = str(manifest.get("focus") or "").strip() if isinstance(manifest, dict) else ""
        if focus:
            return sanitize_key(focus, fallback="focus")
    if source_specs:
        stem = source_specs[0].stem
        if stem.endswith("-spec"):
            stem = stem[:-5]
        return sanitize_key(stem, fallback="focus")
    return "focus"


def _preflight_promotion_copy(
    pairs: list[tuple[Path, Path]],
    *,
    promotion_root: Path,
    overwrite: bool,
) -> None:
    destination_names: set[Path] = set()
    _reject_symlink_components(promotion_root, label="destination")
    promotion_root_resolved = promotion_root.resolve(strict=False)
    for source, destination in pairs:
        _reject_symlink_components(source, label="source")
        if not source.is_file():
            raise FileNotFoundError(f"missing promoted AppMap source file: {source}")
        _reject_symlink_components(destination, label="destination")
        _ensure_destination_inside(destination, promotion_root_resolved)
        if destination in destination_names:
            raise ValueError(f"duplicate promoted AppMap destination: {destination}")
        destination_names.add(destination)
        try:
            destination.lstat()
        except FileNotFoundError:
            continue
        if destination.is_symlink():
            raise ValueError(f"refusing symlink destination for promoted AppMap file: {destination}")
        if not overwrite:
            raise FileExistsError(
                f"refusing to overwrite existing promoted AppMap file: {destination}; "
                "choose a unique run id/spec name or pass overwrite=True"
            )
        if not destination.is_file():
            raise FileExistsError(f"refusing to overwrite non-file promoted AppMap destination: {destination}")


def _preflight_manifest_path(manifest_path: Path, destination_root: Path) -> None:
    _reject_symlink_components(manifest_path, label="destination")
    _ensure_destination_inside(manifest_path, destination_root.resolve(strict=False))
    try:
        manifest_path.lstat()
    except FileNotFoundError:
        return
    if manifest_path.is_symlink():
        raise ValueError(f"refusing symlink destination for promoted AppMap manifest: {manifest_path}")
    if not manifest_path.is_file():
        raise FileExistsError(f"refusing non-file promoted AppMap manifest destination: {manifest_path}")


def _ensure_destination_inside(destination: Path, root: Path) -> None:
    root_resolved = root.resolve(strict=False)
    destination_resolved = destination.resolve(strict=False)
    if destination_resolved != root_resolved and not destination_resolved.is_relative_to(root_resolved):
        raise ValueError(f"promoted AppMap destination escapes promotion root: {destination}")


def _reject_symlink_components(path: Path, *, label: str) -> None:
    expanded = path.expanduser()
    current = Path(expanded.anchor) if expanded.is_absolute() else Path.cwd()
    parts = expanded.parts[1:] if expanded.is_absolute() else expanded.parts
    for part in parts:
        current = current / part
        try:
            if current.is_symlink():
                raise ValueError(f"refusing symlink {label} for promoted AppMap file: {current}")
        except OSError as exc:
            raise ValueError(f"cannot inspect promoted AppMap {label} path {current}: {exc}") from exc


def _safe_relative_filename(value: str) -> str:
    raw = str(value or "").strip()
    if not raw or raw in {".", ".."}:
        raise ValueError("promoted spec filename must not be empty")
    path = Path(raw)
    if path.is_absolute() or len(path.parts) != 1 or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("promoted spec filename must be a single safe filename")
    return path.name


def _with_appmap_run_root_metadata(text: str, run_root: Path) -> str:
    if "\n- AppMap run root:" in text:
        return text
    marker = "\n- AppMap run id:"
    index = text.find(marker)
    if index < 0:
        return text
    line_end = text.find("\n", index + 1)
    if line_end < 0:
        return text + f"\n- AppMap run root: {run_root}\n"
    return text[:line_end] + f"\n- AppMap run root: {run_root}" + text[line_end:]


def _write_research_artifacts(research: dict[str, Any], paths: dict[str, Path]) -> None:
    paths["research"].mkdir(parents=True, exist_ok=True)
    manifest = dict(research.get("manifest") or {})
    manifest["artifacts"] = {
        "sources": _relative_to(paths["research_sources"], paths["run_root"]),
        "technique_packs": _relative_to(paths["research_technique_packs"], paths["run_root"]),
    }
    paths["research_manifest"].write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_jsonl(paths["research_sources"], research.get("sources") or [])
    _write_jsonl(paths["research_technique_packs"], research.get("technique_packs") or [])


def render_run_manifest(
    result: MapResult,
    paths: dict[str, Path],
    *,
    run_id: str,
    output_mode: str,
) -> dict[str, Any]:
    run_root = paths["run_root"]
    artifacts = {
        key: _relative_to(path, run_root)
        for key, path in sorted(paths.items())
        if key
        in {
            "target_profile",
            "architecture",
            "surfaces",
            "flows",
            "candidates",
            "rejected_candidates",
            "summary",
            "spec",
            "agent_contexts",
            "research_manifest",
            "research_sources",
            "research_technique_packs",
        }
    }
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "run_id": run_id,
        "program": result.profile.program,
        "program_slug": sanitize_key(result.profile.program),
        "focus": result.focus,
        "output_mode": output_mode,
        "run_root": str(run_root),
        "target_path": result.profile.target_path,
        "target_kind": result.profile.target_kind,
        "detected_kinds": result.profile.detected_kinds,
        "counts": {
            "surfaces": len(result.surfaces),
            "flows": len(result.flows),
            "candidates": len(result.candidates),
            "rejected_candidates": len(result.rejected_candidates),
            "agent_contexts": len(list(paths["agent_contexts"].glob("*.json"))) if "agent_contexts" in paths else 0,
            "research_sources": len(result.research.get("sources", [])) if result.research else 0,
            "research_technique_packs": len(result.research.get("technique_packs", [])) if result.research else 0,
        },
        "artifacts": artifacts,
    }


def _append_run_index(index_path: Path, manifest: dict[str, Any]) -> None:
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_record = {
        key: manifest[key]
        for key in (
            "schema_version",
            "created_at",
            "run_id",
            "program",
            "program_slug",
            "focus",
            "output_mode",
            "run_root",
            "target_path",
            "target_kind",
            "counts",
        )
    }
    with index_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(index_record, sort_keys=True) + "\n")


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


def render_rce_spec(result: MapResult, *, run_id: str, max_hypotheses: int = MAX_GENERATED_HYPOTHESES) -> str:
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
        research_summaries = _candidate_research_summaries(result, candidate)
        research_notes = _research_notes(research_summaries)
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
        if research_notes:
            notes = f"{notes} Research: {research_notes}."
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
                    f"  - appmap-context:{hypothesis_id}:{candidate['id']}:{agent_key}",
                    *_research_evidence_lines(research_summaries),
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


def write_agent_contexts(
    result: MapResult,
    *,
    run_root: Path,
    run_id: str,
    spec_path: Path,
    parsed_spec: Any,
) -> list[Path]:
    """Write candidate-isolated handoff packets for generated hypotheses."""

    links = _strict_hypothesis_agent_links(parsed_spec, result.candidates)
    if not links:
        return []

    contexts_dir = run_root / "agent_contexts"
    contexts_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    candidates_by_id = {str(candidate["id"]): candidate for candidate in result.candidates}

    for linkage in links:
        candidate_id = str(linkage["candidate_id"])
        candidate = candidates_by_id[candidate_id]
        agent_key = sanitize_key(str(linkage.get("agent_key") or "agent"), fallback="agent")
        hypothesis_id = sanitize_key(str(linkage.get("hypothesis_id") or "hypothesis"), fallback="hypothesis")
        context_path = contexts_dir / f"{hypothesis_id.upper()}-{candidate_id}-{agent_key}.json"
        context = render_agent_context(
            result,
            candidate,
            run_id=run_id,
            spec_path=spec_path,
            run_root=run_root,
            hypothesis_linkage=linkage,
        )
        context_path.write_text(json.dumps(context, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(context_path)

    return written


def render_agent_context(
    result: MapResult,
    candidate: dict[str, Any],
    *,
    run_id: str,
    spec_path: Path,
    run_root: Path,
    hypothesis_linkage: dict[str, Any],
) -> dict[str, Any]:
    source = candidate["source"]
    boundary = candidate["boundary"]
    transform = candidate.get("transform")
    sink = candidate["sink"]
    active_target_pack_keys = _candidate_target_pack_keys(candidate)
    map_ids = {
        "candidate_id": candidate["id"],
        "flow_id": candidate["flow_id"],
        "source_id": source["id"],
        "boundary_id": boundary["id"],
        "transform_id": transform["id"] if transform else None,
        "sink_id": sink["id"],
        "surface_id": candidate["surface_id"],
    }
    return {
        "schema_version": 1,
        "run_id": run_id,
        "appmap_run_root": str(run_root),
        "program": result.profile.program,
        "focus": result.focus,
        "candidate": {
            "id": candidate["id"],
            "priority": candidate["priority"],
            "score": candidate["score"],
            "question": candidate["question"],
            "map_ids": map_ids,
        },
        "target_profile": _minimal_target_profile(result.profile, active_target_pack_keys),
        "active_target_packs": active_target_pack_keys,
        "active_vulnerability_pack": result.focus,
        "hypothesis_linkage": {
            **hypothesis_linkage,
            "spec_file": _relative_to(spec_path, run_root),
        },
        "focus_files": _focus_files_for_candidate(candidate),
        "evidence": {
            "source": _evidence_item(source),
            "boundary": _evidence_item(boundary),
            "transform": _evidence_item(transform) if transform else None,
            "sink": _evidence_item(sink),
        },
        "research": _candidate_research_packet(result, candidate),
        "next_steps": [
            "Use only this packet's map IDs, evidence snippets, and focus files for the hypothesis.",
            "Trace source-to-boundary-to-sink control and data flow in the listed files.",
            "Record findings or no-findings against the linked hypothesis ID, agent key, candidate ID, and flow ID.",
        ],
    }


def _strict_hypothesis_agent_links(
    parsed_spec: Any,
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidate_ids = {str(candidate["id"]) for candidate in candidates}
    linked_candidates: dict[str, str] = {}
    links: list[dict[str, Any]] = []
    for hypothesis in getattr(parsed_spec, "hypotheses", []):
        evidence_refs = list(getattr(hypothesis, "evidence", []))
        candidate_refs = [
            match.group(1)
            for evidence in evidence_refs
            for match in re.finditer(r"\bappmap-(C\d{4})\b", evidence)
        ]
        unique_candidate_refs = sorted(set(candidate_refs))
        if not candidate_refs:
            raise ValueError(f"AppMap hypothesis {hypothesis.id} is missing appmap-C#### candidate evidence")
        if len(candidate_refs) != len(unique_candidate_refs):
            raise ValueError(f"AppMap hypothesis {hypothesis.id} contains duplicate candidate evidence")
        if len(unique_candidate_refs) != 1:
            raise ValueError(
                f"AppMap hypothesis {hypothesis.id} aggregates multiple candidate IDs: "
                f"{', '.join(unique_candidate_refs)}"
            )
        candidate_id = unique_candidate_refs[0]
        if candidate_id not in candidate_ids:
            raise ValueError(f"AppMap hypothesis {hypothesis.id} references unknown candidate {candidate_id}")
        previous_hypothesis = linked_candidates.get(candidate_id)
        if previous_hypothesis is not None:
            raise ValueError(
                f"AppMap candidate {candidate_id} is linked by multiple hypotheses: "
                f"{previous_hypothesis} and {hypothesis.id}"
            )
        linked_candidates[candidate_id] = hypothesis.id
        for agent_key in getattr(hypothesis, "suggested_agents", []):
            links.append(
                {
                    "hypothesis_id": hypothesis.id,
                    "hypothesis_title": hypothesis.title,
                    "candidate_id": candidate_id,
                    "agent_key": agent_key,
                    "evidence_refs": evidence_refs,
                    "surface": hypothesis.surface,
                    "expected_chain": hypothesis.expected_chain,
                }
            )
    return links


def _candidate_target_pack_keys(candidate: dict[str, Any]) -> list[str]:
    keys: set[str] = set()
    for surface_key in ("source", "boundary", "transform", "sink"):
        surface = candidate.get(surface_key)
        if not isinstance(surface, dict):
            continue
        keys.update(str(key) for key in surface.get("target_pack_keys") or [] if str(key).strip())
    if not keys:
        for surface_key in ("source", "boundary"):
            surface = candidate.get(surface_key)
            if isinstance(surface, dict) and str(surface.get("kind", "")) in TARGET_PACKS:
                keys.add(str(surface["kind"]))
    return sorted(keys, key=lambda key: (key == "config", key))


def _minimal_target_profile(profile: TargetProfile, active_target_pack_keys: list[str]) -> dict[str, Any]:
    return {
        "program": profile.program,
        "target_kind": _candidate_target_kind(profile, active_target_pack_keys),
        "languages": profile.languages,
        "manifests": profile.manifests,
        "confidence": profile.confidence,
    }


def _candidate_target_kind(profile: TargetProfile, active_target_pack_keys: list[str]) -> str:
    for key in active_target_pack_keys:
        pack = TARGET_PACKS.get(key)
        if pack and (profile.target_kind == pack.key or profile.target_kind in pack.aliases):
            return profile.target_kind
    for key in active_target_pack_keys:
        if key != "config":
            return key
    return active_target_pack_keys[0] if active_target_pack_keys else profile.target_kind


def _evidence_item(surface: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": surface["id"],
        "role": surface["role"],
        "kind": surface["kind"],
        "name": surface["name"],
        "description": surface["description"],
        "file": surface["file"],
        "line": surface["line"],
        "snippet": surface["snippet"],
        "trust_level": surface["trust_level"],
        "attacker_control": surface["attacker_control"],
        "confidence": surface["confidence"],
        "target_pack_keys": list(surface.get("target_pack_keys") or []),
    }


def _relative_to(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return str(path)


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


def _candidate_research_packet(result: MapResult, candidate: dict[str, Any]) -> dict[str, Any]:
    summaries = _candidate_research_summaries(result, candidate)
    source_ids = sorted({source_id for summary in summaries for source_id in summary.get("source_ids", [])})
    sources_by_id = {
        str(source.get("id")): source
        for source in (result.research or {}).get("sources", [])
        if isinstance(source, dict)
    }
    return {
        "technique_summaries": summaries,
        "sources": [
            {
                "id": source["id"],
                "title": source.get("title", ""),
                "url": source.get("url", ""),
                "citation": source.get("citation", f"[{source['id']}]"),
            }
            for source_id in source_ids
            for source in [sources_by_id.get(source_id)]
            if source is not None
        ],
    }


def _candidate_research_summaries(result: MapResult, candidate: dict[str, Any]) -> list[dict[str, Any]]:
    research = result.research or {}
    technique_packs = [item for item in research.get("technique_packs") or [] if isinstance(item, dict)]
    if not technique_packs:
        return []
    candidate_target_packs = set(_candidate_target_pack_keys(candidate))
    candidate_surface_kinds = {
        str(surface.get("kind"))
        for key in ("source", "boundary", "transform", "sink")
        for surface in [candidate.get(key)]
        if isinstance(surface, dict) and str(surface.get("kind"))
    }
    summaries: list[dict[str, Any]] = []
    for technique in technique_packs:
        vuln_pack = str(technique.get("vulnerability_pack") or result.focus).strip()
        if vuln_pack and vuln_pack != result.focus:
            continue
        applies_to_all = _bool_value(technique.get("applies_to_all"))
        target_keys = {str(item) for item in technique.get("target_pack_keys") or [] if str(item).strip()}
        if not applies_to_all:
            if not target_keys or not (target_keys & candidate_target_packs):
                continue
        surface_kinds = {str(item) for item in technique.get("applicable_surface_kinds") or [] if str(item).strip()}
        if not applies_to_all:
            if not surface_kinds or not (surface_kinds & candidate_surface_kinds):
                continue
        summaries.append(
            {
                "id": str(technique.get("id") or ""),
                "title": str(technique.get("title") or ""),
                "summary": str(technique.get("summary") or ""),
                "guidance": list(technique.get("guidance") or [])[:4],
                "source_ids": list(technique.get("source_ids") or []),
                "citations": list(technique.get("citations") or []),
            }
        )
    return sorted(summaries, key=lambda item: item["id"])[:MAX_RESEARCH_SUMMARIES_PER_CANDIDATE]


def _research_evidence_lines(summaries: list[dict[str, Any]]) -> list[str]:
    return [
        f"  - research-technique:{summary['id']}"
        for summary in summaries
        if summary.get("id")
    ]


def _research_notes(summaries: list[dict[str, Any]]) -> str:
    notes: list[str] = []
    for summary in summaries:
        title = str(summary.get("title") or summary.get("id") or "").strip()
        citations = " ".join(str(item) for item in summary.get("citations") or [])
        if title and citations:
            notes.append(f"{title} {citations}")
        elif title:
            notes.append(title)
    return "; ".join(notes)


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
        f"- Manifest: `{paths['manifest']}`",
        f"- Index: `{paths['index']}`",
    ]
    if result.research is not None:
        lines.extend(
            [
                f"- Research manifest: `{paths['research_manifest']}`",
                f"- Research sources: {len(result.research.get('sources', []))}",
                f"- Research technique packs: {len(result.research.get('technique_packs', []))}",
            ]
        )
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
        if "agent_contexts" in paths:
            context_count = len(list(paths["agent_contexts"].glob("*.json")))
            lines.insert(9, f"- Agent contexts: `{paths['agent_contexts']}` ({context_count})")
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
    parser.add_argument("program", nargs="?", help="Program name used in generated artifacts.")
    parser.add_argument("target_path", nargs="?", help="Local source tree, Electron app source, or extracted code path.")
    parser.add_argument("--target-kind", default="auto", type=_target_kind_arg, help="Target kind hint; defaults to auto.")
    parser.add_argument("--focus", default="rce", choices=sorted(VULNERABILITY_PACKS), help="Vulnerability focus for Phase 2.")
    parser.add_argument("--write-specs", action="store_true", help="Write and validate generated brainstorm specs.")
    parser.add_argument("--output-root", help="Output root. Defaults to ~/Shared/appmap/<program>/static.")
    parser.add_argument(
        "--output-mode",
        choices=("standalone", "canonical"),
        default="standalone",
        help="standalone keeps the legacy output-root layout; canonical writes under ~/Shared/<family>/<program>/<lane>/appmap/<run_id>/.",
    )
    parser.add_argument("--family", help="Canonical Shared family, for example binaries or web.")
    parser.add_argument("--lane", help="Canonical Shared lane, for example exe or source.")
    parser.add_argument("--shared-root", help="Shared root for canonical output. Defaults to ~/Shared.")
    parser.add_argument("--run-id", help="Deterministic run id override for tests or repeatable workflows.")
    parser.add_argument(
        "--research-online",
        action="store_true",
        help=(
            "Allow a network-capable research provider to perform its documented fetches. "
            "The default local-seed provider remains offline even when this flag is set."
        ),
    )
    parser.add_argument(
        "--research-provider",
        choices=sorted(RESEARCH_PROVIDERS),
        default=LocalSeedResearchProvider.key,
        help="Research provider to use. Default local-seed never performs network I/O.",
    )
    parser.add_argument(
        "--research-seed",
        action="append",
        default=[],
        help="Local JSON/JSONL/text research seed to normalize into cited research artifacts. Repeatable.",
    )
    parser.add_argument(
        "--research-source-url",
        action="append",
        default=[],
        help=(
            "Explicit HTTPS source URL for --research-provider web-fetch. Repeatable; no search, crawl, "
            "or target probing is performed."
        ),
    )
    parser.add_argument(
        "--promote-to-brainstorm",
        action="store_true",
        help="Copy generated specs and AppMap context packets into the lane brainstorm area.",
    )
    parser.add_argument(
        "--brainstorm-root",
        help="Destination brainstorm directory for promotion. Defaults to <canonical-lane-root>/brainstorm in canonical mode.",
    )
    parser.add_argument(
        "--promote-spec-name",
        help="Promoted spec filename inside brainstorm/appmap-<run-id>-<focus>/. Defaults to the generated spec filename.",
    )
    parser.add_argument(
        "--promotion-layout",
        choices=("flat", "category"),
        default="flat",
        help=(
            "Promotion directory layout. flat writes brainstorm/appmap-<run-id>-<focus>/; "
            "category writes brainstorm/appmap-<run-id>/<focus>/. Defaults to flat for compatibility."
        ),
    )
    parser.add_argument(
        "--overwrite-brainstorm-spec",
        action="store_true",
        help="Allow promotion to overwrite an existing brainstorm spec/context file.",
    )
    parser.add_argument(
        "--list-handoffs",
        action="store_true",
        help="List promoted AppMap handoffs from --brainstorm-root or a canonical lane.",
    )
    parser.add_argument(
        "--campaign-status",
        action="store_true",
        help="Show promoted AppMap campaign status and brainstorm coverage from --brainstorm-root or a canonical lane.",
    )
    parser.add_argument(
        "--validate-handoff",
        help="Validate a promoted AppMap brainstorm spec and its sibling agent_contexts packets without writing runtime data.",
    )
    parser.add_argument(
        "--plan-handoff",
        help="Print the explicit zero_day_team --brainstorm-spec command for a promoted AppMap spec.",
    )
    parser.add_argument(
        "--brainstorm-hypothesis",
        help="Add one selected --brainstorm-hypothesis value to --plan-handoff output.",
    )
    return parser


def _resolve_handoff_brainstorm_root(args: argparse.Namespace) -> Path:
    if args.brainstorm_root:
        return Path(args.brainstorm_root)
    if args.output_mode == "canonical":
        if not args.program:
            raise SystemExit("handoff discovery with canonical lane discovery requires program")
        try:
            lane_root = resolve_output_root(
                args.program,
                output_mode=args.output_mode,
                family=args.family,
                lane=args.lane,
                shared_root=Path(args.shared_root) if args.shared_root else None,
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        return lane_root / "brainstorm"
    raise SystemExit("handoff discovery requires --brainstorm-root or --output-mode canonical with program, --family, and --lane")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    mode_count = sum(
        bool(value)
        for value in (args.list_handoffs, args.campaign_status, args.validate_handoff, args.plan_handoff)
    )
    if mode_count > 1:
        raise SystemExit("choose only one of --list-handoffs, --campaign-status, --validate-handoff, or --plan-handoff")
    if args.list_handoffs:
        brainstorm_root = _resolve_handoff_brainstorm_root(args)
        handoffs = list_promoted_handoffs(brainstorm_root)
        print(f"[appmap] brainstorm root: {brainstorm_root.expanduser().resolve(strict=False)}")
        print(f"[appmap] promoted handoffs: {len(handoffs)}")
        for handoff in handoffs:
            print(
                "[appmap] "
                f"run_id={handoff.run_id or '-'} focus={handoff.focus} "
                f"contexts={handoff.context_count} source={handoff.source} spec={handoff.spec_path}"
            )
        return 0
    if args.campaign_status:
        brainstorm_root = _resolve_handoff_brainstorm_root(args)
        status = campaign_status(brainstorm_root)
        print(f"[appmap] campaign status: {status['brainstorm_root']}")
        print(f"[appmap] coverage: {status['coverage']}")
        print(f"[appmap] promoted handoffs: {status['handoff_count']}")
        if status["status_counts"]:
            counts = ", ".join(
                f"{name}={count}" for name, count in sorted(status["status_counts"].items())
            )
            print(f"[appmap] statuses: {counts}")
        for item in status["specs"]:
            coverage = item["coverage_events"]
            print(
                "[appmap] "
                f"status={item['status']} run_id={item['run_id'] or '-'} focus={item['focus']} "
                f"hypotheses={item['counts']['appmap_hypotheses']} "
                f"intents={item['counts']['appmap_intents']} "
                f"queued={coverage.get('agent_queued', 0)} "
                f"covered={item['assignments'].get('covered', 0)} "
                f"review={item['assignments'].get('review', 0)} "
                f"running={item['assignments'].get('running', 0)} "
                f"pending={item['assignments'].get('pending', 0)} "
                f"attention={item['assignments'].get('attention', 0)} "
                f"spec={item['spec']}"
            )
            for error in item["validation_errors"]:
                print(f"[appmap] error: {error}", file=sys.stderr)
        return 0
    if args.validate_handoff:
        result = validate_promoted_handoff(Path(args.validate_handoff))
        print(f"[appmap] handoff validation: {'ok' if result.ok else 'failed'}")
        print(f"[appmap] spec: {result.spec_path}")
        print(
            "[appmap] "
            f"hypotheses={result.counts['hypotheses']} "
            f"appmap_hypotheses={result.counts['appmap_hypotheses']} "
            f"appmap_intents={result.counts['appmap_intents']} "
            f"packets={result.counts['packets']} "
            f"errors={len(result.errors)}"
        )
        for error in result.errors:
            print(f"[appmap] error: {error}", file=sys.stderr)
        return 0 if result.ok else 1
    if args.plan_handoff:
        try:
            print(plan_promoted_handoff_command(Path(args.plan_handoff), selected_hypothesis=args.brainstorm_hypothesis))
        except ValueError as exc:
            print(f"[appmap] error: {exc}", file=sys.stderr)
            return 1
        return 0
    if not args.program or not args.target_path:
        raise SystemExit("program and target_path are required unless using --list-handoffs, --validate-handoff, or --plan-handoff")
    try:
        research_provider = _build_research_provider(args.research_provider)
        _validate_research_options(
            research_online=args.research_online,
            provider=research_provider,
            source_urls=args.research_source_url,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    target_path = Path(args.target_path).expanduser().resolve(strict=False)
    if not target_path.exists() or not target_path.is_dir():
        raise SystemExit(f"target_path must be an existing directory: {target_path}")

    run_id = args.run_id or f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{int(time.time())}"
    try:
        output_root = resolve_output_root(
            args.program,
            output_mode=args.output_mode,
            output_root=Path(args.output_root) if args.output_root else None,
            family=args.family,
            lane=args.lane,
            shared_root=Path(args.shared_root) if args.shared_root else None,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    result = map_application(args.program, target_path, target_kind=args.target_kind, focus=args.focus)
    try:
        result.research = generate_research_artifacts(
            result,
            research_online=args.research_online,
            seed_paths=[Path(path) for path in args.research_seed],
            source_urls=args.research_source_url,
            provider=research_provider,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    paths = write_artifacts(
        result,
        output_root=output_root,
        run_id=run_id,
        write_specs=args.write_specs,
        output_mode=args.output_mode,
    )
    promotion: PromotionResult | None = None
    if args.promote_to_brainstorm:
        if not args.write_specs:
            raise SystemExit("--promote-to-brainstorm requires --write-specs")
        if args.brainstorm_root:
            brainstorm_root = Path(args.brainstorm_root)
        elif args.output_mode == "canonical":
            brainstorm_root = output_root / "brainstorm"
        else:
            raise SystemExit("--promote-to-brainstorm in standalone mode requires --brainstorm-root")
        try:
            promotion = promote_appmap_handoff(
                paths,
                brainstorm_root=brainstorm_root,
                run_id=run_id,
                spec_name=args.promote_spec_name,
                overwrite=args.overwrite_brainstorm_spec,
                promotion_layout=args.promotion_layout,
            )
        except (ValueError, OSError) as exc:
            raise SystemExit(str(exc)) from exc
    print(f"[appmap] output: {paths['run_root']}")
    print(f"[appmap] surfaces={len(result.surfaces)} flows={len(result.flows)} candidates={len(result.candidates)}")
    if "spec" in paths:
        print(f"[appmap] generated spec: {paths['spec']}")
    if promotion is not None:
        print(f"[appmap] promoted spec(s): {', '.join(str(path) for path in promotion.spec_paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
