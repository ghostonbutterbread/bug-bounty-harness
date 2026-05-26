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
from collections import Counter
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
from agents.appmap_research import (
    RESEARCH_MODES,
    RESEARCH_PROVIDERS,
    HybridResearchProvider,
    LocalSeedResearchProvider,
    ResearchProvider,
    ResearchQuery,
    ResearchRequest,
    WebFetchResearchProvider,
    bool_value as _bool_value,
    build_research_provider as _build_research_provider,
    generate_research_artifacts,
    normalize_research_mode,
    normalize_research_query,
    provider_key_for_mode,
    validate_research_options as _validate_research_options,
)
from agents.hunting_policy import (
    HuntingPolicy,
    apply_appmap_promotion_policy,
    inject_policy_metadata_into_markdown,
    merge_policy_artifact_metadata,
    policy_config_path_for_artifacts,
    resolve_hunting_policy,
    resolve_policy_selection,
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
    noise_surfaces: list[dict[str, Any]] = field(default_factory=list)
    flows: list[dict[str, Any]] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    rejected_candidates: list[dict[str, Any]] = field(default_factory=list)
    research: dict[str, Any] | None = None
    baseline_context: dict[str, Any] | None = None
    enrichment_records: list[dict[str, Any]] = field(default_factory=list)
    enrichment_summary: dict[str, Any] | None = None


@dataclass
class BaselineContext:
    run_root: Path
    manifest: dict[str, Any]
    records: list[dict[str, Any]]
    relationships: list[dict[str, Any]]
    quality_report: dict[str, Any]
    coverage_gaps: list[dict[str, Any]]
    category_plan: dict[str, Any]


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


TARGET_PACKS: dict[str, TargetPack] = {}
VULNERABILITY_PACKS: dict[str, VulnerabilityPack] = {}
AGENT_GRANULARITIES = {"default", "narrow", "category-master", "per-hypothesis"}
STATIC_CATEGORY_AGENT_KEYS = {
    "dom-xss",
    "exec-sink-reachability",
    "ssrf",
    "path-traversal",
    "prototype-pollution",
    "unsafe-deserialization",
    "native-module-abuse",
    "memory-unsafe-parser",
    "ipc-trust-boundary",
    "node-integration",
}
BASELINE_FOCUS = "baseline"
ENRICHMENT_RECORD_LIMIT = 500
ENRICHMENT_PER_TYPE_LIMIT = 120
ENRICHMENT_PER_FILE_LIMIT = 80
AGENT_PACKET_BASELINE_REF_LIMIT = 20
AGENT_PACKET_QUALITY_REF_LIMIT = 8
AGENT_PACKET_GAP_REF_LIMIT = 8
AGENT_PACKET_FOCUS_FILE_LIMIT = 5
AGENT_PACKET_SNIPPET_LIMIT = 240


def _compile(pattern: str, *, ignore_case: bool = True) -> re.Pattern[str]:
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile(pattern, flags)


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
        _compile(
            r"\b(?:child_process|childProcess)\.(?:exec|execFile|spawn|fork)\s*\("
            r"|\brequire\(\s*['\"](?:node:)?child_process['\"]\s*\)\.(?:exec|execFile|spawn|fork)\s*\("
            r"|\bshelljs\.exec\s*\("
            r"|\bexeca(?:Command|Sync)?\s*\("
            r"|\bexeca\.(?:command|commandSync|node|sync)\s*\(",
            ignore_case=False,
        ),
        "sink",
        "process-exec",
        "Node process execution sink",
        "privileged-local",
        "unknown",
        0.92,
    ),
    PatternSpec(
        "node-dynamic-code",
        _compile(
            r"(?<![\w$.])eval\s*\("
            r"|\bnew\s+Function\s*\("
            r"|(?<![\w$.])Function\s*\("
            r"|\bvm\.(?:runIn\w*|Script)\s*\("
            r"|\b(?:setTimeout|setInterval)\s*\(\s*['\"`]",
            ignore_case=False,
        ),
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

RENDERER_CONTENT_TRUST_SINK_PATTERNS = [
    PatternSpec(
        "electron-webcontents-execute-javascript",
        _compile(r"\bwebContents\.executeJavaScript\s*\(", ignore_case=False),
        "sink",
        "renderer-code-execution",
        "Electron webContents executes JavaScript in a renderer context",
        "renderer",
        "unknown",
        0.86,
    ),
    PatternSpec(
        "electron-load-url-or-file",
        _compile(r"\b(?:webContents\.)?(?:loadURL|loadFile)\s*\(", ignore_case=False),
        "sink",
        "renderer-navigation",
        "Electron renderer navigation or file loading sink",
        "renderer",
        "unknown",
        0.76,
    ),
    PatternSpec(
        "dom-html-injection",
        _compile(r"\b(?:document|[\w$]+)\.(?:innerHTML|outerHTML|insertAdjacentHTML)\b|\bdangerouslySetInnerHTML\b", ignore_case=False),
        "sink",
        "html-injection",
        "renderer HTML injection sink",
        "renderer",
        "unknown",
        0.74,
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


def _generated_or_noise_surface_file(path: Path) -> bool:
    name = path.name.lower()
    return (
        name.endswith(".strings.js")
        or name.endswith(".mapping.json")
        or name == "stats.json"
        or path.suffix.lower() == ".map"
    )


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


JS_IDENTIFIER_PATTERN = r"[A-Za-z_$][A-Za-z0-9_$]*"
CHILD_PROCESS_METHODS = ("exec", "execFile", "spawn", "fork")


def _split_child_process_call_imports(value: str) -> Iterable[str]:
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            imported, local = (part.strip() for part in item.rsplit(":", 1))
        elif " as " in item:
            imported, local = (part.strip() for part in item.rsplit(" as ", 1))
        else:
            imported = local = item
        if imported in CHILD_PROCESS_METHODS and re.fullmatch(JS_IDENTIFIER_PATTERN, local):
            yield local


def _js_module_aliases(text: str, module_pattern: str) -> set[str]:
    aliases: set[str] = set()
    patterns = (
        rf"\b(?:const|let|var)\s+({JS_IDENTIFIER_PATTERN})\s*=\s*require\(\s*{module_pattern}\s*\)",
        rf"\bimport\s+\*\s+as\s+({JS_IDENTIFIER_PATTERN})\s+from\s+{module_pattern}",
        rf"\bimport\s+({JS_IDENTIFIER_PATTERN})\s+from\s+{module_pattern}",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            aliases.add(match.group(1))
    return aliases


def _js_process_exec_import_patterns(path: Path) -> tuple[PatternSpec, ...]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ()

    direct_child_process_calls: set[str] = set()
    quoted_child_process = r"['\"](?:node:)?child_process['\"]"
    for match in re.finditer(rf"\b(?:const|let|var)\s*\{{([^}}]+)\}}\s*=\s*require\(\s*{quoted_child_process}\s*\)", text):
        direct_child_process_calls.update(_split_child_process_call_imports(match.group(1)))
    for match in re.finditer(rf"\bimport\s*\{{([^}}]+)\}}\s*from\s+{quoted_child_process}", text):
        direct_child_process_calls.update(_split_child_process_call_imports(match.group(1)))

    parts: list[str] = []
    child_process_aliases = _js_module_aliases(text, quoted_child_process)
    member_aliases = sorted(child_process_aliases - {"child_process", "childProcess"})
    direct_calls = sorted(direct_child_process_calls)
    if member_aliases:
        aliases = "|".join(re.escape(alias) for alias in member_aliases)
        parts.append(rf"\b(?:{aliases})\.(?:exec|execFile|spawn|fork)\s*\(")
    if direct_calls:
        calls = "|".join(re.escape(call) for call in direct_calls)
        parts.append(rf"(?<![\w$.])(?:{calls})\s*\(")
    shelljs_aliases = _js_module_aliases(text, r"['\"]shelljs['\"]")
    shell_aliases = sorted(shelljs_aliases - {"shelljs"})
    if shell_aliases:
        aliases = "|".join(re.escape(alias) for alias in shell_aliases)
        parts.append(rf"\b(?:{aliases})\.exec\s*\(")
    execa_aliases = _js_module_aliases(text, r"['\"]execa['\"]")
    execa_aliases = sorted(execa_aliases - {"execa"})
    if execa_aliases:
        aliases = "|".join(re.escape(alias) for alias in execa_aliases)
        parts.append(rf"(?<![\w$.])(?:{aliases})\s*\(|\b(?:{aliases})\.(?:command|commandSync|node|sync)\s*\(")
    if not parts:
        return ()

    return (
        PatternSpec(
            "node-process-exec-import",
            _compile("|".join(parts), ignore_case=False),
            "sink",
            "process-exec",
            "Node process execution sink imported from child_process, shelljs, or execa",
            "privileged-local",
            "unknown",
            0.9,
        ),
    )


def _rce_sink_patterns(path: Path) -> tuple[PatternSpec, ...]:
    if _js_like(path):
        return (*JS_SINK_PATTERNS, *_js_process_exec_import_patterns(path))
    if path.suffix.lower() == ".py":
        return tuple(PY_SINK_PATTERNS)
    return ()


def _rce_transform_patterns(path: Path) -> tuple[PatternSpec, ...]:
    if _js_like(path) or path.suffix.lower() == ".py":
        return tuple(TRANSFORM_PATTERNS)
    return ()


def _renderer_content_trust_sink_patterns(path: Path) -> tuple[PatternSpec, ...]:
    if _js_like(path):
        return tuple(RENDERER_CONTENT_TRUST_SINK_PATTERNS)
    return ()


def _renderer_content_trust_transform_patterns(path: Path) -> tuple[PatternSpec, ...]:
    if _js_like(path):
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
    register_vulnerability_pack(
        VulnerabilityPack(
            key="renderer-content-trust",
            sink_patterns_for_file=_renderer_content_trust_sink_patterns,
            transform_patterns_for_file=_renderer_content_trust_transform_patterns,
            build_flows=lambda surfaces: build_focus_flows(
                surfaces,
                focus="renderer-content-trust",
                question_template=(
                    "Can lower-trust renderer or remote content influence "
                    "the {sink_kind} sink across the {boundary_kind} boundary?"
                ),
            ),
            render_spec=lambda result, run_id: render_focus_spec(result, run_id=run_id),
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
    surfaces, _noise_surfaces = scan_surface_sets(target_path, focus=focus, target_profile=target_profile)
    return surfaces


def scan_surface_sets(
    target_path: Path,
    *,
    focus: str = "rce",
    target_profile: TargetProfile | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    surfaces: list[dict[str, Any]] = []
    noise_surfaces: list[dict[str, Any]] = []
    counters: dict[str, int] = {}
    noise_counters: dict[str, int] = {}
    vuln_pack = None if focus == BASELINE_FOCUS else VULNERABILITY_PACKS[focus]
    target_packs = _active_target_packs(target_profile)

    def emit_surface(
        spec: PatternSpec,
        target_pack_keys: tuple[str, ...],
        *,
        rel: str,
        line_no: int,
        snippet: str,
        destination: list[dict[str, Any]] = surfaces,
        filtered_reason: str | None = None,
    ) -> None:
        active_counters = noise_counters if filtered_reason else counters
        active_counters[spec.role] = active_counters.get(spec.role, 0) + 1
        prefix = "N" if filtered_reason else spec.role[:1].upper()
        surface_id = f"{prefix}{active_counters[spec.role]:04d}"
        surface = {
            "id": surface_id,
            "role": spec.role,
            "kind": spec.family,
            "name": spec.name,
            "description": spec.description,
            "file": rel,
            "line": line_no,
            "snippet": snippet[:240],
            "trust_level": spec.trust_level,
            "attacker_control": spec.attacker_control,
            "confidence": spec.confidence,
            "target_pack_keys": list(target_pack_keys),
        }
        if filtered_reason:
            surface["filtered_reason"] = filtered_reason
        destination.append(surface)

    def patterns_for_path(path: Path) -> list[tuple[PatternSpec, tuple[str, ...]]]:
        collected: list[tuple[PatternSpec, tuple[str, ...]]] = []
        for pack in target_packs:
            for spec in pack.source_patterns_for_file(path):
                collected.append((spec, _surface_target_pack_keys(spec, pack.key)))
            for spec in pack.boundary_patterns_for_file(path):
                collected.append((spec, _surface_target_pack_keys(spec, pack.key)))
        if vuln_pack is not None:
            collected.extend((spec, ()) for spec in vuln_pack.transform_patterns_for_file(path))
            collected.extend((spec, ()) for spec in vuln_pack.sink_patterns_for_file(path))
        return collected

    for path in iter_source_files(target_path):
        patterns = patterns_for_path(path)
        if not patterns:
            continue

        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        rel = path.relative_to(target_path).as_posix()
        if _generated_or_noise_surface_file(path):
            for line_no, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                for spec, target_pack_keys in patterns:
                    if not spec.regex.search(stripped):
                        continue
                    emit_surface(
                        spec,
                        target_pack_keys,
                        rel=rel,
                        line_no=line_no,
                        snippet=stripped,
                        destination=noise_surfaces,
                        filtered_reason="generated_or_noise_file",
                    )
            continue

        if _config_like(path):
            remaining_patterns: list[tuple[PatternSpec, tuple[str, ...]]] = []
            emitted_config_surface = False
            for spec, target_pack_keys in patterns:
                if spec.name != CONFIG_FILE_SOURCE_PATTERN.name:
                    remaining_patterns.append((spec, target_pack_keys))
                    continue
                for line_no, line in enumerate(lines, start=1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if not emitted_config_surface:
                        emit_surface(spec, target_pack_keys, rel=rel, line_no=line_no, snippet=stripped)
                        emitted_config_surface = True
                    else:
                        emit_surface(
                            spec,
                            target_pack_keys,
                            rel=rel,
                            line_no=line_no,
                            snippet=stripped,
                            destination=noise_surfaces,
                            filtered_reason="config_file_line_cap",
                        )
            patterns = remaining_patterns
            if not patterns:
                continue

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            for spec, target_pack_keys in patterns:
                if not spec.regex.search(stripped):
                    continue
                emit_surface(spec, target_pack_keys, rel=rel, line_no=line_no, snippet=stripped)
    return surfaces, noise_surfaces


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


def build_focus_flows(
    surfaces: list[dict[str, Any]],
    *,
    focus: str,
    question_template: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
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
                    "reason": f"sink evidence lacks same-file source and trust boundary for {focus}",
                }
            )
            rejected_index += 1
        if sources and not sinks:
            rejected.append(
                {
                    "id": f"R{rejected_index:04d}",
                    "file": file_name,
                    "source_ids": [source["id"] for source in sources],
                    "reason": f"source or boundary evidence lacks same-file {focus} sink",
                }
            )
            rejected_index += 1
        if not sources or not boundaries or not sinks:
            continue

        chain = _best_ordered_chain(sources, boundaries, transforms, sinks)
        if chain is None:
            rejected.append(
                {
                    "id": f"R{rejected_index:04d}",
                    "file": file_name,
                    "source_ids": [source["id"] for source in sources],
                    "boundary_ids": [boundary["id"] for boundary in boundaries],
                    "sink_ids": [sink["id"] for sink in sinks],
                    "reason": f"same-file evidence lacks ordered proximate or linked {focus} chain",
                }
            )
            rejected_index += 1
            continue

        source, boundary, transform, sink, score = chain
        flow_id = f"F{flow_index:04d}"
        candidate_id = f"C{candidate_index:04d}"
        flow_index += 1
        candidate_index += 1
        flow = {
            "id": flow_id,
            "source_id": source["id"],
            "boundary_id": boundary["id"],
            "transform_id": transform["id"] if transform else None,
            "sink_id": sink["id"],
            "file": file_name,
            "chain": [
                f"{source['kind']} source at {source['file']}:{source['line']}",
                f"{boundary['kind']} boundary",
                *([f"{transform['kind']} transform"] if transform else []),
                f"{sink['kind']} sink at {sink['file']}:{sink['line']}",
            ],
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
                "question": question_template.format(
                    source_kind=source["kind"],
                    boundary_kind=boundary["kind"],
                    sink_kind=sink["kind"],
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


def map_application(
    program: str,
    target_path: Path,
    *,
    target_kind: str = "auto",
    focus: str = "rce",
    hunting_policy: HuntingPolicy | dict[str, Any] | None = None,
) -> MapResult:
    profile = classify_target(program, target_path, target_kind=target_kind)
    surfaces, noise_surfaces = scan_surface_sets(target_path, focus=focus, target_profile=profile)
    if focus == BASELINE_FOCUS:
        flows: list[dict[str, Any]] = []
        candidates: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
    else:
        vuln_pack = VULNERABILITY_PACKS[focus]
        flows, candidates, rejected = vuln_pack.build_flows(surfaces)
    result = MapResult(
        profile=profile,
        focus=focus,
        surfaces=surfaces,
        noise_surfaces=noise_surfaces,
        flows=flows,
        candidates=candidates,
        rejected_candidates=rejected,
    )
    return _apply_hunting_policy_to_map_result(result, hunting_policy)


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


def build_baseline_records(result: MapResult) -> list[dict[str, Any]]:
    """Return stable, bounded baseline records derived from AppMap evidence."""

    records: list[dict[str, Any]] = []

    def next_id() -> str:
        return f"base-R{len(records) + 1:06d}"

    seen_components: set[str] = set()
    seen_files: set[str] = set()

    for entrypoint in result.profile.entrypoints:
        path = str(entrypoint.get("path") or entrypoint.get("name") or "").strip()
        records.append(
            {
                "id": next_id(),
                "record_type": "entrypoint",
                "kind": str(entrypoint.get("kind") or "entrypoint"),
                "name": path or str(entrypoint.get("kind") or "entrypoint"),
                "file": path or None,
                "line": None,
                "snippet": "",
                "trust_level": "unknown",
                "attacker_control": "unknown",
                "confidence": result.profile.confidence,
                "target_pack_keys": [],
                "source_tool": "appmap",
                "source_ref": f"entrypoint:{path or len(records) + 1}",
            }
        )

    for surface in sorted(result.surfaces, key=lambda item: (str(item.get("file", "")), int(item.get("line", 0)), str(item.get("id", "")))):
        file_name = str(surface.get("file") or "")
        if file_name:
            seen_files.add(file_name)
            component = str(Path(file_name).parent.as_posix())
            if component and component != ".":
                seen_components.add(component)
        role = str(surface.get("role") or "record")
        records.append(
            {
                "id": next_id(),
                "record_type": role if role in {"source", "boundary", "transform", "sink"} else "surface",
                "kind": surface.get("kind"),
                "name": surface.get("name"),
                "file": file_name or None,
                "line": surface.get("line"),
                "snippet": surface.get("snippet", ""),
                "trust_level": surface.get("trust_level", "unknown"),
                "attacker_control": surface.get("attacker_control", "unknown"),
                "confidence": surface.get("confidence", 0.0),
                "target_pack_keys": surface.get("target_pack_keys", []),
                "source_tool": "appmap",
                "source_ref": f"surface:{surface.get('id')}",
            }
        )

    for component in sorted(seen_components):
        records.append(
            {
                "id": next_id(),
                "record_type": "component",
                "kind": "directory",
                "name": component,
                "file": component,
                "line": None,
                "snippet": "",
                "trust_level": "unknown",
                "attacker_control": "unknown",
                "confidence": 0.5,
                "target_pack_keys": [],
                "source_tool": "appmap",
                "source_ref": f"component:{component}",
            }
        )

    for file_name in sorted(seen_files):
        records.append(
            {
                "id": next_id(),
                "record_type": "file",
                "kind": Path(file_name).suffix.lower().lstrip(".") or "file",
                "name": file_name,
                "file": file_name,
                "line": None,
                "snippet": "",
                "trust_level": "unknown",
                "attacker_control": "unknown",
                "confidence": 0.5,
                "target_pack_keys": [],
                "source_tool": "appmap",
                "source_ref": f"file:{file_name}",
            }
        )

    for enrichment in result.enrichment_records:
        record = dict(enrichment)
        record.pop("id", None)
        record.setdefault("record_type", "scanner_enrichment")
        record.setdefault("source_tool", "electronegativity")
        record.setdefault("target_pack_keys", ["electron"])
        record["id"] = next_id()
        records.append(record)

    return records


def build_noise_summary(result: MapResult) -> dict[str, Any]:
    by_reason = Counter(str(surface.get("filtered_reason") or "unknown") for surface in result.noise_surfaces)
    by_kind = Counter(str(surface.get("kind") or "unknown") for surface in result.noise_surfaces)
    by_file = Counter(str(surface.get("file") or "unknown") for surface in result.noise_surfaces)
    return {
        "schema_version": 1,
        "description": (
            "Filtered AppMap surface evidence kept for audit/tuning. These records are "
            "excluded from normal candidate generation unless a future run promotes them."
        ),
        "filtered_surface_count": len(result.noise_surfaces),
        "primary_surface_count": len(result.surfaces),
        "by_reason": dict(sorted(by_reason.items())),
        "by_kind": dict(sorted(by_kind.items())),
        "top_files": [
            {"file": file_name, "count": count}
            for file_name, count in by_file.most_common(25)
        ],
    }


def build_baseline_relationships(result: MapResult, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_surface_ref = {str(record.get("source_ref")): record["id"] for record in records}
    entrypoints = [record for record in records if record.get("record_type") == "entrypoint"]
    records_by_file: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        file_name = str(record.get("file") or "")
        if file_name:
            records_by_file.setdefault(file_name, []).append(record)
    relationships: list[dict[str, Any]] = []

    def add_edge(source_id: str | None, target_id: str | None, relationship_type: str, confidence: float) -> None:
        if not source_id or not target_id:
            return
        relationships.append(
            {
                "id": f"base-E{len(relationships) + 1:06d}",
                "from": source_id,
                "to": target_id,
                "relationship_type": relationship_type,
                "confidence": round(confidence, 2),
                "source_tool": "appmap",
            }
        )

    for flow in result.flows:
        source_id = by_surface_ref.get(f"surface:{flow.get('source_id')}")
        boundary_id = by_surface_ref.get(f"surface:{flow.get('boundary_id')}")
        transform_id = by_surface_ref.get(f"surface:{flow.get('transform_id')}")
        sink_id = by_surface_ref.get(f"surface:{flow.get('sink_id')}")
        confidence = float(flow.get("confidence") or 0.0)
        add_edge(source_id, boundary_id, "crosses", confidence)
        if transform_id:
            add_edge(boundary_id, transform_id, "transforms", confidence)
            add_edge(transform_id, sink_id, "may_feed", confidence)
        else:
            add_edge(boundary_id, sink_id, "may_feed", confidence)
    for entrypoint in entrypoints:
        entrypoint_id = str(entrypoint.get("id") or "")
        entrypoint_file = str(entrypoint.get("file") or "")
        for record in records_by_file.get(entrypoint_file, []):
            if record.get("id") != entrypoint_id:
                add_edge(entrypoint_id, str(record.get("id") or ""), "contains_evidence", 0.7)
    add_electron_preload_relationships(result, entrypoints, add_edge)
    return relationships


def add_electron_preload_relationships(
    result: MapResult,
    entrypoints: list[dict[str, Any]],
    add_edge: Callable[[str | None, str | None, str, float], None],
) -> None:
    if "electron" not in result.profile.frameworks:
        return
    target_root = Path(result.profile.target_path)
    entrypoint_by_file = {str(entrypoint.get("file") or ""): entrypoint for entrypoint in entrypoints}
    preload_files = {
        str(entrypoint.get("file") or "")
        for entrypoint in entrypoints
        if str(entrypoint.get("kind") or "") == "electron-preload"
    }
    if not preload_files:
        return
    for main_entrypoint in entrypoints:
        if str(main_entrypoint.get("kind") or "") != "electron-main":
            continue
        main_file = str(main_entrypoint.get("file") or "")
        main_path = target_root / main_file
        try:
            text = main_path.read_text(encoding="utf-8", errors="ignore")[:20000]
        except OSError:
            continue
        for match in re.finditer(r"\bpreload\s*:\s*['\"`]([^'\"`]+)['\"`]", text):
            preload_ref = match.group(1).strip()
            normalized = _normalize_preload_ref(preload_ref, main_file)
            preload_entrypoint = entrypoint_by_file.get(normalized)
            if preload_entrypoint is None and Path(normalized).name in {Path(item).name for item in preload_files}:
                preload_entrypoint = next(
                    (entrypoint for entrypoint in entrypoints if Path(str(entrypoint.get("file") or "")).name == Path(normalized).name),
                    None,
                )
            if preload_entrypoint is not None:
                add_edge(
                    str(main_entrypoint.get("id") or ""),
                    str(preload_entrypoint.get("id") or ""),
                    "configures_preload",
                    0.82,
                )


def _normalize_preload_ref(preload_ref: str, main_file: str) -> str:
    preload_path = Path(preload_ref)
    if preload_path.is_absolute():
        return preload_path.name
    main_parent = Path(main_file).parent
    if main_parent.as_posix() == ".":
        return preload_path.as_posix()
    return (main_parent / preload_path).as_posix()


def build_baseline_quality_report(
    result: MapResult,
    records: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
) -> dict[str, Any]:
    record_counts: dict[str, int] = {}
    for record in records:
        key = str(record.get("record_type") or "unknown")
        record_counts[key] = record_counts.get(key, 0) + 1
    mapped_files = {str(record.get("file")) for record in records if record.get("file")}
    mapped_file_count = len(mapped_files)
    try:
        eligible_files = [path for path in iter_source_files(Path(result.profile.target_path))]
    except OSError:
        eligible_files = []
    eligible_file_count = len(eligible_files)
    source_count = record_counts.get("source", 0)
    boundary_count = record_counts.get("boundary", 0)
    sink_count = record_counts.get("sink", 0)
    relationship_count = len(relationships)
    component_count = record_counts.get("component", 0)
    source_tools = sorted({str(record.get("source_tool")) for record in records if record.get("source_tool")})
    enrichment_summary = result.enrichment_summary or {}
    enrichment_records = record_counts.get("scanner_enrichment", 0)
    if enrichment_records:
        enrichment_status = "pass"
    elif "electron" in result.profile.frameworks:
        enrichment_status = "missing"
    else:
        enrichment_status = "not_configured"
    if not records:
        overall = "failed"
    elif source_count and boundary_count and relationship_count:
        overall = "good"
    elif source_count or boundary_count or sink_count:
        overall = "usable"
    else:
        overall = "weak"
    rce_status = "ready" if result.candidates else "usable" if source_count and boundary_count and sink_count else "weak"
    return {
        "schema_version": 1,
        "overall_quality": overall,
        "quality_score": round(
            min(
                1.0,
                (0.2 if records else 0.0)
                + min(source_count, 10) * 0.02
                + min(boundary_count, 10) * 0.02
                + min(sink_count, 10) * 0.02
                + min(relationship_count, 10) * 0.03
                + result.profile.confidence * 0.25,
            ),
            2,
        ),
        "minimum_focus_ready": overall in {"good", "usable"},
        "coverage": {
            "file_scan_coverage": {
                "status": "pass" if eligible_file_count else "warn",
                "eligible_files": eligible_file_count,
                "mapped_files_with_records": mapped_file_count,
                "ratio": round(mapped_file_count / max(eligible_file_count, 1), 3),
            },
            "entrypoint_coverage": {
                "status": "pass" if result.profile.entrypoints else "warn",
                "confidence": result.profile.confidence,
                "entrypoints": len(result.profile.entrypoints),
            },
            "component_coverage": {
                "status": "pass" if component_count else "warn",
                "components": component_count,
                "frameworks": result.profile.frameworks,
            },
            "record_coverage": {
                "status": "pass" if records else "fail",
                "records": len(records),
                "record_types": record_counts,
            },
            "relationship_coverage": {
                "status": "pass" if relationships else "warn",
                "relationships": relationship_count,
                "edges_per_record": round(relationship_count / max(len(records), 1), 3),
            },
            "enrichment_coverage": {
                "status": enrichment_status,
                "source_tools": source_tools,
                "records": enrichment_records,
                "overflow_count": int(enrichment_summary.get("overflow_count") or 0),
                "skipped_count": int(enrichment_summary.get("skipped_count") or 0),
                "read_files": enrichment_summary.get("read_files", []),
                "ignored_files": enrichment_summary.get("ignored_files", []),
            },
        },
        "checks": {
            "file_coverage": {"status": "pass" if mapped_file_count else "warn", "mapped_files": mapped_file_count},
            "entrypoint_detection": {
                "status": "pass" if result.profile.entrypoints else "warn",
                "confidence": result.profile.confidence,
                "entrypoints": len(result.profile.entrypoints),
            },
            "framework_detection": {
                "status": "pass" if result.profile.frameworks else "warn",
                "frameworks": result.profile.frameworks,
            },
            "record_density": {"status": "pass" if records else "fail", "records": len(records), "record_types": record_counts},
            "relationship_density": {
                "status": "pass" if relationships else "warn",
                "relationships": relationship_count,
                "edges_per_record": round(relationship_count / max(len(records), 1), 3),
            },
        },
        "focus_readiness": {
            "rce": {
                "status": rce_status,
                "reason": "candidate chains present" if result.candidates else "baseline has partial source/boundary/sink evidence",
            },
            "renderer-content-trust": {
                "status": "usable" if "electron" in result.profile.frameworks else "weak",
                "reason": "Electron target detected" if "electron" in result.profile.frameworks else "no Electron renderer evidence imported yet",
            },
            "file-upload-import": {
                "status": "weak",
                "reason": "file import overlay not implemented in Phase 1",
            },
            "auth-session-state": {
                "status": "weak",
                "reason": "auth/session overlay not implemented in Phase 1",
            },
            "ssrf-network-fetch": {
                "status": "weak",
                "reason": "network fetch overlay not implemented in Phase 1",
            },
            "tenant-collaboration-boundary": {
                "status": "weak",
                "reason": "tenant/collaboration overlay not implemented in Phase 1",
            },
            "ai-content-trust": {
                "status": "weak",
                "reason": "AI content trust overlay not implemented in Phase 1",
            },
            "supply-chain-update": {
                "status": "weak",
                "reason": "supply-chain/update overlay not implemented in Phase 1",
            },
            "local-file-privacy": {
                "status": "weak",
                "reason": "local file/privacy overlay not implemented in Phase 1",
            },
        },
    }


def build_coverage_gaps(result: MapResult, records: list[dict[str, Any]], relationships: list[dict[str, Any]]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []

    def add_gap(gap_type: str, path: str | None, reason: str, affected_focuses: list[str], recommended_repair: str, blocks_focus: bool) -> None:
        gaps.append(
            {
                "id": f"gap-G{len(gaps) + 1:06d}",
                "gap_type": gap_type,
                "path": path,
                "reason": reason,
                "affected_focuses": affected_focuses,
                "recommended_repair": recommended_repair,
                "blocks_focus": blocks_focus,
            }
        )

    if not result.profile.entrypoints:
        add_gap(
            "missing_entrypoint",
            None,
            "No explicit entrypoints were detected.",
            ["entrypoint-and-boundary-inventory"],
            "Inspect manifests or add target-pack entrypoint detection.",
            False,
        )
    if records and not relationships:
        add_gap(
            "missing_relationships",
            None,
            "Baseline has records but no linked relationships.",
            ["rce", "renderer-content-trust", "file-upload-import"],
            "Run a focused overlay or add relationship builder coverage for this target kind.",
            False,
        )
    if not records:
        add_gap(
            "low_signal_focus",
            None,
            "No baseline records were emitted.",
            ["all"],
            "Review scan extensions, target path, and target-pack detection.",
            True,
        )
    return gaps


def build_baseline_category_plan(
    result: MapResult,
    quality_report: dict[str, Any],
    gaps: list[dict[str, Any]],
) -> dict[str, Any]:
    focus_readiness = quality_report.get("focus_readiness", {})
    categories: list[dict[str, Any]] = []
    for category, readiness in sorted(focus_readiness.items()):
        status = str(readiness.get("status") or "weak")
        categories.append(
            {
                "category": category,
                "priority": "high" if status == "ready" else "medium" if status == "usable" else "low",
                "readiness": status,
                "reason": readiness.get("reason") or "",
                "suggested_agent": f"{category}-triage",
                "next_action": "run focused overlay" if status in {"ready", "usable"} else "repair baseline map first",
            }
        )
    if result.profile.entrypoints:
        categories.insert(
            0,
            {
                "category": "entrypoint-and-boundary-inventory",
                "priority": "medium",
                "readiness": "usable",
                "reason": f"{len(result.profile.entrypoints)} entrypoint(s) detected",
                "suggested_agent": "entrypoint-boundary-triage",
                "next_action": "sample entrypoint-to-boundary relationships",
            },
        )
    return {
        "schema_version": 1,
        "overall_quality": quality_report.get("overall_quality"),
        "gap_count": len(gaps),
        "categories": categories,
    }


def build_baseline_triage_hypotheses(
    category_plan: dict[str, Any],
    records: list[dict[str, Any]],
    gaps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    hypotheses: list[dict[str, Any]] = []
    for category in category_plan.get("categories", []):
        category_name = str(category.get("category") or "")
        baseline_refs = [
            str(record["id"])
            for record in records
            if category_name in {"entrypoint-and-boundary-inventory", "renderer-content-trust", "rce"}
            and record.get("record_type") in {"entrypoint", "source", "boundary", "sink"}
        ][:20]
        if not baseline_refs:
            baseline_refs = [str(record["id"]) for record in records[:10]]
        gap_refs = [
            str(gap["id"])
            for gap in gaps
            if category_name in set(str(item) for item in gap.get("affected_focuses", [])) or "all" in gap.get("affected_focuses", [])
        ][:10]
        hypotheses.append(
            {
                "id": f"triage-H{len(hypotheses) + 1:04d}",
                "category": category.get("category"),
                "priority": category.get("priority"),
                "readiness": category.get("readiness"),
                "baseline_refs": baseline_refs,
                "gap_refs": gap_refs,
                "question": f"What does the baseline imply for {category.get('category')}?",
                "expected_output": "category posture note, candidate focus recommendations, or map-repair request",
                "not_a_finding": True,
            }
        )
    return hypotheses


def build_focus_recommendations(
    quality_report: dict[str, Any],
    category_plan: dict[str, Any],
    gaps: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []
    readiness_weight = {"ready": 90, "usable": 70, "weak": 35, "blocked": 10, "failed": 0}
    priority_weight = {"high": 20, "medium": 10, "low": 0}
    focus_readiness = quality_report.get("focus_readiness", {})
    records_by_type: dict[str, list[str]] = {}
    records_by_kind: dict[str, list[str]] = {}
    for record in records:
        record_id = str(record.get("id") or "")
        if not record_id:
            continue
        records_by_type.setdefault(str(record.get("record_type") or ""), []).append(record_id)
        records_by_kind.setdefault(str(record.get("kind") or ""), []).append(record_id)

    def evidence_for_focus(focus: str) -> tuple[list[str], list[str]]:
        if focus == "rce":
            required = ["source", "boundary", "sink"]
            refs = [
                *records_by_type.get("source", [])[:6],
                *records_by_type.get("boundary", [])[:6],
                *records_by_type.get("sink", [])[:6],
            ]
        elif focus == "renderer-content-trust":
            required = ["entrypoint", "source", "boundary"]
            refs = [
                *records_by_type.get("entrypoint", [])[:4],
                *records_by_kind.get("ipc", [])[:6],
                *records_by_kind.get("electron-boundary", [])[:6],
                *records_by_type.get("boundary", [])[:4],
            ]
        elif focus == "file-upload-import":
            required = ["source", "boundary", "file"]
            refs = [*records_by_type.get("source", [])[:6], *records_by_type.get("file", [])[:8]]
        elif focus == "local-file-privacy":
            required = ["file", "source"]
            refs = [*records_by_type.get("file", [])[:10], *records_by_type.get("source", [])[:6]]
        else:
            required = ["source", "boundary"]
            refs = [*records_by_type.get("source", [])[:6], *records_by_type.get("boundary", [])[:6]]
        return required, list(dict.fromkeys(refs))[:20]

    for category in category_plan.get("categories", []):
        focus = str(category.get("category") or "")
        if focus == "entrypoint-and-boundary-inventory":
            continue
        readiness = str(category.get("readiness") or focus_readiness.get(focus, {}).get("status") or "weak")
        priority = str(category.get("priority") or "low")
        gap_refs = [
            str(gap["id"])
            for gap in gaps
            if focus in set(str(item) for item in gap.get("affected_focuses", [])) or "all" in gap.get("affected_focuses", [])
        ][:10]
        required_records, baseline_refs = evidence_for_focus(focus)
        score = (
            readiness_weight.get(readiness, 0)
            + priority_weight.get(priority, 0)
            + min(len(baseline_refs), 10)
            - min(len(gap_refs) * 5, 25)
        )
        if readiness in {"blocked", "failed"}:
            next_action = "repair baseline before running overlay"
        elif readiness in {"ready", "usable"}:
            next_action = "run focused overlay"
        else:
            next_action = "collect or import more baseline evidence first"
        recommendations.append(
            {
                "id": f"focus-R{len(recommendations) + 1:04d}",
                "focus": focus,
                "rank_score": max(score, 0),
                "readiness": readiness,
                "priority": priority,
                "reason": category.get("reason") or focus_readiness.get(focus, {}).get("reason") or "",
                "required_records": required_records,
                "baseline_refs": baseline_refs,
                "gap_refs": gap_refs,
                "next_action": next_action,
                "not_a_finding": True,
            }
        )
    recommendations.sort(key=lambda item: (-int(item["rank_score"]), str(item["focus"])))
    for index, item in enumerate(recommendations, start=1):
        item["rank"] = index
    return recommendations


def render_baseline_posture_summary(
    result: MapResult,
    quality_report: dict[str, Any],
    category_plan: dict[str, Any],
    gaps: list[dict[str, Any]],
    focus_recommendations: list[dict[str, Any]] | None = None,
) -> str:
    lines = [
        f"# Baseline Posture Summary: {result.profile.program}",
        "",
        f"- Focus: {result.focus}",
        f"- Overall quality: {quality_report.get('overall_quality')}",
        f"- Quality score: {quality_report.get('quality_score')}",
        f"- Records: {quality_report.get('checks', {}).get('record_density', {}).get('records', 0)}",
        f"- Relationships: {quality_report.get('checks', {}).get('relationship_density', {}).get('relationships', 0)}",
        f"- Coverage gaps: {len(gaps)}",
        "",
        "## Category Plan",
        "",
    ]
    for category in category_plan.get("categories", []):
        lines.append(
            f"- {category['category']}: {category['readiness']} / {category['priority']} - {category['reason']}"
        )
    if focus_recommendations:
        lines.extend(["", "## Recommended Focus Overlays", ""])
        for recommendation in focus_recommendations[:8]:
            lines.append(
                f"- #{recommendation['rank']} {recommendation['focus']}: "
                f"{recommendation['readiness']} / score {recommendation['rank_score']} - "
                f"{recommendation['next_action']}"
            )
    if gaps:
        lines.extend(["", "## Gaps", ""])
        for gap in gaps:
            lines.append(f"- {gap['id']} {gap['gap_type']}: {gap['reason']}")
    return "\n".join(lines).rstrip() + "\n"


def import_electronegativity_enrichment(
    root: Path,
    *,
    target_path: Path | None = None,
    max_records: int = ENRICHMENT_RECORD_LIMIT,
    per_type_limit: int = ENRICHMENT_PER_TYPE_LIMIT,
    per_file_limit: int = ENRICHMENT_PER_FILE_LIMIT,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Import bounded Electronegativity records without loading raw findings into agent context."""

    source_root = root.expanduser().resolve(strict=False)
    if not source_root.is_dir():
        raise ValueError(f"Electronegativity root must be an existing directory: {source_root}")
    summary: dict[str, Any] = {
        "schema_version": 1,
        "source_tool": "electronegativity",
        "input_root": str(source_root),
        "records_imported": 0,
        "skipped_count": 0,
        "overflow_count": 0,
        "by_record_type": {},
        "by_file": {},
        "read_files": [],
        "ignored_files": [],
    }
    records: list[dict[str, Any]] = []
    type_counts: dict[str, int] = {}
    file_counts: dict[str, int] = {}

    def allow(record_type: str, file_name: str | None) -> bool:
        if len(records) >= max_records:
            summary["overflow_count"] += 1
            return False
        if type_counts.get(record_type, 0) >= per_type_limit:
            summary["overflow_count"] += 1
            return False
        if file_name and file_counts.get(file_name, 0) >= per_file_limit:
            summary["overflow_count"] += 1
            return False
        return True

    def add_record(payload: dict[str, Any], *, source_ref: str) -> None:
        record_type = _electronegativity_record_type(payload)
        file_name = _normalize_enrichment_path(payload.get("file") or payload.get("path") or payload.get("source_file"), target_path)
        if not allow(record_type, file_name):
            return
        line = _safe_int(payload.get("line") or payload.get("line_no") or payload.get("start_line"))
        snippet = str(payload.get("snippet") or payload.get("code") or payload.get("text") or payload.get("description") or "")[:240]
        record = {
            "record_type": "scanner_enrichment",
            "kind": record_type,
            "name": str(payload.get("name") or payload.get("id") or record_type),
            "file": file_name,
            "line": line,
            "snippet": snippet,
            "trust_level": str(payload.get("trust_level") or payload.get("trust") or "unknown"),
            "attacker_control": str(payload.get("attacker_control") or payload.get("control") or "unknown"),
            "confidence": _safe_float(payload.get("confidence"), default=0.5),
            "target_pack_keys": ["electron"],
            "source_tool": "electronegativity",
            "source_ref": source_ref,
        }
        records.append(record)
        type_counts[record_type] = type_counts.get(record_type, 0) + 1
        if file_name:
            file_counts[file_name] = file_counts.get(file_name, 0) + 1

    inventory_path = source_root / "inventory.json"
    if inventory_path.is_file():
        summary["read_files"].append("inventory.json")
        for index, item in enumerate(_iter_json_records(inventory_path), start=1):
            if isinstance(item, dict):
                add_record(item, source_ref=f"inventory:{index}")
            else:
                summary["skipped_count"] += 1

    hypotheses_path = source_root / "hypotheses.jsonl"
    if hypotheses_path.is_file():
        summary["read_files"].append("hypotheses.jsonl")
        for index, item in enumerate(_read_jsonl_objects(hypotheses_path), start=1):
            add_record(_normalize_electronegativity_hypothesis(item), source_ref=f"hypothesis:{index}")

    team_context_path = source_root / "electron-team-context.json"
    if team_context_path.is_file():
        summary["read_files"].append("electron-team-context.json")
        for index, item in enumerate(_iter_json_records(team_context_path), start=1):
            if isinstance(item, dict):
                item = {**item, "type": item.get("type") or item.get("kind") or "electron_context"}
                add_record(item, source_ref=f"electron-team-context:{index}")

    findings_path = source_root / "findings.json"
    if findings_path.is_file():
        summary["ignored_files"].append(
            {
                "path": "findings.json",
                "reason": "raw findings can be very large; use inventory/hypotheses/context summaries instead",
                "size_bytes": findings_path.stat().st_size,
            }
        )

    summary["records_imported"] = len(records)
    summary["by_record_type"] = dict(sorted(type_counts.items()))
    summary["by_file"] = dict(sorted(file_counts.items()))
    return records, summary


def _iter_json_records(path: Path) -> Iterable[Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if isinstance(payload, list):
        for item in payload:
            yield item
    elif isinstance(payload, dict):
        for key in ("records", "inventory", "items", "components", "findings", "hypotheses"):
            value = payload.get(key)
            if isinstance(value, list):
                for item in value:
                    yield item
                return
        yield payload


def _normalize_electronegativity_hypothesis(item: dict[str, Any]) -> dict[str, Any]:
    source = item.get("source") if isinstance(item.get("source"), dict) else {}
    sink = item.get("sink") if isinstance(item.get("sink"), dict) else {}
    return {
        "type": item.get("type") or item.get("kind") or "source_to_sink_hypothesis",
        "name": item.get("name") or item.get("title") or item.get("hypothesis") or "Electronegativity hypothesis",
        "file": item.get("file") or sink.get("file") or source.get("file"),
        "line": item.get("line") or sink.get("line") or source.get("line"),
        "description": item.get("description") or item.get("summary") or item.get("hypothesis") or "",
        "confidence": item.get("confidence") or item.get("score"),
        "trust_level": item.get("trust_level") or source.get("trust_level") or "unknown",
        "attacker_control": item.get("attacker_control") or source.get("attacker_control") or "unknown",
    }


def _electronegativity_record_type(payload: dict[str, Any]) -> str:
    raw = str(
        payload.get("component_type")
        or payload.get("record_type")
        or payload.get("type")
        or payload.get("kind")
        or payload.get("category")
        or "scanner_enrichment"
    )
    return sanitize_key(raw.replace("_", "-"), fallback="scanner-enrichment")


def _normalize_enrichment_path(value: Any, target_path: Path | None) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    path = Path(text)
    if path.is_absolute() and target_path is not None:
        try:
            return path.resolve(strict=False).relative_to(target_path.resolve(strict=False)).as_posix()
        except ValueError:
            return path.name
    return path.as_posix()


def _safe_int(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _safe_float(value: Any, *, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def load_baseline_context(run_root: Path) -> BaselineContext:
    run_root = run_root.expanduser().resolve(strict=False)
    baseline_root = run_root / "baseline"
    manifest_path = run_root / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"baseline manifest not found: {manifest_path}")
    if not baseline_root.is_dir():
        raise FileNotFoundError(f"baseline artifact directory not found: {baseline_root}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline manifest is not valid JSON: {manifest_path}") from exc
    if not isinstance(manifest, dict):
        raise ValueError(f"baseline manifest must be a JSON object: {manifest_path}")

    def read_required_json(path: Path) -> dict[str, Any]:
        if not path.is_file():
            raise FileNotFoundError(f"required baseline artifact not found: {path}")
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"baseline artifact is not valid JSON: {path}") from exc
        if not isinstance(loaded, dict):
            raise ValueError(f"baseline artifact must be a JSON object: {path}")
        return loaded

    def read_required_jsonl(path: Path) -> list[dict[str, Any]]:
        if not path.is_file():
            raise FileNotFoundError(f"required baseline artifact not found: {path}")
        rows: list[dict[str, Any]] = []
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"baseline artifact {path} has invalid JSON on line {line_no}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"baseline artifact {path} line {line_no} must be a JSON object")
            rows.append(payload)
        return rows

    records = read_required_jsonl(baseline_root / "records.jsonl")
    if not records:
        raise ValueError(f"baseline records are empty: {baseline_root / 'records.jsonl'}")
    quality_report = read_required_json(baseline_root / "quality_report.json")
    if not quality_report.get("minimum_focus_ready", False):
        raise ValueError(f"baseline quality is not focus-ready: {baseline_root / 'quality_report.json'}")

    return BaselineContext(
        run_root=run_root,
        manifest=manifest,
        records=records,
        relationships=read_required_jsonl(baseline_root / "relationships.jsonl"),
        quality_report=quality_report,
        coverage_gaps=read_required_jsonl(baseline_root / "coverage_gaps.jsonl"),
        category_plan=read_required_json(baseline_root / "category_plan.json"),
    )


def baseline_target_path(run_root: Path) -> str | None:
    try:
        context = load_baseline_context(run_root)
    except (OSError, ValueError):
        return None
    value = str(context.manifest.get("target_path") or "").strip()
    return value or None


def validate_baseline_compatibility(
    baseline: BaselineContext,
    *,
    program: str,
    target_path: Path,
    target_kind: str,
    focus: str,
) -> None:
    baseline_program = str(baseline.manifest.get("program") or "").strip()
    if baseline_program and sanitize_key(baseline_program) != sanitize_key(program):
        raise ValueError(f"baseline program {baseline_program!r} does not match requested program {program!r}")
    baseline_target = str(baseline.manifest.get("target_path") or "").strip()
    if baseline_target:
        baseline_resolved = Path(baseline_target).expanduser().resolve(strict=False)
        if baseline_resolved != target_path:
            raise ValueError(f"baseline target_path {baseline_resolved} does not match requested target_path {target_path}")
    baseline_kind = str(baseline.manifest.get("target_kind") or "").strip()
    if target_kind != "auto" and baseline_kind and baseline_kind != target_kind:
        raise ValueError(f"baseline target_kind {baseline_kind!r} does not match requested target_kind {target_kind!r}")
    if str(baseline.manifest.get("focus") or "") != BASELINE_FOCUS:
        raise ValueError("--from-baseline requires a baseline-mode AppMap run")
    focus_status = str(
        baseline.quality_report.get("focus_readiness", {})
        .get(focus, {})
        .get("status", "")
    )
    if focus_status in {"blocked", "failed"}:
        raise ValueError(f"baseline is not ready for focus {focus!r}: {focus_status}")


def apply_baseline_context(result: MapResult, baseline: BaselineContext) -> None:
    records_by_surface_ref: dict[tuple[str, str], str] = {}
    for record in baseline.records:
        source_ref = str(record.get("source_ref") or "")
        record_id = str(record.get("id") or "")
        if record_id and source_ref.startswith("surface:"):
            records_by_surface_ref[(source_ref.removeprefix("surface:"), str(record.get("record_type") or ""))] = record_id
    gap_refs = [str(gap.get("id")) for gap in baseline.coverage_gaps if gap.get("id")][:10]
    quality_refs = ["quality:overall_quality"]
    if baseline.quality_report.get("coverage"):
        quality_refs.extend(f"quality:{key}" for key in sorted(baseline.quality_report["coverage"])[:6])

    def refs_for_candidate(candidate: dict[str, Any]) -> list[str]:
        pairs: list[tuple[str, str]] = []
        for role in ("source", "boundary", "transform", "sink"):
            item = candidate.get(role)
            if isinstance(item, dict) and item.get("id"):
                pairs.append((str(item["id"]), role))
        refs = [records_by_surface_ref[pair] for pair in pairs if pair in records_by_surface_ref]
        return refs[:20]

    for candidate in result.candidates:
        candidate["baseline_refs"] = refs_for_candidate(candidate)
        candidate["baseline_quality"] = baseline.quality_report.get("overall_quality", "unknown")
        candidate["baseline_quality_refs"] = quality_refs
        candidate["baseline_gap_refs"] = gap_refs
        candidate["baseline_run_root"] = str(baseline.run_root)

    result.baseline_context = {
        "run_root": str(baseline.run_root),
        "run_id": baseline.manifest.get("run_id"),
        "focus": baseline.manifest.get("focus"),
        "overall_quality": baseline.quality_report.get("overall_quality", "unknown"),
        "quality_score": baseline.quality_report.get("quality_score"),
        "gap_refs": gap_refs,
        "category_count": len(baseline.category_plan.get("categories", [])),
        "records": len(baseline.records),
        "relationships": len(baseline.relationships),
    }


def write_artifacts(
    result: MapResult,
    *,
    output_root: Path,
    run_id: str,
    write_specs: bool,
    output_mode: str = "standalone",
    hunting_policy: HuntingPolicy | dict[str, Any] | None = None,
    policy_config: str | Path | None = None,
    agent_granularity: str = "default",
) -> dict[str, Path]:
    result = _apply_hunting_policy_to_map_result(result, hunting_policy)
    safe_run_id = validate_run_id(run_id)
    safe_agent_granularity = normalize_agent_granularity(agent_granularity)
    appmap_root = output_root.expanduser().resolve(strict=False) / "appmap"
    run_root = appmap_root / safe_run_id
    if not run_root.resolve(strict=False).is_relative_to(appmap_root):
        raise ValueError(f"run_id {run_id!r} resolves outside output root")
    baseline_root = run_root / "baseline"
    baseline_enrichments = baseline_root / "enrichments"
    noise_root = run_root / "noise"
    generated_specs = run_root / "generated_specs"
    run_root.mkdir(parents=True, exist_ok=True)
    baseline_root.mkdir(parents=True, exist_ok=True)
    baseline_enrichments.mkdir(parents=True, exist_ok=True)
    noise_root.mkdir(parents=True, exist_ok=True)
    generated_specs.mkdir(parents=True, exist_ok=True)

    paths = {
        "run_root": run_root,
        "baseline": baseline_root,
        "baseline_enrichments": baseline_enrichments,
        "noise": noise_root,
        "noise_filtered_surfaces": noise_root / "filtered_surfaces.jsonl",
        "noise_summary": noise_root / "summary.json",
        "baseline_records": baseline_root / "records.jsonl",
        "baseline_relationships": baseline_root / "relationships.jsonl",
        "baseline_quality_report": baseline_root / "quality_report.json",
        "baseline_coverage_gaps": baseline_root / "coverage_gaps.jsonl",
        "baseline_posture_summary": baseline_root / "posture_summary.md",
        "baseline_category_plan": baseline_root / "category_plan.json",
        "baseline_triage_hypotheses": baseline_root / "triage_hypotheses.jsonl",
        "baseline_focus_recommendations": baseline_root / "focus_recommendations.jsonl",
        "baseline_components": baseline_root / "components.jsonl",
        "baseline_trust_boundaries": baseline_root / "trust_boundaries.jsonl",
        "baseline_sources": baseline_root / "sources.jsonl",
        "baseline_transforms": baseline_root / "transforms.jsonl",
        "baseline_sinks": baseline_root / "sinks.jsonl",
        "baseline_files": baseline_root / "files.jsonl",
        "baseline_electronegativity_enrichment": baseline_enrichments / "electronegativity.json",
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
    _write_jsonl(paths["noise_filtered_surfaces"], result.noise_surfaces)
    paths["noise_summary"].write_text(
        json.dumps(build_noise_summary(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_jsonl(paths["flows"], result.flows)
    _write_jsonl(paths["candidates"], result.candidates)
    _write_jsonl(paths["rejected_candidates"], result.rejected_candidates)
    baseline_records = build_baseline_records(result)
    baseline_relationships = build_baseline_relationships(result, baseline_records)
    quality_report = build_baseline_quality_report(result, baseline_records, baseline_relationships)
    coverage_gaps = build_coverage_gaps(result, baseline_records, baseline_relationships)
    category_plan = build_baseline_category_plan(result, quality_report, coverage_gaps)
    triage_hypotheses = build_baseline_triage_hypotheses(category_plan, baseline_records, coverage_gaps)
    focus_recommendations = build_focus_recommendations(quality_report, category_plan, coverage_gaps, baseline_records)
    _write_jsonl(paths["baseline_records"], baseline_records)
    _write_jsonl(paths["baseline_relationships"], baseline_relationships)
    paths["baseline_quality_report"].write_text(json.dumps(quality_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_jsonl(paths["baseline_coverage_gaps"], coverage_gaps)
    paths["baseline_category_plan"].write_text(json.dumps(category_plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_jsonl(paths["baseline_triage_hypotheses"], triage_hypotheses)
    _write_jsonl(paths["baseline_focus_recommendations"], focus_recommendations)
    paths["baseline_posture_summary"].write_text(
        render_baseline_posture_summary(result, quality_report, category_plan, coverage_gaps, focus_recommendations),
        encoding="utf-8",
    )
    _write_jsonl(paths["baseline_components"], [record for record in baseline_records if record["record_type"] == "component"])
    _write_jsonl(paths["baseline_trust_boundaries"], [record for record in baseline_records if record["record_type"] == "boundary"])
    _write_jsonl(paths["baseline_sources"], [record for record in baseline_records if record["record_type"] == "source"])
    _write_jsonl(paths["baseline_transforms"], [record for record in baseline_records if record["record_type"] == "transform"])
    _write_jsonl(paths["baseline_sinks"], [record for record in baseline_records if record["record_type"] == "sink"])
    _write_jsonl(paths["baseline_files"], [record for record in baseline_records if record["record_type"] == "file"])
    if result.enrichment_summary is not None:
        paths["baseline_electronegativity_enrichment"].write_text(
            json.dumps(result.enrichment_summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:
        paths.pop("baseline_electronegativity_enrichment", None)
    if result.research is not None:
        _write_research_artifacts(result.research, paths)

    if write_specs and result.candidates:
        focus_slug = sanitize_key(result.focus, fallback="focus")
        spec_path = generated_specs / f"{focus_slug}-spec.md"
        rendered = render_spec_for_granularity(
            result,
            run_id=safe_run_id,
            agent_granularity=safe_agent_granularity,
        )
        rendered = _with_appmap_run_root_metadata(rendered, run_root)
        rendered = inject_policy_metadata_into_markdown(rendered, hunting_policy)
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
            hunting_policy=hunting_policy,
        )
        if context_paths:
            paths["agent_contexts"] = run_root / "agent_contexts"
            for index, context_path in enumerate(context_paths, start=1):
                stem_parts = context_path.stem.split("-", 2)
                if len(stem_parts) >= 2:
                    hypothesis_id, candidate_id = stem_parts[0].lower(), stem_parts[1].lower()
                    paths.setdefault(f"agent_context_{candidate_id}", context_path)
                    paths[f"agent_context_{hypothesis_id}_{candidate_id}_{index}"] = context_path

    manifest = render_run_manifest(
        result,
        paths,
        run_id=safe_run_id,
        output_mode=output_mode,
        hunting_policy=hunting_policy,
        policy_config=policy_config,
        agent_granularity=safe_agent_granularity,
    )
    paths["manifest"].write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _append_run_index(paths["index"], manifest)
    paths["summary"].write_text(
        render_summary(result, paths, run_id=safe_run_id, hunting_policy=hunting_policy, policy_config=policy_config),
        encoding="utf-8",
    )
    return paths


def normalize_agent_granularity(value: str | None) -> str:
    normalized = str(value or "default").strip().lower()
    aliases = {
        "default": "category-master",
        "categories": "category-master",
        "category": "category-master",
        "category-master": "category-master",
        "narrow": "per-hypothesis",
        "per-hypothesis": "per-hypothesis",
    }
    if normalized not in aliases:
        expected = ", ".join(sorted(AGENT_GRANULARITIES))
        raise ValueError(f"agent_granularity must be one of: {expected}")
    return aliases[normalized]


def render_spec_for_granularity(
    result: MapResult,
    *,
    run_id: str,
    agent_granularity: str,
) -> str:
    safe_agent_granularity = normalize_agent_granularity(agent_granularity)
    if result.focus == "rce":
        return render_rce_spec(result, run_id=run_id, agent_granularity=safe_agent_granularity)
    return VULNERABILITY_PACKS[result.focus].render_spec(result, run_id)


def _apply_hunting_policy_to_map_result(
    result: MapResult,
    hunting_policy: HuntingPolicy | dict[str, Any] | None,
) -> MapResult:
    candidates, rejected = apply_appmap_promotion_policy(
        result.candidates,
        result.rejected_candidates,
        hunting_policy,
    )
    if candidates == result.candidates and rejected == result.rejected_candidates:
        return result
    return MapResult(
        profile=result.profile,
        focus=result.focus,
        surfaces=result.surfaces,
        flows=result.flows,
        candidates=candidates,
        rejected_candidates=rejected,
        research=result.research,
        baseline_context=result.baseline_context,
        enrichment_records=result.enrichment_records,
        enrichment_summary=result.enrichment_summary,
    )


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
    manifest: dict[str, Any] = {}
    if run_root:
        manifest_path = Path(run_root).expanduser() / "manifest.json"
        if manifest_path.is_file():
            try:
                loaded_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                loaded_manifest = {}
            manifest = loaded_manifest if isinstance(loaded_manifest, dict) else {}
            if str(manifest.get("target_path") or "").strip():
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
    policy_id = str(manifest.get("hunting_policy_id") or "").strip()
    if policy_id:
        command.extend(["--hunting-policy", policy_id])
    policy_config = str(manifest.get("hunting_policy_config") or "").strip()
    if policy_id and policy_config:
        command.extend(["--policy-config", policy_config])
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
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _jsonl_count(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


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
    hunting_policy: HuntingPolicy | dict[str, Any] | None = None,
    policy_config: str | Path | None = None,
    agent_granularity: str = "default",
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
            "noise_filtered_surfaces",
            "noise_summary",
            "flows",
            "candidates",
            "rejected_candidates",
            "summary",
            "baseline_records",
            "baseline_relationships",
            "baseline_quality_report",
            "baseline_coverage_gaps",
            "baseline_posture_summary",
            "baseline_category_plan",
            "baseline_triage_hypotheses",
            "baseline_focus_recommendations",
            "baseline_components",
            "baseline_trust_boundaries",
            "baseline_sources",
            "baseline_transforms",
            "baseline_sinks",
            "baseline_files",
            "baseline_electronegativity_enrichment",
            "spec",
            "agent_contexts",
            "research_manifest",
            "research_sources",
            "research_technique_packs",
        }
    }
    manifest = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "run_id": run_id,
        "program": result.profile.program,
        "program_slug": sanitize_key(result.profile.program),
        "focus": result.focus,
        "agent_granularity": normalize_agent_granularity(agent_granularity),
        "output_mode": output_mode,
        "run_root": str(run_root),
        "target_path": result.profile.target_path,
        "target_kind": result.profile.target_kind,
        "detected_kinds": result.profile.detected_kinds,
        "counts": {
            "surfaces": len(result.surfaces),
            "noise_filtered_surfaces": len(result.noise_surfaces),
            "flows": len(result.flows),
            "candidates": len(result.candidates),
            "rejected_candidates": len(result.rejected_candidates),
            "baseline_records": _jsonl_count(paths["baseline_records"]) if "baseline_records" in paths else 0,
            "baseline_relationships": _jsonl_count(paths["baseline_relationships"]) if "baseline_relationships" in paths else 0,
            "baseline_coverage_gaps": _jsonl_count(paths["baseline_coverage_gaps"]) if "baseline_coverage_gaps" in paths else 0,
            "baseline_triage_hypotheses": _jsonl_count(paths["baseline_triage_hypotheses"]) if "baseline_triage_hypotheses" in paths else 0,
            "baseline_focus_recommendations": _jsonl_count(paths["baseline_focus_recommendations"]) if "baseline_focus_recommendations" in paths else 0,
            "baseline_scanner_enrichments": len(result.enrichment_records),
            "agent_contexts": len(list(paths["agent_contexts"].glob("*.json"))) if "agent_contexts" in paths else 0,
            "research_sources": len(result.research.get("sources", [])) if result.research else 0,
            "research_technique_packs": len(result.research.get("technique_packs", [])) if result.research else 0,
        },
        "artifacts": artifacts,
    }
    if result.baseline_context:
        manifest["input_baseline"] = result.baseline_context
    manifest = merge_policy_artifact_metadata(manifest, hunting_policy)
    effective_policy_config = str(Path(policy_config).expanduser()) if policy_config else policy_config_path_for_artifacts(hunting_policy)
    if effective_policy_config and manifest.get("hunting_policy_id"):
        manifest["hunting_policy_config"] = effective_policy_config
    if result.research:
        research_manifest = result.research.get("manifest") or {}
        manifest.update(
            {
                "research_mode": research_manifest.get("research_mode", "local"),
                "research_query": research_manifest.get("research_query", {}),
                "categories": research_manifest.get("categories", []),
                "research_validation_status": research_manifest.get("validation_status", "unreviewed"),
            }
        )
    return manifest


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


def render_rce_spec(
    result: MapResult,
    *,
    run_id: str,
    max_hypotheses: int = MAX_GENERATED_HYPOTHESES,
    agent_granularity: str = "default",
) -> str:
    safe_agent_granularity = normalize_agent_granularity(agent_granularity)
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
        agent_key = _agent_key_for_candidate(program_slug, candidate, agent_granularity=safe_agent_granularity)
        category_tags = [agent_key] if safe_agent_granularity == "category-master" else []
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
                    "- Tags: rce, appmap, static, "
                    + ", ".join([*category_tags, source["kind"], sink["kind"]]),
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
        f"- Agent granularity: {safe_agent_granularity}\n"
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


def render_focus_spec(
    result: MapResult,
    *,
    run_id: str,
    max_hypotheses: int = MAX_GENERATED_HYPOTHESES,
) -> str:
    program_slug = sanitize_key(result.profile.program)
    created = datetime.now(timezone.utc).date().isoformat()
    focus_slug = sanitize_key(result.focus, fallback="focus")
    primitives: list[str] = []
    hypotheses: list[str] = []
    for index, candidate in enumerate(result.candidates[:max_hypotheses], start=1):
        primitive_id = f"P{index:03d}"
        hypothesis_id = f"H{index:03d}"
        source = candidate["source"]
        boundary = candidate["boundary"]
        transform = candidate.get("transform")
        sink = candidate["sink"]
        agent_key = f"{focus_slug}-triage"
        baseline_evidence = [f"  - baseline-ref:{ref}" for ref in candidate.get("baseline_refs", [])[:20]]
        quality_evidence = [f"  - baseline-quality:{ref}" for ref in candidate.get("baseline_quality_refs", [])[:8]]
        gap_evidence = [f"  - baseline-gap:{ref}" for ref in candidate.get("baseline_gap_refs", [])[:8]]
        primitives.append(
            "\n".join(
                [
                    f"### {primitive_id} - {sink['kind']} reachable from {source['kind']} evidence",
                    f"- Source: {source['description']}",
                    f"- Impact: lower-trust content may reach {sink['description']}",
                    f"- Evidence: appmap-{candidate['id']}",
                    "- Status: active",
                ]
            )
        )
        transform_text = f" -> {transform['kind']} transform" if transform else ""
        focus_files = _focus_files_for_candidate(candidate)
        hypotheses.append(
            "\n".join(
                [
                    f"### {hypothesis_id} - {_title_case(source['kind'])} may influence {_title_case(sink['kind'])}",
                    candidate["question"],
                    "- Status: untested",
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
                    f"- Tags: {focus_slug}, appmap, static, {source['kind']}, {sink['kind']}",
                    "- Evidence:",
                    f"  - appmap-{candidate['id']}",
                    f"  - appmap-context:{hypothesis_id}:{candidate['id']}:{agent_key}",
                    *baseline_evidence,
                    *quality_evidence,
                    *gap_evidence,
                    f"  - surface-{candidate['surface_id']}",
                    f"  - flow-{candidate['flow_id']}",
                    (
                        f"- Notes: AppMap run {run_id}; candidate {candidate['id']}; "
                        f"flow {candidate['flow_id']}; baseline refs "
                        f"{', '.join(candidate.get('baseline_refs', [])) or 'none'}."
                    ),
                ]
            )
        )

    return (
        f"# Brainstorm Spec: {result.profile.program} AppMap {result.focus}\n\n"
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
        f"{_mental_model(result)}\n\n"
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
    hunting_policy: HuntingPolicy | dict[str, Any] | None = None,
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
            hunting_policy=hunting_policy,
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
    hunting_policy: HuntingPolicy | dict[str, Any] | None = None,
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
    candidate_payload = {
        "id": candidate["id"],
        "priority": candidate["priority"],
        "score": candidate["score"],
        "question": candidate["question"],
        "map_ids": map_ids,
    }
    if candidate.get("policy") is not None:
        candidate_payload["policy"] = candidate.get("policy")
    if candidate.get("baseline_refs") is not None:
        candidate_payload["baseline_refs"] = list(candidate.get("baseline_refs", []))[:AGENT_PACKET_BASELINE_REF_LIMIT]
        candidate_payload["baseline_quality"] = candidate.get("baseline_quality", "unknown")
        candidate_payload["baseline_quality_refs"] = list(candidate.get("baseline_quality_refs", []))[:AGENT_PACKET_QUALITY_REF_LIMIT]
        candidate_payload["baseline_gap_refs"] = list(candidate.get("baseline_gap_refs", []))[:AGENT_PACKET_GAP_REF_LIMIT]
        candidate_payload["baseline_run_root"] = candidate.get("baseline_run_root")
    context = {
        "schema_version": 1,
        "run_id": run_id,
        "appmap_run_root": str(run_root),
        "program": result.profile.program,
        "focus": result.focus,
        "candidate": candidate_payload,
        "target_profile": _minimal_target_profile(result.profile, active_target_pack_keys),
        "active_target_packs": active_target_pack_keys,
        "active_vulnerability_pack": result.focus,
        "hypothesis_linkage": {
            **hypothesis_linkage,
            "spec_file": _relative_to(spec_path, run_root),
        },
        "focus_files": _focus_files_for_candidate(candidate)[:AGENT_PACKET_FOCUS_FILE_LIMIT],
        "evidence": {
            "source": _evidence_item(source),
            "boundary": _evidence_item(boundary),
            "transform": _evidence_item(transform) if transform else None,
            "sink": _evidence_item(sink),
        },
        "research": _candidate_research_packet(result, candidate),
        "ingestion_budget": {
            "baseline_ref_limit": AGENT_PACKET_BASELINE_REF_LIMIT,
            "quality_ref_limit": AGENT_PACKET_QUALITY_REF_LIMIT,
            "gap_ref_limit": AGENT_PACKET_GAP_REF_LIMIT,
            "focus_file_limit": AGENT_PACKET_FOCUS_FILE_LIMIT,
            "snippet_limit": AGENT_PACKET_SNIPPET_LIMIT,
            "raw_artifacts_excluded": [
                "baseline/records.jsonl",
                "baseline/relationships.jsonl",
                "surfaces.jsonl",
                "candidates.jsonl",
                "rejected_candidates.jsonl",
                "raw scanner findings",
            ],
        },
        "baseline_context": result.baseline_context or {},
        "next_steps": [
            "Use only this packet's map IDs, evidence snippets, and focus files for the hypothesis.",
            "Trace source-to-boundary-to-sink control and data flow in the listed files.",
            "Record findings or no-findings against the linked hypothesis ID, agent key, candidate ID, and flow ID.",
        ],
    }
    return merge_policy_artifact_metadata(context, hunting_policy)


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
        "snippet": str(surface["snippet"])[:AGENT_PACKET_SNIPPET_LIMIT],
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


def _agent_key_for_candidate(
    program_slug: str,
    candidate: dict[str, Any],
    *,
    agent_granularity: str,
) -> str:
    if normalize_agent_granularity(agent_granularity) == "category-master":
        return _static_category_agent_key(candidate)
    return _stable_agent_key(program_slug, candidate)


def _static_category_agent_key(candidate: dict[str, Any]) -> str:
    sink = candidate.get("sink") if isinstance(candidate.get("sink"), dict) else {}
    source = candidate.get("source") if isinstance(candidate.get("source"), dict) else {}
    boundary = candidate.get("boundary") if isinstance(candidate.get("boundary"), dict) else {}
    transform = candidate.get("transform") if isinstance(candidate.get("transform"), dict) else {}
    kinds = {
        str(item.get("kind") or "").strip().lower()
        for item in (source, boundary, transform, sink)
        if isinstance(item, dict)
    }
    sink_kind = str(sink.get("kind") or "").strip().lower()
    if sink_kind == "unsafe-deserialization" or "deserialization" in kinds:
        category = "unsafe-deserialization"
    elif sink_kind in {"process-exec", "dynamic-code", "dynamic-module"}:
        category = "exec-sink-reachability"
    elif "ipc" in kinds or "electron-boundary" in kinds:
        category = "ipc-trust-boundary"
    else:
        category = "exec-sink-reachability"
    if category not in STATIC_CATEGORY_AGENT_KEYS:
        raise ValueError(f"unknown static category agent key: {category}")
    return category


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
        "research_mode": (result.research or {}).get("manifest", {}).get("research_mode", ""),
        "research_query": (result.research or {}).get("manifest", {}).get("research_query", {}),
        "categories": (result.research or {}).get("manifest", {}).get("categories", []),
        "technique_summaries": summaries,
        "sources": [
            {
                "id": source["id"],
                "title": source.get("title", ""),
                "url": source.get("url", ""),
                "citation": source.get("citation", f"[{source['id']}]"),
                "source_type": source.get("source_type", ""),
                "trust_score": source.get("trust_score"),
                "validation_status": source.get("validation_status", "unreviewed"),
                "categories": source.get("categories", []),
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
                "research_mode": technique.get("research_mode", ""),
                "research_query": technique.get("research_query", ""),
                "categories": list(technique.get("categories") or []),
                "source_type": technique.get("source_type", "technique-pack"),
                "trust_score": technique.get("trust_score"),
                "validation_status": technique.get("validation_status", "unreviewed"),
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


def render_summary(
    result: MapResult,
    paths: dict[str, Path],
    *,
    run_id: str,
    hunting_policy: HuntingPolicy | dict[str, Any] | None = None,
    policy_config: str | Path | None = None,
) -> str:
    lines = [
        f"# AppMap Summary: {result.profile.program}",
        "",
        f"- Run ID: {run_id}",
        f"- Target path: `{result.profile.target_path}`",
        f"- Output root: `{paths['run_root']}`",
        f"- Surfaces: {len(result.surfaces)}",
        f"- Filtered/noise surfaces: {len(result.noise_surfaces)} (`{paths['noise_filtered_surfaces']}`)",
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
        suggested_command = _summary_handoff_command(
            result,
            paths["spec"],
            hunting_policy=hunting_policy,
            policy_config=policy_config,
        )
        lines.extend(
            [
                f"- Generated {focus_label} spec: `{paths['spec']}`",
                "",
                "Suggested run command:",
                "",
                "```bash",
                suggested_command,
                "```",
            ]
        )
        if "agent_contexts" in paths:
            context_count = len(list(paths["agent_contexts"].glob("*.json")))
            lines.insert(9, f"- Agent contexts: `{paths['agent_contexts']}` ({context_count})")
    else:
        lines.append(f"- Generated {result.focus.upper()} spec: none; no candidate met the MVP threshold.")
    return "\n".join(lines).rstrip() + "\n"


def _summary_handoff_command(
    result: MapResult,
    spec_path: Path,
    *,
    hunting_policy: HuntingPolicy | dict[str, Any] | None = None,
    policy_config: str | Path | None = None,
) -> str:
    command = [
        "python3",
        "agents/zero_day_team.py",
        sanitize_key(result.profile.program),
        result.profile.target_path,
        "--brainstorm-spec",
        str(spec_path),
        "--brainstorm-only",
    ]
    policy_metadata = merge_policy_artifact_metadata({}, hunting_policy)
    policy_id = str(policy_metadata.get("hunting_policy_id") or "").strip()
    if policy_id:
        command.extend(["--hunting-policy", policy_id])
        effective_policy_config = str(Path(policy_config).expanduser()) if policy_config else policy_config_path_for_artifacts(hunting_policy)
        if effective_policy_config:
            command.extend(["--policy-config", effective_policy_config])
    return shlex.join(command)


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
    parser.add_argument(
        "--mode",
        choices=("baseline", "focus"),
        default="focus",
        help="Operator-visible run mode. baseline is pre-runtime posture mapping; focus uses --focus.",
    )
    parser.add_argument(
        "--focus",
        default="rce",
        choices=sorted([*VULNERABILITY_PACKS, BASELINE_FOCUS]),
        help="Vulnerability focus for Phase 2. 'baseline' is a compatibility alias for --mode baseline.",
    )
    parser.add_argument(
        "--from-baseline",
        help="Existing AppMap run root to use as baseline context for a focused overlay.",
    )
    parser.add_argument(
        "--electronegativity-root",
        help="Controlled Electronegativity output directory to import as bounded Electron enrichment.",
    )
    parser.add_argument(
        "--enrichment-record-limit",
        type=int,
        default=ENRICHMENT_RECORD_LIMIT,
        help=f"Maximum Electronegativity enrichment records to import. Defaults to {ENRICHMENT_RECORD_LIMIT}.",
    )
    parser.add_argument(
        "--enrichment-per-type-limit",
        type=int,
        default=ENRICHMENT_PER_TYPE_LIMIT,
        help=f"Maximum imported Electronegativity records per type. Defaults to {ENRICHMENT_PER_TYPE_LIMIT}.",
    )
    parser.add_argument(
        "--enrichment-per-file-limit",
        type=int,
        default=ENRICHMENT_PER_FILE_LIMIT,
        help=f"Maximum imported Electronegativity records per file. Defaults to {ENRICHMENT_PER_FILE_LIMIT}.",
    )
    parser.add_argument("--write-specs", action="store_true", help="Write and validate generated brainstorm specs.")
    parser.add_argument(
        "--agent-granularity",
        choices=sorted(AGENT_GRANULARITIES),
        default="default",
        help=(
            "Generated brainstorm agent assignment shape. default uses static zero_day_team category keys; "
            "narrow keeps one unique agent per hypothesis. Compatibility aliases: category-master, per-hypothesis."
        ),
    )
    parser.add_argument(
        "--category-master-agents",
        action="store_true",
        help="Compatibility shortcut for --agent-granularity category-master.",
    )
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
        "--hunting-policy",
        default="off",
        help="Shared hunting policy id. Defaults to off; use auto or a named policy to enable.",
    )
    parser.add_argument(
        "--triage-policy",
        help="Alias/override for --hunting-policy used by triage-oriented workflows.",
    )
    parser.add_argument(
        "--no-triage-policy",
        action="store_true",
        help="Disable shared hunting-policy metadata and prompt guidance for this AppMap run.",
    )
    parser.add_argument(
        "--policy-config",
        help="Path to a custom hunting-policy JSON config.",
    )
    parser.add_argument(
        "--research-mode",
        choices=RESEARCH_MODES,
        default="local",
        help=(
            "Research behavior. local reads only seed artifacts; web fetches explicit source URLs; "
            "hybrid reads local seeds first and fetches explicit source URLs only when --research-online is set."
        ),
    )
    parser.add_argument(
        "--research-query",
        action="append",
        nargs="+",
        default=[],
        metavar="WORD",
        help="Research query terms such as 'electron xss'. Repeatable; terms are normalized into artifact metadata.",
    )
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
        default=None,
        help="Deprecated compatibility flag. Prefer --research-mode local|web|hybrid.",
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
            "Explicit HTTPS source URL for --research-mode web|hybrid. Repeatable; no search, crawl, "
            "or target probing is performed. --research-mode web implies online fetch permission."
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


def _flatten_research_query(values: Iterable[Iterable[str]]) -> tuple[str, ...]:
    return tuple(term for group in values for term in group if str(term).strip())


def _resolve_research_provider(args: argparse.Namespace, raw_argv: list[str]) -> tuple[str, ResearchProvider]:
    mode_explicit = any(arg == "--research-mode" or arg.startswith("--research-mode=") for arg in raw_argv)
    research_mode = normalize_research_mode(args.research_mode)
    provider_key = args.research_provider
    if provider_key is None:
        provider_key = provider_key_for_mode(research_mode)
    elif not mode_explicit and provider_key in {"web-fetch", "hybrid"}:
        research_mode = "web" if provider_key == "web-fetch" else "hybrid"
    elif provider_key != provider_key_for_mode(research_mode):
        raise ValueError("--research-provider is deprecated; when combined with --research-mode it must match the selected mode")
    args.research_mode = research_mode
    return research_mode, _build_research_provider(provider_key)


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(raw_argv)
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
    if args.mode == BASELINE_FOCUS:
        args.focus = BASELINE_FOCUS
        args.write_specs = False
    elif args.focus == BASELINE_FOCUS:
        args.mode = BASELINE_FOCUS
        args.write_specs = False
    baseline_context: BaselineContext | None = None
    if args.from_baseline:
        try:
            baseline_context = load_baseline_context(Path(args.from_baseline))
        except (OSError, ValueError) as exc:
            raise SystemExit(str(exc)) from exc
        if args.mode == BASELINE_FOCUS:
            raise SystemExit("--from-baseline is only valid for focus overlays")
        if not args.target_path:
            args.target_path = str(baseline_context.manifest.get("target_path") or "").strip()
    if not args.program or not args.target_path:
        raise SystemExit(
            "program and target_path are required unless using --list-handoffs, --validate-handoff, --plan-handoff, "
            "or --from-baseline with a manifest target_path"
        )
    try:
        research_mode, research_provider = _resolve_research_provider(args, raw_argv)
        _validate_research_options(
            research_online=bool(args.research_online or research_mode == "web"),
            provider=research_provider,
            source_urls=args.research_source_url,
            research_mode=research_mode,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    target_path = Path(args.target_path).expanduser().resolve(strict=False)
    if not target_path.exists() or not target_path.is_dir():
        raise SystemExit(f"target_path must be an existing directory: {target_path}")
    if baseline_context is not None:
        try:
            validate_baseline_compatibility(
                baseline_context,
                program=args.program,
                target_path=target_path,
                target_kind=args.target_kind,
                focus=args.focus,
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc

    run_id = args.run_id or f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{int(time.time())}"
    try:
        agent_granularity = "category-master" if args.category_master_agents else normalize_agent_granularity(args.agent_granularity)
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
    try:
        policy_selection = resolve_policy_selection(
            args.hunting_policy,
            triage_policy=args.triage_policy,
            no_triage_policy=args.no_triage_policy,
        )
        hunting_policy = resolve_hunting_policy(
            policy_selection,
            target_kind=args.target_kind,
            target_path=target_path,
            policy_config=args.policy_config,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    result = map_application(
        args.program,
        target_path,
        target_kind=args.target_kind,
        focus=args.focus,
        hunting_policy=hunting_policy,
    )
    if args.electronegativity_root:
        if args.enrichment_record_limit < 1 or args.enrichment_per_type_limit < 1 or args.enrichment_per_file_limit < 1:
            raise SystemExit("enrichment limits must be positive integers")
        try:
            enrichment_records, enrichment_summary = import_electronegativity_enrichment(
                Path(args.electronegativity_root),
                target_path=target_path,
                max_records=args.enrichment_record_limit,
                per_type_limit=args.enrichment_per_type_limit,
                per_file_limit=args.enrichment_per_file_limit,
            )
        except (OSError, ValueError) as exc:
            raise SystemExit(str(exc)) from exc
        result.enrichment_records = enrichment_records
        result.enrichment_summary = enrichment_summary
    if baseline_context is not None:
        apply_baseline_context(result, baseline_context)
    try:
        result.research = generate_research_artifacts(
            result,
            research_online=bool(args.research_online or research_mode == "web"),
            seed_paths=[Path(path) for path in args.research_seed],
            source_urls=args.research_source_url,
            research_mode=research_mode,
            research_query_terms=_flatten_research_query(args.research_query),
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
        hunting_policy=hunting_policy,
        policy_config=args.policy_config,
        agent_granularity=agent_granularity,
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
