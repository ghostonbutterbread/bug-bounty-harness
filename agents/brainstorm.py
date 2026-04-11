"""Repo-surface brainstorming for dynamic zero_day_team agents."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
import sys
import time
from pathlib import Path
from typing import Any

_AGENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _AGENT_DIR.parent
if _PROJECT_ROOT.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _PROJECT_ROOT.as_posix())
_BOUNTY_TOOLS_ROOT = Path.home() / "projects" / "bounty-tools"
if _BOUNTY_TOOLS_ROOT.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _BOUNTY_TOOLS_ROOT.as_posix())

from agents.dynamic_agent_builder import AgentSpec
from agents.shared_brain import RepoIndex, build_index

try:
    from subagent_logger import SubagentLogger, compute_pte_lite
except ImportError:  # pragma: no cover
    SubagentLogger = None

    def compute_pte_lite(**kwargs: Any) -> int:
        return (
            int(kwargs.get("prompt_tokens") or 0)
            + int(kwargs.get("completion_tokens") or 0)
            + int(kwargs.get("tool_output_tokens") or 0)
        )


COMMON_IGNORE_GLOBS = [
    "**/node_modules/**",
    "**/.git/**",
    "**/dist/**",
    "**/build/**",
    "**/coverage/**",
    "**/test/**",
    "**/tests/**",
    "**/__pycache__/**",
]

SURFACE_RULES: dict[str, dict[str, Any]] = {
    "rpc-endpoint": {
        "patterns": [
            r"\bjsonrpc\b",
            r"\bgrpc\b",
            r"\btRPC\b",
            r"\brpc(Main|Renderer)?\b",
            r"\b(method|procedure)\s*:",
            r"\.proto\b",
        ],
        "vulns": ["command_injection", "auth_bypass", "unsafe_deserialization"],
        "description": "Custom RPC or procedure dispatch surface where attacker input may select methods or arguments.",
    },
    "websocket": {
        "patterns": [
            r"\bWebSocket\b",
            r"\bws\.Server\b",
            r"\bsocket\.io\b",
            r"\bFastAPI\.websocket\b",
            r"\bwebsocket[s]?\b",
        ],
        "vulns": ["auth_bypass", "prototype_pollution", "command_injection"],
        "description": "Stateful bidirectional channel surface where messages may bypass normal request validation.",
    },
    "ipc-channel": {
        "patterns": [
            r"\bipcMain\.(handle|on)\b",
            r"\bipcRenderer\.(invoke|send|on)\b",
            r"\bcontextBridge\.exposeInMainWorld\b",
            r"\bpostMessage\b",
            r"\bMessagePort\b",
        ],
        "vulns": ["privilege_escalation", "auth_bypass", "command_injection"],
        "description": "Renderer-to-privileged-process message channel surface with trust-boundary risk.",
    },
    "custom-protocol": {
        "patterns": [
            r"\bprotocol\.register",
            r"\bsetAsDefaultProtocolClient\b",
            r"\bcreateServer\b",
            r"\bnet\.Server\b",
            r"\bserialport\b",
            r"\bTLSSocket\b",
        ],
        "vulns": ["auth_bypass", "path_traversal", "request_smuggling"],
        "description": "Non-HTTP or OS-level protocol handling surface with bespoke parsing and authorization assumptions.",
    },
    "file-format": {
        "patterns": [
            r"\bparse[A-Z]\w+",
            r"\bdecode[A-Z]\w+",
            r"\bread(File|Stream)\b",
            r"\bprotobuf\b",
            r"\barchive\b",
            r"\bmagic\s*number\b",
        ],
        "vulns": ["unsafe_deserialization", "memory_corruption", "path_traversal"],
        "description": "Custom file or archive parsing surface where malformed inputs can reach dangerous parser logic.",
    },
    "template-engine": {
        "patterns": [
            r"\bdangerouslySetInnerHTML\b",
            r"\bJinja2?\b",
            r"\bhandlebars\b",
            r"\bmustache\b",
            r"\bEJS\b",
            r"\bcompile(Template|String)?\b",
        ],
        "vulns": ["template_injection", "xss", "auth_bypass"],
        "description": "Template rendering surface where attacker-controlled data may become executable markup or code.",
    },
    "plugin-system": {
        "patterns": [
            r"\bplugin[s]?\b",
            r"\bextension[s]?\b",
            r"\bhook[s]?\b",
            r"\bloadPlugin\b",
            r"\bdynamic\s+import\b",
            r"\brequire\s*\(\s*plugin",
        ],
        "vulns": ["code_execution", "auth_bypass", "sandbox_escape"],
        "description": "Extension loading surface where untrusted packages, manifests, or hooks may gain elevated capabilities.",
    },
    "native-bridge": {
        "patterns": [
            r"\bffi-napi\b",
            r"\bprocess\.dlopen\b",
            r"\bctypes\b",
            r"\bcgo\b",
            r"\bJNI\b",
            r"\bnative\b.*\bbridge\b",
        ],
        "vulns": ["memory_corruption", "privilege_escalation", "command_injection"],
        "description": "Native-to-managed bridge surface where validation gaps can reach privileged or memory-unsafe code.",
    },
    "config-format": {
        "patterns": [
            r"\byaml\.load\b",
            r"\btoml\b",
            r"\bconfigparser\b",
            r"\bdotenv\b",
            r"\bini\b",
            r"\bparseConfig\b",
        ],
        "vulns": ["unsafe_deserialization", "auth_bypass", "template_injection"],
        "description": "Configuration ingestion surface where trusted behavior can be steered by attacker-controlled config files.",
    },
    "job-queue": {
        "patterns": [
            r"\bcelery\b",
            r"\bbullmq?\b",
            r"\bSidekiq\b",
            r"\bcron\b",
            r"\bworker\b",
            r"\btask queue\b",
        ],
        "vulns": ["command_injection", "auth_bypass", "ssrf"],
        "description": "Background execution surface where queued payloads may execute outside normal request controls.",
    },
}

SINK_TO_VULN = {
    "child_process.exec": "command_injection",
    "subprocess": "command_injection",
    "eval": "code_execution",
    "Function": "code_execution",
    "pickle": "unsafe_deserialization",
    "yaml.load": "unsafe_deserialization",
    "marshal": "unsafe_deserialization",
    "contextBridge": "privilege_escalation",
    "ipcMain": "privilege_escalation",
    "ipcRenderer": "privilege_escalation",
    "fs-read": "path_traversal",
    "fs-write": "path_traversal",
    "native-memory-op": "memory_corruption",
    "rust-unsafe-op": "memory_corruption",
}

ROLE_HINTS = {
    "electron-main": "ipc-channel",
    "electron-preload": "ipc-channel",
    "ipc": "ipc-channel",
}


def _timestamp_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _estimate_tokens_from_text(text: str | bytes | None) -> int:
    if text is None:
        return 0
    if isinstance(text, bytes):
        size = len(text)
    else:
        size = len(str(text).encode("utf-8", errors="replace"))
    return max(0, math.ceil(size / 4))


def _safe_log_span(logger: SubagentLogger | None, **fields: Any) -> None:
    if logger is None:
        return
    try:
        logger.log_span(**fields)
    except Exception:
        pass


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip().lower())
    return cleaned.strip("-") or "dynamic-agent"


@dataclass
class SurfaceMatch:
    surface_type: str
    score: int
    evidence: list[str]
    files: list[str]
    patterns: list[str]
    suggested_vulns: list[str]
    summary: str


def brainstorm_agent_specs(
    *,
    target_path: str | Path,
    tech_stack: list[str] | None,
    app_version: str,
    program_slug: str,
    logger: SubagentLogger | None = None,
) -> list[AgentSpec]:
    target_root = Path(target_path).expanduser().resolve()
    started = time.time()
    index = build_index(target_root, program_slug)
    frameworks = list(tech_stack or _framework_names(index))
    surfaces = _detect_surfaces(index, frameworks)
    specs = _build_agent_specs(
        surfaces=surfaces,
        app_version=app_version,
        program_slug=program_slug,
        frameworks=frameworks,
    )
    _log_brainstorm_summary(
        logger=logger,
        target_root=target_root,
        frameworks=frameworks,
        surfaces=surfaces,
        specs=specs,
        started=started,
    )
    return specs


def _framework_names(index: RepoIndex) -> list[str]:
    names = [str(item.get("name", "")).strip() for item in index.frameworks if item.get("name")]
    if names:
        return names
    languages: dict[str, int] = {}
    for data in index.files.values():
        lang = str(data.get("lang", "")).strip()
        if not lang:
            continue
        languages[lang] = languages.get(lang, 0) + 1
    return [name for name, _ in sorted(languages.items(), key=lambda item: (-item[1], item[0]))[:3]]


def _detect_surfaces(index: RepoIndex, frameworks: list[str]) -> list[SurfaceMatch]:
    matches: list[SurfaceMatch] = []
    lowered_frameworks = {item.lower() for item in frameworks}
    file_cache: dict[str, str] = {}

    for surface_type, rule in SURFACE_RULES.items():
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in rule["patterns"]]
        evidence: list[str] = []
        files: set[str] = set()
        score = 0

        for relpath, meta in index.files.items():
            roles = {str(role) for role in (meta.get("roles") or [])}
            if surface_type in {ROLE_HINTS.get(role) for role in roles}:
                files.add(relpath)
                score += 2

            abs_path = Path(index.target_root) / relpath
            content = file_cache.get(relpath)
            if content is None:
                try:
                    content = abs_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    content = ""
                file_cache[relpath] = content
            if not content:
                continue

            for line_number, raw_line in enumerate(content.splitlines(), start=1):
                for pattern in compiled_patterns:
                    if not pattern.search(raw_line):
                        continue
                    snippet = raw_line.strip()
                    evidence.append(f"{relpath}:{line_number} {snippet[:180]}")
                    files.add(relpath)
                    score += 3
                    break
                if len(evidence) >= 8:
                    break
            if len(evidence) >= 8:
                break

        if surface_type == "ipc-channel" and "electron" in lowered_frameworks:
            score += 3
        if surface_type == "native-bridge" and lowered_frameworks & {"electron", "node"}:
            score += 1
        if surface_type == "rpc-endpoint" and _inventory_matches(index, {"http-route", "ipc-main-handler"}):
            score += 1
        if score < 3:
            continue

        suggested_vulns = _rank_vulns_for_surface(index=index, surface_type=surface_type, files=sorted(files), defaults=rule["vulns"])
        matches.append(
            SurfaceMatch(
                surface_type=surface_type,
                score=score,
                evidence=evidence[:6],
                files=sorted(files)[:8],
                patterns=list(rule["patterns"]),
                suggested_vulns=suggested_vulns,
                summary=str(rule["description"]),
            )
        )

    matches.sort(key=lambda item: (-item.score, item.surface_type))
    return matches


def _inventory_matches(index: RepoIndex, preferred_kinds: set[str]) -> bool:
    for item in index.inventories.get("entries", []):
        if str(item.get("kind", "")) in preferred_kinds:
            return True
    return False


def _rank_vulns_for_surface(
    *,
    index: RepoIndex,
    surface_type: str,
    files: list[str],
    defaults: list[str],
) -> list[str]:
    votes: dict[str, int] = {name: max(1, len(defaults) - idx) for idx, name in enumerate(defaults)}
    for relpath in files:
        meta = index.files.get(relpath) or {}
        for sink in meta.get("signals", {}).get("sinks", []) or []:
            vuln = SINK_TO_VULN.get(str(sink.get("kind", "")))
            if vuln:
                votes[vuln] = votes.get(vuln, 0) + 4
        roles = {str(role) for role in (meta.get("roles") or [])}
        if surface_type == "ipc-channel" and {"electron-main", "electron-preload"} & roles:
            votes["privilege_escalation"] = votes.get("privilege_escalation", 0) + 3
        if surface_type == "file-format":
            lang = str(meta.get("lang", "")).lower()
            if lang in {"c", "cpp", "rust"}:
                votes["memory_corruption"] = votes.get("memory_corruption", 0) + 2
    ranked = sorted(votes.items(), key=lambda item: (-item[1], item[0]))
    return [name for name, _ in ranked[:2]]


def _build_agent_specs(
    *,
    surfaces: list[SurfaceMatch],
    app_version: str,
    program_slug: str,
    frameworks: list[str],
) -> list[AgentSpec]:
    created_at = _timestamp_iso()
    specs: list[AgentSpec] = []
    for surface in surfaces:
        vuln_class = surface.suggested_vulns[0] if surface.suggested_vulns else "trust_boundary"
        key = f"{_slug(program_slug)}-{surface.surface_type}-{_slug(vuln_class)}"
        focus_globs = _focus_globs(surface.files)
        prompt_template = _build_prompt_template(
            surface=surface,
            vuln_class=vuln_class,
            app_version=app_version,
            frameworks=frameworks,
            focus_globs=focus_globs,
        )
        specs.append(
            AgentSpec(
                key=key,
                name=_render_agent_name(surface.surface_type, vuln_class),
                description=f"{surface.summary} Prioritize {vuln_class.replace('_', ' ')} paths for this app.",
                surface_type=surface.surface_type,
                vuln_class=vuln_class,
                patterns=_unique_strings(surface.patterns + surface.evidence),
                focus_files_glob=focus_globs,
                ignore_files_glob=list(COMMON_IGNORE_GLOBS),
                agent_prompt_template=prompt_template,
                parent_keys=[],
                created_by="brainstorm",
                version=app_version,
                created_at=created_at,
            )
        )
    return specs


def _focus_globs(files: list[str]) -> list[str]:
    globs: list[str] = []
    seen: set[str] = set()
    for relpath in files[:6]:
        path = Path(relpath)
        suffix = path.suffix or ""
        parent = path.parent.as_posix()
        if parent == ".":
            candidate = f"**/*{suffix}" if suffix else path.as_posix()
        else:
            candidate = f"{parent}/**/*{suffix}" if suffix else f"{parent}/**"
        if candidate not in seen:
            globs.append(candidate)
            seen.add(candidate)
        exact = path.as_posix()
        if exact not in seen:
            globs.append(exact)
            seen.add(exact)
    return globs or ["**/*"]


def _render_agent_name(surface_type: str, vuln_class: str) -> str:
    surface_label = surface_type.replace("-", " ").title()
    vuln_label = vuln_class.replace("_", " ").replace("-", " ").title()
    return f"{surface_label} {vuln_label} Hunter"


def _build_prompt_template(
    *,
    surface: SurfaceMatch,
    vuln_class: str,
    app_version: str,
    frameworks: list[str],
    focus_globs: list[str],
) -> str:
    framework_text = ", ".join(frameworks) if frameworks else "unknown"
    evidence_lines = "\n".join(f"- {line}" for line in surface.evidence[:5]) or "- No direct evidence lines captured."
    focus_lines = "\n".join(f"- {item}" for item in focus_globs[:6])
    pattern_lines = "\n".join(f"- {pattern}" for pattern in surface.patterns[:6])
    return (
        f"You are a dynamic application-specific security agent for app version {app_version}.\n\n"
        f"Targeted surface: {surface.surface_type}\n"
        f"Primary vulnerability class: {vuln_class}\n"
        f"Detected frameworks or dominant languages: {framework_text}\n\n"
        "Mission:\n"
        f"- Hunt for trust-boundary mistakes, attacker-controlled dispatch, parser confusion, and dangerous sink reachability specific to the {surface.surface_type} surface.\n"
        f"- Prefer issues that make {vuln_class.replace('_', ' ')} materially reachable from the detected surface.\n"
        "- Stay anchored in the brainstorm evidence below instead of re-scanning the entire repo blindly.\n\n"
        "Focus globs:\n"
        f"{focus_lines}\n\n"
        "Surface clues to start from:\n"
        f"{evidence_lines}\n\n"
        "Relevant code patterns:\n"
        f"{pattern_lines}\n\n"
        "For every candidate bug, prove: entry point, trust boundary, intermediate flow, privileged sink, and practical exploit path."
    )


def _unique_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        normalized = str(item).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output


def _log_brainstorm_summary(
    *,
    logger: SubagentLogger | None,
    target_root: Path,
    frameworks: list[str],
    surfaces: list[SurfaceMatch],
    specs: list[AgentSpec],
    started: float,
) -> None:
    payload = json.dumps(
        {
            "target": str(target_root),
            "frameworks": frameworks,
            "surfaces": [surface.surface_type for surface in surfaces],
            "specs": [spec.key for spec in specs],
        },
        sort_keys=True,
    )
    output_text = "\n".join(spec.key for spec in specs)
    prompt_tokens = _estimate_tokens_from_text(payload)
    completion_tokens = _estimate_tokens_from_text(output_text)
    context_tokens_after = prompt_tokens + completion_tokens
    tool_output_tokens = _estimate_tokens_from_text(output_text)
    _safe_log_span(
        logger,
        span_type="tool",
        phase="preflight",
        level="RESULT",
        message=f"Brainstormed {len(specs)} dynamic agent spec(s)",
        tool_name="brainstorm_surface_mapper",
        tool_category="dynamic_agents",
        target=str(target_root),
        params={"frameworks": frameworks, "surface_count": len(surfaces)},
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        context_tokens_before=prompt_tokens,
        context_tokens_after=context_tokens_after,
        tool_output_tokens=tool_output_tokens,
        pte_lite=compute_pte_lite(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            tool_output_tokens=tool_output_tokens,
            context_tokens_after=context_tokens_after,
        ),
        latency_ms=int((time.time() - started) * 1000),
        input_bytes=len(payload.encode("utf-8", errors="replace")),
        output_bytes=len(output_text.encode("utf-8", errors="replace")),
        success=True,
    )
