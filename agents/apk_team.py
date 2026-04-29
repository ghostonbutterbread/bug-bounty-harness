"""APK-specific progressive attack-surface hunting team."""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

_AGENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _AGENT_DIR.parent
if _PROJECT_ROOT.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _PROJECT_ROOT.as_posix())
_BOUNTY_TOOLS_ROOT = Path.home() / "projects" / "bounty-tools"
if _BOUNTY_TOOLS_ROOT.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _BOUNTY_TOOLS_ROOT.as_posix())

# MGP / BountyMemory (lazy, best-effort — never blocks the scan)
_MGP_ROOT = Path.home() / "projects" / "memory-graph-protocol"
if _MGP_ROOT.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _MGP_ROOT.as_posix())
try:
    from mgp.bounty_integration import BountyMemory
except ImportError:
    BountyMemory = None

from agents.base_team import AgentSession, AgentSpec as TeamAgentSpec
from agents.base_team import BaseTeam
from agents.base_team import display_file_reference, ensure_directory, extract_findings_from_log, is_placeholder_finding, load_findings, pretty_print_findings, reset_findings_store, run_agent_session, stage2_ghost_review, summarize_findings, write_chainable_findings_input
from agents.apk_prefingerprint import build_surface_registry
from agents.apk_profiles import ApkHuntProfile, BUILTIN_PROFILES, PROFILE_BY_KEY
from agents.apk_surface_registry import ApkSurfaceRegistry
from agents.chain_matrix import build_chain_graph, get_chainable_findings
from agents.decompiler import decompile_smali_targets
from agents.dynamic_agent_builder import DynamicAgentBuilder
from agents.ledger import create_team_ledger_from_storage, update_team_finding
from agents.base_team.reports import dated_report_index_paths
from agents.base_team.storage import resolve_team_storage
from agents.snapshot_identity import get_snapshot_identity
from agents.verbosity import clamp_verbosity

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


FINDINGS_FILENAME = "findings.jsonl"
DEFAULT_MAX_AGENTS = 8
MAX_PARALLEL_AGENTS = 10
_APK_TEAM_LOGGER = None

APK_STATIC_PROFILE_DEFS: list[dict[str, Any]] = [
    {
        "key": "dom-xss",
        "surface": "webview",
        "description": "Hunt for attacker-controlled data reaching WebView HTML or JavaScript execution sinks.",
        "patterns": ["addJavascriptInterface", "evaluateJavascript", "loadUrl", "loadDataWithBaseURL"],
    },
    {
        "key": "exec-sink-reachability",
        "surface": "android-exec",
        "description": "Find attacker influence over command execution, dynamic loading, or privileged helper invocation.",
        "patterns": ["Runtime.getRuntime().exec", "ProcessBuilder", "DexClassLoader", "System.loadLibrary"],
    },
    {
        "key": "ipc-trust-boundary",
        "surface": "android-ipc",
        "description": "Trace Intents, Binder, PendingIntent, and exported component trust boundaries.",
        "patterns": ["onReceive", "onStartCommand", "Binder", "PendingIntent", "Intent.get*Extra"],
    },
    {
        "key": "native-module-abuse",
        "surface": "jni",
        "description": "Look for dangerous JNI/native library entry points reachable from app-controlled data.",
        "patterns": ["System.loadLibrary", "JNI_OnLoad", "native ", "registerNatives"],
    },
    {
        "key": "memory-unsafe-parser",
        "surface": "parser",
        "description": "Prioritize file, image, media, and archive parsing paths that cross into native code.",
        "patterns": ["BitmapFactory", "MediaExtractor", "ZipInputStream", "Parcel", "ByteBuffer"],
    },
    {
        "key": "path-traversal",
        "surface": "filesystem",
        "description": "Search for unsafe path joins, file-provider exposure, and external storage abuse.",
        "patterns": ["openFile", "File(", "getExternalFilesDir", "Uri.getPath", "../"],
    },
    {
        "key": "prototype-pollution",
        "surface": "javascript-bridge",
        "description": "Check embedded JavaScript bundles and hybrid bridges for object merge abuse.",
        "patterns": ["Object.assign", "__proto__", "merge", "JSON.parse", "WebMessagePort"],
    },
    {
        "key": "unsafe-deserialization",
        "surface": "serialization",
        "description": "Inspect Parcel, Bundle, Serializable, and custom object loading boundaries.",
        "patterns": ["readSerializable", "ObjectInputStream", "Parcel.read", "Bundle.getParcelable"],
    },
    {
        "key": "ssrf",
        "surface": "network-client",
        "description": "Look for attacker-controlled URLs reaching internal network or local resource fetchers.",
        "patterns": ["OkHttp", "HttpURLConnection", "WebView.loadUrl", "content://", "file://"],
    },
]


class APKTeam(BaseTeam):
    """Class-based APK team built on the shared BaseTeam framework."""

    def get_static_profiles(self) -> list[TeamAgentSpec]:
        snapshot_id = self._snapshot_id() or "unspecified"
        created_at = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        return [
            TeamAgentSpec(
                key=item["key"],
                vuln_class=item["key"],
                surface=item["surface"],
                prompt_template=self._static_prompt(item),
                focus_globs=["**/*.xml", "**/*.smali", "**/*.kt", "**/*.java", "**/*.js"],
                code_patterns=list(item["patterns"]),
                program=self.program,
                created_at=created_at,
                snapshot_id=snapshot_id,
            )
            for item in APK_STATIC_PROFILE_DEFS
        ]

    def generate_dynamic_from_surfaces(
        self,
        surfaces: Sequence[dict[str, Any]],
        *,
        snapshot_id: str,
    ) -> list[TeamAgentSpec]:
        created_at = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        specs: list[TeamAgentSpec] = []
        for surface in surfaces:
            surface_type = str(surface.get("surface_type") or "apk-surface").strip() or "apk-surface"
            vuln_class = str(surface.get("vuln_class") or "apk-flow").strip() or "apk-flow"
            key = str(surface.get("key") or f"{self.program}-{surface_type}-{vuln_class}").strip()
            patterns = [str(item).strip() for item in (surface.get("patterns") or []) if str(item).strip()]
            focus_globs = [
                str(item).strip()
                for item in (surface.get("focus_files_glob") or [])
                if str(item).strip()
            ]
            specs.append(
                TeamAgentSpec(
                    key=key,
                    vuln_class=vuln_class,
                    surface=surface_type,
                    prompt_template=self._dynamic_prompt(
                        key=key,
                        surface_type=surface_type,
                        vuln_class=vuln_class,
                        description=str(surface.get("description") or "").strip(),
                        patterns=patterns,
                        upstream_prompt=str(surface.get("agent_prompt_template") or "").rstrip(),
                    ),
                    focus_globs=focus_globs,
                    code_patterns=patterns,
                    program=self.program,
                    created_at=created_at,
                    snapshot_id=snapshot_id,
                )
            )
        return specs

    def _static_prompt(self, profile: dict[str, Any]) -> str:
        pattern_lines = "\n".join(f"- {item}" for item in profile["patterns"]) or "- None"
        return (
            f"You are an APK static-analysis hunter focused on '{profile['key']}'.\n\n"
            "Program: {program}\n"
            "Extracted APK root: {target_path}\n"
            "Shared brain index: {shared_brain_index}\n"
            "Append-only findings file: {findings_path}\n"
            "Ledger path: {ledger_path}\n"
            "Snapshot id: {snapshot_id}\n\n"
            f"Mission: {profile['description']}\n\n"
            "Prioritized file globs:\n"
            "{focus_globs}\n\n"
            "Relevant code patterns:\n"
            f"{pattern_lines}\n\n"
            "Rules:\n"
            "- Review the extracted APK statically only.\n"
            "- Start from exported components, manifest routes, WebViews, native boundaries, and privileged sinks.\n"
            "- If a finding does not fit the current class but appears meaningful, mark category=novel.\n"
            "- If there is no real issue, print exactly {{}}.\n"
            "- When you find an issue, append a single-line JSON object to {findings_path} and print the same JSON line to stdout.\n"
            "- Use keys: agent, category, class_name, type, file, line, description, severity, context, source, trust_boundary, flow_path, sink, exploitability.\n"
        )

    def _dynamic_prompt(
        self,
        *,
        key: str,
        surface_type: str,
        vuln_class: str,
        description: str,
        patterns: Sequence[str],
        upstream_prompt: str,
    ) -> str:
        pattern_lines = "\n".join(f"- {item}" for item in patterns) or "- None"
        upstream_section = upstream_prompt.strip()
        if upstream_section:
            upstream_section = f"\n\nExisting brainstorm context:\n{upstream_section}\n"
        return (
            f"You are an APK dynamic hunter for the detected '{surface_type}' surface.\n\n"
            "Program: {program}\n"
            "Extracted APK root: {target_path}\n"
            "Shared brain index: {shared_brain_index}\n"
            "Append-only findings file: {findings_path}\n"
            "Ledger path: {ledger_path}\n"
            "Snapshot id: {snapshot_id}\n\n"
            f"Dynamic agent key: {key}\n"
            f"Primary vulnerability class: {vuln_class}\n"
            f"Surface summary: {description or surface_type}\n\n"
            "Prioritized file globs:\n"
            "{focus_globs}\n\n"
            "Relevant code patterns:\n"
            f"{pattern_lines}"
            f"{upstream_section}\n"
            "Rules:\n"
            "- Stay focused on the detected APK surface rather than mapping the whole app.\n"
            "- Prioritize attacker-controlled Intents, URIs, providers, WebViews, parsers, native bridges, and exported components.\n"
            "- If there is no real issue, print exactly {{}}.\n"
            "- When you find an issue, append a single-line JSON object to {findings_path} and print the same JSON line to stdout.\n"
            "- Use keys: agent, category, class_name, type, file, line, description, severity, context, source, trust_boundary, flow_path, sink, exploitability.\n"
        )


def _estimate_tokens(text: str | bytes | None) -> int:
    if text is None:
        return 0
    if isinstance(text, bytes):
        size = len(text)
    else:
        size = len(str(text).encode("utf-8", errors="replace"))
    return max(0, math.ceil(size / 4))


def _safe_log_span(**fields: Any) -> None:
    if _APK_TEAM_LOGGER is None:
        return
    try:
        _APK_TEAM_LOGGER.log_span(**fields)
    except Exception:
        pass


def _sanitize_program_name(program: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(program or "").strip()) or "default_program"


def _select_profiles(selected_profile: str | None, extra_profiles: Sequence[ApkHuntProfile]) -> list[ApkHuntProfile]:
    all_profiles = list(BUILTIN_PROFILES) + list(extra_profiles)
    if not selected_profile:
        return all_profiles
    normalized = str(selected_profile or "").strip().lower()
    for profile in all_profiles:
        if profile.key.lower() == normalized:
            return [profile]
    known = ", ".join(sorted(profile.key for profile in all_profiles))
    raise ValueError(f"unknown APK profile {selected_profile!r}. Expected one of: {known}")


def _infer_surface_types_from_dynamic_spec(spec: Any) -> tuple[str, ...]:
    blob = " ".join(
        str(item)
        for item in (
            getattr(spec, "key", ""),
            getattr(spec, "name", ""),
            getattr(spec, "description", ""),
            getattr(spec, "surface_type", ""),
            " ".join(getattr(spec, "patterns", []) or []),
        )
    ).lower()
    matches: list[str] = []
    if any(token in blob for token in ("deep", "scheme", "uri", "browsable", "intent-filter")):
        matches.extend(["url-scheme", "exported-activity"])
    if any(token in blob for token in ("webview", "javascriptinterface", "javascript", "evaluatejavascript")):
        matches.append("webview")
    if any(token in blob for token in ("receiver", "broadcast")):
        matches.extend(["exported-receiver", "ordered-broadcast"])
    if any(token in blob for token in ("provider", "contentprovider", "sqlite", "openfile")):
        matches.extend(["content-provider", "exported-provider"])
    if any(token in blob for token in ("native", "jni", "loadlibrary")):
        matches.extend(["native-library", "jni-load"])
    if any(token in blob for token in ("service", "activity", "pendingintent", "ipc", "intent")):
        matches.extend(["exported-activity", "exported-service", "pending-intent"])
    if any(token in blob for token in ("dexclassloader", "classloader", "loadclass", "dynamic")):
        matches.append("dynamic-loader")
    if any(token in blob for token in ("runtime.exec", "processbuilder", "command", "exec")):
        matches.append("command-exec")
    if not matches:
        matches.append("permission")
    return tuple(dict.fromkeys(matches))


def _profile_from_agent_spec(spec: Any) -> ApkHuntProfile:
    surface_types = _infer_surface_types_from_dynamic_spec(spec)
    surface_text = ", ".join(surface_types)
    return ApkHuntProfile(
        key=str(getattr(spec, "key", "")).strip(),
        title=str(getattr(spec, "name", "")).strip() or str(getattr(spec, "key", "")).replace("-", " ").title(),
        description=str(getattr(spec, "description", "")).strip(),
        surface_types=surface_types,
        entry_questions=(
            f"Which APK entry points expose the surface(s): {surface_text}?",
            "Which smali files from the provided targeted set make this flow reachable?",
        ),
        cross_questions=(
            "Where does attacker-controlled data cross from Android IPC, URI, network, or file input into privileged code?",
            "Which validation or permission checks fail or can be bypassed in the targeted APK slice?",
        ),
        sink_categories=tuple(str(item).strip() for item in (getattr(spec, "patterns", []) or []) if str(item).strip())[:8]
        or ("APK-specific sink reachability",),
        reasoning=(
            f"Use the brainstorm dynamic spec for APK surfaces {surface_text}. Stay anchored to the surface registry and targeted files first."
        ),
        prompt_addendum=str(getattr(spec, "agent_prompt_template", "")).rstrip(),
        tags=tuple(surface_types),
    )


def _launcher_script() -> str:
    return r'''
set +e
log_path="${APK_TEAM_AGENTS_DIR}/agent_${APK_TEAM_AGENT_NAME}_$$.log"
prompt="${APK_TEAM_AGENT_PROMPT_BASE}

Agent working directory: ${APK_TEAM_AGENT_WORKDIR}
Agent log file: ${log_path}
"

{
  printf 'agent=%s\n' "$APK_TEAM_AGENT_NAME"
  printf 'pid=%s\n' "$$"
  printf 'cli=%s\n' "$APK_TEAM_AGENT_CLI"
  printf 'workspace=%s\n' "$APK_TEAM_AGENT_WORKDIR"
  printf 'target=%s\n' "$APK_TEAM_TARGET_PATH"
} >> "$log_path"

if [ "$APK_TEAM_AGENT_CLI" = "codex" ]; then
  codex exec -s danger-full-access --skip-git-repo-check "$prompt" >> "$log_path" 2>&1
  status=$?
else
  printf 'unsupported_cli=%s\n' "$APK_TEAM_AGENT_CLI" >> "$log_path"
  status=127
fi

printf 'exit_code=%s\n' "$status" >> "$log_path"
exit "$status"
'''.strip()


def _build_prompt_base(
    profile: ApkHuntProfile,
    *,
    program: str,
    extracted_root: Path,
    findings_path: Path,
    registry_path: Path,
    registry_context: dict[str, Any],
    profile_context: str,
    targeted_files: Sequence[str],
    pseudo_java: dict[str, str],
) -> str:
    entry_lines = "\n".join(f"- {item}" for item in profile.entry_questions)
    cross_lines = "\n".join(f"- {item}" for item in profile.cross_questions)
    sink_lines = "\n".join(f"- {item}" for item in profile.sink_categories)
    target_file_lines = "\n".join(f"- {item}" for item in targeted_files[:40]) or "- None"
    pseudo_sections = []
    for path, text in list(pseudo_java.items())[:4]:
        pseudo_sections.append(f"### {path}\n{text}")
    pseudo_block = "\n\n".join(pseudo_sections) or "None."
    registry_json = json.dumps(registry_context, indent=2, sort_keys=True)
    return f"""You are a specialized APK static-analysis agent focused on "{profile.key}" ({profile.title}).

Program: {program}
Extracted APK root: {extracted_root}
Surface registry JSON: {registry_path}
Append-only findings file: {findings_path}

Prior APK context:
{profile_context}

Core rule:
- Do NOT build a whole-app mental model or index the full smali tree.
- Start from the provided surface registry and targeted files.
- Expand only when the flow demands nearby classes in the same package, receiver chain, provider implementation, or deep-link route.

Profile description:
{profile.description}

ENTRY questions:
{entry_lines}

CROSS questions:
{cross_lines}

Dangerous sinks:
{sink_lines}

Reasoning:
{profile.reasoning}

Profile-specific instructions:
{profile.prompt_addendum or "None."}

Targeted files to inspect first:
{target_file_lines}

Surface registry excerpt:
{registry_json}

Targeted pseudo-Java summaries:
{pseudo_block}

Output rules:
- Static review only. Do not run the APK, emulators, tests, or build steps.
- Every finding must identify source, trust boundary, flow path, sink, and exploitability.
- If a pattern looks real but incomplete, still report it as dormant-quality evidence rather than inventing a PoC.
- Prefer zero findings over weak findings. Empty output is good when the evidence is not there.
- If you do not find a real issue, output exactly: {{}}
- Do NOT copy literal placeholder text from this prompt. Any finding that uses generic filler values will be rejected.

Finding contract:
- Emit a single-line JSON object only for real evidence-backed findings.
- A CLASS finding must use:
  - agent = {profile.key}
  - category = class
  - class_name = {profile.key}
- A NOVEL finding must use:
  - agent = {profile.key}
  - category = novel
  - class_name = novel
- Required fields for any finding:
  - type: specific vulnerability label, not a generic placeholder
  - file: real relative smali path you actually inspected
  - line: real line number from that file
  - description: concrete reason this path is dangerous
  - severity: one of LOW, MEDIUM, HIGH, CRITICAL
  - context: concrete smali reasoning tied to this APK
  - source: real attacker-controlled input or trust entrypoint
  - trust_boundary: actual boundary crossed or missing guard
  - flow_path: concrete data flow, or the exact missing hop if incomplete
  - sink: real dangerous sink category or concrete sink
  - exploitability: concrete triggerability reasoning
- Never use values like "short vulnerability label", "relative/path.smali", "123", "LOW|MEDIUM|HIGH|CRITICAL", "identified source", "what boundary is crossed", "how the data moves", or other schema filler.
- Also print each finding JSON object on one line to stdout so the orchestrator can salvage findings from the agent log.
- Never emit placeholder findings, fake lines, or template text.
"""


def _spawn_apk_agent(
    profile: ApkHuntProfile,
    *,
    program: str,
    extracted_root: Path,
    findings_path: Path,
    agents_root: Path,
    registry_path: Path,
    registry_context: dict[str, Any],
    profile_context: str,
    targeted_files: Sequence[str],
    pseudo_java: dict[str, str],
    fresh: bool,
) -> AgentSession:
    workspace = agents_root / f"{profile.key}_{int(time.time() * 1000)}"
    ensure_directory(workspace)

    env = os.environ.copy()
    env["APK_TEAM_AGENT_NAME"] = profile.key
    env["APK_TEAM_AGENT_CLI"] = "codex"
    env["APK_TEAM_AGENT_PROMPT_BASE"] = _build_prompt_base(
        profile,
        program=program,
        extracted_root=extracted_root,
        findings_path=findings_path,
        registry_path=registry_path,
        registry_context=registry_context,
        profile_context=profile_context,
        targeted_files=targeted_files,
        pseudo_java=pseudo_java,
    )
    env["APK_TEAM_TARGET_PATH"] = str(extracted_root)
    env["APK_TEAM_AGENT_WORKDIR"] = str(workspace)
    env["APK_TEAM_AGENTS_DIR"] = str(agents_root)
    spawn_start = time.time()
    prompt_base = env["APK_TEAM_AGENT_PROMPT_BASE"]

    try:
        process = subprocess.Popen(
            ["bash", "-lc", _launcher_script()],
            cwd=str(extracted_root),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError as exc:
        fallback_log = agents_root / f"agent_{profile.key}_spawn_error.log"
        fallback_log.write_text(f"spawn failed: {exc}\n", encoding="utf-8")
        _safe_log_span(
            span_type="tool",
            phase="spawn",
            level="ERROR",
            message=f"spawn failed for {profile.key}",
            tool_name="codex_exec_spawn",
            tool_category="subprocess",
            target=str(extracted_root),
            prompt_tokens=_estimate_tokens(prompt_base),
            completion_tokens=0,
            context_tokens_before=_estimate_tokens(prompt_base),
            context_tokens_after=_estimate_tokens(prompt_base),
            tool_output_tokens=0,
            pte_lite=compute_pte_lite(
                prompt_tokens=_estimate_tokens(prompt_base),
                completion_tokens=0,
                tool_output_tokens=0,
                context_tokens_after=_estimate_tokens(prompt_base),
            ),
            latency_ms=int((time.time() - spawn_start) * 1000),
            input_bytes=len(prompt_base.encode("utf-8", errors="replace")),
            output_bytes=0,
            success=False,
            error=str(exc),
        )
        return AgentSession(profile=profile, workspace=workspace, log_path=fallback_log, process=None, skip_ledger=fresh)

    log_path = agents_root / f"agent_{profile.key}_{process.pid}.log"
    _safe_log_span(
        span_type="tool",
        phase="spawn",
        level="STEP",
        message=f"spawned {profile.key}",
        tool_name="codex_exec_spawn",
        tool_category="subprocess",
        target=str(extracted_root),
        prompt_tokens=_estimate_tokens(prompt_base),
        completion_tokens=0,
        context_tokens_before=_estimate_tokens(prompt_base),
        context_tokens_after=_estimate_tokens(prompt_base),
        tool_output_tokens=0,
        pte_lite=compute_pte_lite(
            prompt_tokens=_estimate_tokens(prompt_base),
            completion_tokens=0,
            tool_output_tokens=0,
            context_tokens_after=_estimate_tokens(prompt_base),
        ),
        latency_ms=int((time.time() - spawn_start) * 1000),
        input_bytes=len(prompt_base.encode("utf-8", errors="replace")),
        output_bytes=0,
        success=True,
    )
    return AgentSession(profile=profile, workspace=workspace, log_path=log_path, process=process, skip_ledger=fresh)


def _targeted_files_for_profile(registry: ApkSurfaceRegistry, profile: ApkHuntProfile) -> list[str]:
    direct_files = registry.file_paths_for_surfaces(profile.surface_types, limit=24)
    if len(direct_files) >= 12:
        return direct_files
    expanded = registry.expand_for_surface_types(profile.key, profile.surface_types, limit=60)
    return list(dict.fromkeys([*direct_files, *expanded]))


def _decompile_context(extracted_root: Path, targeted_files: Sequence[str]) -> dict[str, str]:
    candidate_paths = [extracted_root / item for item in targeted_files[:6]]
    if not candidate_paths:
        return {}
    return decompile_smali_targets(candidate_paths, base_root=extracted_root, max_files=4, max_methods=10)


def _prepare_profile_bundle(
    registry: ApkSurfaceRegistry,
    profile: ApkHuntProfile,
) -> tuple[dict[str, Any], list[str], dict[str, str]]:
    targeted_files = _targeted_files_for_profile(registry, profile)
    registry_context = registry.prompt_context(profile.surface_types, max_entries=20, max_files=40, max_expansions=5)
    pseudo_java = _decompile_context(registry.extracted_root, targeted_files)
    return registry_context, targeted_files, pseudo_java


def _run_single_profile(
    profile: ApkHuntProfile,
    *,
    program: str,
    extracted_root: Path,
    findings_path: Path,
    agents_root: Path,
    ledger: Any,
    fresh: bool,
    prepared_bundle: tuple[dict[str, Any], list[str], dict[str, str]],
    registry: ApkSurfaceRegistry,
) -> tuple[ApkHuntProfile, int]:
    registry_context, targeted_files, pseudo_java = prepared_bundle
    session = _spawn_apk_agent(
        profile,
        program=program,
        extracted_root=extracted_root,
        findings_path=findings_path,
        agents_root=agents_root,
        registry_path=registry.registry_path,
        registry_context=registry_context,
        profile_context=ledger.get_class_context(profile.key),
        targeted_files=targeted_files,
        pseudo_java=pseudo_java,
        fresh=fresh,
    )
    exit_code = run_agent_session(
        session,
        findings_path,
        ledger,
        extract_findings_from_log=extract_findings_from_log,
        maybe_log_span=_safe_log_span,
    )
    return profile, exit_code


def orchestrate_apk_team(
    program: str,
    apk_path: str,
    *,
    selected_profile: str | None = None,
    parallel: bool = False,
    chain: bool = False,
    fresh: bool = False,
    max_agents: int = DEFAULT_MAX_AGENTS,
    version_label: str | None = None,
    force_refresh_dynamic_agents: bool = False,
    output_root: str | Path | None = None,
    verbose: int = 0,
) -> dict[str, Any]:
    """
    1. Extract APK if not already (apktool)
    2. Run prefingerprint scan (~30s, builds surface_registry)
    3. Load built-in profiles and dynamic APK-focused profiles
    4. Run profiles in parallel with targeted file sets
    5. Ghost review -> dedupe -> optional chainer
    """
    global _APK_TEAM_LOGGER

    program_slug = _sanitize_program_name(program)
    storage_root_override = (
        Path(output_root).expanduser().resolve(strict=False) if output_root is not None else None
    )
    storage = resolve_team_storage(
        program_slug,
        team_type="apk",
        output_root=storage_root_override,
    )
    team_root = storage.lane_root
    agents_root = team_root / "agents"
    findings_path = storage.ledgers_root / FINDINGS_FILENAME
    ensure_directory(team_root)
    ensure_directory(agents_root)
    reset_findings_store(findings_path)

    if SubagentLogger is not None:
        try:
            _APK_TEAM_LOGGER = SubagentLogger("apk_team", program_slug, f"apkt_{int(time.time())}")
            _APK_TEAM_LOGGER.start(target=str(apk_path))
        except Exception:
            _APK_TEAM_LOGGER = None

    prefingerprint = build_surface_registry(
        program_slug,
        apk_path,
        output_root=team_root,
        logger=_APK_TEAM_LOGGER,
    )
    registry = ApkSurfaceRegistry.load(prefingerprint["surface_registry_path"])
    extracted_root = registry.extracted_root
    verbosity = clamp_verbosity(locals().get("verbose", 0))
    snapshot_identity = get_snapshot_identity(extracted_root, version_label=version_label or str(registry.payload.get("version_name") or ""))
    ledger = create_team_ledger_from_storage(
        program_slug,
        storage=storage,
        target_root=extracted_root,
        version_label=str(snapshot_identity.get("version_label") or registry.payload.get("version_name") or ""),
        snapshot_identity=snapshot_identity,
        agent="apk-team",
    )

    if verbosity.verbose:
        print(f"[apk_team] storage lane root={storage.lane_root}")
        print(f"[apk_team] reports root={storage.reports_root}")
        print(f"[apk_team] ledgers root={storage.ledgers_root}")
        print(f"[apk_team] snapshot id={snapshot_identity.get('snapshot_id')} version={snapshot_identity.get('version_label') or '(unspecified)'}")
        print(f"[apk_team] ledger path={ledger.path}")
    if verbosity.very_verbose:
        print(f"[apk_team] context root={storage.context_root}")
        print(f"[apk_team] working root={storage.working_root}")
        print(f"[apk_team] extracted root={extracted_root}")

    # MGP — shared memory across agents; best-effort
    mem = None
    if BountyMemory:
        try:
            mem = BountyMemory(agent_id=f"apk_team.{program_slug}", program=program_slug)
            print(f"[apk_team] 🌐 MGP initialized: apk_team.{program_slug}", flush=True)
        except Exception:
            mem = None

    dynamic_profiles: list[ApkHuntProfile] = []
    dynamic_version = (
        str(snapshot_identity.get("version_label") or "").strip()
        or str(registry.payload.get("version_name") or "").strip()
        or str(snapshot_identity.get("snapshot_id") or "").strip()
        or "unversioned"
    )
    dynamic_started = time.time()
    try:
        builder = DynamicAgentBuilder(program=program_slug, logger=_APK_TEAM_LOGGER)
        dynamic_specs = builder.run(
            extracted_root,
            program_slug,
            force_refresh=force_refresh_dynamic_agents,
            app_version=dynamic_version,
        )
        dynamic_profiles = [_profile_from_agent_spec(spec) for spec in dynamic_specs if getattr(spec, "key", "")]
        _safe_log_span(
            span_type="tool",
            phase="preflight",
            level="RESULT",
            message=f"dynamic agent builder loaded {len(dynamic_profiles)} APK profile(s)",
            tool_name="dynamic_agent_builder",
            tool_category="dynamic_agents",
            target=str(extracted_root),
            params={"version": dynamic_version, "count": len(dynamic_profiles)},
            prompt_tokens=_estimate_tokens(dynamic_version),
            completion_tokens=0,
            context_tokens_before=_estimate_tokens(dynamic_version),
            context_tokens_after=_estimate_tokens(dynamic_version),
            tool_output_tokens=_estimate_tokens("\n".join(profile.key for profile in dynamic_profiles)),
            pte_lite=compute_pte_lite(
                prompt_tokens=_estimate_tokens(dynamic_version),
                completion_tokens=0,
                tool_output_tokens=_estimate_tokens("\n".join(profile.key for profile in dynamic_profiles)),
                context_tokens_after=_estimate_tokens(dynamic_version),
            ),
            latency_ms=int((time.time() - dynamic_started) * 1000),
            input_bytes=len(dynamic_version.encode("utf-8", errors="replace")),
            output_bytes=len("\n".join(profile.key for profile in dynamic_profiles).encode("utf-8", errors="replace")),
            success=True,
        )
    except Exception as exc:
        _safe_log_span(
            span_type="tool",
            phase="preflight",
            level="ERROR",
            message="dynamic agent builder failed",
            tool_name="dynamic_agent_builder",
            tool_category="dynamic_agents",
            target=str(extracted_root),
            params={"version": dynamic_version},
            prompt_tokens=_estimate_tokens(dynamic_version),
            completion_tokens=0,
            context_tokens_before=_estimate_tokens(dynamic_version),
            context_tokens_after=_estimate_tokens(dynamic_version),
            tool_output_tokens=0,
            pte_lite=compute_pte_lite(
                prompt_tokens=_estimate_tokens(dynamic_version),
                completion_tokens=0,
                tool_output_tokens=0,
                context_tokens_after=_estimate_tokens(dynamic_version),
            ),
            latency_ms=int((time.time() - dynamic_started) * 1000),
            input_bytes=len(dynamic_version.encode("utf-8", errors="replace")),
            output_bytes=0,
            success=False,
            error=str(exc),
        )

    profiles = _select_profiles(selected_profile, dynamic_profiles)
    prepared_bundles: dict[str, tuple[dict[str, Any], list[str], dict[str, str]]] = {}
    for profile in profiles:
        prepared_bundles[profile.key] = _prepare_profile_bundle(registry, profile)

    # MGP: record APK profile coverage, but do not block reruns.
    # APK analysis is intentionally incremental: the same profile may need to be rerun
    # as prompts evolve, evidence accumulates, or the profile mix changes over time.
    mgp_skipped: list[str] = []
    mgp_scheduled: list[str] = []
    if mem is not None:
        mgp_scheduled = [profile.key for profile in profiles]
        if fresh:
            print("[apk_team] 🌐 fresh mode enabled, forcing a real rerun of all selected profiles", flush=True)
        else:
            print("[apk_team] 🌐 MGP logging enabled, but tested-profile skip gate is disabled for incremental APK reruns", flush=True)

    worker_cap = min(MAX_PARALLEL_AGENTS, max(1, int(max_agents or DEFAULT_MAX_AGENTS)))
    if parallel:
        print(f"[apk_team] Running {len(profiles)} profiles in PARALLEL mode (cap: {worker_cap})")
        with ThreadPoolExecutor(max_workers=min(worker_cap, len(profiles) or 1)) as pool:
            futures = {
                pool.submit(
                    _run_single_profile,
                    profile,
                    program=program_slug,
                    extracted_root=extracted_root,
                    findings_path=findings_path,
                    agents_root=agents_root,
                    ledger=ledger,
                    fresh=fresh,
                    prepared_bundle=prepared_bundles[profile.key],
                    registry=registry,
                ): profile
                for profile in profiles
            }
            for future in as_completed(futures):
                profile = futures[future]
                try:
                    completed_profile, exit_code = future.result()
                    print(f"[apk_team] {completed_profile.key} finished (exit={exit_code})")
                    # MGP: record that this profile was tested (regardless of outcome)
                    if mem is not None:
                        profile_key = f"profile:{dynamic_version}:{completed_profile.key}"
                        mem.claim_tested(program_slug, profile_key, result=f"exit={exit_code}")
                except Exception as exc:
                    print(f"[apk_team] {profile.key} raised: {exc}")
    else:
        print(f"[apk_team] Running {len(profiles)} profiles in SEQUENTIAL mode")
        for index, profile in enumerate(profiles, start=1):
            print(f"[apk_team] Starting {index}/{len(profiles)}: {profile.key}")
            _run_single_profile(
                profile,
                program=program_slug,
                extracted_root=extracted_root,
                findings_path=findings_path,
                agents_root=agents_root,
                ledger=ledger,
                fresh=fresh,
                prepared_bundle=prepared_bundles[profile.key],
                registry=registry,
            )
            # MGP: record that this profile was tested
            if mem is not None:
                profile_key = f"profile:{dynamic_version}:{profile.key}"
                mem.claim_tested(program_slug, profile_key, result="completed")
            print(f"[apk_team] Finished {index}/{len(profiles)}: {profile.key}")

    raw_findings = load_findings(findings_path)
    prefiltered_findings: list[dict[str, Any]] = []
    prefilter_rejected = 0
    for finding in raw_findings:
        if is_placeholder_finding(finding):
            prefilter_rejected += 1
            if verbosity.very_verbose:
                title = str(finding.get("vulnerability_name") or finding.get("type") or "untitled").strip()
                print(f"[prefilter] REJECTED placeholder before review: {title}")
            continue
        prefiltered_findings.append(finding)
    if verbosity.verbose and prefilter_rejected:
        print(f"[apk_team] prefilter rejected {prefilter_rejected} placeholder finding(s) before review")
    confirmed_findings, dormant_findings, novel_findings = stage2_ghost_review(
        prefiltered_findings,
        extracted_root,
        program_slug,
        "apk",
        output_root=storage_root_override,
    )
    reviewed_findings = confirmed_findings + dormant_findings + novel_findings
    ledger_updates = 0
    for finding in reviewed_findings:
        title = str(finding.get("vulnerability_name") or finding.get("type") or "").strip() or "untitled"
        if is_placeholder_finding(finding):
            print(f"[ledger] REJECTED placeholder finding: {title}", flush=True)
            continue
        fid = str(finding.get("fid", "")).strip()
        if fid:
            try:
                update_team_finding(
                    program_slug,
                    finding,
                    snapshot_id=str(snapshot_identity.get("snapshot_id") or ""),
                    version_label=str(snapshot_identity.get("version_label") or ""),
                    run_id=getattr(ledger, "run_id", None),
                    agent="apk-team",
                    family=storage.family,
                    lane=storage.lane,
                    root_override=getattr(ledger, "root_override", storage_root_override),
                    write_report=False,
                    refresh=False,
                    update_current=False,
                    update_sighting=False,
                )
                ledger_updates += 1
                if verbosity.very_verbose:
                    print(f"[ledger] UPDATED {fid} via {ledger.path}")
            except Exception as exc:
                print(f"[ledger] FAILED update {fid}: {exc}", flush=True)
        registry.record_progressive_finding(finding, requested_by=str(finding.get("agent") or "apk-team"))
        # MGP: claim this finding so other agents know it's confirmed
        if mem is not None:
            try:
                severity = str(finding.get("severity") or finding.get("review_tier") or "UNKNOWN").strip()
                mem.claim_finding(
                    program=program_slug,
                    fid=fid,
                    severity=severity,
                    description=title,
                    evidence=[str(findings_path / "findings.jsonl")],
                    confidence=0.85,
                )
            except Exception:
                pass
        _safe_log_span(
            span_type="finding",
            level="RESULT",
            message=f"Finding: {fid or title}",
            finding_fid=fid or title,
            review_tier=str(finding.get("review_tier") or finding.get("severity") or "UNKNOWN"),
            duplicate=False,
            finding_reward=0,
            allocated_pte_lite=0,
        )

    confirmed_report_path, dormant_report_path, novel_report_path = dated_report_index_paths(storage)
    report_root = confirmed_report_path.parent
    rejected_count = max(0, len(raw_findings) - len(reviewed_findings))
    summary = summarize_findings(reviewed_findings)
    summary["raw_findings"] = len(raw_findings)
    summary["profiles_run"] = [profile.key for profile in profiles]
    summary["by_tier"] = {
        "confirmed": len(confirmed_findings),
        "dormant": len(dormant_findings),
        "rejected": rejected_count,
    }
    summary["storage"] = {
        "lane_root": str(storage.lane_root),
        "reports_root": str(storage.reports_root),
        "ledgers_root": str(storage.ledgers_root),
    }
    summary["reports"] = {
        "confirmed_date_root": str(confirmed_report_path.parent),
        "dormant_date_root": str(dormant_report_path.parent),
        "novel_date_root": str(novel_report_path.parent),
        "confirmed": str(confirmed_report_path),
        "dormant": str(dormant_report_path),
        "novel_findings": str(novel_report_path),
    }
    summary["surface_registry"] = {
        "path": str(registry.registry_path),
        "stats": registry.payload.get("stats") or {},
        "package_name": registry.payload.get("package_name"),
        "version_name": registry.payload.get("version_name"),
    }
    summary["snapshot"] = snapshot_identity
    summary["dynamic_agents"] = {
        "count": len(dynamic_profiles),
        "keys": [profile.key for profile in dynamic_profiles],
        "version": dynamic_version,
    }
    summary["ledger_updates"] = ledger_updates
    if verbosity.verbose:
        print(f"[apk_team] ledger_updates={ledger_updates} ledger_path={ledger.path}")
        print(f"[apk_team] confirmed_date_root={confirmed_report_path.parent}")
        print(f"[apk_team] dormant_date_root={dormant_report_path.parent}")
        print(f"[apk_team] novel_date_root={novel_report_path.parent}")
        print(f"[apk_team] confirmed_report={confirmed_report_path}")
        print(f"[apk_team] dormant_report={dormant_report_path}")
        print(f"[apk_team] novel_report={novel_report_path}")
    pretty_print_findings(reviewed_findings, display_file_reference=display_file_reference)

    if chain and reviewed_findings:
        graph = build_chain_graph(reviewed_findings)
        chainable = get_chainable_findings(reviewed_findings)
        print(f"[chain] {len(chainable)}/{len(reviewed_findings)} findings are chainable")
        if chainable:
            chain_input_path = write_chainable_findings_input(team_root / "chainable_findings.json", chainable)
            try:
                spec = importlib.util.spec_from_file_location("chainer", Path(__file__).parent / "chainer.py")
                chainer_mod = importlib.util.module_from_spec(spec)  # type: ignore[assignment]
                assert spec.loader is not None
                spec.loader.exec_module(chainer_mod)  # type: ignore[union-attr]
                chainer_result = chainer_mod.main(
                    [
                        program_slug,
                        "--source",
                        str(extracted_root),
                        "--findings-json",
                        str(chain_input_path),
                        "--output-dir",
                        str(storage.reports_root / "chained"),
                    ]
                )
                print(
                    f"[apk_team] Chainer complete: {chainer_result} chain(s); "
                    f"graph nodes={len(graph.get('nodes', []))} edges={len(graph.get('edges', []))}"
                )
            except Exception as exc:
                print(f"[apk_team] Chainer failed: {exc}")
        else:
            print("[apk_team] No chainable findings; skipping chainer.")
    elif chain:
        print("[apk_team] --chain set but there are no reviewed findings to chain.")

    return summary


def _parse_cli_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run APK-specific progressive surface hunting.")
    parser.add_argument("program", nargs="?", help="Bug bounty program name used for output directories.")
    parser.add_argument("apk_path", help="APK file or already-extracted APK directory.")
    parser.add_argument("--program", dest="program_override", help="Optional override for the program slug.")
    parser.add_argument("--profile", dest="selected_profile", help="Run only a single APK profile.")
    parser.add_argument("--parallel", action="store_true", help="Run APK profiles concurrently.")
    parser.add_argument("--chain", action="store_true", help="Run the chainer after review.")
    parser.add_argument("--fresh", action="store_true", help="Skip ledger dedupe and treat findings as new.")
    parser.add_argument("--max-agents", type=int, default=DEFAULT_MAX_AGENTS, help="Default 8, hard cap 10.")
    parser.add_argument("--version", dest="version_label", help="Override snapshot version label.")
    parser.add_argument(
        "--force-refresh-dynamic-agents",
        action="store_true",
        help="Regenerate dynamic agent specs for the current APK version.",
    )
    parser.add_argument("--output-root", help="Override the apk_team output root.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v or -vv).")
    args = parser.parse_args(list(argv))
    if not args.program and not args.program_override:
        parser.error("program is required either positionally or via --program")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_cli_args(argv or sys.argv[1:])
    program = args.program_override or args.program
    result = orchestrate_apk_team(
        program,
        args.apk_path,
        selected_profile=args.selected_profile,
        parallel=args.parallel,
        chain=args.chain,
        fresh=args.fresh,
        max_agents=args.max_agents,
        version_label=args.version_label,
        force_refresh_dynamic_agents=args.force_refresh_dynamic_agents,
        output_root=args.output_root,
        verbose=args.verbose,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
