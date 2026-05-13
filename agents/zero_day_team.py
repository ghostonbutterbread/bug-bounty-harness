"""Zero-day team orchestration for class-based static-analysis security agents."""

from __future__ import annotations

import argparse
import fcntl
import json
import math
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

# Allow standalone execution from project root or agents/ subdirectory
_agent_dir = Path(__file__).resolve().parent
_project_root = _agent_dir.parent
if _project_root.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _project_root.as_posix())
_bounty_tools_root = Path.home() / "projects" / "bounty-tools"
if _bounty_tools_root.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _bounty_tools_root.as_posix())
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from agents.base_team import AgentSpec as TeamAgentSpec
from agents.base_team import BaseTeam
from agents.base_team import (
    extract_findings_from_log as shared_extract_findings_from_log,
    normalize_finding as shared_normalize_finding,
    read_findings_jsonl as shared_read_findings_jsonl,
    safe_int as shared_safe_int,
)
from agents.chain_matrix import build_chain_graph, get_chainable_findings  # type: ignore[attr-defined]
from agents.hybrid_preflight import run_preflight  # type: ignore[attr-defined]
from agents.dynamic_agent_builder import DynamicAgentBuilder  # type: ignore[attr-defined]
from agents.ledger import create_team_ledger_from_storage, update_team_finding
from agents.shared_brain import (  # type: ignore[attr-defined]
    build_index,
    get_class_context as get_shared_brain_class_context,
    get_diverse_entry_points,
    load_index,
    save_index,
    update_index,
)
from agents.coverage_store import CoverageStore
from agents.base_team.promotion import promote_reviewed_findings
from agents.base_team.review import stage2_ghost_review as shared_stage2_ghost_review
from agents.base_team.storage import resolve_team_storage
from agents.brainstorm_adapters import (
    brainstorm_intents_to_dynamic_agent_specs,
    spec_uses_category_master_agents,
)
from agents.brainstorm_spec import parse_brainstorm_spec
from agents.bounty_core_bootstrap import ensure_bounty_core_importable
from agents.hunting_policy import HuntingPolicy, coerce_hunting_policy, resolve_hunting_policy, resolve_policy_selection
from agents.base_team.scheduler import BaseTeamSchedulerOptions, schedule_profiles
from agents.snapshot_identity import get_snapshot_identity
from agents.verbosity import clamp_verbosity

ensure_bounty_core_importable()

from bounty_core.reports import DAILY_REPORT_DATE_FORMAT, daily_report_paths  # noqa: E402

ensure_bounty_core_importable("bounty_core.brainstorm_spec")

from bounty_core.brainstorm_spec import (  # noqa: E402
    append_coverage,
    appmap_assignment_identity,
    is_appmap_assignment_covered,
    read_coverage_jsonl,
)

try:
    from subagent_logger import SubagentLogger, compute_pte_lite
except ImportError:  # pragma: no cover
    SubagentLogger = None

    def compute_pte_lite(**kwargs) -> int:
        return (
            int(kwargs.get("prompt_tokens") or 0)
            + int(kwargs.get("completion_tokens") or 0)
            + int(kwargs.get("tool_output_tokens") or 0)
        )

FINDINGS_FILENAME = "findings.jsonl"
AGENT_TIMEOUT_SECONDS = 1800
CLAUDE_REVIEW_TIMEOUT_SECONDS = 600
CLAUDE_REVIEW_MAX_WORKERS = 4
MAX_PARALLEL_AGENTS = 10  # hard cap on concurrent sub-agents
SOURCE_EXCERPT_MAX_LINE_CHARS = 1200
_ZERO_DAY_TEAM_LOGGER = None


def _timestamp_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")

SOURCE_TRUST_CONTEXT_PROMPT = (
    "Treat sources conceptually as data originating outside the current trust "
    "context, not as a closed checklist. This includes but is not limited to: "
    "IPC messages, file paths, network responses, localStorage/sessionStorage, "
    "postMessage origins, clipboard data, URL parameters, config files, plugin "
    "inputs, environment variables, and any data crossing from a less-trusted "
    "component into a more-trusted one."
)

FIVE_STEP_REASONING_FLOW = (
    "1. ENTRY   -> Where does untrusted data enter?\n"
    "2. CROSS   -> Does it cross a trust boundary distinct from the entry point?\n"
    "3. FLOW    -> How does it move through the application?\n"
    "4. SINK    -> What dangerous operation category does it reach?\n"
    "5. EXPLOIT -> Can an attacker actually trigger the full path in practice?"
)


def _estimate_tokens_from_text(text: str | bytes | None) -> int:
    if text is None:
        return 0
    if isinstance(text, bytes):
        size = len(text)
    else:
        size = len(str(text).encode("utf-8", errors="replace"))
    return max(0, math.ceil(size / 4))


def _safe_log_span(**fields: Any) -> None:
    if _ZERO_DAY_TEAM_LOGGER is None:
        return
    try:
        _ZERO_DAY_TEAM_LOGGER.log_span(**fields)
    except Exception:
        pass


@dataclass(frozen=True)
class VulnerabilityClassProfile:
    """Definition of a class-focused static analysis pass."""

    key: str
    description: str
    entry_questions: Tuple[str, ...]
    cross_questions: Tuple[str, ...]
    sink_categories: Tuple[str, ...]
    reasoning: str
    display_name: str | None = None
    prompt_addendum: str = ""
    focus_globs: Tuple[str, ...] = ()
    ignore_globs: Tuple[str, ...] = ()
    brainstorm_metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def title(self) -> str:
        return str(self.display_name or self.key.replace("-", " ").title())


CLASS_PROFILES: Dict[str, VulnerabilityClassProfile] = {
    "dom-xss": VulnerabilityClassProfile(
        key="dom-xss",
        description=(
            "Cross-Site Scripting in the browser renderer. Any code that takes "
            "data from an external or untrusted source and passes it to an "
            "operation that interprets it as HTML, JS, or CSS."
        ),
        entry_questions=(
            "What data enters the renderer from outside?",
            "Is any of it derived from user-controlled sources (files, IPC, network)?",
        ),
        cross_questions=(
            "Does data from a lower-privilege context reach a higher-privilege operation?",
            "Does IPC data from the main process contain unsanitized user-controlled values?",
        ),
        sink_categories=(
            "DOM operations that interpret content as HTML/JS (innerHTML, outerHTML, insertAdjacentHTML, document.write)",
            "String-to-code evaluation (eval, setTimeout/setInterval with string, Function constructor, new Function, running JS from strings)",
            "Remote resource loading from attacker-controlled URLs (script src, img src, link href, fetch from user-controlled URL)",
        ),
        reasoning=(
            "Ask: can an attacker position malicious data at this source? Ask: does "
            "the app sanitize or encode before reaching this sink? Ask: even if "
            "sanitized, is there a bypass for this specific context?"
        ),
    ),
    "exec-sink-reachability": VulnerabilityClassProfile(
        key="exec-sink-reachability",
        description=(
            "Remote code execution by reaching a privileged execution sink. "
            "Any flow where attacker-influenced data can control process execution, "
            "dynamic code evaluation, deserialization with gadget execution, "
            "module/plugin/library loading, or execution of downloaded/extracted helpers. "
            "This is the highest-impact RCE class for desktop apps: IPC-to-child_process, "
            "updater abuse, helper tool invocation, and plugin loading from attacker-controlled sources."
        ),
        entry_questions=(
            "What untrusted data enters from IPC, files, archives, network, update metadata, deep links, plugin manifests, or renderer content?",
            "Can any of that data influence commands, executable paths, arguments, code strings, module paths, serialized bytes, or helper selection?",
            "Does the app invoke external helper tools (ffmpeg, convert, tar, unzip, osascript, powershell, gs)?",
            "Does the app have an auto-update or download-and-execute feature?",
        ),
        cross_questions=(
            "Does data cross renderer->preload->main, managed->native, parser->helper, archive->filesystem, or updater->executor boundaries?",
            "Can a lower-privilege component choose what code/process/module executes in a higher-privilege component?",
            "Can attacker-controlled data in a file, archive, or IPC message reach a shell or subprocess invocation?",
        ),
        sink_categories=(
            "OS/process execution sinks (child_process.exec/spawn/fork, subprocess.Popen, Runtime.exec, system/exec/CreateProcess/ShellExecute, os.system, popen, node-pty)",
            "Dynamic code evaluation or embedded interpreter execution (eval, Function, vm.runIn*, ScriptEngine, GroovyShell, Python eval/exec/compile)",
            "Module/plugin/library/class loading from attacker-influenced path, URL, bytes, or name (require, __import__, importlib, dlopen, LoadLibrary, URLClassLoader, defineClass)",
            "Execution of downloaded, extracted, converted, or updated helper artifacts (auto-updater, installer hooks, converter scripts)",
            "Archive extraction writing to autoload directories, startup folders, or search-path locations",
        ),
        reasoning=(
            "Ask: does the attacker control code, command text, executable path, arguments, module path, or serialized payload bytes? "
            "Ask: are there strict allowlists, argument arrays, type gates, signatures, or path constraints in place? "
            "Ask: is execution immediate, or does it require restart, update, or a secondary trigger? "
            "Ask: if a helper tool is invoked, can the attacker control its path, arguments, or input files? "
            "Ask: if an updater downloads and runs a binary, can the attacker intercept or control that binary?"
        ),
    ),
    "ipc-trust-boundary": VulnerabilityClassProfile(
        key="ipc-trust-boundary",
        description=(
            "IPC/preload bridge trust boundary abuse. The preload bridge is a "
            "critical trust boundary. Data flowing from the main process to the "
            "renderer should be considered untrusted if the main process can be influenced."
        ),
        entry_questions=(
            "What functions are exposed via the preload bridge (window.localUserData, etc.)?",
            "Can attacker-controlled data reach these functions?",
        ),
        cross_questions=(
            "Does IPC data passed through the preload bridge get validated?",
            "Can a compromised renderer call privileged main-process functions?",
        ),
        sink_categories=(
            "Direct IPC invoke calls to main process methods",
            "fs/child_process access via preload bridge",
            "Arbitrary code execution via executeHostFunction or similar bridges",
        ),
        reasoning=(
            "Ask: what can the renderer do via the preload bridge that it couldn't "
            "do directly? Ask: if the renderer is compromised, what can it reach "
            "via IPC? Ask: is the preload API surface minimal and safe, or is "
            "everything exposed?"
        ),
    ),
    "native-module-abuse": VulnerabilityClassProfile(
        key="native-module-abuse",
        description=(
            "Native Node module abuse. Native modules like better-sqlite3, keytar, "
            "fswin have full system access. If accessible from renderer, any "
            "vulnerability in them becomes critical."
        ),
        entry_questions=(
            "What native modules are loaded (better-sqlite3, keytar, native extensions)?",
            "Are they accessible from the renderer context?",
        ),
        cross_questions=(
            "Can renderer JS load and interact with native modules?",
            "Do native modules handle untrusted input unsafely?",
        ),
        sink_categories=(
            "SQL execution via better-sqlite3 with attacker-controlled SQL",
            "Credential storage access via keytar",
            "Arbitrary file access via fswin or similar native fs wrappers",
        ),
        reasoning=(
            "Ask: what happens when a native module receives malformed input? "
            "Ask: if the renderer can call native modules, what's the blast radius?"
        ),
    ),
    "memory-unsafe-parser": VulnerabilityClassProfile(
        key="memory-unsafe-parser",
        description=(
            "Memory corruption bugs in native parsers: buffer overflows, integer overflows, "
            "format string vulnerabilities, and unsafe operations in C/C++/Rust code that parses "
            "external input (fonts, media, archives, images, network protocols). "
            "NOTE: Exploitability confirmation requires binary analysis with knowledge of memory layout, "
            "ASLR, canaries, and allocator behavior. Source analysis alone can identify dangerous "
            "patterns but cannot confirm RCE. Flag these as DORMANT unless binary validation is available."
        ),
        entry_questions=(
            "What native code parses external input (files, network data, protocol messages)?",
            "Are there C/C++/Rust parsers for fonts, media, archives, images, or custom protocols?",
            "What data formats are parsed: binary file formats, network protocols, serialization formats?",
        ),
        cross_questions=(
            "Does external data reach native memory operations (memcpy, strcpy, sprintf, read, recv, fread)?",
            "Are size/length fields from the input used without validation in allocation or copy operations?",
            "Can integer overflow in size calculations lead to underallocation or out-of-bounds access?",
        ),
        sink_categories=(
            "Unbounded memory operations: memcpy/memmove/strcpy/strcat/sprintf/vsprintf without length checks",
            "Integer overflow in allocation math: count * size, width * height * channels without overflow checks",
            "Format string bugs: printf/fprintf/sprintf with user-controlled format strings",
            "Unchecked reads: read/recv/fread reading into fixed buffers without validating size",
            "Missing bounds checks in recursive parsers (nested archives, recursive includes, deep font tables)",
            "Rust unsafe: from_raw_parts, copy_nonoverlapping, get_unchecked, unchecked arithmetic",
            "Go unsafe: unsafe.Pointer in cgo or manual slice manipulation with attacker-controlled data",
        ),
        reasoning=(
            "Ask: does attacker-controlled data from a file or network reach a native memory operation? "
            "Ask: are size/length fields from the input used in allocation or copy operations without validation? "
            "Ask: could integer overflow, truncation, or signedness issues cause a wrong size calculation? "
            "Ask: are there format string vulnerabilities where user data reaches a formatting function? "
            "IMPORTANT: Even if a dangerous pattern is found, assess exploitability as UNKNOWN without binary analysis. "
            "Mark as DORMANT and note: requires Ghidra/Binary Ninja analysis + memory layout knowledge to confirm."
        ),
    ),
    "node-integration": VulnerabilityClassProfile(
        key="node-integration",
        description=(
            "nodeIntegration and contextIsolation misconfiguration. "
            "nodeIntegration:true gives the renderer full Node.js access. "
            "contextIsolation:false means preload scripts share the renderer JS context."
        ),
        entry_questions=(
            "Is nodeIntegration enabled in BrowserWindow config?",
            "Is contextIsolation disabled?",
            "Is the remote module enabled?",
        ),
        cross_questions=(
            "Can renderer JS access require(), process, or fs directly?",
            "Can prototype pollution in renderer affect main process?",
        ),
        sink_categories=(
            "Direct Node.js API access from renderer (require, process, fs, child_process, net, tls)",
            "Prototype pollution reaching main process objects",
            "Remote module exposure to renderer",
        ),
        reasoning=(
            "Ask: if XSS exists in this renderer, what can the attacker do with "
            "Node access? Ask: is contextIsolation actually protecting anything if "
            "preload has vulnerabilities?"
        ),
    ),
    "path-traversal": VulnerabilityClassProfile(
        key="path-traversal",
        description=(
            "File operations on attacker-controlled paths. Any file operation "
            "(open, read, write, copy, mkdir, chmod) on a path derived from user "
            "input or external data."
        ),
        entry_questions=(
            "What file operations exist in the codebase?",
            "Are any paths derived from user input, IPC messages, or file selection dialogs?",
        ),
        cross_questions=(
            "Can an attacker provide paths outside the intended directory?",
            "Do path traversal protections actually work for all edge cases?",
        ),
        sink_categories=(
            "File read on attacker-controlled path (readFile, open with user path)",
            "File write on attacker-controlled path (writeFile, copyFile, mkdir creating outside target dir)",
            "Symlink attacks (reading/writing through symlinks to sensitive locations)",
        ),
        reasoning=(
            "Ask: if an attacker can control the path, what can they read/write? "
            "Ask: does the app handle ~, .., absolute paths, UNC paths (Windows), "
            "/proc (Linux)? Ask: what files are actually accessible via traversal?"
        ),
    ),
    "prototype-pollution": VulnerabilityClassProfile(
        key="prototype-pollution",
        description=(
            "JavaScript prototype pollution. Merge/object spread operations that "
            "pollute Object.prototype or constructor.prototype. Dangerous in "
            "Electron when polluted prototypes affect renderer or main process objects."
        ),
        entry_questions=(
            "Does the app use JSON.parse on external data?",
            "Are there deep merge/assign operations on user-controlled objects?",
            "Does the app use __proto__, constructor, or prototype in any operation?",
        ),
        cross_questions=(
            "Can prototype pollution in renderer affect IPC message objects?",
            "Can polluted objects reach main process via preload?",
        ),
        sink_categories=(
            "Deep object merge/assign without prototype checks",
            "__proto__ assignment in user-data handling",
            "Constructor.prototype assignment",
        ),
        reasoning=(
            "Ask: if you pollute Object.prototype, what becomes available to all "
            "objects? Ask: can prototype pollution enable a secondary attack "
            "(XSS to RCE, auth bypass)?"
        ),
    ),
    "unsafe-deserialization": VulnerabilityClassProfile(
        key="unsafe-deserialization",
        description=(
            "Unsafe deserialization leading to arbitrary code execution via gadget chains. "
            "When user-controllable data is deserialized without strict type validation, "
            "an attacker can craft a payload that invokes dangerous operations during reconstruction. "
            "Affects pickle, YAML, JSON (in some languages), XML decoding, and custom binary formats."
        ),
        entry_questions=(
            "What deserialization functions are called in this codebase?",
            "What data reaches them — files, IPC messages, network responses, URL params, localStorage?",
            "Are serialized formats used for IPC, plugin manifests, config files, update metadata, or user data?",
        ),
        cross_questions=(
            "Does deserialized data originate from an untrusted source (renderer, file, network, user input)?",
            "Can an attacker supply a malicious serialized payload?",
            "Are there gadget-capable classes in scope that could be chained during deserialization?",
        ),
        sink_categories=(
            "Python: pickle.loads, dill.loads, yaml.load (unsafe), marshal.loads, any unsafe unpickler",
            "Ruby: Marshal.load, YAML.load (unsafe), Oj.load with unsafe mode",
            "Java: ObjectInputStream.readObject, XMLDecoder, XStream (unsafe configs), SnakeYAML, Kryo, Hessian, Fastjson, Jackson with polymorphic typing",
            "JavaScript/Node: deserialization libraries reviving functions or objects (e.g., node-serialize, deserialize)",
            "Custom binary or protocol deserializers with no type allowlisting",
        ),
        reasoning=(
            "Ask: does user-controllable data reach a deserialization function? "
            "Ask: is there any type validation, signature check, or allowlist before deserialization? "
            "Ask: are there known gadget classes in scope that could execute code or commands when materialized? "
            "Ask: could a crafted payload cause remote code execution, file write, or command execution?"
        ),
    ),
    "ssrf": VulnerabilityClassProfile(
        key="ssrf",
        description=(
            "Server-Side Request Forgery. HTTP requests made by the app where the "
            "URL is derived from user input or external data."
        ),
        entry_questions=(
            "Does the app make HTTP requests?",
            "Are any URLs derived from user input, file contents, or external sources?",
        ),
        cross_questions=(
            "Can an attacker probe internal services (169.254.169.254, localhost, internal networks)?",
            "Can SSRF exfiltrate cloud metadata or internal API responses?",
        ),
        sink_categories=(
            "HTTP requests to user-controlled URLs (fetch, axios, request, urllib)",
            "URLs constructed from path parameters or file contents",
            "Redirect following from untrusted sources",
        ),
        reasoning=(
            "Ask: can an attacker control the destination URL? Ask: can they read "
            "the response (information disclosure) or just trigger the request "
            "(blind SSRF)? Ask: are there cloud metadata endpoints reachable "
            "(169.254.169.254)?"
        ),
    ),
}


class ZeroDayTeam(BaseTeam):
    """Class-based zero-day team built on the shared BaseTeam framework."""

    def get_static_profiles(self) -> list[TeamAgentSpec]:
        snapshot_id = self._snapshot_id() or "unspecified"
        created_at = _timestamp_iso()
        return [
            self._spec_from_profile(profile, snapshot_id=snapshot_id, created_at=created_at)
            for profile in CLASS_PROFILES.values()
        ]

    def generate_dynamic_from_surfaces(
        self,
        surfaces: Sequence[dict[str, Any]],
        *,
        snapshot_id: str,
    ) -> list[TeamAgentSpec]:
        created_at = _timestamp_iso()
        specs: list[TeamAgentSpec] = []
        for surface in surfaces:
            surface_type = str(surface.get("surface_type") or "repo-surface").strip() or "repo-surface"
            vuln_class = str(surface.get("vuln_class") or "custom-flow").strip() or "custom-flow"
            key = str(surface.get("key") or f"{self.program}-{surface_type}-{vuln_class}").strip()
            description = str(surface.get("description") or "").strip()
            patterns = [str(item).strip() for item in (surface.get("patterns") or []) if str(item).strip()]
            focus_globs = [
                str(item).strip()
                for item in (surface.get("focus_files_glob") or [])
                if str(item).strip()
            ]
            prompt_template = self._dynamic_prompt(
                key=key,
                surface_type=surface_type,
                vuln_class=vuln_class,
                description=description,
                patterns=patterns,
                upstream_prompt=str(surface.get("agent_prompt_template") or "").rstrip(),
            )
            specs.append(
                TeamAgentSpec(
                    key=key,
                    vuln_class=vuln_class,
                    surface=surface_type,
                    prompt_template=prompt_template,
                    focus_globs=focus_globs,
                    code_patterns=patterns,
                    program=self.program,
                    created_at=created_at,
                    snapshot_id=snapshot_id,
                )
            )
        return specs

    def _spec_from_profile(
        self,
        profile: VulnerabilityClassProfile,
        *,
        snapshot_id: str,
        created_at: str,
    ) -> TeamAgentSpec:
        return TeamAgentSpec(
            key=profile.key,
            vuln_class=profile.key,
            surface=profile.key,
            prompt_template=self._static_prompt(profile),
            focus_globs=list(profile.focus_globs),
            code_patterns=list(profile.sink_categories),
            program=self.program,
            created_at=created_at,
            snapshot_id=snapshot_id,
        )

    def _static_prompt(self, profile: VulnerabilityClassProfile) -> str:
        entry_questions = "\n".join(f"- {item}" for item in profile.entry_questions) or "- None"
        cross_questions = "\n".join(f"- {item}" for item in profile.cross_questions) or "- None"
        sink_categories = "\n".join(f"- {item}" for item in profile.sink_categories) or "- None"
        return (
            f"You are a zero-day static-analysis hunter focused on the vulnerability class "
            f"'{profile.key}' ({profile.title}).\n\n"
            "Program: {program}\n"
            "Target root: {target_path}\n"
            "Shared brain index: {shared_brain_index}\n"
            "Append-only findings file: {findings_path}\n"
            "Ledger path: {ledger_path}\n"
            "Snapshot id: {snapshot_id}\n\n"
            f"Class description:\n{profile.description}\n\n"
            "Entry questions:\n"
            f"{entry_questions}\n\n"
            "Trust-boundary questions:\n"
            f"{cross_questions}\n\n"
            "Sink categories:\n"
            f"{sink_categories}\n\n"
            "Preferred focus globs:\n"
            "{focus_globs}\n\n"
            "Relevant code patterns:\n"
            "{code_patterns}\n\n"
            "Rules:\n"
            "- Perform static review only.\n"
            "- Prove the source, trust boundary, flow, sink, and practical exploitability.\n"
            "- If a strong issue does not fit this class, mark it as category=novel instead of forcing it.\n"
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
            f"You are a zero-day dynamic hunter for the '{surface_type}' surface with primary focus "
            f"on '{vuln_class}'.\n\n"
            "Program: {program}\n"
            "Target root: {target_path}\n"
            "Shared brain index: {shared_brain_index}\n"
            "Append-only findings file: {findings_path}\n"
            "Ledger path: {ledger_path}\n"
            "Snapshot id: {snapshot_id}\n\n"
            f"Dynamic agent key: {key}\n"
            f"Surface summary: {description or surface_type}\n"
            "Focus globs:\n"
            "{focus_globs}\n\n"
            "Relevant code patterns:\n"
            f"{pattern_lines}"
            f"{upstream_section}\n"
            "Rules:\n"
            "- Perform static review only.\n"
            "- Stay anchored to this detected surface rather than rescanning the whole repository blindly.\n"
            "- Prioritize concrete source-to-sink reachability that makes the target vulnerability class materially exploitable.\n"
            "- If there is no real issue, print exactly {{}}.\n"
            "- When you find an issue, append a single-line JSON object to {findings_path} and print the same JSON line to stdout.\n"
            "- Use keys: agent, category, class_name, type, file, line, description, severity, context, source, trust_boundary, flow_path, sink, exploitability.\n"
        )


@dataclass
class AgentSession:
    """Live or completed agent execution context."""

    profile: VulnerabilityClassProfile
    workspace: Path
    log_path: Path
    process: Optional[subprocess.Popen]
    skip_ledger: bool = False
    coverage_path: Path | None = None


def _sanitize_program_name(program: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", program.strip())
    return cleaned or "default_program"


def _ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _reset_findings_store(path: Path) -> None:
    _ensure_directory(path.parent)
    path.write_text("", encoding="utf-8")


def _normalize_class_name(value: str) -> str:
    return value.strip().lower()


def _profile_from_agent_spec(spec: Any) -> VulnerabilityClassProfile:
    focus_globs = tuple(
        str(item).strip()
        for item in (
            getattr(spec, "focus_files_glob", None)
            or getattr(spec, "focus_globs", None)
            or []
        )
        if str(item).strip()
    )
    ignore_globs = tuple(str(item).strip() for item in (getattr(spec, "ignore_files_glob", []) or []) if str(item).strip())
    patterns = tuple(
        str(item).strip()
        for item in (
            getattr(spec, "patterns", None)
            or getattr(spec, "code_patterns", None)
            or []
        )
        if str(item).strip()
    )
    surface = str(getattr(spec, "surface_type", "") or "custom surface").replace("-", " ")
    vuln_class = str(getattr(spec, "vuln_class", "") or "custom vulnerability").replace("_", " ").replace("-", " ")
    entry_questions = (
        f"Which entry points expose the {surface} surface in this application?",
        f"Which code paths under the brainstorm focus set make {vuln_class} reachable?",
    )
    cross_questions = (
        f"How does attacker-controlled data from the {surface} surface cross into privileged code?",
        "What validation, allowlists, auth checks, or boundary checks exist and where do they fail?",
    )
    sink_categories = patterns[:6] or (
        f"Surface-specific flows related to {surface}",
        f"Sinks that make {vuln_class} practically reachable",
    )
    reasoning = (
        f"Use the brainstorm evidence for app version {getattr(spec, 'version', 'unknown')}. "
        f"Prioritize {vuln_class} paths on the {surface} surface, stay inside the focus globs first, "
        "and treat ignore globs as low-priority unless a strong cross-file flow forces expansion."
    )
    key = str(getattr(spec, "key", "")).strip()
    brainstorm_metadata = dict(getattr(spec, "brainstorm_metadata", {}) or {})
    static_profile = CLASS_PROFILES.get(key) if brainstorm_metadata.get("category_master") else None
    if static_profile is not None:
        return VulnerabilityClassProfile(
            key=static_profile.key,
            description=str(getattr(spec, "description", "")).strip() or static_profile.description,
            entry_questions=static_profile.entry_questions,
            cross_questions=static_profile.cross_questions,
            sink_categories=static_profile.sink_categories,
            reasoning=static_profile.reasoning,
            display_name=str(getattr(spec, "name", "")).strip() or static_profile.display_name,
            prompt_addendum=str(getattr(spec, "agent_prompt_template", "")).rstrip(),
            focus_globs=focus_globs or static_profile.focus_globs,
            ignore_globs=ignore_globs or static_profile.ignore_globs,
            brainstorm_metadata=brainstorm_metadata,
        )

    return VulnerabilityClassProfile(
        key=key,
        description=str(getattr(spec, "description", "")).strip(),
        entry_questions=entry_questions,
        cross_questions=cross_questions,
        sink_categories=sink_categories,
        reasoning=reasoning,
        display_name=str(getattr(spec, "name", "")).strip() or None,
        prompt_addendum=str(getattr(spec, "agent_prompt_template", "")).rstrip(),
        focus_globs=focus_globs,
        ignore_globs=ignore_globs,
        brainstorm_metadata=brainstorm_metadata,
    )


def _select_from_profiles(
    selected_class: Optional[str],
    profiles: Sequence[VulnerabilityClassProfile],
) -> List[VulnerabilityClassProfile]:
    if not selected_class:
        return list(profiles)
    normalized = _normalize_class_name(selected_class)
    matches = [profile for profile in profiles if profile.key.casefold() == normalized]
    if not matches:
        known = ", ".join(sorted({profile.key.casefold() for profile in profiles}))
        raise ValueError(f"Unknown class {selected_class!r}. Expected one of: {known}")
    return matches


def _select_profiles(
    selected_class: Optional[str],
    extra_profiles: Sequence[VulnerabilityClassProfile] = (),
    excluded_builtin_keys: Sequence[str] = (),
) -> List[VulnerabilityClassProfile]:
    excluded = {str(key).casefold() for key in excluded_builtin_keys}
    ordered_profiles = [
        profile for profile in CLASS_PROFILES.values() if profile.key.casefold() not in excluded
    ] + list(extra_profiles)
    if not selected_class:
        return ordered_profiles

    normalized = _normalize_class_name(selected_class)
    matches = [profile for profile in ordered_profiles if profile.key.casefold() == normalized]
    if not matches:
        known = ", ".join(sorted({profile.key.casefold() for profile in ordered_profiles}))
        raise ValueError(f"Unknown class {selected_class!r}. Expected one of: {known}")
    return matches


def _merge_brainstorm_profiles_into_builtin(
    base: VulnerabilityClassProfile,
    brainstorm_profiles: Sequence[VulnerabilityClassProfile],
) -> VulnerabilityClassProfile:
    """Return a builtin category profile enriched with AppMap/brainstorm assignments."""
    prompt_sections: list[str] = []
    if str(base.prompt_addendum or "").strip():
        prompt_sections.append(str(base.prompt_addendum).strip())
    assignments: list[dict[str, Any]] = []
    focus_globs: list[str] = list(base.focus_globs)
    ignore_globs: list[str] = list(base.ignore_globs)
    for profile in brainstorm_profiles:
        profile_prompt = str(getattr(profile, "prompt_addendum", "") or "").strip()
        if profile_prompt:
            prompt_sections.append(
                f"## AppMap/brainstorm assignment for {profile.key}\n{profile_prompt}"
            )
        for item in _brainstorm_assignment_metadata(profile):
            assignments.append(dict(item))
        for pattern in getattr(profile, "focus_globs", ()) or ():
            if pattern not in focus_globs:
                focus_globs.append(pattern)
        for pattern in getattr(profile, "ignore_globs", ()) or ():
            if pattern not in ignore_globs:
                ignore_globs.append(pattern)

    metadata = dict(getattr(base, "brainstorm_metadata", {}) or {})
    if assignments:
        metadata.update(
            {
                "category_master": True,
                "scheduler_category_master": True,
                "brainstorm_cluster_size": len(assignments),
                "brainstorm_cluster_assignments": assignments,
                "scheduler_master_agent_key": base.key,
                "member_agent_keys": sorted(
                    {
                        str(item.get("brainstorm_agent_key") or item.get("agent_key") or base.key).strip()
                        for item in assignments
                        if str(item.get("brainstorm_agent_key") or item.get("agent_key") or base.key).strip()
                    }
                ),
                "member_hypothesis_ids": [
                    str(item.get("hypothesis_id") or "").strip()
                    for item in assignments
                    if str(item.get("hypothesis_id") or "").strip()
                ],
            }
        )

    return VulnerabilityClassProfile(
        key=base.key,
        description=(
            f"{base.description} Includes {len(assignments)} AppMap/brainstorm assignment(s) "
            "for per-hypothesis attribution."
        ),
        entry_questions=base.entry_questions,
        cross_questions=base.cross_questions,
        sink_categories=base.sink_categories,
        reasoning=base.reasoning,
        display_name=base.display_name,
        prompt_addendum="\n\n".join(prompt_sections),
        focus_globs=tuple(focus_globs),
        ignore_globs=tuple(ignore_globs),
        brainstorm_metadata=metadata,
    )


def _merge_brainstorm_profiles_with_builtins(
    brainstorm_profiles: Sequence[VulnerabilityClassProfile],
) -> tuple[list[VulnerabilityClassProfile], list[str]]:
    """Merge AppMap category-master specs into matching static category profiles."""
    builtin_key_lookup = {key.casefold(): key for key in CLASS_PROFILES}
    by_builtin_key: dict[str, list[VulnerabilityClassProfile]] = {}
    passthrough: list[VulnerabilityClassProfile] = []
    for profile in brainstorm_profiles:
        normalized = profile.key.casefold()
        if normalized in builtin_key_lookup:
            by_builtin_key.setdefault(normalized, []).append(profile)
        else:
            passthrough.append(profile)

    merged: list[VulnerabilityClassProfile] = []
    excluded: list[str] = []
    for normalized_key, profiles in by_builtin_key.items():
        base_key = builtin_key_lookup[normalized_key]
        merged.append(_merge_brainstorm_profiles_into_builtin(CLASS_PROFILES[base_key], profiles))
        excluded.append(base_key)
    return [*passthrough, *merged], excluded


def _build_prompt_base(
    profile: VulnerabilityClassProfile,
    program: str,
    target_path: Path,
    findings_path: Path,
    class_context: str = "",
    repo_context: str = "",
    starting_entry: dict[str, Any] | None = None,
    policy_snippet: str = "",
) -> str:
    entry_lines = "\n".join(f"- {question}" for question in profile.entry_questions)
    cross_lines = "\n".join(f"- {question}" for question in profile.cross_questions)
    sink_lines = "\n".join(f"- {category}" for category in profile.sink_categories)
    focus_lines = "\n".join(f"- {pattern}" for pattern in profile.focus_globs)
    ignore_lines = "\n".join(f"- {pattern}" for pattern in profile.ignore_globs)
    context_parts: List[str] = []
    if class_context.strip():
        context_parts.append(
            f"{class_context}\n\nYou are analyzing with KNOWLEDGE OF PRIOR FINDINGS. "
            "Do not re-report findings that appear in the prior list above — focus on "
            "finding NEW vulnerabilities in files/sinks not already covered."
        )
    else:
        context_parts.append(
            "You are running with CLEAN CONTEXT for this class. Do not assume prior "
            "class passes found everything, and do not read prior findings before starting analysis."
        )
    if repo_context.strip():
        context_parts.append(
            "## Shared Repo Context\n"
            f"{repo_context}\n\n"
            "Do NOT re-scan the entire repository. Start from the files listed above and expand outward."
        )
    if starting_entry:
        entry_point_file = str(starting_entry.get("file", "")).strip() or "unknown"
        entry_point_line = _safe_int(starting_entry.get("line")) or "?"
        entry_point_kind = str(starting_entry.get("kind", "")).strip() or "unknown"
        entry_point_text = str(starting_entry.get("text", "")).strip() or "unknown"
        context_parts.append(
            "You are assigned a specific ENTRY POINT to start your analysis from:\n\n"
            f"Entry Point: {entry_point_file}:{entry_point_line}\n"
            f"Kind: {entry_point_kind}\n"
            f"Signal: {entry_point_text}\n\n"
            "Starting from this entry point, trace the data flow:\n"
            "- What data enters through this entry point?\n"
            "- How does the data flow through the codebase?\n"
            "- Where does it cross a trust boundary?\n"
            "- What dangerous operation (sink) does it ultimately reach?\n\n"
            "Do NOT just scan all files. Start from YOUR assigned entry point and follow the data flow."
        )
    context_block = "\n\n".join(context_parts)

    return f"""You are a specialized static-analysis security agent focused on the vulnerability class "{profile.key}" ({profile.title}).

{context_block}

Program: {program}
Target codebase: {target_path}
Shared findings file for append-only output: {findings_path}

Requirements:
- Analyze the codebase only through static review. Do NOT run the target app, tests, build steps, containers, or helper scripts.
- Focus on this vulnerability class, but do not limit yourself to only the listed examples or named APIs.
- Think in terms of trust boundaries, dataflow, dangerous operation categories, and practical exploitability.
- Prefer a small number of precise, high-confidence findings over speculation.

Class description:
{profile.description}

Five-step reasoning flow:
{FIVE_STEP_REASONING_FLOW}

Source framing:
- {SOURCE_TRUST_CONTEXT_PROMPT}

ENTRY questions:
{entry_lines}

CROSS questions:
{cross_lines}

Dangerous sink categories to reason about:
{sink_lines}

Reasoning prompts:
{profile.reasoning}

Preferred focus globs:
{focus_lines or "- None provided"}

Low-priority ignore globs:
{ignore_lines or "- None provided"}

Custom agent instructions:
{profile.prompt_addendum or "None."}

{policy_snippet.strip()}

Output rules:
- A class finding should identify the source, the trust boundary crossing, the flow, the dangerous sink category, and why exploitation is or is not realistically reachable.
- If you discover a strong pattern that does NOT fit this class, record it as a NOVEL finding instead of forcing it into the current class.
- A novel finding must identify at least one SOURCE and one SINK, even if the flow between them is still incomplete.
- Novel findings must never be used to expand the class profile.
- IMPORTANT: If you do not find a real exploitable vulnerability, output exactly: {{}} (empty JSON object). Do NOT output placeholder or template text.

Append every finding to {findings_path} in JSONL format using one of these schemas:
Class finding:
{{"agent": "{profile.key}", "category": "class", "class_name": "{profile.key}", "type": "short vulnerability label", "file": "path", "line": 123, "description": "why this path is dangerous", "severity": "LOW|MEDIUM|HIGH|CRITICAL", "context": "relevant code context and reasoning", "source": "identified source", "trust_boundary": "what boundary is crossed", "flow_path": "how the data moves", "sink": "dangerous sink category or concrete sink", "exploitability": "why an attacker can or cannot trigger it"}}
Novel finding:
{{"agent": "{profile.key}", "category": "novel", "class_name": "novel", "type": "short novel pattern label", "file": "path", "line": 123, "description": "why this appears novel and dangerous", "severity": "LOW|MEDIUM|HIGH|CRITICAL", "context": "relevant code context and reasoning", "source": "identified source", "trust_boundary": "boundary crossed or unresolved boundary question", "flow_path": "known or suspected flow", "sink": "identified dangerous sink", "exploitability": "what is known or missing about exploitability"}}

- Also print each finding JSON object on a single line to stdout so the orchestrator can recover findings if direct file append fails.
- Log progress to the agent log file path provided by the launcher.
- Do not emit placeholder findings, fake line numbers, or template text.
"""


def _launcher_script() -> str:
    return r'''
set +e
log_path="${ZERO_DAY_AGENTS_DIR}/agent_${ZERO_DAY_AGENT_NAME}_$$.log"
prompt="${ZERO_DAY_AGENT_PROMPT_BASE}

Agent working directory: ${ZERO_DAY_AGENT_WORKDIR}
Agent log file: ${log_path}
"

{
  printf 'agent=%s\n' "$ZERO_DAY_AGENT_NAME"
  printf 'pid=%s\n' "$$"
  printf 'cli=%s\n' "$ZERO_DAY_AGENT_CLI"
  printf 'workspace=%s\n' "$ZERO_DAY_AGENT_WORKDIR"
  printf 'target=%s\n' "$ZERO_DAY_TARGET_PATH"
} >> "$log_path"

if [ "$ZERO_DAY_AGENT_CLI" = "claude" ]; then
  claude --permission-mode bypassPermissions --print "$prompt" >> "$log_path" 2>&1
  status=$?
elif [ "$ZERO_DAY_AGENT_CLI" = "codex" ]; then
  codex exec -s danger-full-access --skip-git-repo-check "$prompt" >> "$log_path" 2>&1
  status=$?
else
  printf 'unsupported_cli=%s\n' "$ZERO_DAY_AGENT_CLI" >> "$log_path"
  status=127
fi

printf 'exit_code=%s\n' "$status" >> "$log_path"
exit "$status"
'''.strip()


def _spawn_agent(
    profile: VulnerabilityClassProfile,
    program: str,
    target_path: Path,
    findings_path: Path,
    agents_root: Path,
    class_context: str = "",
    repo_context: str = "",
    starting_entry: dict[str, Any] | None = None,
    skip_ledger: bool = False,
    hunt_type: str = "source",
    coverage_path: Path | None = None,
    policy_snippet: str = "",
) -> AgentSession:
    workspace = agents_root / f"{profile.key}_{int(time.time() * 1000)}"
    _ensure_directory(workspace)

    env = os.environ.copy()
    env["ZERO_DAY_AGENT_NAME"] = profile.key
    env["ZERO_DAY_AGENT_CLI"] = "codex"
    env["ZERO_DAY_AGENT_PROMPT_BASE"] = _build_prompt_base(
        profile=profile,
        program=program,
        target_path=target_path,
        findings_path=findings_path,
        class_context=class_context,
        repo_context=repo_context,
        starting_entry=starting_entry,
        policy_snippet=policy_snippet,
    )
    env["ZERO_DAY_TARGET_PATH"] = str(target_path)
    env["ZERO_DAY_AGENT_WORKDIR"] = str(workspace)
    env["ZERO_DAY_AGENTS_DIR"] = str(agents_root)
    spawn_start = time.time()
    prompt_base = env.get("ZERO_DAY_AGENT_PROMPT_BASE", "")
    input_bytes = len(prompt_base.encode("utf-8", errors="replace"))

    try:
        process = subprocess.Popen(
            ["bash", "-lc", _launcher_script()],
            cwd=str(target_path),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError as exc:
        fallback_log = agents_root / f"agent_{profile.key}_spawn_error.log"
        with fallback_log.open("a", encoding="utf-8") as handle:
            handle.write(f"Failed to spawn codex: {exc}\n")
        _safe_log_span(
            span_type="tool",
            level="STEP",
            message=f"Tool: spawn {profile.key}",
            tool_name="codex_exec_spawn",
            tool_category="subprocess",
            input_bytes=input_bytes,
            output_bytes=0,
            latency_ms=int((time.time() - spawn_start) * 1000),
            success=False,
        )
        return AgentSession(
            profile=profile,
            workspace=workspace,
            log_path=fallback_log,
            process=None,
            skip_ledger=skip_ledger,
            coverage_path=coverage_path,
        )

    log_path = agents_root / f"agent_{profile.key}_{process.pid}.log"
    _safe_log_span(
        span_type="tool",
        level="STEP",
        message=f"Tool: spawn {profile.key}",
        tool_name="codex_exec_spawn",
        tool_category="subprocess",
        input_bytes=input_bytes,
        output_bytes=0,
        latency_ms=int((time.time() - spawn_start) * 1000),
        success=True,
    )
    return AgentSession(
        profile=profile,
        workspace=workspace,
        log_path=log_path,
        process=process,
        skip_ledger=skip_ledger,
        coverage_path=coverage_path,
    )


def _safe_int(value: Any) -> int:
    return shared_safe_int(value)


def _normalize_finding(raw: Any, default_agent: str) -> Optional[Dict[str, Any]]:
    """Apply zero-day-specific validation on top of shared finding normalization."""
    if not isinstance(raw, dict):
        return None

    normalized = shared_normalize_finding(raw, default_agent=default_agent, default_class=default_agent)
    if normalized is None:
        return None

    description = str(normalized.get("description") or "").strip()
    if not description:
        return None
    if is_placeholder_finding(raw) or is_placeholder_finding(normalized):
        return None

    raw_category = str(raw.get("category") or "").strip().lower()
    class_name = str(normalized.get("class_name") or raw.get("class_name") or "").strip().lower()
    category = raw_category if raw_category in {"class", "novel"} else ("novel" if class_name == "novel" else "class")

    source = str(normalized.get("source") or "").strip()
    sink = str(normalized.get("sink") or "").strip()
    if category == "novel" and (not source or not sink):
        return None

    if category == "class" and class_name not in CLASS_PROFILES:
        class_name = default_agent
    elif not class_name:
        class_name = "novel" if category == "novel" else default_agent

    normalized["category"] = category
    normalized["class_name"] = class_name
    normalized["fid"] = str(raw.get("fid") or normalized.get("fid") or "").strip()
    return normalized


def _load_findings(findings_path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for parsed in shared_read_findings_jsonl(findings_path):
        normalized = _normalize_finding(parsed, default_agent="unknown")
        if normalized is not None:
            findings.append(normalized)
    return findings


def _write_findings_jsonl(findings_path: Path, findings: Sequence[Dict[str, Any]]) -> None:
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(json.dumps(dict(finding), sort_keys=True) + "\n" for finding in findings)
    findings_path.write_text(payload, encoding="utf-8")


def _extract_findings_from_log(log_path: Path, default_agent: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for parsed in shared_extract_findings_from_log(log_path, default_agent=default_agent):
        normalized = _normalize_finding(parsed, default_agent=default_agent)
        if normalized is not None:
            findings.append(normalized)
    return findings


def _split_file_reference(file_value: Any) -> Tuple[str, int]:
    raw = str(file_value or "").strip()
    if not raw:
        return "", 0

    parts = raw.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return raw, 0


def _display_file_reference(finding: Dict[str, Any]) -> str:
    file_path, inline_line = _split_file_reference(finding.get("file", ""))
    line_number = _safe_int(finding.get("line")) or inline_line
    if line_number > 0:
        return f"{file_path}:{line_number}"
    return file_path


def _resolve_zero_day_storage(
    program: str,
    output_root: str | Path | None = None,
    target_path: str | Path | None = None,
    target_kind: str | None = None,
    intent_text: str | None = None,
):
    program_slug = _sanitize_program_name(program)
    return resolve_team_storage(
        program=program_slug,
        team_type="0day_team",
        output_root=output_root,
        target_path=target_path,
        target_kind=target_kind,
        intent_text=intent_text,
    )


def _report_index_paths_from_storage(storage) -> Tuple[Path, Path, Path]:
    paths = daily_report_paths(storage, datetime.now().strftime(DAILY_REPORT_DATE_FORMAT))
    return paths["confirmed"], paths["dormant"], paths["novel"]


def _resolve_finding_source(target_path: Path, file_value: Any) -> Optional[Path]:
    file_path, _ = _split_file_reference(file_value)
    if not file_path:
        return None

    raw_path = Path(file_path).expanduser()
    candidates: List[Path] = []
    if raw_path.is_absolute():
        candidates.append(raw_path)
    else:
        trimmed = file_path[2:] if file_path.startswith("./") else file_path
        relative_path = Path(trimmed)
        candidates.append((target_path / relative_path).resolve())
        candidates.append((Path.cwd() / relative_path).resolve())
        if relative_path.parts and relative_path.parts[0] == target_path.name:
            candidates.append((target_path.parent / relative_path).resolve())

    seen: set[str] = set()
    for candidate in candidates:
        candidate_key = str(candidate)
        if candidate_key in seen:
            continue
        seen.add(candidate_key)
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _read_source_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _source_excerpt(
    source_text: str,
    line_number: int,
    radius: int = 20,
    *,
    focus_terms: Sequence[str] = (),
    max_line_chars: int = SOURCE_EXCERPT_MAX_LINE_CHARS,
) -> str:
    lines = source_text.splitlines()
    if not lines:
        return ""

    if line_number <= 0:
        start = 0
        end = min(len(lines), (radius * 2) + 1)
    else:
        start = max(0, line_number - radius - 1)
        end = min(len(lines), line_number + radius)

    excerpt_lines = []
    for index in range(start, end):
        line = lines[index]
        line_prefix = f"{index + 1}: "
        if len(line) <= max_line_chars:
            excerpt_lines.append(f"{line_prefix}{line}")
            continue

        focus_index = -1
        focus_label = ""
        for term in focus_terms:
            normalized_term = str(term or "").strip()
            if len(normalized_term) < 4:
                continue
            focus_index = line.find(normalized_term)
            if focus_index >= 0:
                focus_label = normalized_term[:80]
                break

        if focus_index >= 0:
            start_char = max(0, focus_index - (max_line_chars // 2))
        else:
            start_char = 0
        end_char = min(len(line), start_char + max_line_chars)
        start_char = max(0, end_char - max_line_chars)
        snippet = line[start_char:end_char]
        if start_char > 0:
            snippet = "..." + snippet
        if end_char < len(line):
            snippet = snippet + "..."

        focus_note = f" around focus term {focus_label!r}" if focus_label else ""
        excerpt_lines.append(
            f"[truncated line {index + 1}: original length {len(line)} chars; "
            f"showing chars {start_char + 1}-{end_char}{focus_note}]"
        )
        excerpt_lines.append(f"{line_prefix}{snippet}")
    return "\n".join(excerpt_lines)


def _finding_line_number(finding: Dict[str, Any]) -> int:
    return _safe_int(finding.get("line")) or _split_file_reference(finding.get("file", ""))[1]


def _default_vulnerability_name(finding: Dict[str, Any]) -> str:
    return str(finding.get("type", "Vulnerability")).replace("-", " ").title()


def _optional_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _extract_json_object(text: str) -> str:
    stripped = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", stripped, re.DOTALL)
    if fenced:
        stripped = fenced.group(1).strip()

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("Claude output did not contain a JSON object")
    return stripped[start:end + 1]


def _looks_placeholder_poc(poc: str) -> bool:
    normalized = poc.lower()
    placeholders = (
        "attacker_controlled",
        "invoke_target(",
        "replace with",
        "placeholder",
        "example payload",
        "generic payload",
        "build_malicious",
    )
    return any(marker in normalized for marker in placeholders)


def is_placeholder_finding(finding: dict) -> bool:
    """
    Detects garbage findings by checking for:
    - Title in ("short vulnerability label", "short novel pattern label", "placeholder")
    - file_ref in ("path:123", "")
    - Combined title+description contains placeholder markers
    """
    title = str(finding.get("title") or finding.get("type") or "").strip()
    title_lc = title.lower()
    file_ref = str(finding.get("file_ref") or finding.get("file") or "").strip()
    description = str(finding.get("description") or "").strip()
    combined = f"{title} {description}".lower()
    markers = (
        "path:123",
        "why this path is dangerous",
        "why this appears novel and dangerous",
        "relevant code context and reasoning",
        "identified source",
        "boundary crossed or unresolved boundary question",
        "known or suspected flow",
        "identified dangerous sink",
        "what is known or missing about exploitability",
        "dangerous sink category",
        "what boundary is crossed",
        "how the data moves",
        "none provided.",
    )

    if title_lc in {"short vulnerability label", "short novel pattern label", "placeholder"}:
        return True
    if file_ref in {"path:123", "path", ""}:
        return True
    return any(marker in combined for marker in markers)


def _build_claude_review_prompt(
    finding: Dict[str, Any],
    target_path: Path,
    source_path: Optional[Path],
    excerpt: str,
    policy: HuntingPolicy | dict[str, Any] | None = None,
    policy_snippet: str = "",
) -> str:
    line_number = _finding_line_number(finding)
    resolved_file = str(source_path) if source_path is not None else "UNRESOLVED"
    excerpt_text = excerpt or "UNAVAILABLE"
    policy_enabled = bool(getattr(policy, "enabled", False)) or (
        isinstance(policy, dict) and bool(policy.get("enabled"))
    ) or bool(policy_snippet.strip())
    policy_schema_suffix = ""
    policy_block = ""
    policy_rules = ""
    if policy_enabled:
        policy_schema_suffix = (
            ', "policy_id": "...", "finding_role": "entry|amplifier|chain|hardening", '
            '"entry_status": "proven|plausible|missing|not_required", '
            '"entry_vector": "full URL/file/protocol/context or null", '
            '"impact_amplifiers": ["..."], "reportability": "submit|hold_for_chain|notes_only", '
            '"payout_confidence": "high|medium|low"'
        )
        policy_block = f"""
Policy context:
{policy_snippet.strip()}
"""
        policy_rules = """
Policy-aware review rules:
- Policies guide priority and report framing; they do not hard-ban a surface unless an avoid rule explicitly says so.
- Deprioritized surfaces are not forbidden. IPC, HostRpc, preload, and native bridge work is soft-deprioritized by default, not banned.
- Amplifier-only or missing-entry findings should usually be held as chain material.
- Standalone critical IPC/native impact is allowed when direct exploitability is proven.
- Headline the application entry path when one exists; use IPC/native behavior as impact expansion.
"""

    return f"""You are reviewing a single static-analysis security finding for exploitability and report quality.

Output ONLY a JSON object. Do not output markdown, code fences, or any extra text.
IMPORTANT: If you do not find a real exploitable vulnerability, output exactly: {{}}.
Do NOT output placeholder or template text.

Required JSON schema:
{{"tier": "CONFIRMED" or "DORMANT_ACTIVE" or "DORMANT_HYPOTHETICAL", "poc": "..." or null, "impact": "...", "cvss_vector": "...", "cvss_score": "...", "severity_label": "...", "vulnerability_name": "...", "blocked_reason": "..." or null, "chain_requirements": "..." or null, "remediation": "...", "review_notes": "..."{policy_schema_suffix}}}

Review rules:
- Use "CONFIRMED" only when the code evidence supports a concrete exploitable issue with a working standalone PoC.
- Use "DORMANT_ACTIVE" when the vulnerability is real but requires a documented prerequisite to exploit (e.g. "needs prior XSS to trigger"). The blocked_reason must explain what prerequisite is needed.
- Use "DORMANT_HYPOTHETICAL" when the finding is incomplete, inconclusive, or the blocked_reason is vague (e.g. "inconclusive", "needs more research"). No concrete exploit path defined.
- For "DORMANT_ACTIVE", "chain_requirements" must describe the specific prerequisite needed.
- "impact" must explain the concrete security outcome if exploitation succeeds.
- "review_notes" must summarize the code evidence and reasoning.
- Base your answer on the supplied finding and source context, and you may read related files under the target directory if needed.
{policy_rules}

Target directory:
{target_path}
{policy_block}

Exact finding:
{json.dumps({
    "agent": finding.get("agent"),
    "category": finding.get("category"),
    "class_name": finding.get("class_name"),
    "file": finding.get("file"),
    "line": line_number,
    "type": finding.get("type"),
    "description": finding.get("description"),
    "severity": finding.get("severity"),
    "context": finding.get("context"),
    "source": finding.get("source"),
    "trust_boundary": finding.get("trust_boundary"),
    "flow_path": finding.get("flow_path"),
    "sink": finding.get("sink"),
    "exploitability": finding.get("exploitability"),
}, indent=2, sort_keys=True)}

Source file:
- Claimed path: {finding.get("file", "")}
- Resolved path: {resolved_file}

Surrounding source code (+/- 20 lines around line {line_number or "unknown"}):
{excerpt_text}
"""


def _inconclusive_review(
    finding: Dict[str, Any],
    source_path: Optional[Path],
    excerpt: str,
    note: str,
) -> Dict[str, Any]:
    reviewed = dict(finding)
    reviewed["resolved_file"] = str(source_path) if source_path is not None else ""
    reviewed["source_excerpt"] = excerpt
    reviewed["review_tier"] = "DORMANT_HYPOTHETICAL"
    reviewed["tier"] = "DORMANT_HYPOTHETICAL"
    reviewed["poc"] = None
    reviewed["impact"] = ""
    reviewed["cvss_vector"] = ""
    reviewed["cvss_score"] = ""
    reviewed["severity_label"] = str(finding.get("severity", "UNKNOWN")).upper()
    reviewed["vulnerability_name"] = _default_vulnerability_name(finding)
    reviewed["blocked_reason"] = note
    reviewed["chain_requirements"] = None
    reviewed["remediation"] = ""
    reviewed["review_notes"] = note
    reviewed["review_reason"] = note
    reviewed["severity"] = reviewed["severity_label"]
    return reviewed


def _normalize_claude_review(
    finding: Dict[str, Any],
    source_path: Optional[Path],
    excerpt: str,
    review_data: Dict[str, Any],
) -> Dict[str, Any]:
    tier = str(review_data.get("tier", "") or review_data.get("review_tier", "")).strip().upper()
    if tier not in {"CONFIRMED", "DORMANT", "DORMANT_ACTIVE", "DORMANT_HYPOTHETICAL"}:
        raise ValueError(f"invalid review tier: {tier!r}")

    poc = review_data.get("poc")
    if tier == "CONFIRMED":
        poc_text = _optional_text(poc)
        if not poc_text:
            raise ValueError("confirmed review missing poc")
        if _looks_placeholder_poc(poc_text):
            raise ValueError("confirmed review returned placeholder poc")
        poc = poc_text
    else:
        poc = None

    impact = _optional_text(review_data.get("impact"))
    severity_label = _optional_text(review_data.get("severity_label"))
    vulnerability_name = _optional_text(review_data.get("vulnerability_name"))
    cvss_vector = _optional_text(review_data.get("cvss_vector"))
    cvss_score = _optional_text(review_data.get("cvss_score"))
    remediation = _optional_text(review_data.get("remediation"))
    review_notes = _optional_text(review_data.get("review_notes"))
    blocked_reason = _optional_text(review_data.get("blocked_reason"))
    chain_requirements = _optional_text(review_data.get("chain_requirements"))

    # Fall back to finding's existing data for any missing fields
    finding_severity = str(finding.get("severity", "")).upper()
    severity_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "UNKNOWN": "UNKNOWN"}
    if not severity_label or severity_label == "UNKNOWN":
        severity_label = next((v for k, v in severity_map.items() if k in finding_severity), None)
    if not severity_label:
        severity_label = "UNKNOWN"

    if not impact:
        impact = f"Vulnerability in {finding.get('class_name', 'unknown')} class — {finding.get('description', 'see finding')[:100]}"
    if not vulnerability_name:
        vulnerability_name = _default_vulnerability_name(finding)
    if not cvss_vector:
        cvss_vector = ""
    if not cvss_score:
        cvss_score = ""
    if not remediation:
        remediation = "Implement input validation and least-privilege access controls."
    if not review_notes:
        review_notes = review_data.get("review_notes", "") or f"Claude returned review data for {finding.get('type', 'unknown')}."
    if tier == "DORMANT" and not blocked_reason:
        blocked_reason = review_data.get("blocked_reason") or "Exploitability not confirmed — see review_notes."

    # Split DORMANT into ACTIVE vs HYPOTHETICAL based on blocked_reason quality
    if tier == "DORMANT":
        # Seed chain_requirements from blocked_reason before splitting
        if not chain_requirements and blocked_reason:
            chain_requirements = blocked_reason
        concrete_prereq_markers = (
            "needs prior", "requires prior", "prior xss", "javascript execution first",
            "separate exploit", "xss first", "arbitrary js", "file write first",
            "renderer compromise", "code execution first", "depends on",
            "authenticated access", "admin role", "user interaction", "network position",
            "local foothold", "feature enablement", "attacker control",
        )
        vague_markers = (
            "inconclusive", "needs more research", "placeholder", "not confirmed",
            "unclear", "insufficient", "could not verify", "requires further",
            "short vulnerability label", "review inconclusive", "possible",
            "potential", "may", "might",
            "appears", "seems", "theoretical", "assumed", "likely",
        )
        prereq_blob = " ".join(part for part in (blocked_reason, chain_requirements) if part).lower()
        has_concrete = any(marker in prereq_blob for marker in concrete_prereq_markers)
        has_vague = any(marker in prereq_blob for marker in vague_markers)
                # Requirement-verb check (replaces word-count heuristic)
        requirement_verbs = ("needs", "requires", "must", "after", "once", "with", "depend", "necessary", "prerequisite")
        hedge_words = ("maybe", "possible", "might", "could", "perhaps", "theoretical", "assumed", "unclear")
        block_words = ("none", "none provided", "...", "see blocked reason", "see review notes")
        if chain_requirements:
            cr_lower = chain_requirements.lower()
            has_req_verb = any(v in cr_lower for v in requirement_verbs)
            has_hedge = any(h in cr_lower for h in hedge_words)
            has_block_word = any(b in cr_lower for b in block_words)
            has_explicit_chain_req = bool(has_req_verb and not has_hedge and not has_block_word)
        else:
            has_explicit_chain_req = False

        if has_vague:
            tier = "DORMANT_HYPOTHETICAL"
        elif has_explicit_chain_req:
            tier = "DORMANT_ACTIVE"
        elif has_concrete:
            tier = "DORMANT_ACTIVE"
        else:
            tier = "DORMANT_HYPOTHETICAL"
    reviewed = dict(finding)
    reviewed["resolved_file"] = str(source_path) if source_path is not None else ""
    reviewed["source_excerpt"] = excerpt
    reviewed["review_tier"] = tier
    reviewed["tier"] = tier
    reviewed["poc"] = poc
    reviewed["impact"] = impact
    reviewed["cvss_vector"] = cvss_vector
    reviewed["cvss_score"] = cvss_score
    reviewed["severity_label"] = severity_label
    reviewed["vulnerability_name"] = vulnerability_name
    reviewed["blocked_reason"] = blocked_reason
    reviewed["chain_requirements"] = chain_requirements
    reviewed["remediation"] = remediation
    reviewed["review_notes"] = review_notes
    reviewed["review_reason"] = review_notes
    reviewed["severity"] = severity_label
    for key in (
        "policy_id",
        "finding_role",
        "entry_status",
        "entry_vector",
        "impact_amplifiers",
        "reportability",
        "payout_confidence",
    ):
        if key in review_data:
            reviewed[key] = review_data.get(key)
    return reviewed


def _review_single_finding(
    finding: Dict[str, Any],
    target_path: Path,
    policy: HuntingPolicy | dict[str, Any] | None = None,
    policy_snippet: str = "",
) -> Tuple[str, Dict[str, Any], str]:
    source_path = _resolve_finding_source(target_path, finding.get("file", ""))
    excerpt = ""
    if source_path is not None:
        try:
            source_text = _read_source_text(source_path)
            excerpt = _source_excerpt(
                source_text,
                _finding_line_number(finding),
                focus_terms=(
                    str(finding.get("source") or ""),
                    str(finding.get("sink") or ""),
                    str(finding.get("context") or ""),
                    str(finding.get("type") or ""),
                ),
            )
        except OSError:
            excerpt = ""

    prompt = _build_claude_review_prompt(
        finding=finding,
        target_path=target_path,
        source_path=source_path,
        excerpt=excerpt,
        policy=policy,
        policy_snippet=policy_snippet,
    )

    def _call_claude(prompt: str, target_path: Path) -> tuple[str, str, str, int]:
        """Try claude CLI first."""
        _context_tokens_before = _estimate_tokens_from_text(prompt)
        _start = time.time()
        try:
            process = subprocess.Popen(
                ["claude", "--print", "--permission-mode", "bypassPermissions"],
                cwd=str(target_path),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError:
            return "", "", "claude not available", -1

        try:
            stdout_text, stderr_text = process.communicate(
                input=prompt,
                timeout=CLAUDE_REVIEW_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.communicate(timeout=5)
            except Exception:
                pass
            return "", "", "claude timeout", -1

        response_text = stdout_text or stderr_text or ""
        output_bytes = len(response_text.encode("utf-8", errors="replace"))
        completion_tokens = _estimate_tokens_from_text(response_text)
        context_tokens_after = _context_tokens_before + completion_tokens
        tool_output_tokens = max(0, math.ceil(output_bytes / 4))
        _safe_log_span(
            span_type="model",
            level="STEP",
            message="Model call: claude",
            model_name="claude",
            prompt_tokens=_context_tokens_before,
            completion_tokens=completion_tokens,
            context_tokens_before=_context_tokens_before,
            context_tokens_after=context_tokens_after,
            tool_output_tokens=tool_output_tokens,
            pte_lite=compute_pte_lite(
                prompt_tokens=_context_tokens_before,
                completion_tokens=completion_tokens,
                tool_output_tokens=tool_output_tokens,
                context_tokens_after=context_tokens_after,
            ),
            latency_ms=int((time.time() - _start) * 1000),
            output_bytes=output_bytes,
            success=process.returncode == 0,
        )
        return stdout_text, stderr_text, "", process.returncode

    def _call_codex(prompt: str, target_path: Path) -> tuple[str, str, str, int]:
        """Fail over to codex CLI with full source access (prompt as CLI arg)."""
        import shlex
        cmd = ["codex", "exec", "-s", "danger-full-access", "--skip-git-repo-check", prompt]
        _context_tokens_before = _estimate_tokens_from_text(prompt)
        _start = time.time()
        try:
            process = subprocess.Popen(
                cmd,
                cwd=str(target_path),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError:
            return "", "", "codex not available", -1

        try:
            stdout_text, stderr_text = process.communicate(
                timeout=CLAUDE_REVIEW_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.communicate(timeout=5)
            except Exception:
                pass
            return "", "", "codex timeout", -1

        response_text = stdout_text or stderr_text or ""
        output_bytes = len(response_text.encode("utf-8", errors="replace"))
        completion_tokens = _estimate_tokens_from_text(response_text)
        context_tokens_after = _context_tokens_before + completion_tokens
        tool_output_tokens = max(0, math.ceil(output_bytes / 4))
        _safe_log_span(
            span_type="model",
            level="STEP",
            message="Model call: codex",
            model_name="codex",
            prompt_tokens=_context_tokens_before,
            completion_tokens=completion_tokens,
            context_tokens_before=_context_tokens_before,
            context_tokens_after=context_tokens_after,
            tool_output_tokens=tool_output_tokens,
            pte_lite=compute_pte_lite(
                prompt_tokens=_context_tokens_before,
                completion_tokens=completion_tokens,
                tool_output_tokens=tool_output_tokens,
                context_tokens_after=context_tokens_after,
            ),
            latency_ms=int((time.time() - _start) * 1000),
            output_bytes=output_bytes,
            success=process.returncode == 0,
        )
        return stdout_text, stderr_text, "", process.returncode

    # Try Claude first, then Codex on failure or rate-limit error
    stdout_text, stderr_text, error, code = _call_claude(prompt, target_path)

    # Detect rate-limit or unavailable error → failover to Codex
    rate_limit = any(err in (stderr_text + stdout_text).lower()
                     for err in ("rate limit", "quota", "429", "usage limit",
                                 "daily limit", "TooManyRequests", "claude unavailable"))
    if (code != 0 and not stdout_text) or rate_limit or error:
        stdout_text, stderr_text, error, code = _call_codex(prompt, target_path)

    if not stdout_text or code != 0:
        reviewed = _inconclusive_review(finding, source_path, excerpt, f"review failed: {error or stderr_text.strip()[:80]}")
        return "DORMANT", reviewed, "review inconclusive"

    try:
        parsed = json.loads(_extract_json_object(stdout_text))
        if not isinstance(parsed, dict):
            raise ValueError("review output was not a JSON object")
        if not parsed:
            note = "review rejected finding as non-vulnerable"
            reviewed = dict(finding)
            reviewed["resolved_file"] = str(source_path) if source_path is not None else ""
            reviewed["source_excerpt"] = excerpt
            reviewed["review_tier"] = "REJECTED"
            reviewed["tier"] = "REJECTED"
            reviewed["review_notes"] = note
            reviewed["review_reason"] = note
            return "REJECTED", reviewed, note
        reviewed = _normalize_claude_review(finding, source_path, excerpt, parsed)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        note = f"review parse error: {exc}"
        reviewed = _inconclusive_review(finding, source_path, excerpt, note)
        return "DORMANT", reviewed, note

    tier = str(reviewed["review_tier"])
    return tier, reviewed, str(reviewed.get("review_notes", "")).strip() or tier.lower()


def _render_confirmed_report(findings: Sequence[Dict[str, Any]]) -> str:
    if not findings:
        return "# Confirmed Findings\n\nNo confirmed findings.\n"

    sections = ["# Confirmed Findings", ""]
    for finding in findings:
        severity_label = str(finding.get("severity_label") or finding.get("severity", "UNKNOWN"))
        sections.extend(
            [
                f"## [{severity_label}] {finding['vulnerability_name']}",
                f"**Type:** {finding['type']}",
                f"**Class:** {finding.get('class_name', 'unknown')}",
                f"**File:** {_display_file_reference(finding)}",
                f"**Agent:** {finding['agent']}",
                "",
                "### Description",
                finding["description"],
                "",
                "### Source -> Sink",
                f"Source: {str(finding.get('source', '')).strip() or 'None provided.'}",
                f"Trust boundary: {str(finding.get('trust_boundary', '')).strip() or 'None provided.'}",
                f"Flow: {str(finding.get('flow_path', '')).strip() or 'None provided.'}",
                f"Sink: {str(finding.get('sink', '')).strip() or 'None provided.'}",
                "",
                "### Impact",
                str(finding.get("impact", "")).strip() or "None provided.",
                "",
                "### Review Notes",
                str(finding.get("review_notes", "")).strip() or "None provided.",
                "",
                "### PoC",
                str(finding.get("poc", "")).strip() or "None provided.",
                "",
                "### CVSS Estimate",
                f"{finding.get('cvss_vector', '')} -> {finding.get('cvss_score', '')} ({severity_label})",
                "",
                "### Remediation",
                str(finding.get("remediation", "")).strip() or "None provided.",
                "",
            ]
        )
    return "\n".join(sections).rstrip() + "\n"


def _render_dormant_report(findings: Sequence[Dict[str, Any]]) -> str:
    if not findings:
        return "# Dormant Findings\n\nNo dormant findings.\n"

    sections = ["# Dormant Findings", ""]
    for finding in findings:
        tier = str(finding.get("review_tier", "DORMANT")).upper()
        sections.extend(
            [
                f"## [{tier}] {finding['vulnerability_name']}",
                f"**Type:** {finding['type']}",
                f"**Class:** {finding.get('class_name', 'unknown')}",
                f"**File:** {_display_file_reference(finding)}",
                f"**Agent:** {finding['agent']}",
                "",
                "### Why It's Dangerous (if triggered)",
                finding["description"],
                "",
                "### Source -> Sink",
                f"Source: {str(finding.get('source', '')).strip() or 'None provided.'}",
                f"Trust boundary: {str(finding.get('trust_boundary', '')).strip() or 'None provided.'}",
                f"Flow: {str(finding.get('flow_path', '')).strip() or 'None provided.'}",
                f"Sink: {str(finding.get('sink', '')).strip() or 'None provided.'}",
                "",
                "### Impact If Chained",
                str(finding.get("impact", "")).strip() or "None provided.",
                "",
                "### Review Notes",
                str(finding.get("review_notes", "")).strip() or "None provided.",
                "",
                "### Why It's Blocked Right Now",
                str(finding.get("blocked_reason", "")).strip() or "None provided.",
                "",
                "### What's Needed to Exploit",
                str(finding.get("chain_requirements", "")).strip() or "None provided.",
                "",
                "### Remediation",
                str(finding.get("remediation", "")).strip() or "None provided.",
                "",
            ]
        )
    return "\n".join(sections).rstrip() + "\n"


def _render_novel_findings_report(findings: Sequence[Dict[str, Any]]) -> str:
    if not findings:
        return "# Novel Findings\n\nNo reviewed novel findings.\n"

    sections = ["# Novel Findings", ""]
    for finding in findings:
        tier = str(finding.get("review_tier", "DORMANT")).upper()
        sections.extend(
            [
                f"## [{tier}] {finding['vulnerability_name']}",
                f"**Type:** {finding['type']}",
                f"**Discovered During Class Pass:** {finding['agent']}",
                f"**File:** {_display_file_reference(finding)}",
                "",
                "### Why It Looks Novel",
                finding["description"],
                "",
                "### Source -> Sink",
                f"Source: {str(finding.get('source', '')).strip() or 'None provided.'}",
                f"Trust boundary: {str(finding.get('trust_boundary', '')).strip() or 'None provided.'}",
                f"Flow: {str(finding.get('flow_path', '')).strip() or 'None provided.'}",
                f"Sink: {str(finding.get('sink', '')).strip() or 'None provided.'}",
                "",
                "### Impact",
                str(finding.get("impact", "")).strip() or "None provided.",
                "",
                "### Review Notes",
                str(finding.get("review_notes", "")).strip() or "None provided.",
                "",
            ]
        )

        if tier == "CONFIRMED":
            sections.extend(
                [
                    "### PoC",
                    str(finding.get("poc", "")).strip() or "None provided.",
                    "",
                ]
            )
        else:
            sections.extend(
                [
                    "### Why It's Blocked Right Now",
                    str(finding.get("blocked_reason", "")).strip() or "None provided.",
                    "",
                    "### What's Needed to Chain It",
                    str(finding.get("chain_requirements", "")).strip() or "None provided.",
                    "",
                ]
            )

        sections.extend(
            [
                "### Remediation",
                str(finding.get("remediation", "")).strip() or "None provided.",
                "",
            ]
        )

    return "\n".join(sections).rstrip() + "\n"


def _finding_dedupe_key(finding: Dict[str, Any]) -> Tuple[str, str, str, str, str, str]:
    return (
        str(finding.get("category", "class")).strip().lower(),
        str(finding.get("class_name", "")).strip().lower(),
        str(_split_file_reference(finding.get("file", ""))[0]).strip().lower(),
        str(finding.get("type", "")).strip().lower(),
        str(finding.get("source", "")).strip().lower(),
        str(finding.get("sink", "")).strip().lower(),
    )


def _canonical_text(value: Any) -> str:
    return re.sub(r"[^a-z0-9_.:-]+", " ", str(value or "").casefold()).strip()


def _canonical_source_family(finding: Dict[str, Any]) -> str:
    text = _canonical_text(
        " ".join(
            str(finding.get(key, ""))
            for key in ("source", "trust_boundary", "flow_path", "description", "context")
        )
    )
    if "ipcmain" in text or "ipc renderer" in text or "ipc message" in text or " ipc " in f" {text} ":
        return "electron-ipc"
    if "protocol" in text or "deeplink" in text or "deep link" in text:
        return "custom-protocol"
    if "file" in text or "path" in text:
        return "filesystem"
    if "http" in text or "url" in text or "fetch" in text:
        return "network-url"
    return text[:120]


def _canonical_sink_family(finding: Dict[str, Any]) -> str:
    text = _canonical_text(
        " ".join(
            str(finding.get(key, ""))
            for key in ("sink", "type", "description", "context", "flow_path")
        )
    )
    if "child_process.exec" in text or "exec " in f" {text} " or "process execution" in text:
        return "process-exec"
    if "readfilesync" in text or "writefilesync" in text or "path traversal" in text:
        return "filesystem-path"
    if "innerhtml" in text or "eval" in text or "document.write" in text:
        return "dom-code-html"
    if "fetch" in text or "http" in text or "request" in text:
        return "server-side-request"
    return text[:120]


def _canonical_finding_root_key(finding: Dict[str, Any]) -> tuple[str, str, str]:
    file_path = str(_split_file_reference(finding.get("file", ""))[0]).strip().casefold()
    return (file_path, _canonical_source_family(finding), _canonical_sink_family(finding))


def _canonical_owner_class(finding: Dict[str, Any]) -> str | None:
    source_family = _canonical_source_family(finding)
    sink_family = _canonical_sink_family(finding)
    if sink_family == "process-exec":
        return "exec-sink-reachability"
    if source_family == "electron-ipc":
        return "ipc-trust-boundary"
    if sink_family == "filesystem-path":
        return "path-traversal"
    if sink_family == "dom-code-html":
        return "dom-xss"
    if sink_family == "server-side-request":
        return "ssrf"
    return None


def _finding_reported_class(finding: Dict[str, Any]) -> str:
    class_name = str(finding.get("class_name") or "").strip()
    if class_name and class_name.casefold() not in {"novel", "unknown"}:
        return class_name
    return str(finding.get("agent") or class_name or "").strip()


def _is_class_owned_finding(finding: Dict[str, Any]) -> bool:
    reported = _finding_reported_class(finding).casefold()
    category = str(finding.get("category") or "").strip().casefold()
    return bool(reported and reported != "novel" and category != "novel")


def _triage_canonical_ownership(
    confirmed: Sequence[Dict[str, Any]],
    dormant: Sequence[Dict[str, Any]],
    novel: Sequence[Dict[str, Any]],
) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]], list[Dict[str, Any]], list[Dict[str, Any]]]:
    """Suppress off-owner duplicates once the canonical owner reported the same root cause."""
    owner_keys: set[tuple[str, str, str]] = set()
    for finding in [*confirmed, *dormant, *novel]:
        owner = (_canonical_owner_class(finding) or "").casefold()
        reported = _finding_reported_class(finding).casefold()
        if owner and reported == owner and _is_class_owned_finding(finding):
            owner_keys.add(_canonical_finding_root_key(finding))

    def split_tier(items: Sequence[Dict[str, Any]]) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
        kept: list[Dict[str, Any]] = []
        demoted_items: list[Dict[str, Any]] = []
        for finding in items:
            reported = _finding_reported_class(finding).casefold()
            owner = (_canonical_owner_class(finding) or "").casefold()
            root_key = _canonical_finding_root_key(finding)
            if owner and reported != owner and root_key in owner_keys:
                updated = dict(finding)
                updated["canonical_owner_class"] = owner
                updated["canonical_root_key"] = "|".join(root_key)
                updated["rejected_reason"] = (
                    "off-category duplicate: canonical root cause is owned by " f"{owner}"
                )
                demoted_items.append(updated)
            else:
                kept.append(finding)
        return kept, demoted_items

    kept_confirmed, demoted_confirmed = split_tier(confirmed)
    kept_dormant, demoted_dormant = split_tier(dormant)
    kept_novel, demoted_novel = split_tier(novel)
    return kept_confirmed, kept_dormant, kept_novel, [*demoted_confirmed, *demoted_dormant, *demoted_novel]


def stage2_ghost_review(
    findings: List[Dict[str, Any]],
    target_path: Path,
    program: str,
    hunt_type: str,
    output_root: Path | None = None,
    *,
    write_reports: bool = True,
    hunting_policy: HuntingPolicy | dict[str, Any] | None = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Compatibility wrapper for the shared BaseTeam Stage 2 review gate."""
    policy_snippet = ""
    if isinstance(hunting_policy, HuntingPolicy):
        policy_snippet = hunting_policy.snippet("review")
    elif isinstance(hunting_policy, dict) and hunting_policy.get("enabled"):
        policy_snippet = coerce_hunting_policy(hunting_policy).snippet("review")

    def _legacy_review_single(finding: Dict[str, Any], review_target: Path) -> Dict[str, Any]:
        _tier, reviewed, _reason = _review_single_finding(
            finding,
            review_target,
            policy=hunting_policy,
            policy_snippet=policy_snippet,
        )
        return reviewed

    # Historically this procedural zero-day path always wrote to the 0day
    # storage lane regardless of the caller's older hunt_type label (often
    # "web"). Keep that output shape while making the review gate shared.
    return shared_stage2_ghost_review(
        findings,
        target_path,
        program,
        "0day_team",
        review_single=_legacy_review_single,
        review_timeout=CLAUDE_REVIEW_TIMEOUT_SECONDS,
        max_workers=CLAUDE_REVIEW_MAX_WORKERS,
        output_root=output_root,
        write_reports=write_reports,
    )

def _finding_signature(finding: Dict[str, Any]) -> str:
    return json.dumps(finding, sort_keys=True, separators=(",", ":"))


def _append_unique_findings(findings_path: Path, findings: Sequence[Dict[str, Any]]) -> None:
    if not findings:
        return

    lock_path = findings_path.with_suffix(".lock")
    lock_handle = open(lock_path, "w")
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            existing = {_finding_signature(item) for item in _load_findings(findings_path)}
            pending: List[Dict[str, Any]] = []
            for finding in findings:
                if is_placeholder_finding(finding):
                    continue
                signature = _finding_signature(finding)
                if signature in existing:
                    continue
                existing.add(signature)
                pending.append(finding)

            if not pending:
                return

            with findings_path.open("a", encoding="utf-8") as fh:
                for finding in pending:
                    fh.write(json.dumps(finding, sort_keys=True) + "\n")
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    finally:
        lock_handle.close()


def _appmap_candidate_identity(metadata: dict[str, Any]) -> str:
    return str(metadata.get("candidate_id") or metadata.get("appmap_candidate_id") or "").strip()


def _is_appmap_brainstorm_profile(profile: VulnerabilityClassProfile) -> bool:
    metadata = dict(getattr(profile, "brainstorm_metadata", {}) or {})
    if not metadata:
        return False
    if _appmap_candidate_identity(metadata):
        return True
    if str(metadata.get("appmap_context_packet") or "").strip():
        return True
    return bool(re.search(r"\bappmap\b", ",".join(str(item) for item in metadata.get("brainstorm_tags", []))))


def _appmap_coverage_identity(profile: VulnerabilityClassProfile) -> dict[str, str] | None:
    metadata = dict(getattr(profile, "brainstorm_metadata", {}) or {})
    return appmap_assignment_identity(metadata, default_agent_key=profile.key)


def _read_brainstorm_coverage_events(coverage_path: Path) -> list[dict[str, Any]]:
    return read_coverage_jsonl(coverage_path)


def _filter_appmap_profiles_by_coverage(
    profiles: Sequence[VulnerabilityClassProfile],
    *,
    coverage_path: Path | None,
    fresh: bool,
) -> tuple[list[VulnerabilityClassProfile], list[VulnerabilityClassProfile]]:
    if fresh or coverage_path is None:
        return list(profiles), []
    events = _read_brainstorm_coverage_events(coverage_path)
    if not events:
        return list(profiles), []

    active: list[VulnerabilityClassProfile] = []
    skipped: list[VulnerabilityClassProfile] = []
    for profile in profiles:
        identities = [
            identity
            for metadata in _brainstorm_assignment_metadata(profile)
            for identity in [appmap_assignment_identity(metadata, default_agent_key=profile.key)]
            if identity is not None
        ]
        if not identities:
            active.append(profile)
            continue
        if all(is_appmap_assignment_covered(identity, events) for identity in identities):
            skipped.append(profile)
        else:
            active.append(profile)
    return active, skipped


def _brainstorm_event_base_from_metadata(
    profile: VulnerabilityClassProfile,
    metadata: dict[str, Any],
) -> dict[str, Any] | None:
    hypothesis_id = str(metadata.get("hypothesis_id") or "").strip()
    agent_key = str(metadata.get("brainstorm_agent_key") or metadata.get("agent_key") or profile.key).strip()
    if not hypothesis_id or not agent_key:
        return None
    base = {
        "hypothesis_id": hypothesis_id,
        "hypothesis_title": metadata.get("hypothesis_title"),
        "agent_key": agent_key,
        "source_spec_path": metadata.get("source_spec_path") or metadata.get("brainstorm_spec"),
        "expected_chain": metadata.get("expected_chain"),
        "brainstorm_spec": metadata.get("brainstorm_spec"),
    }
    if _is_appmap_brainstorm_profile(profile) or metadata.get("appmap_candidate_id") or metadata.get("appmap_context_packet"):
        candidate_id = _appmap_candidate_identity(metadata)
        if candidate_id:
            base["appmap_candidate_id"] = candidate_id
            if metadata.get("candidate_id"):
                base["candidate_id"] = str(metadata.get("candidate_id")).strip()
        appmap_context_packet = str(metadata.get("appmap_context_packet") or "").strip()
        if appmap_context_packet:
            base["appmap_context_packet"] = appmap_context_packet
        for source_key, coverage_key in (
            ("appmap_run_id", "appmap_run_id"),
            ("appmap_flow_id", "appmap_flow_id"),
            ("_snapshot_id", "snapshot_id"),
            ("_snapshot_version", "snapshot_version"),
        ):
            value = str(metadata.get(source_key) or "").strip()
            if value:
                base[coverage_key] = value
    cluster_id = str(metadata.get("brainstorm_cluster_id") or "").strip()
    if cluster_id:
        base["brainstorm_cluster_id"] = cluster_id
    return base


def _brainstorm_event_base(profile: VulnerabilityClassProfile) -> dict[str, Any] | None:
    metadata = dict(getattr(profile, "brainstorm_metadata", {}) or {})
    return _brainstorm_event_base_from_metadata(profile, metadata)


def _append_brainstorm_coverage_for_metadata(
    coverage_path: Path | None,
    profile: VulnerabilityClassProfile,
    metadata: dict[str, Any],
    event: str,
    **fields: Any,
) -> None:
    if coverage_path is None:
        return
    base = _brainstorm_event_base_from_metadata(profile, metadata)
    if base is None:
        return
    try:
        append_coverage(coverage_path, {"event": event, **base, **fields})
    except Exception as exc:
        print(f"[brainstorm] coverage warning for {profile.key}: {exc}", flush=True)


def _append_brainstorm_coverage(
    coverage_path: Path | None,
    profile: VulnerabilityClassProfile,
    event: str,
    **fields: Any,
) -> None:
    for metadata in _brainstorm_assignment_metadata(profile):
        _append_brainstorm_coverage_for_metadata(coverage_path, profile, metadata, event, **fields)


def _append_brainstorm_hypothesis_loaded(
    coverage_path: Path,
    *,
    hypothesis: Any,
    run_id: str | None,
    spec_path: Path,
) -> None:
    try:
        append_coverage(
            coverage_path,
            {
                "event": "hypothesis_loaded",
                "hypothesis_id": hypothesis.id,
                "hypothesis_title": hypothesis.title,
                "status": hypothesis.status,
                "run_id": run_id,
                "source_spec_path": str(spec_path),
                "brainstorm_spec": str(spec_path),
            },
        )
    except Exception as exc:
        print(f"[brainstorm] coverage warning for {hypothesis.id}: {exc}", flush=True)


def _agent_log_has_empty_result(log_path: Path) -> bool:
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(r"(?m)^\s*\{\s*\}\s*$", text))


def _findings_by_assignment_key(
    findings: Sequence[Dict[str, Any]],
) -> dict[tuple[str, str, str], list[Dict[str, Any]]]:
    grouped: dict[tuple[str, str, str], list[Dict[str, Any]]] = {}
    for finding in findings:
        key = _finding_assignment_key(finding)
        if key is None:
            continue
        grouped.setdefault(key, []).append(finding)
    return grouped


def _append_clustered_brainstorm_completion(
    session: AgentSession,
    *,
    initial_salvaged: Sequence[Dict[str, Any]],
    final_salvaged: Sequence[Dict[str, Any]],
) -> bool:
    coverage_path = getattr(session, "coverage_path", None)
    assignments = _brainstorm_assignment_metadata(session.profile)
    if coverage_path is None or len(assignments) <= 1:
        return False

    final_by_key = _findings_by_assignment_key(final_salvaged)
    initial_by_key = _findings_by_assignment_key(initial_salvaged)
    assignment_keys = {
        key
        for metadata in assignments
        if (key := _brainstorm_metadata_key(metadata, default_agent_key=session.profile.key)) is not None
    }
    unmatched_salvaged = any(
        _finding_assignment_key(item) not in assignment_keys
        for item in [*initial_salvaged, *final_salvaged]
    )
    log_empty = _agent_log_has_empty_result(session.log_path)
    for metadata in assignments:
        key = _brainstorm_metadata_key(metadata, default_agent_key=session.profile.key)
        final_matches = final_by_key.get(key, []) if key is not None else []
        if final_matches:
            _append_brainstorm_coverage_for_metadata(
                coverage_path,
                session.profile,
                metadata,
                "agent_completed_with_raw_findings",
                raw_finding_signatures=[_finding_signature(item) for item in final_matches],
            )
            continue
        initial_matches = initial_by_key.get(key, []) if key is not None else []
        if initial_matches:
            _append_brainstorm_coverage_for_metadata(coverage_path, session.profile, metadata, "agent_duplicate_only")
            continue
        if unmatched_salvaged:
            _append_brainstorm_coverage_for_metadata(
                coverage_path,
                session.profile,
                metadata,
                "agent_invalid_output",
                unassigned_raw_finding_count=len([*initial_salvaged, *final_salvaged]),
            )
        elif log_empty or final_salvaged or initial_salvaged:
            _append_brainstorm_coverage_for_metadata(coverage_path, session.profile, metadata, "agent_completed_no_finding")
        else:
            _append_brainstorm_coverage_for_metadata(coverage_path, session.profile, metadata, "agent_invalid_output")
    return True


def _append_brainstorm_completion(
    session: AgentSession,
    *,
    exit_code: int,
    initial_salvaged: Sequence[Dict[str, Any]],
    final_salvaged: Sequence[Dict[str, Any]],
) -> None:
    coverage_path = getattr(session, "coverage_path", None)
    if coverage_path is None or not getattr(session.profile, "brainstorm_metadata", None):
        return
    if exit_code == -9:
        _append_brainstorm_coverage(coverage_path, session.profile, "agent_timeout")
        return
    if exit_code != 0:
        _append_brainstorm_coverage(
            coverage_path,
            session.profile,
            "agent_crashed",
            exit_code=exit_code,
        )
        return
    if _append_clustered_brainstorm_completion(
        session,
        initial_salvaged=initial_salvaged,
        final_salvaged=final_salvaged,
    ):
        return
    if initial_salvaged and not final_salvaged:
        _append_brainstorm_coverage(coverage_path, session.profile, "agent_duplicate_only")
        return
    if final_salvaged:
        _append_brainstorm_coverage(
            coverage_path,
            session.profile,
            "agent_completed_with_raw_findings",
            raw_finding_signatures=[_finding_signature(item) for item in final_salvaged],
        )
        return
    if _agent_log_has_empty_result(session.log_path):
        _append_brainstorm_coverage(coverage_path, session.profile, "agent_completed_no_finding")
        return
    _append_brainstorm_coverage(coverage_path, session.profile, "agent_invalid_output")


def _normalize_brainstorm_source_spec_path(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        return raw
    return str(Path(raw).expanduser().resolve(strict=False))


def _brainstorm_profile_key(profile: VulnerabilityClassProfile) -> tuple[str, str, str] | None:
    metadata = dict(getattr(profile, "brainstorm_metadata", {}) or {})
    hypothesis_id = str(metadata.get("hypothesis_id") or "").strip()
    agent_key = str(metadata.get("brainstorm_agent_key") or profile.key).strip()
    source_spec_path = _normalize_brainstorm_source_spec_path(
        metadata.get("source_spec_path") or metadata.get("brainstorm_spec")
    )
    if not hypothesis_id or not agent_key or not source_spec_path:
        return None
    return source_spec_path, hypothesis_id, agent_key


def _brainstorm_assignment_keys(profile: VulnerabilityClassProfile) -> list[tuple[str, str, str]]:
    primary = _brainstorm_profile_key(profile)
    keys: list[tuple[str, str, str]] = [primary] if primary is not None else []
    metadata = dict(getattr(profile, "brainstorm_metadata", {}) or {})
    for assignment in metadata.get("brainstorm_cluster_assignments") or []:
        if not isinstance(assignment, dict):
            continue
        hypothesis_id = str(assignment.get("hypothesis_id") or "").strip()
        agent_key = str(assignment.get("brainstorm_agent_key") or assignment.get("agent_key") or "").strip()
        source_spec_path = _normalize_brainstorm_source_spec_path(
            assignment.get("source_spec_path") or assignment.get("brainstorm_spec")
        )
        key = (source_spec_path, hypothesis_id, agent_key)
        if all(key) and key not in keys:
            keys.append(key)
    return keys


def _brainstorm_assignment_metadata(profile: VulnerabilityClassProfile) -> list[dict[str, Any]]:
    metadata = dict(getattr(profile, "brainstorm_metadata", {}) or {})
    assignments = [item for item in metadata.get("brainstorm_cluster_assignments") or [] if isinstance(item, dict)]
    return [dict(item) for item in assignments] or [metadata]


def _brainstorm_profile_assignments(profile: VulnerabilityClassProfile) -> list[dict[str, str]]:
    assignments: list[dict[str, str]] = []
    for metadata in _brainstorm_assignment_metadata(profile):
        assignments.append(
            {
                "profile": profile.key,
                "hypothesis_id": str(metadata.get("hypothesis_id") or "").strip(),
                "agent_key": str(metadata.get("brainstorm_agent_key") or metadata.get("agent_key") or profile.key).strip(),
                "source_spec_path": _normalize_brainstorm_source_spec_path(
                    metadata.get("source_spec_path") or metadata.get("brainstorm_spec")
                ),
            }
        )
    return assignments


def _brainstorm_hypothesis_assignment(hypothesis: Any) -> dict[str, str]:
    return {
        "hypothesis_id": str(getattr(hypothesis, "id", "")).strip(),
        "title": str(getattr(hypothesis, "title", "")).strip(),
        "source_spec_path": _normalize_brainstorm_source_spec_path(
            getattr(hypothesis, "source_spec_path", "")
        ),
    }


def _finding_brainstorm_assignment(
    finding: Dict[str, Any],
    profiles_by_key: dict[tuple[str, str, str], tuple[VulnerabilityClassProfile, dict[str, Any]]],
) -> tuple[VulnerabilityClassProfile, dict[str, Any]] | None:
    hypothesis_id = str(finding.get("hypothesis_id") or "").strip()
    agent_key = str(finding.get("brainstorm_agent_key") or finding.get("agent") or "").strip()
    source_spec_path = _normalize_brainstorm_source_spec_path(
        finding.get("source_spec_path") or finding.get("brainstorm_spec")
    )
    if not hypothesis_id or not agent_key or not source_spec_path:
        return None
    return profiles_by_key.get((source_spec_path, hypothesis_id, agent_key))


def _brainstorm_metadata_key(metadata: dict[str, Any], *, default_agent_key: str = "") -> tuple[str, str, str] | None:
    hypothesis_id = str(metadata.get("hypothesis_id") or "").strip()
    agent_key = str(metadata.get("brainstorm_agent_key") or metadata.get("agent_key") or default_agent_key).strip()
    source_spec_path = _normalize_brainstorm_source_spec_path(
        metadata.get("source_spec_path") or metadata.get("brainstorm_spec")
    )
    if not hypothesis_id or not agent_key or not source_spec_path:
        return None
    return source_spec_path, hypothesis_id, agent_key


def _finding_assignment_key(finding: Dict[str, Any]) -> tuple[str, str, str] | None:
    hypothesis_id = str(finding.get("hypothesis_id") or "").strip()
    agent_key = str(finding.get("brainstorm_agent_key") or finding.get("agent") or "").strip()
    source_spec_path = _normalize_brainstorm_source_spec_path(
        finding.get("source_spec_path") or finding.get("brainstorm_spec")
    )
    if not hypothesis_id or not agent_key or not source_spec_path:
        return None
    return source_spec_path, hypothesis_id, agent_key


def _review_match_key(finding: Dict[str, Any]) -> tuple[str, ...]:
    fid = str(finding.get("fid") or "").strip()
    if fid:
        return ("fid", fid)
    return (
        "shape",
        _normalize_brainstorm_source_spec_path(
            finding.get("source_spec_path") or finding.get("brainstorm_spec")
        ),
        str(finding.get("hypothesis_id") or "").strip(),
        str(finding.get("brainstorm_agent_key") or finding.get("agent") or "").strip(),
        str(finding.get("type") or "").strip(),
        str(finding.get("file") or "").strip(),
        str(finding.get("line") or "").strip(),
        str(finding.get("source") or "").strip(),
        str(finding.get("sink") or "").strip(),
    )


def _append_brainstorm_review_coverage(
    coverage_path: Path | None,
    *,
    raw_findings: Sequence[Dict[str, Any]],
    reviewed_findings: Sequence[Dict[str, Any]],
    profiles: Sequence[VulnerabilityClassProfile],
) -> None:
    if coverage_path is None:
        return
    profiles_by_key: dict[tuple[str, str, str], tuple[VulnerabilityClassProfile, dict[str, Any]]] = {}
    for profile in profiles:
        for metadata in _brainstorm_assignment_metadata(profile):
            hypothesis_id = str(metadata.get("hypothesis_id") or "").strip()
            agent_key = str(metadata.get("brainstorm_agent_key") or metadata.get("agent_key") or profile.key).strip()
            source_spec_path = _normalize_brainstorm_source_spec_path(
                metadata.get("source_spec_path") or metadata.get("brainstorm_spec")
            )
            key = (source_spec_path, hypothesis_id, agent_key)
            if all(key):
                profiles_by_key[key] = (profile, metadata)
    if not profiles_by_key:
        return
    reviewed_by_key = {_review_match_key(item): item for item in reviewed_findings}
    for raw in raw_findings:
        assignment = _finding_brainstorm_assignment(raw, profiles_by_key)
        if assignment is None:
            continue
        profile, metadata = assignment
        reviewed = reviewed_by_key.get(_review_match_key(raw))
        if reviewed is None:
            _append_brainstorm_coverage_for_metadata(coverage_path, profile, metadata, "review_rejected")
            continue
        fid = str(reviewed.get("fid") or raw.get("fid") or "").strip()
        if fid:
            _append_brainstorm_coverage_for_metadata(
                coverage_path,
                profile,
                metadata,
                "review_promoted",
                linked_fids=[fid],
            )


def _reserve_missing_fids_for_review(
    findings: Sequence[Dict[str, Any]],
    ledger: Any,
) -> List[Dict[str, Any]]:
    """Assign stable ledger FIDs before review without suppressing duplicates."""
    reserved_findings: List[Dict[str, Any]] = []
    known_fids_by_key: dict[Tuple[str, str, str, str, str, str], str] = {}
    for finding in findings:
        fid = str(finding.get("fid") or "").strip()
        if fid:
            known_fids_by_key.setdefault(_finding_dedupe_key(finding), fid)

    for finding in findings:
        existing_fid = str(finding.get("fid") or "").strip()
        if existing_fid:
            reserved_findings.append(dict(finding))
            continue

        batch_fid = known_fids_by_key.get(_finding_dedupe_key(finding))
        if batch_fid:
            queued = dict(finding)
            queued["fid"] = batch_fid
            reserved_findings.append(queued)
            continue

        try:
            is_duplicate, fid, reserved = ledger.check(finding)
        except Exception as exc:
            queued = dict(finding)
            queued["ledger_reservation_error"] = str(exc)
            reserved_findings.append(queued)
            continue

        queued = dict(finding)
        if isinstance(reserved, dict):
            queued.update({key: value for key, value in reserved.items() if value not in (None, "")})
        if fid:
            queued["fid"] = fid
            known_fids_by_key.setdefault(_finding_dedupe_key(queued), fid)
        if is_duplicate and fid:
            print(
                f'[ledger] reusing duplicate fid {fid}: '
                f'{finding.get("type", finding.get("description", "unknown"))[:60]}',
                flush=True,
            )
        reserved_findings.append(queued)
    return reserved_findings


def _run_agent_session(
    session: AgentSession,
    findings_path: Path,
    ledger: Any,
) -> int:
    if session.process is None:
        return -1

    try:
        exit_code = session.process.wait(timeout=AGENT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            session.process.kill()
            session.process.wait(timeout=5)
        except Exception:
            pass
        exit_code = -9
        try:
            with session.log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"Timed out after {AGENT_TIMEOUT_SECONDS} seconds\n")
        except OSError:
            pass
    except Exception as exc:
        try:
            session.process.kill()
        except Exception:
            pass
        exit_code = -1
        try:
            with session.log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"Unhandled agent wait failure: {exc}\n")
        except OSError:
            pass

    try:
        salvaged = _extract_findings_from_log(session.log_path, default_agent=session.profile.key)
        initial_salvaged = list(salvaged)
        # Deduplicate through ledger before reviewer sees anything
        if salvaged and not getattr(session, "skip_ledger", False):
            deduped = []
            for f in salvaged:
                try:
                    is_dup, fid, f_with_fid = ledger.check(f)
                except Exception as exc:
                    queued = dict(f)
                    queued["ledger_reservation_error"] = str(exc)
                    deduped.append(queued)
                    continue
                if not is_dup:
                    deduped.append(f_with_fid)
                elif fid:
                    print(
                        f'[ledger] SKIPPED duplicate {fid}: '
                        f'{f.get("type", f.get("description", "unknown"))[:60]}',
                        flush=True,
                    )
            salvaged = deduped
        _append_unique_findings(findings_path, salvaged)
        _append_brainstorm_completion(
            session,
            exit_code=exit_code,
            initial_salvaged=initial_salvaged,
            final_salvaged=salvaged,
        )
        for finding in salvaged:
            fid = str(finding.get("fid") or f"{session.profile.key}:{finding.get('file')}:{finding.get('line')}")
            _safe_log_span(
                span_type="finding",
                level="RESULT",
                message=f"Finding: {fid}",
                finding_fid=fid,
                review_tier=str(finding.get("severity", "UNKNOWN")),
                duplicate=False,
                finding_reward=0,
                allocated_pte_lite=0,
            )
    except OSError:
        _append_brainstorm_completion(
            session,
            exit_code=exit_code,
            initial_salvaged=[],
            final_salvaged=[],
        )

    return exit_code


def _summarize_findings(findings: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    by_agent: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    by_class: Dict[str, int] = {}

    for finding in findings:
        agent = str(finding.get("agent", "unknown"))
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        category = str(finding.get("category", "class")).lower()
        class_name = str(finding.get("class_name", "unknown")).lower()
        by_agent[agent] = by_agent.get(agent, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1
        by_class[class_name] = by_class.get(class_name, 0) + 1

    return {
        "total_findings": len(findings),
        "by_agent": dict(sorted(by_agent.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_class": dict(sorted(by_class.items())),
    }


def _pretty_print_findings(findings: Sequence[Dict[str, Any]]) -> None:
    summary = _summarize_findings(findings)
    print("Zero-Day Team Findings")
    print("=" * 80)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("-" * 80)

    if not findings:
        print("No findings recorded.")
        return

    for index, finding in enumerate(findings, start=1):
        category = str(finding.get("category", "class")).lower()
        tier = str(finding.get("review_tier", "")).upper()
        if category == "novel":
            label = f"NOVEL/{tier or finding.get('severity', 'UNKNOWN')}"
        else:
            label = "DORMANT" if tier.startswith("DORMANT") else str(finding.get("severity", "UNKNOWN"))

        print(f"{index}. [{label}] {finding['type']} ({finding['agent']})")
        print(f"   File: {_display_file_reference(finding)}")
        print(f"   Why: {finding['description']}")
        source = str(finding.get("source", "")).strip()
        sink = str(finding.get("sink", "")).strip()
        if source:
            print(f"   Source: {source}")
        if sink:
            print(f"   Sink: {sink}")
        review_reason = str(finding.get("review_reason", "")).strip()
        if review_reason:
            print(f"   Review: {review_reason}")
        print("-" * 80)


def _run_single_agent(
    profile: VulnerabilityClassProfile,
    program: str,
    target: Path,
    findings_path: Path,
    agents_root: Path,
    ledger: Any,
    class_context: str = "",
    repo_context: str = "",
    starting_entry: dict[str, Any] | None = None,
    fresh: bool = False,
    hunt_type: str = "source",
    coverage_path: Path | None = None,
    policy_snippet: str = "",
) -> Tuple[VulnerabilityClassProfile, int]:
    session = _spawn_agent(
        profile=profile,
        program=program,
        target_path=target,
        findings_path=findings_path,
        agents_root=agents_root,
        class_context=class_context,
        repo_context=repo_context,
        starting_entry=starting_entry,
        skip_ledger=fresh,
        coverage_path=coverage_path,
        policy_snippet=policy_snippet,
    )
    if session.process is not None:
        _append_brainstorm_coverage(
            coverage_path,
            profile,
            "agent_spawned",
            pid=getattr(session.process, "pid", None),
        )
    else:
        _append_brainstorm_coverage(
            coverage_path,
            profile,
            "agent_crashed",
            spawn_failed=True,
        )
    exit_code = _run_agent_session(session, findings_path, ledger)
    return profile, exit_code


def _write_chainable_findings_input(path: Path, findings: Sequence[Dict[str, Any]]) -> Path:
    _ensure_directory(path.parent)
    path.write_text(json.dumps(list(findings), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _is_url(value: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value))


def _resolve_analysis_target(
    target_path: str,
    team_root: Path,
    target_type: str,
) -> Path:
    normalized_type = target_type.strip().lower()
    if normalized_type == "auto":
        if _is_url(target_path):
            normalized_type = "url"
        else:
            candidate = Path(target_path).expanduser().resolve()
            if not candidate.exists():
                raise FileNotFoundError(f"Target path does not exist: {candidate}")
            normalized_type = "directory" if candidate.is_dir() else "file"

    if normalized_type == "directory":
        target = Path(target_path).expanduser().resolve()
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")
        if not target.is_dir():
            raise NotADirectoryError(f"Target path is not a directory: {target}")
        return target

    if normalized_type in {"file", "script", "url"}:
        from agents.decompiler import decompile

        decompiled_path, warnings = decompile(target_path, team_root / "decompiled")
        for warning in warnings:
            print(f"[orchestrator] decompiler warning: {warning}")
        return decompiled_path.resolve()

    raise ValueError(f"Unsupported target_type: {target_type!r}")


def _cluster_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-") or "cluster"


def _load_appmap_cluster_packet(profile: VulnerabilityClassProfile) -> dict[str, Any] | None:
    metadata = dict(getattr(profile, "brainstorm_metadata", {}) or {})
    packet_path = str(metadata.get("appmap_context_packet") or "").strip()
    if not packet_path:
        return None
    path = Path(packet_path).expanduser()
    if path.is_symlink() or not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _surface_cluster_part(packet: dict[str, Any], key: str) -> tuple[str, str, str]:
    evidence = packet.get("evidence") if isinstance(packet.get("evidence"), dict) else {}
    surface = evidence.get(key) if isinstance(evidence.get(key), dict) else {}
    return (
        str(surface.get("file") or "").strip(),
        str(surface.get("kind") or "").strip(),
        str(surface.get("line") or "").strip(),
    )


def _brainstorm_cluster_key(profile: VulnerabilityClassProfile) -> tuple[Any, ...] | None:
    if not _is_appmap_brainstorm_profile(profile):
        return None
    packet = _load_appmap_cluster_packet(profile)
    if packet is None:
        return None
    metadata = dict(getattr(profile, "brainstorm_metadata", {}) or {})
    source = _surface_cluster_part(packet, "source")
    sink = _surface_cluster_part(packet, "sink")
    if not source[0] or not sink[0]:
        return None
    return (
        _normalize_brainstorm_source_spec_path(metadata.get("source_spec_path") or metadata.get("brainstorm_spec")),
        str(metadata.get("appmap_run_id") or packet.get("run_id") or "").strip(),
        tuple(profile.focus_globs),
        source,
        sink,
    )


def _cluster_brainstorm_profiles(
    profiles: Sequence[VulnerabilityClassProfile],
    *,
    max_cluster_size: int,
) -> tuple[list[VulnerabilityClassProfile], list[dict[str, Any]]]:
    if max_cluster_size <= 1:
        return list(profiles), []

    groups: dict[tuple[Any, ...], list[VulnerabilityClassProfile]] = {}
    passthrough: list[VulnerabilityClassProfile] = []
    for profile in profiles:
        key = _brainstorm_cluster_key(profile)
        if key is None:
            passthrough.append(profile)
        else:
            groups.setdefault(key, []).append(profile)

    clustered: list[VulnerabilityClassProfile] = []
    summaries: list[dict[str, Any]] = []
    for key, group in groups.items():
        for offset in range(0, len(group), max_cluster_size):
            chunk = group[offset : offset + max_cluster_size]
            if len(chunk) == 1:
                clustered.append(chunk[0])
                continue
            first = chunk[0]
            cluster_id = _cluster_slug(
                "cluster-" + "-".join(
                    str(dict(getattr(item, "brainstorm_metadata", {}) or {}).get("hypothesis_id") or item.key)
                    for item in chunk
                )
            )
            assignments: list[dict[str, Any]] = []
            prompt_sections: list[str] = []
            for item in chunk:
                item_metadata = dict(getattr(item, "brainstorm_metadata", {}) or {})
                item_metadata["brainstorm_cluster_id"] = cluster_id
                assignments.append(item_metadata)
                prompt_sections.append(f"### Cluster member: {item.key}\n{item.prompt_addendum}")
            metadata = dict(getattr(first, "brainstorm_metadata", {}) or {})
            metadata["brainstorm_cluster_id"] = cluster_id
            metadata["brainstorm_cluster_size"] = len(chunk)
            metadata["brainstorm_cluster_assignments"] = assignments
            cluster_key = _cluster_slug(f"{first.key}-{cluster_id}")
            clustered_profile = VulnerabilityClassProfile(
                key=cluster_key,
                description=(
                    f"Clustered AppMap brainstorm agent for {len(chunk)} hypotheses that share the same "
                    "focus files, source, and sink evidence."
                ),
                entry_questions=first.entry_questions,
                cross_questions=first.cross_questions,
                sink_categories=first.sink_categories,
                reasoning=first.reasoning,
                display_name=f"{first.title} Cluster ({len(chunk)} assignments)",
                prompt_addendum=(
                    "Clustered brainstorm assignment: evaluate each member independently, but use the shared "
                    "source/sink context to avoid duplicate agent spawns. Emit findings separately with the exact "
                    "metadata for the matching member. If no member has a real issue, output exactly {}.\n\n"
                    "Cluster assignment metadata:\n"
                    + json.dumps(assignments, indent=2, sort_keys=True)
                    + "\n\n"
                    + "\n\n".join(prompt_sections)
                ),
                focus_globs=first.focus_globs,
                ignore_globs=first.ignore_globs,
                brainstorm_metadata=metadata,
            )
            clustered.append(clustered_profile)
            summaries.append(
                {
                    "cluster_id": cluster_id,
                    "profile": clustered_profile.key,
                    "members": [
                        assignment
                        for item in chunk
                        for assignment in _brainstorm_profile_assignments(item)
                    ],
                }
            )
    return [*passthrough, *clustered], summaries


def _category_master_profile_from_assignment(assignment: Any) -> VulnerabilityClassProfile:
    """Build a runtime profile for a scheduler-created category master.

    The pure scheduler decides *whether* hypotheses should be bundled. The
    zero-day runtime owns the concrete prompt/profile shape because coverage and
    finding attribution are brainstorm-specific here.
    """

    metadata = dict(getattr(assignment, "scheduler_metadata", {}) or {})
    if not metadata.get("category_master"):
        return assignment.profile

    first = assignment.profile
    assignments = [
        dict(item)
        for item in (getattr(assignment, "assigned_hypotheses", ()) or ())
        if isinstance(item, dict)
    ]
    if len(assignments) <= 1:
        return first

    master_key = str(getattr(assignment, "key", "") or getattr(first, "key", "") or "category-master").strip()
    family = str(getattr(assignment, "surface_family", "") or metadata.get("surface_family") or "unknown").strip()
    member_keys = [str(item).strip() for item in metadata.get("member_agent_keys", []) if str(item).strip()]
    member_ids = [str(item).strip() for item in metadata.get("member_hypothesis_ids", []) if str(item).strip()]
    prompt_sections = [
        "Category-master brainstorm assignment: evaluate each assigned hypothesis independently, "
        "but use one broad surface-family agent so related hypotheses can share context and avoid duplicate spawns.",
        f"Surface family: {family}",
        f"Member agents: {', '.join(member_keys) if member_keys else '(unknown)'}",
        f"Member hypotheses: {', '.join(member_ids) if member_ids else '(unknown)'}",
        "Emit findings separately with the exact source_spec_path, hypothesis_id, and brainstorm_agent_key for the matching member. "
        "If no member has a real issue, output exactly {}.",
        "Category-master assignment metadata:",
        json.dumps(assignments, indent=2, sort_keys=True),
    ]
    first_addendum = str(getattr(first, "prompt_addendum", "") or "").strip()
    if first_addendum:
        prompt_sections.extend(["Seed prompt from the first bundled hypothesis:", first_addendum])

    master_metadata = dict(getattr(first, "brainstorm_metadata", {}) or {})
    master_metadata.update(
        {
            "category_master": True,
            "scheduler_category_master": True,
            "surface_family": family,
            "brainstorm_cluster_id": _cluster_slug(master_key),
            "brainstorm_cluster_size": len(assignments),
            "brainstorm_cluster_assignments": assignments,
            "scheduler_master_agent_key": master_key,
            "member_agent_keys": member_keys,
            "member_hypothesis_ids": member_ids,
        }
    )

    return VulnerabilityClassProfile(
        key=master_key,
        description=(
            f"Category-master brainstorm agent for {len(assignments)} {family or 'unknown'} hypotheses. "
            "Explores a generic surface category while preserving per-hypothesis attribution."
        ),
        entry_questions=getattr(first, "entry_questions", ()),
        cross_questions=getattr(first, "cross_questions", ()),
        sink_categories=getattr(first, "sink_categories", ()),
        reasoning=getattr(first, "reasoning", ""),
        display_name=f"{family or 'Category'} Master ({len(assignments)} hypotheses)",
        prompt_addendum="\n\n".join(prompt_sections),
        focus_globs=getattr(first, "focus_globs", ()),
        ignore_globs=getattr(first, "ignore_globs", ()),
        brainstorm_metadata=master_metadata,
    )


def _profiles_from_scheduler_result(result: Any) -> list[VulnerabilityClassProfile]:
    assignments = list(getattr(result, "selected_assignments", ()) or ())
    if not assignments:
        return list(getattr(result, "selected_profiles", ()) or ())
    return [_category_master_profile_from_assignment(assignment) for assignment in assignments]


def _reject_brainstorm_profile_collisions(
    brainstorm_profiles: Sequence[VulnerabilityClassProfile],
    existing_profiles: Sequence[VulnerabilityClassProfile],
) -> None:
    existing_keys = {profile.key.casefold(): profile.key for profile in existing_profiles}
    seen_assignments: dict[tuple[str, str, str], str] = {}
    seen_non_assignments: dict[str, str] = {}
    for profile in brainstorm_profiles:
        normalized_key = profile.key.casefold()
        assignment_key = _brainstorm_profile_key(profile)
        if assignment_key is None and normalized_key in seen_non_assignments:
            raise ValueError(
                "duplicate brainstorm profile key "
                f"{profile.key!r} conflicts with {seen_non_assignments[normalized_key]!r}"
            )
        if assignment_key is not None and assignment_key in seen_assignments:
            raise ValueError(
                "duplicate brainstorm assignment "
                f"{assignment_key[1]!r}/{assignment_key[2]!r} from {assignment_key[0]} "
                f"conflicts with {seen_assignments[assignment_key]!r}"
            )
        if assignment_key is None:
            seen_non_assignments[normalized_key] = profile.key
        else:
            seen_assignments[assignment_key] = profile.key
        if normalized_key in existing_keys:
            raise ValueError(
                "brainstorm profile key "
                f"{profile.key!r} conflicts with existing profile {existing_keys[normalized_key]!r}"
            )


def _load_brainstorm_profiles(
    *,
    spec_path: str | Path,
    program_slug: str,
    version: str,
    selected_hypothesis: str | None = None,
    require_selected: bool = True,
) -> tuple[list[VulnerabilityClassProfile], list[Any], Path]:
    spec = parse_brainstorm_spec(spec_path)
    selected_id = str(selected_hypothesis or "").strip()
    selected_hypotheses = []
    for hypothesis in spec.hypotheses:
        if hypothesis.status == "retired":
            continue
        if selected_id and hypothesis.id != selected_id:
            continue
        setattr(hypothesis, "source_spec_path", spec.path)
        selected_hypotheses.append(hypothesis)
    if selected_id and require_selected and not selected_hypotheses:
        raise ValueError(f"brainstorm hypothesis {selected_id!r} was not found or is retired")

    profiles: list[VulnerabilityClassProfile] = []
    intents: list[Any] = []
    for hypothesis in selected_hypotheses:
        for intent in hypothesis_to_agent_intents_for_profile(spec, hypothesis):
            intents.append(intent)
    dynamic_specs = brainstorm_intents_to_dynamic_agent_specs(
        intents,
        program=program_slug,
        version=version,
        category_master=spec_uses_category_master_agents(spec),
    )
    appmap_run_id = str(
        spec.metadata.get("AppMap run id")
        or spec.metadata.get("appmap_run_id")
        or ""
    ).strip()
    for dynamic_spec in dynamic_specs:
        profile = _profile_from_agent_spec(dynamic_spec)
        if appmap_run_id and _is_appmap_brainstorm_profile(profile):
            profile.brainstorm_metadata.setdefault("appmap_run_id", appmap_run_id)
            for assignment in profile.brainstorm_metadata.get("brainstorm_cluster_assignments") or []:
                if isinstance(assignment, dict):
                    assignment.setdefault("appmap_run_id", appmap_run_id)
        profiles.append(profile)
    return profiles, selected_hypotheses, spec.path


def _discover_brainstorm_spec_dir(spec_dir: str | Path) -> list[Path]:
    raw_root = Path(spec_dir).expanduser()
    if raw_root.is_symlink():
        raise ValueError(f"--brainstorm-spec-dir must not be a symlink: {raw_root}")
    root = raw_root.resolve(strict=False)
    if not root.exists():
        raise FileNotFoundError(f"--brainstorm-spec-dir does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"--brainstorm-spec-dir is not a directory: {root}")

    def discover_category_spec_dirs_from_manifest() -> list[Path]:
        manifest_path = root.parent / "appmap_promotions.jsonl"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            return []
        dirs: list[Path] = []
        try:
            lines = manifest_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict) or record.get("promotion_layout") != "category":
                continue
            promotion_root = str(record.get("promotion_root") or "").strip()
            parts = Path(promotion_root).parts
            if len(parts) != 2 or parts[0] != root.name:
                continue
            child = root / parts[1]
            if child.is_symlink():
                raise ValueError(f"--brainstorm-spec-dir category child must not be a symlink: {child}")
            resolved_child = child.resolve(strict=False)
            if not resolved_child.is_dir():
                continue
            if not resolved_child.is_relative_to(root):
                raise ValueError(f"--brainstorm-spec-dir category child escapes directory: {child}")
            dirs.append(resolved_child)
        return sorted(set(dirs), key=lambda path: (path.name.casefold(), path.name, str(path)))

    specs: list[Path] = []
    seen_names: dict[str, str] = {}

    def collect_specs(spec_roots: Sequence[Path]) -> None:
        for spec_root in spec_roots:
            for path in spec_root.iterdir():
                is_candidate = path.suffix.lower() == ".md" and (path.name == "spec.md" or path.name.endswith("-spec.md"))
                if not is_candidate:
                    continue
                relative_key = str(path.relative_to(root))
                folded = relative_key.casefold()
                existing_name = seen_names.get(folded)
                if existing_name is not None and existing_name != relative_key:
                    raise ValueError(
                        "--brainstorm-spec-dir has case-insensitive spec path collision: "
                        f"{existing_name!r} and {relative_key!r}"
                    )
                seen_names[folded] = relative_key
                if path.is_symlink():
                    raise ValueError(f"--brainstorm-spec-dir spec must not be a symlink: {path}")
                if not path.is_file():
                    continue
                resolved = path.resolve(strict=False)
                if not resolved.is_relative_to(root):
                    raise ValueError(f"--brainstorm-spec-dir spec escapes directory: {path}")
                specs.append(resolved)

    collect_specs([root])
    if not specs:
        collect_specs(discover_category_spec_dirs_from_manifest())
    if not specs:
        raise ValueError(f"--brainstorm-spec-dir contains no spec.md or *-spec.md files: {root}")
    return sorted(specs, key=lambda path: (str(path.relative_to(root)).casefold(), str(path.relative_to(root)), str(path)))


def _brainstorm_spec_path_inputs(value: str | Path | Sequence[str | Path] | None) -> list[str | Path]:
    if value is None:
        return []
    if isinstance(value, (str, Path)):
        return [value]
    return list(value)


def _resolve_brainstorm_spec_paths(
    *,
    brainstorm_spec: str | Path | Sequence[str | Path] | None,
    brainstorm_spec_dir: str | Path | None,
) -> list[Path]:
    paths: list[Path] = []
    seen: set[str] = set()
    for item in [*_brainstorm_spec_path_inputs(brainstorm_spec)]:
        path = Path(item).expanduser().resolve(strict=False)
        key = str(path)
        if key not in seen:
            seen.add(key)
            paths.append(path)
    if brainstorm_spec_dir:
        for path in _discover_brainstorm_spec_dir(brainstorm_spec_dir):
            resolved = path.expanduser().resolve(strict=False)
            key = str(resolved)
            if key not in seen:
                seen.add(key)
                paths.append(resolved)
    return paths


def _load_brainstorm_campaign_profiles(
    *,
    spec_paths: Sequence[str | Path],
    program_slug: str,
    version: str,
    selected_hypothesis: str | None = None,
) -> tuple[list[VulnerabilityClassProfile], list[Any], list[Path]]:
    profiles: list[VulnerabilityClassProfile] = []
    hypotheses: list[Any] = []
    loaded_paths: list[Path] = []
    selected_id = str(selected_hypothesis or "").strip()
    for spec_path in spec_paths:
        spec_profiles, spec_hypotheses, parsed_path = _load_brainstorm_profiles(
            spec_path=spec_path,
            program_slug=program_slug,
            version=version,
            selected_hypothesis=selected_id or None,
            require_selected=False,
        )
        loaded_paths.append(parsed_path)
        profiles.extend(spec_profiles)
        hypotheses.extend(spec_hypotheses)
    if selected_id and not hypotheses:
        spec_list = ", ".join(str(path) for path in loaded_paths) or "(no specs loaded)"
        raise ValueError(
            f"brainstorm hypothesis {selected_id!r} was not found or is retired in selected specs: {spec_list}"
        )
    return profiles, hypotheses, loaded_paths


def hypothesis_to_agent_intents_for_profile(spec: Any, hypothesis: Any) -> list[Any]:
    from bounty_core.brainstorm_spec import hypothesis_to_agent_intents

    return hypothesis_to_agent_intents(spec, hypothesis)


def _parse_agent_wave_size(value: int | str | None) -> int | str:
    if value is None:
        return "all"
    if isinstance(value, int):
        return max(0, value)
    normalized = str(value).strip().lower()
    if normalized in {"", "all", "none", "unlimited"}:
        return "all"
    parsed = int(normalized)
    return max(0, parsed)


def _scheduler_decisions_path(lane_root: Path) -> Path:
    return lane_root / "brainstorm" / "scheduler_decisions.jsonl"


def _write_scheduler_decisions(path: Path, events: Sequence[dict[str, Any]]) -> None:
    if not events:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")


def _append_scheduler_events_to_coverage(coverage_path: Path | None, events: Sequence[dict[str, Any]]) -> None:
    if coverage_path is None:
        return
    for event in events:
        hypothesis_id = str(event.get("hypothesis_id") or "").strip()
        agent_key = str(event.get("agent_key") or "").strip()
        source_spec = str(event.get("source_spec_path") or event.get("brainstorm_spec") or "").strip()
        if not hypothesis_id or not agent_key or not source_spec:
            continue
        coverage_event = dict(event)
        scheduler_event = str(coverage_event.get("event") or "").strip()
        coverage_event["scheduler_event"] = scheduler_event
        coverage_event["scheduler_agent_key"] = coverage_event.pop("agent_key", "")
        coverage_event["event"] = "coverage_status_changed"
        if scheduler_event == "agent_selected":
            coverage_event["status"] = "queued"
        else:
            # bounty_core currently has no durable "deferred"/"skipped" coverage status.
            # Keep the scheduler-specific state in scheduler_event/scheduler_decisions.jsonl
            # while preserving a valid non-terminal hypothesis coverage status.
            coverage_event["status"] = "untested"
        coverage_event.pop("coverage_status", None)
        try:
            append_coverage(coverage_path, coverage_event)
        except Exception as exc:
            print(f"[scheduler] coverage warning for {agent_key}: {exc}", flush=True)


def _read_scheduler_decision_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if isinstance(row, dict):
                rows.append(row)
    except (OSError, json.JSONDecodeError):
        return []
    return rows


def _scheduler_resume_key(metadata: dict[str, Any], *, default_agent_key: str = "") -> tuple[str, str, str, str, str] | None:
    base = _brainstorm_metadata_key(metadata, default_agent_key=default_agent_key)
    if base is None:
        return None
    snapshot_id = str(metadata.get("snapshot_id") or metadata.get("_snapshot_id") or "").strip()
    snapshot_version = str(
        metadata.get("snapshot_version")
        or metadata.get("_snapshot_version")
        or metadata.get("version_label")
        or metadata.get("app_version")
        or ""
    ).strip()
    return (*base, snapshot_id, snapshot_version)


def _latest_scheduler_event_for_metadata(events: Sequence[dict[str, Any]], metadata: dict[str, Any], *, default_agent_key: str = "") -> str:
    key = _scheduler_resume_key(metadata, default_agent_key=default_agent_key)
    if key is None:
        return ""
    for event in reversed(events):
        event_type = str(event.get("event") or "").strip()
        if event_type not in {"agent_deferred", "agent_selected", "agent_skipped_policy_budget"}:
            continue
        event_key = _scheduler_resume_key(event, default_agent_key=default_agent_key)
        if event_key == key:
            return event_type
    return ""


def _annotate_scheduler_deferred_status(
    profiles: Sequence[VulnerabilityClassProfile],
    *,
    coverage_path: Path | None,
    scheduler_decisions_path: Path | None = None,
) -> list[VulnerabilityClassProfile]:
    events: list[dict[str, Any]] = []
    if scheduler_decisions_path is not None:
        events.extend(_read_scheduler_decision_events(scheduler_decisions_path))
    if coverage_path is not None and coverage_path.exists():
        try:
            events.extend(read_coverage_jsonl(coverage_path))
        except Exception:
            pass
    if not events:
        return list(profiles)
    for profile in profiles:
        metadata = getattr(profile, "brainstorm_metadata", None)
        if not isinstance(metadata, dict):
            continue
        latest_events = [
            _latest_scheduler_event_for_metadata(events, assignment, default_agent_key=profile.key)
            for assignment in _brainstorm_assignment_metadata(profile)
        ]
        if any(event == "agent_deferred" for event in latest_events):
            metadata["coverage_status"] = "deferred"
        elif metadata.get("coverage_status") == "deferred":
            metadata.pop("coverage_status", None)
    return list(profiles)


def _scheduler_summary_line(summary: dict[str, Any], *, decisions_path: Path) -> str:
    return (
        f"[scheduler] mode={summary.get('mode')} wave_size={summary.get('wave_size')} "
        f"selected={summary.get('selected')} deferred={summary.get('deferred')} "
        f"skipped={summary.get('skipped')} families={len(summary.get('families') or [])} "
        f"decisions={decisions_path}"
    )


def orchestrate_zero_day_team(
    program: str,
    target_path: str,
    selected_class: Optional[str] = None,
    target_type: str = "auto",
    parallel: bool = False,
    num_agents: Optional[int] = None,
    chain: bool = False,
    fresh: bool = False,
    model: Optional[str] = None,
    no_preflight: bool = False,
    force_preflight_llm: bool = False,
    no_shared_brain: bool = False,
    hunt_type: str = "source",
    version_label: str | None = None,
    force_refresh_dynamic_agents: bool = False,
    output_root: str | None = None,
    target_kind: str | None = None,
    intent_text: str | None = None,
    brainstorm_spec: str | Path | Sequence[str | Path] | None = None,
    brainstorm_spec_dir: str | Path | None = None,
    brainstorm_only: bool = False,
    brainstorm_hypothesis: str | None = None,
    brainstorm_cluster_size: int = 1,
    hunting_policy: str | None = "off",
    triage_policy: str | None = None,
    no_triage_policy: bool = False,
    policy_config: str | None = None,
    scheduler: str = "legacy",
    agent_wave_size: int | str | None = "all",
    max_per_surface_family: int = 2,
    max_amplifier_family_first_wave: int = 3,
    category_master_mode: bool = False,
    max_hypotheses_per_master_agent: int = 6,
    prefer_deferred: bool = True,
    verbose: int = 0,
) -> Dict[str, Any]:
    """Run one clean static-analysis agent per vulnerability class."""
    global _ZERO_DAY_TEAM_LOGGER

    if num_agents is not None:
        print("[orchestrator] Ignoring legacy num_agents argument; class-based mode runs one agent per class.")
    if brainstorm_cluster_size < 1:
        raise ValueError("--brainstorm-cluster-size must be at least 1")

    program_slug = _sanitize_program_name(program)
    storage_root_override = (
        Path(output_root).expanduser().resolve(strict=False) if output_root is not None else None
    )
    storage = _resolve_zero_day_storage(
        program_slug,
        output_root=storage_root_override,
        target_path=target_path,
        target_kind=target_kind,
        intent_text=intent_text,
    )
    family = storage.family
    lane = storage.lane
    resolved_storage_root_override = (
        Path(storage.base_root).expanduser().resolve(strict=False)
        if getattr(storage, "root_mode", "") == "explicit-local"
        else None
    )
    team_root = storage.lane_root
    agents_root = team_root / "agents"
    findings_path = storage.ledgers_root / FINDINGS_FILENAME

    _ensure_directory(team_root)
    _ensure_directory(agents_root)
    if SubagentLogger is not None:
        try:
            _ZERO_DAY_TEAM_LOGGER = SubagentLogger("zero_day_team", program_slug, f"zdt_{int(time.time())}")
            _ZERO_DAY_TEAM_LOGGER.start(target=str(target_path))
        except Exception:
            _ZERO_DAY_TEAM_LOGGER = None
    _reset_findings_store(findings_path)
    target = _resolve_analysis_target(target_path, team_root=team_root, target_type=target_type)
    policy_selection = resolve_policy_selection(
        hunting_policy,
        triage_policy=triage_policy,
        no_triage_policy=no_triage_policy,
    )
    resolved_policy = resolve_hunting_policy(
        policy_selection,
        target_kind=target_kind or storage.lane,
        target_path=target,
        policy_config=policy_config,
    )
    agent_policy_snippet = resolved_policy.snippet("agent")
    snapshot_identity = get_snapshot_identity(target, version_label=version_label)
    ledger = create_team_ledger_from_storage(
        program_slug,
        storage=storage,
        target_root=target,
        version_label=str(snapshot_identity.get("version_label") or ""),
        snapshot_identity=snapshot_identity,
        agent="zero-day-team",
    )
    verbosity = clamp_verbosity(verbose)
    print(
        f"[snapshot] id={snapshot_identity.get('snapshot_id')} "
        f"version={snapshot_identity.get('version_label') or '(unspecified)'} "
        f"channel={snapshot_identity.get('channel') or 'stable'}"
    )
    if verbosity.verbose:
        print(f"[orchestrator] ledger path={ledger.path}")
        print(f"[orchestrator] findings path={findings_path}")
        print(f"[orchestrator] hunting_policy={resolved_policy.id} enabled={resolved_policy.enabled}")
    if verbosity.very_verbose:
        print(f"[orchestrator] target={target}")
        print(f"[orchestrator] context root={storage.context_root}")
        print(f"[orchestrator] working root={storage.working_root}")
    dynamic_specs = []
    dynamic_profiles: List[VulnerabilityClassProfile] = []
    brainstorm_profiles: List[VulnerabilityClassProfile] = []
    brainstorm_hypotheses: list[Any] = []
    brainstorm_spec_paths: list[Path] = []
    brainstorm_coverage_path: Path | None = None
    merged_brainstorm_builtin_keys: list[str] = []
    dynamic_version = (
        str(snapshot_identity.get("version_label") or "").strip()
        or str(snapshot_identity.get("snapshot_id") or "").strip()
        or "unversioned"
    )
    dynamic_builder_started = time.time()
    try:
        builder = DynamicAgentBuilder(program=program_slug, logger=_ZERO_DAY_TEAM_LOGGER)
        dynamic_specs = builder.run(
            target,
            program_slug,
            force_refresh=force_refresh_dynamic_agents,
            app_version=dynamic_version,
        )
        dynamic_profiles = [_profile_from_agent_spec(spec) for spec in dynamic_specs if getattr(spec, "key", "")]
        print(
            f"[dynamic_agents] version={dynamic_version} "
            f"loaded={len(dynamic_profiles)} registry={builder.registry.reg_dir}"
        )
        dynamic_output = "\n".join(profile.key for profile in dynamic_profiles)
        dynamic_payload = json.dumps(
            {
                "target": str(target),
                "version": dynamic_version,
                "force_refresh": force_refresh_dynamic_agents,
                "dynamic_agent_count": len(dynamic_profiles),
            },
            sort_keys=True,
        )
        dynamic_prompt_tokens = _estimate_tokens_from_text(dynamic_payload)
        dynamic_completion_tokens = 0
        dynamic_tool_output_tokens = _estimate_tokens_from_text(dynamic_output)
        dynamic_context_after = dynamic_prompt_tokens + dynamic_completion_tokens
        _safe_log_span(
            span_type="tool",
            phase="preflight",
            level="RESULT",
            message=f"Dynamic agent builder loaded {len(dynamic_profiles)} spec(s)",
            tool_name="dynamic_agent_builder",
            tool_category="dynamic_agents",
            target=str(target),
            params={"version": dynamic_version, "force_refresh": force_refresh_dynamic_agents},
            prompt_tokens=dynamic_prompt_tokens,
            completion_tokens=dynamic_completion_tokens,
            context_tokens_before=dynamic_prompt_tokens,
            context_tokens_after=dynamic_context_after,
            tool_output_tokens=dynamic_tool_output_tokens,
            pte_lite=compute_pte_lite(
                prompt_tokens=dynamic_prompt_tokens,
                completion_tokens=dynamic_completion_tokens,
                tool_output_tokens=dynamic_tool_output_tokens,
                context_tokens_after=dynamic_context_after,
            ),
            latency_ms=int((time.time() - dynamic_builder_started) * 1000),
            input_bytes=len(dynamic_payload.encode("utf-8", errors="replace")),
            output_bytes=len(dynamic_output.encode("utf-8", errors="replace")),
            success=True,
        )
    except Exception as exc:
        print(f"[dynamic_agents] warning: {exc}; continuing without custom agents")
        failure_payload = json.dumps(
            {
                "target": str(target),
                "version": dynamic_version,
                "error": str(exc),
            },
            sort_keys=True,
        )
        failure_tokens = _estimate_tokens_from_text(failure_payload)
        _safe_log_span(
            span_type="tool",
            phase="preflight",
            level="ERROR",
            message="Dynamic agent builder failed",
            tool_name="dynamic_agent_builder",
            tool_category="dynamic_agents",
            target=str(target),
            params={"version": dynamic_version},
            prompt_tokens=failure_tokens,
            completion_tokens=0,
            context_tokens_before=failure_tokens,
            context_tokens_after=failure_tokens,
            tool_output_tokens=0,
            pte_lite=compute_pte_lite(
                prompt_tokens=failure_tokens,
                completion_tokens=0,
                tool_output_tokens=0,
                context_tokens_after=failure_tokens,
            ),
            latency_ms=int((time.time() - dynamic_builder_started) * 1000),
            input_bytes=len(failure_payload.encode("utf-8", errors="replace")),
            output_bytes=0,
            success=False,
            error=str(exc),
        )
    resolved_brainstorm_spec_paths = _resolve_brainstorm_spec_paths(
        brainstorm_spec=brainstorm_spec,
        brainstorm_spec_dir=brainstorm_spec_dir,
    )
    if brainstorm_only and not resolved_brainstorm_spec_paths:
        raise ValueError("--brainstorm-only requires --brainstorm-spec or --brainstorm-spec-dir")
    if brainstorm_hypothesis and not resolved_brainstorm_spec_paths:
        raise ValueError("--brainstorm-hypothesis requires --brainstorm-spec or --brainstorm-spec-dir")
    if resolved_brainstorm_spec_paths:
        brainstorm_coverage_path = storage.lane_root / "brainstorm" / "coverage.jsonl"
        brainstorm_profiles, brainstorm_hypotheses, brainstorm_spec_paths = _load_brainstorm_campaign_profiles(
            spec_paths=resolved_brainstorm_spec_paths,
            program_slug=program_slug,
            version=dynamic_version,
            selected_hypothesis=brainstorm_hypothesis,
        )
        if not brainstorm_only:
            brainstorm_profiles, merged_brainstorm_builtin_keys = _merge_brainstorm_profiles_with_builtins(
                brainstorm_profiles
            )
        _reject_brainstorm_profile_collisions(
            brainstorm_profiles,
            [] if brainstorm_only else dynamic_profiles,
        )
        for profile in brainstorm_profiles:
            profile.brainstorm_metadata["_coverage_path"] = str(brainstorm_coverage_path)
            if _is_appmap_brainstorm_profile(profile):
                snapshot_id = str(snapshot_identity.get("snapshot_id") or "").strip()
                snapshot_version = str(snapshot_identity.get("version_label") or dynamic_version or "").strip()
                if snapshot_id:
                    profile.brainstorm_metadata["_snapshot_id"] = snapshot_id
                if snapshot_version:
                    profile.brainstorm_metadata["_snapshot_version"] = snapshot_version
        for hypothesis in brainstorm_hypotheses:
            _append_brainstorm_hypothesis_loaded(
                brainstorm_coverage_path,
                hypothesis=hypothesis,
                run_id=getattr(ledger, "run_id", None),
                spec_path=Path(getattr(hypothesis, "source_spec_path", "") or brainstorm_spec_paths[0]),
            )
        print(
            f"[brainstorm] loaded {len(brainstorm_profiles)} profile(s) "
            f"from {len(brainstorm_spec_paths)} spec(s)"
        )
    if brainstorm_only:
        profiles = _select_from_profiles(selected_class, brainstorm_profiles)
    else:
        profiles = _select_profiles(
            selected_class,
            extra_profiles=[*dynamic_profiles, *brainstorm_profiles],
            excluded_builtin_keys=merged_brainstorm_builtin_keys,
        )
    shared_brain_index = None

    if no_shared_brain:
        print("[shared_brain] disabled via --no-shared-brain; continuing without repo index")
    else:
        try:
            shared_brain_index = load_index(
                program_slug,
                family=family,
                lane=lane,
                root_override=resolved_storage_root_override,
            )
            if shared_brain_index is not None:
                shared_brain_index = update_index(target, shared_brain_index)
            else:
                shared_brain_index = build_index(target, program_slug)
            save_index(
                shared_brain_index,
                program_slug,
                family=family,
                lane=lane,
                root_override=resolved_storage_root_override,
            )
            print(
                f"[shared_brain] indexed {len(shared_brain_index.files)} files "
                f"across {len(shared_brain_index.frameworks)} framework signal(s)"
            )
        except Exception as exc:
            shared_brain_index = None
            print(f"[shared_brain] warning: {exc}; continuing without shared brain")

    built_in_profiles = [profile for profile in profiles if profile.key in CLASS_PROFILES]
    always_on_dynamic_profiles = [profile for profile in profiles if profile.key not in CLASS_PROFILES]
    active_profiles = built_in_profiles + always_on_dynamic_profiles
    skipped_profile_keys: List[str] = []
    preflight_decisions = []
    if no_preflight:
        print("[preflight] disabled via --no-preflight; running all selected classes")
    else:
        preflight_index = shared_brain_index
        if preflight_index is None:
            try:
                preflight_index = build_index(target, program_slug)
                print("[preflight] built transient index because shared brain was unavailable")
            except Exception as exc:
                preflight_index = None
                print(f"[preflight] warning: {exc}; running all selected classes")

        if preflight_index is not None and built_in_profiles:
            try:
                preflight_decisions = run_preflight(
                    target,
                    preflight_index,
                    model=model,
                    vuln_classes=[profile.key for profile in built_in_profiles],
                    class_descriptions={profile.key: profile.description for profile in built_in_profiles},
                    force_llm=force_preflight_llm,
                )
                active_keys = {decision.vuln_class for decision in preflight_decisions if decision.run_agent}
                skipped_profile_keys = [
                    decision.vuln_class
                    for decision in preflight_decisions
                    if not decision.run_agent
                ]
                active_profiles = (
                    [profile for profile in built_in_profiles if profile.key in active_keys]
                    + always_on_dynamic_profiles
                )
                print(f"[preflight] active={len(active_profiles)} skipped={len(skipped_profile_keys)}")
                for decision in preflight_decisions:
                    _safe_log_span(
                        span_type="spawn_decision",
                        level="STEP",
                        message=f"Spawn decision: {decision.vuln_class}",
                        agent_name=decision.vuln_class,
                        preflight_regex_score=decision.regex_score,
                        expected_worth=float(decision.regex_score),
                        redundancy_penalty=0.0,
                        spawned=decision.run_agent,
                    )
                    if not decision.run_agent:
                        print(f"  skip {decision.vuln_class}: {decision.decision_reason}")
            except Exception as exc:
                active_profiles = built_in_profiles + always_on_dynamic_profiles
                print(f"[preflight] warning: {exc}; continuing with all selected classes")
        elif always_on_dynamic_profiles:
            print(f"[preflight] auto-enabling {len(always_on_dynamic_profiles)} dynamic agent(s)")

    for profile in always_on_dynamic_profiles:
        _safe_log_span(
            span_type="spawn_decision",
            phase="preflight",
            level="STEP",
            message=f"Spawn decision: {profile.key}",
            agent_name=profile.key,
            prompt_tokens=0,
            completion_tokens=0,
            context_tokens_before=0,
            context_tokens_after=0,
            tool_output_tokens=0,
            pte_lite=compute_pte_lite(
                prompt_tokens=0,
                completion_tokens=0,
                tool_output_tokens=0,
                context_tokens_after=0,
            ),
            expected_worth=1.0,
            redundancy_penalty=0.0,
            spawned=profile in active_profiles,
        )

    active_profiles, appmap_coverage_skipped_profiles = _filter_appmap_profiles_by_coverage(
        active_profiles,
        coverage_path=brainstorm_coverage_path,
        fresh=fresh,
    )
    active_profiles, brainstorm_clusters = _cluster_brainstorm_profiles(
        active_profiles,
        max_cluster_size=brainstorm_cluster_size,
    )
    if brainstorm_clusters:
        print(
            "[brainstorm] clustered "
            f"{sum(len(cluster['members']) for cluster in brainstorm_clusters)} assignment(s) "
            f"into {len(brainstorm_clusters)} agent(s)"
        )
    if appmap_coverage_skipped_profiles:
        skipped_keys = [profile.key for profile in appmap_coverage_skipped_profiles]
        skipped_profile_keys.extend(skipped_keys)
        print(
            "[brainstorm] coverage gate skipped "
            f"{len(skipped_keys)} AppMap profile(s): {', '.join(skipped_keys)}"
        )

    scheduler_decisions_path = _scheduler_decisions_path(storage.lane_root)
    scheduler_events: list[dict[str, Any]] = []
    scheduler_plan_summary: dict[str, Any] = {
        "mode": scheduler,
        "wave_size": _parse_agent_wave_size(agent_wave_size),
        "selected": len(active_profiles),
        "deferred": 0,
        "skipped": 0,
        "families": [],
        "decisions_path": str(scheduler_decisions_path),
    }
    if scheduler not in {"off", "legacy", "policy-aware"}:
        raise ValueError("--scheduler must be one of: off, legacy, policy-aware")
    if scheduler == "policy-aware":
        if not fresh:
            active_profiles = _annotate_scheduler_deferred_status(
                active_profiles,
                coverage_path=brainstorm_coverage_path,
                scheduler_decisions_path=scheduler_decisions_path,
            )
        scheduler_result = schedule_profiles(
            active_profiles,
            policy=resolved_policy,
            options=BaseTeamSchedulerOptions(
                mode="policy-aware",
                agent_wave_size=_parse_agent_wave_size(agent_wave_size),
                max_per_surface_family=max_per_surface_family,
                max_amplifier_family_first_wave=max_amplifier_family_first_wave,
                category_master_mode=category_master_mode,
                max_hypotheses_per_master_agent=max_hypotheses_per_master_agent,
                prefer_deferred=prefer_deferred,
                fresh=fresh,
                scheduler_wave_id=datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
                run_id=getattr(ledger, "run_id", None),
            ),
        )
        active_profiles = _profiles_from_scheduler_result(scheduler_result)
        deferred_profile_keys = list(scheduler_result.deferred_keys)
        skipped_profile_keys.extend(deferred_profile_keys)
        scheduler_plan_summary = dict(scheduler_result.summary)
        scheduler_plan_summary.update(
            {
                "wave_size": _parse_agent_wave_size(agent_wave_size),
                "decisions_path": str(scheduler_decisions_path),
                "category_master_mode": category_master_mode,
                "max_hypotheses_per_master_agent": max_hypotheses_per_master_agent,
            }
        )
        scheduler_events = list(scheduler_result.decision_events)
        _write_scheduler_decisions(scheduler_decisions_path, scheduler_events)
        _append_scheduler_events_to_coverage(brainstorm_coverage_path, scheduler_events)
        print(_scheduler_summary_line(scheduler_plan_summary, decisions_path=scheduler_decisions_path))
        if deferred_profile_keys:
            preview = ", ".join(deferred_profile_keys[:8])
            suffix = "..." if len(deferred_profile_keys) > 8 else ""
            print(f"[scheduler] deferred {len(deferred_profile_keys)} profile(s): {preview}{suffix}")

    # Pre-assign DIVERSE entry points across all active profiles (no two profiles
    # get the same file if alternatives exist), so agents don't all start from
    # the same position in the codebase.
    starting_entries_by_profile: Dict[str, dict[str, Any] | None] = {}
    used_files: set[str] = set()
    if shared_brain_index is not None:
        for profile in active_profiles:
            entry_points = get_diverse_entry_points(
                shared_brain_index, profile.key, count=3
            )
            chosen = None
            for ep in entry_points:
                fp = str(ep.get("file") or "")
                if fp and fp not in used_files:
                    chosen = ep
                    used_files.add(fp)
                    break
            # Fallback: take first available even if already used by another class
            if chosen is None and entry_points:
                chosen = entry_points[0]
            starting_entries_by_profile[profile.key] = chosen

    for profile in active_profiles:
        if getattr(profile, "brainstorm_metadata", None):
            _append_brainstorm_coverage(
                brainstorm_coverage_path,
                profile,
                "agent_queued",
                run_id=getattr(ledger, "run_id", None),
            )

    if parallel:
        print(f"[orchestrator] Running {len(active_profiles)} class agents in PARALLEL mode (cap: {MAX_PARALLEL_AGENTS})")
        if active_profiles:
            with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_AGENTS, len(active_profiles))) as pool:
                futures = {
                    pool.submit(
                        _run_single_agent,
                        profile,
                        program_slug,
                        target,
                        findings_path,
                        agents_root,
                        ledger,
                        ledger.get_class_context(profile.key),
                        get_shared_brain_class_context(shared_brain_index, profile.key)
                        if shared_brain_index is not None
                        else "",
                        starting_entries_by_profile.get(profile.key),
                        fresh,
                        coverage_path=brainstorm_coverage_path,
                        policy_snippet=agent_policy_snippet,
                    ): profile
                    for profile in active_profiles
                }
                for future in as_completed(futures):
                    profile = futures[future]
                    try:
                        completed_profile, exit_code = future.result()
                        print(f"[orchestrator] {completed_profile.key} finished (exit={exit_code})")
                    except Exception as exc:
                        print(f"[orchestrator] {profile.key} raised: {exc}")
    else:
        print(f"[orchestrator] Running {len(active_profiles)} class agents in SEQUENTIAL mode")
        for index, profile in enumerate(active_profiles, start=1):
            print(f"[orchestrator] Starting {index}/{len(active_profiles)}: {profile.key}")
            _run_single_agent(
                profile,
                program_slug,
                target,
                findings_path,
                agents_root,
                ledger,
                class_context=ledger.get_class_context(profile.key),
                repo_context=(
                    get_shared_brain_class_context(shared_brain_index, profile.key)
                    if shared_brain_index is not None
                    else ""
                ),
                starting_entry=starting_entries_by_profile.get(profile.key),
                fresh=fresh,
                coverage_path=brainstorm_coverage_path,
                policy_snippet=agent_policy_snippet,
            )
            print(f"[orchestrator] Finished {index}/{len(active_profiles)}: {profile.key}")

    raw_findings = _load_findings(findings_path)
    if raw_findings:
        raw_findings = _reserve_missing_fids_for_review(raw_findings, ledger)
        _write_findings_jsonl(findings_path, raw_findings)
    confirmed_findings, dormant_findings, novel_findings = stage2_ghost_review(
        raw_findings,
        target,
        program_slug,
        "web",
        output_root=resolved_storage_root_override,
        write_reports=False,
        hunting_policy=resolved_policy,
    )
    ownership_demoted_findings: list[Dict[str, Any]] = []
    confirmed_findings, dormant_findings, novel_findings, ownership_demoted_findings = (
        _triage_canonical_ownership(confirmed_findings, dormant_findings, novel_findings)
    )
    if ownership_demoted_findings:
        print(
            "[triage] demoted "
            f"{len(ownership_demoted_findings)} off-category duplicate finding(s) via canonical ownership",
            flush=True,
        )
    promotion = promote_reviewed_findings(
        program=program_slug,
        storage=storage,
        reviewed_groups={
            "confirmed": confirmed_findings,
            "dormant": dormant_findings,
            "novel": novel_findings,
        },
        snapshot_identity=snapshot_identity,
        run_id=getattr(ledger, "run_id", None),
        agent="zero-day-team",
        root_override=getattr(ledger, "root_override", resolved_storage_root_override),
        update_finding=update_team_finding,
        log_span=_safe_log_span,
        verbose=verbosity.very_verbose,
        ledger_path=ledger.path,
    )
    confirmed_findings = promotion["confirmed"]
    dormant_findings = promotion["dormant"]
    novel_findings = promotion["novel"]
    reviewed_findings = promotion["reviewed"]
    ledger_updates = promotion["ledger_updates"]
    _append_brainstorm_review_coverage(
        brainstorm_coverage_path,
        raw_findings=raw_findings,
        reviewed_findings=reviewed_findings,
        profiles=active_profiles,
    )
    print(f"[ledger] Updated {ledger_updates} findings in ledger", flush=True)
    rejected_count = max(0, len(raw_findings) - len(reviewed_findings))

    confirmed_report_path, dormant_report_path, novel_report_path = promotion.get("report_paths") or (None, None, None)
    planned_confirmed_report_path, planned_dormant_report_path, planned_novel_report_path = _report_index_paths_from_storage(storage)
    planned_daily_paths = daily_report_paths(storage, datetime.now().strftime(DAILY_REPORT_DATE_FORMAT))
    daily_root = confirmed_report_path.parent if confirmed_report_path else planned_daily_paths["root"]
    novel_tier_summary = {
        "confirmed": sum(1 for item in novel_findings if str(item.get("review_tier", "")).upper() == "CONFIRMED"),
        "dormant": sum(1 for item in novel_findings if str(item.get("review_tier", "")).upper() != "CONFIRMED"),
    }

    print(
        "[orchestrator] Review complete: "
        f"confirmed={len(confirmed_findings)} "
        f"dormant={len(dormant_findings)} "
        f"novel={len(novel_findings)} "
        f"rejected={rejected_count}"
    )
    print(f"[orchestrator] Storage lane root: {storage.lane_root}")
    print(f"[orchestrator] Reports root: {storage.reports_root}")
    print(f"[orchestrator] Ledgers root: {storage.ledgers_root}")
    print(f"[orchestrator] Confirmed report: {confirmed_report_path or '(not written)'}")
    print(f"[orchestrator] Dormant report: {dormant_report_path or '(not written)'}")
    print(f"[orchestrator] Novel report: {novel_report_path or '(not written)'}")

    summary = _summarize_findings(reviewed_findings)
    summary["raw_findings"] = len(raw_findings)
    summary["classes_run"] = [profile.key for profile in active_profiles]
    summary["classes_skipped"] = skipped_profile_keys
    summary["scheduler"] = scheduler_plan_summary
    summary["by_tier"] = {
        "confirmed": len(confirmed_findings),
        "dormant": len(dormant_findings),
        "rejected": rejected_count,
    }
    summary["novel"] = {
        "total": len(novel_findings),
        "by_tier": novel_tier_summary,
    }
    summary["reports"] = {
        "daily_root": str(daily_root),
        "daily_index": str(daily_root / "index.md"),
        "daily_confirmed": str(confirmed_report_path or planned_confirmed_report_path),
        "daily_dormant": str(dormant_report_path or planned_dormant_report_path),
        "daily_novel": str(novel_report_path or planned_novel_report_path),
        "findings_root": str(storage.reports_root / "findings"),
        "categories_root": str(storage.reports_root / "categories"),
        "confirmed_date_root": str(confirmed_report_path.parent) if confirmed_report_path else None,
        "dormant_date_root": str(dormant_report_path.parent) if dormant_report_path else None,
        "novel_date_root": str(novel_report_path.parent) if novel_report_path else None,
        "confirmed": str(confirmed_report_path) if confirmed_report_path else None,
        "dormant": str(dormant_report_path) if dormant_report_path else None,
        "novel_findings": str(novel_report_path) if novel_report_path else None,
        "planned_confirmed": str(planned_confirmed_report_path),
        "planned_dormant": str(planned_dormant_report_path),
        "planned_novel_findings": str(planned_novel_report_path),
    }
    summary["snapshot"] = {
        "snapshot_id": snapshot_identity.get("snapshot_id"),
        "version_label": snapshot_identity.get("version_label"),
        "channel": snapshot_identity.get("channel"),
    }
    summary["dynamic_agents"] = {
        "count": len(dynamic_profiles),
        "keys": [profile.key for profile in dynamic_profiles],
        "version": dynamic_version,
    }
    if resolved_policy.enabled:
        summary["hunting_policy"] = resolved_policy.to_dict()
    if brainstorm_spec_paths:
        summary["brainstorm"] = {
            "spec": str(brainstorm_spec_paths[0]),
            "specs": [str(path) for path in brainstorm_spec_paths],
            "coverage": str(brainstorm_coverage_path),
            "profiles": [profile.key for profile in brainstorm_profiles],
            "profile_assignments": [
                assignment
                for profile in brainstorm_profiles
                for assignment in _brainstorm_profile_assignments(profile)
            ],
            "hypotheses": [hypothesis.id for hypothesis in brainstorm_hypotheses],
            "hypothesis_assignments": [
                _brainstorm_hypothesis_assignment(hypothesis) for hypothesis in brainstorm_hypotheses
            ],
            "only": brainstorm_only,
            "coverage_skipped": [profile.key for profile in appmap_coverage_skipped_profiles],
            "coverage_skipped_assignments": [
                assignment
                for profile in appmap_coverage_skipped_profiles
                for assignment in _brainstorm_profile_assignments(profile)
            ],
            "cluster_size": brainstorm_cluster_size,
            "clusters": brainstorm_clusters,
        }
    _pretty_print_findings(reviewed_findings)

    # Run chainer if --chain was requested
    if chain and reviewed_findings:
        graph = build_chain_graph(reviewed_findings)
        chainable = get_chainable_findings(reviewed_findings)
        print(f"[chain] {len(chainable)}/{len(reviewed_findings)} findings are chainable")
        if not chainable:
            print("[orchestrator] No chainable findings; skipping chainer.")
        else:
            print(f"[orchestrator] Chain graph has {len(graph.get('nodes', []))} node(s) and {len(graph.get('edges', []))} edge(s)")
            print("[orchestrator] --chain set: running exploit chainer...")
            chain_input_path = _write_chainable_findings_input(
                team_root / "chainable_findings.json",
                chainable,
            )
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    "chainer", Path(__file__).parent / "chainer.py"
                )
                chainer_mod = importlib.util.module_from_spec(spec)  # type: ignore[assignment]
                spec.loader.exec_module(chainer_mod)  # type: ignore[union-attr]
                chainer_result = chainer_mod.main([
                    program_slug,
                    "--source", str(target),
                    "--findings-json", str(chain_input_path),
                    "--output-dir", str(storage.reports_root / "chained"),
                    "--family", str(storage.family),
                    "--lane", str(storage.lane),
                    "--target-kind", str(target_kind or storage.lane),
                ])
                print(f"[orchestrator] Chainer complete: {chainer_result} chain(s) developed.")
            except Exception as exc:
                print(f"[orchestrator] Chainer failed: {exc}")
    elif chain:
        print("[orchestrator] --chain set but there are no reviewed findings to chain.")

    return summary


def _parse_cli_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run class-based zero-day static analysis.")
    parser.add_argument("program", help="Bug bounty program name used for output directories.")
    parser.add_argument("target_path", help="Target directory, file, script, or URL.")
    parser.add_argument("legacy_num_agents", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument(
        "--class",
        dest="selected_class",
        help="Run only a single built-in vulnerability class or dynamic agent key with clean context.",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run class agents concurrently instead of sequentially.",
    )
    parser.add_argument(
        "--target-type",
        default="auto",
        choices=("auto", "directory", "file", "script", "url"),
        help="Override target handling. Default: auto.",
    )
    parser.add_argument(
        "--chain",
        action="store_true",
        help="After review, run the chainer to develop exploit chains from findings. "
             "Disabled by default. To use: python3 agents/zero_day_team.py <program> <target> --chain",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Skip per-agent ledger dedupe; reserve identities before review. Default: False.",
    )
    parser.add_argument(
        "--model", "-m", type=str, default=None,
        help="Model for light LLM preflight (default: one step down from main)",
    )
    parser.add_argument(
        "--no-preflight",
        action="store_true",
        help="Skip preflight checks, run all agents",
    )
    parser.add_argument(
        "--force-preflight-llm",
        action="store_true",
        help="Force LLM call for all preflight classes",
    )
    parser.add_argument(
        "--no-shared-brain",
        action="store_true",
        help="Skip shared brain, build fresh per-agent",
    )
    parser.add_argument(
        "--hunt-type",
        default="source",
        choices=("source", "web"),
        help="Type of target: source (exe/apk/desktop app) or web. "
             "Determines output directory: reports_source vs reports_web. Default: source.",
    )
    parser.add_argument(
        "--version",
        dest="version_label",
        help="Override the snapshot version label for this hunt.",
    )
    parser.add_argument(
        "--force-refresh-dynamic-agents",
        action="store_true",
        help="Rebuild dynamic agent specs for the current app version even if cached specs exist.",
    )
    parser.add_argument(
        "--output-root",
        help="Optional explicit local canonical root override. Defaults to Shared canonical storage.",
    )
    parser.add_argument(
        "--target-kind",
        help="Optional target kind hint for storage routing, such as web, api, apk, exe, electron-exe, or mac.",
    )
    parser.add_argument(
        "--intent-text",
        help="Optional natural-language task text used as routing evidence before path/artifact fallback.",
    )
    parser.add_argument(
        "--hunting-policy",
        default="off",
        help="Hunting policy id: off, auto, or electron-application-first-loose. Default: off.",
    )
    parser.add_argument(
        "--triage-policy",
        dest="triage_policy",
        help="Compatibility alias for --hunting-policy.",
    )
    parser.add_argument(
        "--no-triage-policy",
        action="store_true",
        help="Compatibility flag that disables hunting policy injection.",
    )
    parser.add_argument("--policy-config", help="Optional JSON policy config override.")
    parser.add_argument(
        "--brainstorm-spec",
        action="append",
        help="Path to a brainstorm spec markdown file to convert into additional procedural profiles.",
    )
    parser.add_argument(
        "--brainstorm-spec-dir",
        help="Directory containing spec.md or *-spec.md brainstorm specs to run as one campaign.",
    )
    parser.add_argument(
        "--brainstorm-only",
        action="store_true",
        help="Run only profiles generated from --brainstorm-spec.",
    )
    parser.add_argument(
        "--brainstorm-hypothesis",
        help="Only load profiles for one non-retired brainstorm hypothesis id.",
    )
    parser.add_argument(
        "--brainstorm-cluster-size",
        type=int,
        default=1,
        help=(
            "Maximum AppMap brainstorm assignments to merge into one agent when they share "
            "the same focus files, source, and sink. Defaults to 1 (one agent per hypothesis)."
        ),
    )
    parser.add_argument(
        "--scheduler",
        choices=("off", "legacy", "policy-aware"),
        default="legacy",
        help="Runtime agent scheduler mode. Default: legacy preserves existing all-agent behavior.",
    )
    parser.add_argument(
        "--agent-wave-size",
        default="all",
        help="Number of selected agents to spawn for the first scheduler wave, or 'all'.",
    )
    parser.add_argument(
        "--max-per-surface-family",
        type=int,
        default=2,
        help="Policy-aware scheduler cap per surface family when alternatives exist. Default: 2.",
    )
    parser.add_argument(
        "--max-amplifier-family-first-wave",
        type=int,
        default=3,
        help="Policy-aware first-wave cap for amplifier families when app-entry alternatives exist. Default: 3.",
    )
    parser.add_argument(
        "--category-master-mode",
        action="store_true",
        help=(
            "When policy-aware scheduling is enabled, bundle related hypotheses into explicit "
            "generic category-master agents that preserve per-hypothesis metadata."
        ),
    )
    parser.add_argument(
        "--max-hypotheses-per-master-agent",
        type=int,
        default=6,
        help="Maximum hypotheses to feed into one category-master agent. Default: 6.",
    )
    parser.add_argument(
        "--no-prefer-deferred",
        action="store_true",
        help="Do not prefer previously deferred agents when policy-aware scheduling is enabled.",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v or -vv).")
    return parser.parse_args(list(argv))


if __name__ == "__main__":
    args = _parse_cli_args(sys.argv[1:])
    legacy_num_agents = None
    if args.legacy_num_agents:
        try:
            legacy_num_agents = int(args.legacy_num_agents)
        except ValueError:
            legacy_num_agents = None

    result = orchestrate_zero_day_team(
        args.program,
        args.target_path,
        selected_class=args.selected_class,
        target_type=args.target_type,
        parallel=args.parallel,
        num_agents=legacy_num_agents,
        chain=args.chain,
        fresh=args.fresh,
        model=args.model,
        no_preflight=args.no_preflight,
        force_preflight_llm=args.force_preflight_llm,
        no_shared_brain=args.no_shared_brain,
        hunt_type=args.hunt_type,
        version_label=args.version_label,
        force_refresh_dynamic_agents=args.force_refresh_dynamic_agents,
        output_root=args.output_root,
        target_kind=args.target_kind,
        intent_text=args.intent_text,
        brainstorm_spec=args.brainstorm_spec,
        brainstorm_spec_dir=args.brainstorm_spec_dir,
        brainstorm_only=args.brainstorm_only,
        brainstorm_hypothesis=args.brainstorm_hypothesis,
        brainstorm_cluster_size=args.brainstorm_cluster_size,
        hunting_policy=args.hunting_policy,
        triage_policy=args.triage_policy,
        no_triage_policy=args.no_triage_policy,
        policy_config=args.policy_config,
        scheduler=args.scheduler,
        agent_wave_size=args.agent_wave_size,
        max_per_surface_family=args.max_per_surface_family,
        max_amplifier_family_first_wave=args.max_amplifier_family_first_wave,
        category_master_mode=args.category_master_mode,
        max_hypotheses_per_master_agent=args.max_hypotheses_per_master_agent,
        prefer_deferred=not args.no_prefer_deferred,
        verbose=args.verbose,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
