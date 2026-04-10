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
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from agents.chain_matrix import build_chain_graph, get_chainable_findings  # type: ignore[attr-defined]
from agents.hybrid_preflight import run_preflight  # type: ignore[attr-defined]
from agents.dynamic_agent_builder import DynamicAgentBuilder  # type: ignore[attr-defined]
from agents.ledger_v2 import VersionedFindingsLedger  # type: ignore[attr-defined]
from agents.shared_brain import (  # type: ignore[attr-defined]
    build_index,
    get_class_context as get_shared_brain_class_context,
    get_diverse_entry_points,
    load_index,
    save_index,
    update_index,
)
from agents.coverage_store import CoverageStore
from agents.snapshot_identity import get_snapshot_identity

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
_ZERO_DAY_TEAM_LOGGER = None

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


@dataclass
class AgentSession:
    """Live or completed agent execution context."""

    profile: VulnerabilityClassProfile
    workspace: Path
    log_path: Path
    process: Optional[subprocess.Popen]
    skip_ledger: bool = False


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
    focus_globs = tuple(str(item).strip() for item in (getattr(spec, "focus_files_glob", []) or []) if str(item).strip())
    ignore_globs = tuple(str(item).strip() for item in (getattr(spec, "ignore_files_glob", []) or []) if str(item).strip())
    patterns = tuple(str(item).strip() for item in (getattr(spec, "patterns", []) or []) if str(item).strip())
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
    return VulnerabilityClassProfile(
        key=str(getattr(spec, "key", "")).strip(),
        description=str(getattr(spec, "description", "")).strip(),
        entry_questions=entry_questions,
        cross_questions=cross_questions,
        sink_categories=sink_categories,
        reasoning=reasoning,
        display_name=str(getattr(spec, "name", "")).strip() or None,
        prompt_addendum=str(getattr(spec, "agent_prompt_template", "")).rstrip(),
        focus_globs=focus_globs,
        ignore_globs=ignore_globs,
    )


def _select_profiles(
    selected_class: Optional[str],
    extra_profiles: Sequence[VulnerabilityClassProfile] = (),
) -> List[VulnerabilityClassProfile]:
    ordered_profiles = list(CLASS_PROFILES.values()) + list(extra_profiles)
    all_profiles = {profile.key.lower(): profile for profile in ordered_profiles}
    if not selected_class:
        return ordered_profiles

    normalized = _normalize_class_name(selected_class)
    if normalized not in all_profiles:
        known = ", ".join(sorted(all_profiles))
        raise ValueError(f"Unknown class {selected_class!r}. Expected one of: {known}")
    return [all_profiles[normalized]]


def _build_prompt_base(
    profile: VulnerabilityClassProfile,
    program: str,
    target_path: Path,
    findings_path: Path,
    class_context: str = "",
    repo_context: str = "",
    starting_entry: dict[str, Any] | None = None,
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
    )


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _normalize_finding(raw: Any, default_agent: str) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None

    category = str(raw.get("category", "")).strip().lower()
    class_name = str(raw.get("class_name", "")).strip().lower()
    if category not in {"class", "novel"}:
        category = "novel" if class_name == "novel" else "class"

    finding_type = str(raw.get("type", "")).strip()
    file_path = str(raw.get("file", "")).strip()
    description = str(raw.get("description", "")).strip()
    source = str(raw.get("source", "")).strip()
    sink = str(raw.get("sink", "")).strip()
    if not finding_type or not file_path or not description:
        return None
    if category == "novel" and (not source or not sink):
        return None

    normalized_class = class_name or ("novel" if category == "novel" else default_agent)
    if category == "class" and normalized_class not in CLASS_PROFILES:
        normalized_class = default_agent

    return {
        "agent": str(raw.get("agent") or default_agent),
        "category": category,
        "class_name": normalized_class,
        "fid": str(raw.get("fid", "")).strip(),
        "type": finding_type,
        "file": file_path,
        "line": _safe_int(raw.get("line")),
        "description": description,
        "severity": str(raw.get("severity", "UNKNOWN")).upper(),
        "context": str(raw.get("context", "")).strip(),
        "source": source,
        "trust_boundary": str(raw.get("trust_boundary", "")).strip(),
        "flow_path": str(raw.get("flow_path", "")).strip(),
        "sink": sink,
        "exploitability": str(raw.get("exploitability", "")).strip(),
    }


def _load_findings(findings_path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not findings_path.exists():
        return findings

    with findings_path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            normalized = _normalize_finding(parsed, default_agent="unknown")
            if normalized is not None:
                findings.append(normalized)
    return findings


def _extract_findings_from_log(log_path: Path, default_agent: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not log_path.exists():
        return findings

    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
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


def _ghost_reports_dir(program: str, target_type: str = "source") -> Path:
    date_folder = time.strftime("%d-%m-%Y")
    reports_subdir = "reports_source" if target_type == "source" else "reports_web"
    return (
        Path.home()
        / "Shared"
        / "bounty_recon"
        / _sanitize_program_name(program)
        / "ghost"
        / reports_subdir
        / date_folder
    )


def _ghost_report_paths(program: str, target_type: str = "source") -> Tuple[Path, Path, Path]:
    reports_dir = _ghost_reports_dir(program, target_type)
    reports_dir.mkdir(parents=True, exist_ok=True)
    return (
        reports_dir / "confirmed.md",
        reports_dir / "dormant.md",
        reports_dir / "novel_findings.md",
    )


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


def _source_excerpt(source_text: str, line_number: int, radius: int = 20) -> str:
    lines = source_text.splitlines()
    if not lines:
        return ""

    if line_number <= 0:
        start = 0
        end = min(len(lines), (radius * 2) + 1)
    else:
        start = max(0, line_number - radius - 1)
        end = min(len(lines), line_number + radius)

    excerpt_lines = [
        f"{index + 1}: {lines[index]}"
        for index in range(start, end)
    ]
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
        "identified source",
        "dangerous sink category",
        "what boundary is crossed",
        "how the data moves",
        "none provided.",
    )

    if title_lc in {"short vulnerability label", "short novel pattern label", "placeholder"}:
        return True
    if file_ref in {"path:123", ""}:
        return True
    return any(marker in combined for marker in markers)


def _build_claude_review_prompt(
    finding: Dict[str, Any],
    target_path: Path,
    source_path: Optional[Path],
    excerpt: str,
) -> str:
    line_number = _finding_line_number(finding)
    resolved_file = str(source_path) if source_path is not None else "UNRESOLVED"
    excerpt_text = excerpt or "UNAVAILABLE"

    return f"""You are reviewing a single static-analysis security finding for exploitability and report quality.

Output ONLY a JSON object. Do not output markdown, code fences, or any extra text.
IMPORTANT: If you do not find a real exploitable vulnerability, output exactly: {{}}.
Do NOT output placeholder or template text.

Required JSON schema:
{{"tier": "CONFIRMED" or "DORMANT_ACTIVE" or "DORMANT_HYPOTHETICAL", "poc": "..." or null, "impact": "...", "cvss_vector": "...", "cvss_score": "...", "severity_label": "...", "vulnerability_name": "...", "blocked_reason": "..." or null, "chain_requirements": "..." or null, "remediation": "...", "review_notes": "..."}}

Review rules:
- Use "CONFIRMED" only when the code evidence supports a concrete exploitable issue with a working standalone PoC.
- Use "DORMANT_ACTIVE" when the vulnerability is real but requires a documented prerequisite to exploit (e.g. "needs prior XSS to trigger"). The blocked_reason must explain what prerequisite is needed.
- Use "DORMANT_HYPOTHETICAL" when the finding is incomplete, inconclusive, or the blocked_reason is vague (e.g. "inconclusive", "needs more research"). No concrete exploit path defined.
- For "DORMANT_ACTIVE", "chain_requirements" must describe the specific prerequisite needed.
- "impact" must explain the concrete security outcome if exploitation succeeds.
- "review_notes" must summarize the code evidence and reasoning.
- Base your answer on the supplied finding and source context, and you may read related files under the target directory if needed.

Target directory:
{target_path}

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
    return reviewed


def _review_single_finding(
    finding: Dict[str, Any],
    target_path: Path,
) -> Tuple[str, Dict[str, Any], str]:
    source_path = _resolve_finding_source(target_path, finding.get("file", ""))
    excerpt = ""
    if source_path is not None:
        try:
            source_text = _read_source_text(source_path)
            excerpt = _source_excerpt(source_text, _finding_line_number(finding))
        except OSError:
            excerpt = ""

    prompt = _build_claude_review_prompt(
        finding=finding,
        target_path=target_path,
        source_path=source_path,
        excerpt=excerpt,
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


def stage2_ghost_review(
    findings: List[Dict[str, Any]],
    target_path: Path,
    program: str,
    hunt_type: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Review raw agent findings and classify them into report buckets."""

    confirmed: List[Dict[str, Any]] = []
    dormant: List[Dict[str, Any]] = []
    novel: List[Dict[str, Any]] = []
    seen_keys: set[Tuple[str, str, str, str, str, str]] = set()
    review_candidates: List[Dict[str, Any]] = []

    for finding in findings:
        dedupe_key = _finding_dedupe_key(finding)
        description = str(finding.get("description", "")).strip()
        severity = str(finding.get("severity", "")).strip()
        category = str(finding.get("category", "class")).strip().lower()
        finding_type = str(finding.get("type", "unknown"))
        finding_file = str(finding.get("file", "unknown"))

        if description == "..." or is_placeholder_finding(finding):
            print(f"[REVIEW] REJECTED | {finding_type} | {finding_file} | placeholder finding")
            continue
        if not severity:
            print(f"[REVIEW] REJECTED | {finding_type} | {finding_file} | missing severity")
            continue
        if category == "novel" and (not str(finding.get("source", "")).strip() or not str(finding.get("sink", "")).strip()):
            print(f"[REVIEW] REJECTED | {finding_type} | {finding_file} | novel finding missing source or sink")
            continue
        if dedupe_key in seen_keys:
            print(f"[REVIEW] REJECTED | {finding_type} | {finding_file} | duplicate finding")
            continue

        seen_keys.add(dedupe_key)
        review_candidates.append(finding)

    with ThreadPoolExecutor(max_workers=CLAUDE_REVIEW_MAX_WORKERS) as pool:
        futures = {
            pool.submit(_review_single_finding, finding, target_path): finding
            for finding in review_candidates
        }
        for future in as_completed(futures):
            finding = futures[future]
            try:
                tier, reviewed, reason = future.result()
            except Exception:
                tier = "DORMANT"
                reason = "review inconclusive"
                reviewed = _inconclusive_review(finding, None, "", reason)

            print(
                f"[REVIEW] {tier} | {finding.get('category', 'class')} | "
                f"{finding.get('type', 'unknown')} | {finding.get('file', 'unknown')} | {reason}"
            )

            if tier == "REJECTED":
                continue
            if str(reviewed.get("category", "class")).strip().lower() == "novel":
                novel.append(reviewed)
            elif tier == "CONFIRMED":
                confirmed.append(reviewed)
            else:
                dormant.append(reviewed)

    reports_dir = _ghost_reports_dir(program, hunt_type)
    _ensure_directory(reports_dir)
    confirmed_path, dormant_path, novel_path = _ghost_report_paths(program, hunt_type)
    confirmed_path.write_text(_render_confirmed_report(confirmed), encoding="utf-8")
    dormant_path.write_text(_render_dormant_report(dormant), encoding="utf-8")
    novel_path.write_text(_render_novel_findings_report(novel), encoding="utf-8")

    return confirmed, dormant, novel


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


def _run_agent_session(
    session: AgentSession,
    findings_path: Path,
    ledger: VersionedFindingsLedger,
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
        # Deduplicate through ledger before reviewer sees anything
        if salvaged and not getattr(session, "skip_ledger", False):
            deduped = []
            for f in salvaged:
                is_dup, fid, f_with_fid = ledger.check(f)
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
        pass

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
    ledger: VersionedFindingsLedger,
    class_context: str = "",
    repo_context: str = "",
    starting_entry: dict[str, Any] | None = None,
    fresh: bool = False,
    hunt_type: str = "source",
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
) -> Dict[str, Any]:
    """Run one clean static-analysis agent per vulnerability class."""
    global _ZERO_DAY_TEAM_LOGGER

    if num_agents is not None:
        print("[orchestrator] Ignoring legacy num_agents argument; class-based mode runs one agent per class.")

    program_slug = _sanitize_program_name(program)
    team_root = Path.home() / "Shared" / "bounty_recon" / program_slug / "0day_team"
    agents_root = team_root / "agents"
    findings_path = team_root / FINDINGS_FILENAME

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
    snapshot_identity = get_snapshot_identity(target, version_label=version_label)
    ledger = VersionedFindingsLedger(
        program_slug,
        target_root=target,
        version_label=str(snapshot_identity.get("version_label") or ""),
        snapshot_identity=snapshot_identity,
        agent="zero-day-team",
    )
    print(
        f"[snapshot] id={snapshot_identity.get('snapshot_id')} "
        f"version={snapshot_identity.get('version_label') or '(unspecified)'} "
        f"channel={snapshot_identity.get('channel') or 'stable'}"
    )
    dynamic_specs = []
    dynamic_profiles: List[VulnerabilityClassProfile] = []
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
    profiles = _select_profiles(selected_class, extra_profiles=dynamic_profiles)
    shared_brain_index = None

    if no_shared_brain:
        print("[shared_brain] disabled via --no-shared-brain; continuing without repo index")
    else:
        try:
            shared_brain_index = load_index(program_slug)
            if shared_brain_index is not None:
                shared_brain_index = update_index(target, shared_brain_index)
            else:
                shared_brain_index = build_index(target, program_slug)
            save_index(shared_brain_index, program_slug)
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
            )
            print(f"[orchestrator] Finished {index}/{len(active_profiles)}: {profile.key}")

    raw_findings = _load_findings(findings_path)
    confirmed_findings, dormant_findings, novel_findings = stage2_ghost_review(raw_findings, target, program_slug)
    reviewed_findings = confirmed_findings + dormant_findings + novel_findings
    # Update ledger with reviewer results
    ledger_updates = 0
    for finding in reviewed_findings:
        title = str(finding.get("vulnerability_name") or finding.get("type") or "").strip() or "untitled"
        if is_placeholder_finding(finding):
            print(f"[ledger] REJECTED placeholder finding: {title}", flush=True)
            continue
        fid = str(finding.get("fid", "")).strip()
        if fid:
            try:
                ledger.update(finding)
                ledger_updates += 1
            except Exception as exc:
                print(f"[ledger] FAILED update {fid}: {exc}", flush=True)
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
    print(f"[ledger] Updated {ledger_updates} findings in ledger", flush=True)
    rejected_count = max(0, len(raw_findings) - len(reviewed_findings))

    confirmed_report_path, dormant_report_path, novel_report_path = _ghost_report_paths(program_slug, hunt_type)
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
    print(f"[orchestrator] Confirmed report: {confirmed_report_path}")
    print(f"[orchestrator] Dormant report: {dormant_report_path}")
    print(f"[orchestrator] Novel report: {novel_report_path}")

    summary = _summarize_findings(reviewed_findings)
    summary["raw_findings"] = len(raw_findings)
    summary["classes_run"] = [profile.key for profile in active_profiles]
    summary["classes_skipped"] = skipped_profile_keys
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
        "confirmed": str(confirmed_report_path),
        "dormant": str(dormant_report_path),
        "novel_findings": str(novel_report_path),
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
        help="Skip ledger dedupe — treat all findings as new. Default: False.",
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
    )
    print(json.dumps(result, indent=2, sort_keys=True))
