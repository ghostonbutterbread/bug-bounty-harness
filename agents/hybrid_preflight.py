"""Hybrid regex and light-LLM preflight for vulnerability class selection."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Iterable

from agents.shared_brain import RepoIndex


@dataclass
class PreflightDecision:
    """Per-class decision produced by the preflight stage."""

    vuln_class: str
    regex_score: int
    run_agent: bool
    confidence: str
    decision_reason: str
    focus_files: list[str] = field(default_factory=list)
    sink_matches: list[str] = field(default_factory=list)
    llm_used: bool = False
    llm_result: dict[str, Any] | None = None


SCORE_RULES: list[tuple[str, int]] = [
    (r"\.innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\s*=", 5),
    (r"eval\s*\(|Function\s*\(|execScript\s*\(", 5),
    (r"child_process\.|subprocess\.|os\.system\s*\(|\bpopen\s*\(", 5),
    (r"pickle\.loads?|yaml\.load\s*\(|marshal\.loads", 5),
    (r"nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false", 5),
    (r"require\s*\(\s*['\"]better-sqlite3|keytar|node-pty", 5),
    (r"fetch\s*\(|axios\.|requests\.(get|post)|httpx\.", 3),
    (r"fs\.(readFile|writeFile|createReadStream|createWriteStream)", 3),
    (r"ipcRenderer\.|ipcMain\.|contextBridge\.", 4),
    (r"Object\.assign|merge\s*\(|deepAssign|prototype", 3),
    (r"\.json\.loads?\(|JSON\.parse\b", -3),
    (r"\.json\.dumps|JSON\.stringify", -2),
]

CLASS_PATTERNS: dict[str, list[tuple[re.Pattern[str], int]]] = {
    "dom-xss": [
        (re.compile(r"\.innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\s*=", re.IGNORECASE), 5),
        (re.compile(r"document\.write\s*\(|dangerouslySetInnerHTML|v-html|ng-bind-html", re.IGNORECASE), 5),
        (re.compile(r"eval\s*\(|Function\s*\(|execScript\s*\(", re.IGNORECASE), 5),
    ],
    "exec-sink-reachability": [
        (re.compile(r"child_process\.|subprocess\.|os\.system\s*\(|\bpopen\s*\(", re.IGNORECASE), 5),
        (re.compile(r"eval\s*\(|Function\s*\(", re.IGNORECASE), 5),
        (re.compile(r"process\.dlopen|execFile|spawn\s*\(", re.IGNORECASE), 5),
    ],
    "ipc-trust-boundary": [
        (re.compile(r"ipcRenderer\.|ipcMain\.|contextBridge\.", re.IGNORECASE), 4),
        (re.compile(r"BrowserWindow|webContents\.", re.IGNORECASE), 3),
    ],
    "native-module-abuse": [
        (re.compile(r"require\s*\(\s*['\"]better-sqlite3|keytar|node-pty", re.IGNORECASE), 5),
        (re.compile(r"process\.dlopen", re.IGNORECASE), 5),
    ],
    "memory-unsafe-parser": [
        (re.compile(r"\b(memcpy|memmove|strcpy|strcat|sprintf|vsprintf)\b", re.IGNORECASE), 5),
        (re.compile(r"\bfrom_raw_parts|get_unchecked|copy_nonoverlapping\b", re.IGNORECASE), 5),
        (re.compile(r"\bunsafe\b", re.IGNORECASE), 2),
    ],
    "node-integration": [
        (re.compile(r"nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false", re.IGNORECASE), 5),
        (re.compile(r"enableRemoteModule\s*:\s*true|remote\s*:", re.IGNORECASE), 4),
        (re.compile(r"BrowserWindow", re.IGNORECASE), 2),
    ],
    "path-traversal": [
        (re.compile(r"fs\.(readFile|writeFile|createReadStream|createWriteStream|copyFile|mkdir)", re.IGNORECASE), 3),
        (re.compile(r"path\.(join|resolve|normalize)|\.\./|~\/", re.IGNORECASE), 3),
    ],
    "prototype-pollution": [
        (re.compile(r"Object\.assign|merge\s*\(|deepAssign|deepMerge", re.IGNORECASE), 3),
        (re.compile(r"__proto__|constructor\.prototype|prototype", re.IGNORECASE), 4),
    ],
    "unsafe-deserialization": [
        (re.compile(r"pickle\.loads?|yaml\.load\s*\(|marshal\.loads", re.IGNORECASE), 5),
        (re.compile(r"ObjectInputStream|XMLDecoder|XStream|SnakeYAML|deserialize", re.IGNORECASE), 4),
        (re.compile(r"JSON\.parse\b|json\.loads?\(", re.IGNORECASE), -3),
    ],
    "ssrf": [
        (re.compile(r"fetch\s*\(|axios\.|requests\.(get|post|put|request)|httpx\.", re.IGNORECASE), 3),
        (re.compile(r"http\.request|https\.request|urllib\.request", re.IGNORECASE), 3),
        (re.compile(r"localhost|127\.0\.0\.1|169\.254\.169\.254", re.IGNORECASE), 2),
    ],
}

CLASS_DESCRIPTIONS: dict[str, str] = {
    "dom-xss": "JavaScript and DOM execution surface in browser or renderer contexts.",
    "exec-sink-reachability": "Reachability of command execution, dynamic code execution, or helper execution sinks.",
    "ipc-trust-boundary": "Renderer to preload to main trust boundaries and IPC exposure surface.",
    "native-module-abuse": "Native extension loading or direct use of privileged native modules.",
    "memory-unsafe-parser": "Native parser or unsafe-memory handling reachable from attacker-controlled inputs.",
    "node-integration": "Electron renderer configuration that exposes Node APIs or disables isolation.",
    "path-traversal": "File-system read, write, or path resolution surface reachable from untrusted input.",
    "prototype-pollution": "Deep merge or prototype mutation surface in JavaScript object handling.",
    "unsafe-deserialization": "Deserialization of attacker-controlled bytes or structured data into dangerous objects.",
    "ssrf": "Outbound network request surface where attacker influence could steer destinations or read responses.",
}


def run_preflight(
    target_path: str | Path,
    index: RepoIndex,
    *,
    model: str | None,
    vuln_classes: Iterable[str] | None = None,
    class_descriptions: dict[str, str] | None = None,
    force_llm: bool = False,
) -> list[PreflightDecision]:
    """Run regex-first preflight and selectively escalate to a light LLM."""
    target_root = Path(target_path).expanduser().resolve()
    classes = list(vuln_classes or CLASS_PATTERNS.keys())
    descriptions = {**CLASS_DESCRIPTIONS, **(class_descriptions or {})}
    scan = _regex_scan_repo(target_root, index, classes)
    frameworks = [str(item.get("name", "")).strip() for item in index.frameworks if item.get("name")]

    decisions: list[PreflightDecision] = []
    for vuln_class in classes:
        class_scan = scan.get(vuln_class) or {"score": 0, "focus_files": [], "sink_matches": []}
        score = int(class_scan["score"])
        focus_files = list(class_scan["focus_files"])
        sink_matches = list(class_scan["sink_matches"])

        if not force_llm and score >= 7:
            decisions.append(
                PreflightDecision(
                    vuln_class=vuln_class,
                    regex_score=score,
                    run_agent=True,
                    confidence="high",
                    decision_reason="strong regex surface area detected",
                    focus_files=focus_files,
                    sink_matches=sink_matches,
                )
            )
            continue

        if not force_llm and score >= 4:
            decisions.append(
                PreflightDecision(
                    vuln_class=vuln_class,
                    regex_score=score,
                    run_agent=True,
                    confidence="medium",
                    decision_reason="moderate regex surface area detected",
                    focus_files=focus_files,
                    sink_matches=sink_matches,
                )
            )
            continue

        if not model:
            decisions.append(
                PreflightDecision(
                    vuln_class=vuln_class,
                    regex_score=score,
                    run_agent=True,
                    confidence="low",
                    decision_reason="LLM preflight unavailable without --model; failing open",
                    focus_files=focus_files,
                    sink_matches=sink_matches,
                )
            )
            continue

        prompt = _build_light_llm_prompt(
            vuln_class=vuln_class,
            class_description=descriptions.get(vuln_class, vuln_class),
            frameworks=frameworks,
            candidate_files=focus_files,
            sink_matches=sink_matches,
            score=score,
        )
        try:
            llm_result = _call_light_llm(prompt, model)
            llm_has_surface = bool(llm_result.get("has_surface_area"))
            llm_confidence = str(llm_result.get("confidence", "low")).strip().lower() or "low"
            llm_reason = str(llm_result.get("reason", "")).strip() or "light LLM preflight completed"
            llm_files = [
                str(item).strip()
                for item in (llm_result.get("focus_files") or [])
                if str(item).strip()
            ]
            merged_focus = _merge_focus_files(focus_files, llm_files)
            should_skip = score <= 0 and (not llm_has_surface) and llm_confidence == "high"
            decisions.append(
                PreflightDecision(
                    vuln_class=vuln_class,
                    regex_score=score,
                    run_agent=not should_skip,
                    confidence=llm_confidence,
                    decision_reason=llm_reason if not should_skip else f"skip: {llm_reason}",
                    focus_files=merged_focus,
                    sink_matches=sink_matches,
                    llm_used=True,
                    llm_result=llm_result,
                )
            )
        except Exception as exc:
            decisions.append(
                PreflightDecision(
                    vuln_class=vuln_class,
                    regex_score=score,
                    run_agent=True,
                    confidence="low",
                    decision_reason=f"LLM preflight failed; failing open ({exc})",
                    focus_files=focus_files,
                    sink_matches=sink_matches,
                    llm_used=True,
                    llm_result={"error": str(exc)},
                )
            )

    return decisions


def _regex_scan_repo(
    target_root: Path,
    index: RepoIndex,
    vuln_classes: list[str],
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {
        vuln_class: {"score": 0, "focus_files": [], "sink_matches": [], "file_scores": {}}
        for vuln_class in vuln_classes
    }
    frameworks = {str(item.get("name", "")).strip().lower() for item in index.frameworks if item.get("name")}

    for relpath, meta in index.files.items():
        abs_path = target_root / relpath
        try:
            content = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for vuln_class in vuln_classes:
            class_rules = CLASS_PATTERNS.get(vuln_class, [])
            file_score = 0
            sink_hits: list[str] = []
            for line_number, raw_line in enumerate(content.splitlines(), start=1):
                for pattern, weight in class_rules:
                    if not pattern.search(raw_line):
                        continue
                    file_score += weight
                    if len(sink_hits) < 6:
                        sink_hits.append(f"{relpath}:{line_number} {raw_line.strip()[:180]}")
            if file_score == 0:
                continue
            file_scores = results[vuln_class]["file_scores"]
            file_scores[relpath] = file_scores.get(relpath, 0) + file_score
            results[vuln_class]["score"] += file_score
            existing_hits = results[vuln_class]["sink_matches"]
            remaining = max(0, 8 - len(existing_hits))
            if remaining:
                existing_hits.extend(sink_hits[:remaining])

    for vuln_class in vuln_classes:
        results[vuln_class]["score"] += _framework_penalty(vuln_class, frameworks, results[vuln_class]["sink_matches"])
        file_scores = results[vuln_class].pop("file_scores")
        results[vuln_class]["focus_files"] = [
            relpath
            for relpath, _score in sorted(file_scores.items(), key=lambda item: (-item[1], item[0]))[:6]
        ]

    return results


def _framework_penalty(vuln_class: str, frameworks: set[str], sink_matches: list[str]) -> int:
    python_only = "python" in frameworks and not ({"node", "electron"} & frameworks)
    js_only = ("node" in frameworks or "electron" in frameworks) and "python" not in frameworks
    if python_only and vuln_class in {"dom-xss", "ipc-trust-boundary", "prototype-pollution"}:
        return -8
    if js_only and vuln_class == "unsafe-deserialization":
        joined = "\n".join(sink_matches).lower()
        if "pickle" not in joined and "yaml.load" not in joined and "marshal" not in joined:
            return -4
    return 0


def _build_light_llm_prompt(
    *,
    vuln_class: str,
    class_description: str,
    frameworks: list[str],
    candidate_files: list[str],
    sink_matches: list[str],
    score: int,
) -> str:
    framework_text = ", ".join(frameworks) if frameworks else "unknown"
    file_text = json.dumps(candidate_files[:8])
    sink_text = json.dumps(sink_matches[:8])
    return f"""You are a security preflight classifier for static code review.

Goal: decide whether this repository has plausible review surface for vulnerability class "{vuln_class}".

Be CONSERVATIVE — return has_surface_area=false only when absence of surface area is STRONG.

Vulnerability class: {class_description}
Repo frameworks: {framework_text}
Top candidate files: {file_text}
Relevant sinks found: {sink_text}
Regex signal score for this class: {score}

Output JSON only — no prose:
{{"has_surface_area": true|false, "confidence": "low|medium|high", "reason": "brief sentence", "focus_files": ["file1", "file2"]}}"""


def _call_light_llm(prompt: str, model: str | None) -> dict[str, Any]:
    """Call a light LLM through the codex CLI and parse its JSON response."""
    if not model:
        raise ValueError("model is required for light LLM call")
    cmd = ["codex", "exec", "-s", "danger-full-access", "--skip-git-repo-check", "-m", model, prompt]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"Light LLM call failed: {result.stderr.strip() or result.stdout.strip()}")
    for raw_line in reversed(result.stdout.strip().splitlines()):
        line = raw_line.strip()
        if line.startswith("{") and line.endswith("}"):
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                return parsed
    raise ValueError("No JSON in light LLM output")


def _merge_focus_files(primary: list[str], secondary: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for item in primary + secondary:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        merged.append(text)
    return merged[:8]
