#!/usr/bin/env python3
"""
Retard Collaboration Harness — Creative 3-agent brainstorming for bug bounty hunting.

Architecture:
    1. Creative Chaos Agent  (model=gpt-4.1 — weaker, weirder, FREE)
       → Reads zero_day findings + app map, writes wild ideas to creative/findings.txt
    2. Analyst Agent        (model=gpt-5.4 — normal Codex)
       → Reads creative output, filters to 2-3 diamonds, writes to analyst/filtered.txt
    3. Synthesizer Agent   (model=gpt-5.4 — normal Codex)
       → Reads filtered ideas + zero_day findings, outputs novel chains to synthesizer/chains.md

File-based comms via /tmp/collab_{program}_{date}/
Output → ~/Shared/bounty_recon/{program}/ghost/collaboration/

Usage:
    python agents/retard_collaboration.py evernote --source ~/Shared/bounty_recon/evernote/0day_team/
    python agents/retard_collaboration.py evernote --source ~/Shared/bounty_recon/evernote/0day_team/ --target ~/source/

Workflow:
    zero_day_team → retard_collaboration → chainer
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import date
from pathlib import Path
from typing import Optional

# ── Logger ────────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path.home() / "projects/bounty-tools"))
try:
    from subagent_logger import SubagentLogger
    _HAS_LOGGER = True
except ImportError:
    _HAS_LOGGER = False

# ── Paths ────────────────────────────────────────────────────────────────────
AGENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = AGENT_DIR.parent
FINDINGS_FILENAME = "findings.jsonl"


# ═══════════════════════════════════════════════════════════════════════════════
# PROMPTS
# ═══════════════════════════════════════════════════════════════════════════════

CREATIVE_PROMPT = """You are the CREATIVE CHAOS AGENT.

Your job is to generate target-grounded, lateral bug bounty ideas. You are not
here to judge feasibility too early; you are here to produce concrete attack
scenarios that a normal researcher might miss.

MANDATORY READ ORDER:
1. FIRST read `shared_context/state.txt`.
   - Extract the `Unexplored vectors to focus on` list.
   - Those unexplored vectors are your primary scope. Spend your effort there.
2. THEN read `shared_context/app_map.txt`.
   - Use the real entry points, dangerous sinks, trust boundaries, frameworks,
     snippets, and file paths to ground your ideas in the actual codebase.
3. THEN read `shared_context/zero_day_findings.txt`.
   - Do not duplicate or lightly rephrase what zero_day_team already found.
4. THEN read `shared_context/task.txt`.

GENERATE IDEAS:
- Write AT LEAST 10 ideas to `creative/findings.txt`.
- Every idea must target one or more unexplored vectors from `shared_context/state.txt`.
- Every idea must be specific to THIS target, not a generic "test for XSS/IDOR" suggestion.
- Use the app map entries, sinks, trust boundaries, endpoints, handlers, and file
  paths to anchor each idea in actual code.
- Each idea must be a full attack scenario: entry point -> vulnerability ->
  exploitation path -> impact.
- Prefer lateral compositions, trust-boundary mistakes, parser mismatches, cache or
  concurrency weirdness, framework-specific misuse, and broken assumptions.
- If an idea depends on an assumption, state the assumption explicitly.
- Avoid filler, checklists, and duplicates of zero_day_team findings.

OUTPUT FORMAT for `creative/findings.txt`:

## Idea 1: [Short title]
Attack Category: [category]
Unexplored Vector Targeted: [vector from state.txt]
Target-Specific Details: [entry point, sink, trust boundary, file path, code clue]
Attack Scenario: [1-3 sentences describing entry -> bug -> impact]
Why This Is Novel: [why a normal researcher might miss it]
Rough Attack Steps:
1. [step]
2. [step]
3. [step]
Not A Duplicate Of zero_day_team Because: [brief reason]

Repeat for at least 10 ideas.

When done, write `DONE` to `creative/done.txt`
"""

ANALYST_PROMPT = """You are the SENIOR SECURITY RESEARCHER — the gatekeeper.

Your job is to filter the creative agent's output down to the few ideas that are
actually worth testing. Be strict, but do not lose the rare high-value idea.

MANDATORY READ ORDER:
1. FIRST read `shared_context/state.txt`.
   - Note which vectors are still unexplored. Prefer ideas that directly cover them.
2. THEN read `creative/findings.txt`.
3. THEN read `shared_context/app_map.txt`.
   - Verify whether the idea is grounded in real entries, sinks, trust boundaries,
     handlers, or files from the target.
4. THEN read `shared_context/zero_day_findings.txt`.
   - Reject anything that duplicates or only slightly extends zero_day_team findings.
5. THEN read `shared_context/task.txt`.

FILTERING RULES:
- Keep only 2-3 ideas with real security potential.
- Prefer ideas that are both novel and grounded in the target's actual attack surface.
- Reject ideas that are generic, unsupported by the app map, redundant with
  zero_day_team, or too hand-wavy to test.
- For every kept idea, explain exactly why it deserves time.

OUTPUT FORMAT for `analyst/filtered.txt`:

## Keep 1: [Short title]
Attack Category: [category]
Unexplored Vector Targeted: [vector]
Why It Has Merit: [why this is plausibly exploitable]
Grounding In Target: [entries/sinks/trust boundaries/files that support it]
Why It Is Not A Duplicate: [brief reason]
Rough Validation Steps:
1. [step]
2. [step]
3. [step]

## Keep 2: ...

## Rejected Ideas
- [Idea title]: [short rejection reason]
- [Idea title]: [short rejection reason]

When done, write `DONE` to `analyst/done.txt`
"""

SYNTHESIZER_PROMPT = """You are the SYNTHESIS EXPERT — the builder.

Your job is to combine the strongest creative ideas with zero_day_team context and
the app map to produce concrete attack chains that neither side generated alone.

MANDATORY READ ORDER:
1. FIRST read `shared_context/state.txt`.
   - Track which vectors are still unexplored and which ones this run should cover.
2. THEN read `analyst/filtered.txt`.
3. THEN read `shared_context/app_map.txt`.
   - Ground chains in actual entries, sinks, trust boundaries, frameworks, and files.
4. THEN read `shared_context/zero_day_findings.txt`.
   - Avoid duplicating what zero_day_team already found.
5. THEN read `shared_context/task.txt`.

SYNTHESIS RULES:
- Propose 3-5 concrete, testable attack chains.
- Each chain must combine ideas in a way that neither team produced alone.
- Each chain must identify which unexplored vectors it targets.
- Each chain must be specific to the target and cite app_map evidence.
- Do not produce vague strategy notes; produce executable attack thinking.

OUTPUT FORMAT for `synthesizer/chains.md`:

# Collaborative Findings - [program] - [date]

## Novel Attack Chains

### Chain 1: [Name]
**Targeted Vectors:** [vector 1, vector 2]
**Idea Source:** [which kept idea(s) inspired this]
**Target-Specific Details:** [entry points, sinks, files, trust boundaries]
**Novel Because:** [why this is new relative to zero_day_team]
**Attack Steps:**
1. [step]
2. [step]
3. [step]
**Test Plan:** [how to validate]
**Impact:** [security impact]

### Chain 2: ...

## Why These Are Novel
[Explain how these differ from what zero_day_team found]

## State Update
Vectors targeted this run:
- [vector]
Vectors that should now move from unexplored to explored:
- [vector]
Vectors still unexplored after this run:
- [vector]

After writing `synthesizer/chains.md`, append the exact block below to
`shared_context/state.txt` so the harness can persist the coverage update:

=== SYNTHESIZER RUN UPDATE ===
Vectors targeted this run:
- [vector]
Vectors confirmed explored this run:
- [vector]
Vectors still unexplored after this run:
- [vector]
Ideas kept this run:
- [short idea or chain name]
=== END SYNTHESIZER RUN UPDATE ===

When done, write `DONE` to `synthesizer/done.txt`
"""


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _call_codex(prompt: str, workdir: Path, model: str = "gpt-5.4", timeout: int = 600) -> tuple[str, int]:
    """Run a codex exec call and return (stdout, returncode).
    
    Writes prompt to a temp task file to avoid CLI argument length limits.
    Codex reads from stdin so the full prompt isn't truncated.
    """
    import tempfile
    
    # Write prompt to a temp file to avoid argv truncation
    # Use workdir so Codex can read files in its working context
    task_file = workdir / "current_task.txt"
    task_file.write_text(prompt, encoding="utf-8")
    
    # Use bash heredoc to pipe content to codex stdin, or read from file
    # Codex CLI: pass --read option if available, otherwise use stdin redirect
    cmd = [
        "bash", "-lc",
        f"codex exec -s danger-full-access --skip-git-repo-check -C '{workdir}' < '{task_file}'"
    ]
    if model != "gpt-5.4":
        cmd[2] = cmd[2].replace("codex exec", f"codex exec -m {model}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(workdir),
        )
        # Clean up task file
        try:
            task_file.unlink(missing_ok=True)
        except Exception:
            pass
        return result.stdout or "", result.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -1
    except FileNotFoundError:
        return "CODEX_NOT_FOUND", -1


def _load_jsonl(path: Path) -> list[dict]:
    """Load findings from a JSONL file."""
    if not path.exists():
        return []
    items = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return items


def _render_findings_for_prompt(findings: list[dict]) -> str:
    """Render findings as readable text for prompt injection."""
    if not findings:
        return "No zero-day findings loaded."
    lines = [f"Found {len(findings)} zero-day findings:\n"]
    for i, f in enumerate(findings[:20], 1):  # cap at 20 to avoid huge prompts
        fid = f.get("fid", "?")
        title = f.get("vulnerability_name", f.get("type", "unknown"))
        desc = f.get("description", "")[:200]
        file_ref = f.get("file", "")
        lines.append(f"\n[{i}] {fid} — {title}")
        lines.append(f"    File: {file_ref}")
        lines.append(f"    Desc: {desc}")
    if len(findings) > 20:
        lines.append(f"\n[... +{len(findings) - 20} more findings]")
    return "\n".join(lines)


def _load_app_map(workdir: Path) -> str:
    """Load app map if it exists in shared_context."""
    app_map = workdir / "shared_context" / "app_map.txt"
    if app_map.exists():
        text = app_map.read_text(encoding="utf-8", errors="replace")
        if text.strip():
            return f"\n\n=== APPLICATION MAP ===\n{text[:5000]}"
    return ""


def _generate_app_map_from_shared_brain(program: str) -> str:
    """Auto-generate an application map from shared_brain/index.json.
    
    This is the mental-map output — per-file signals with entries, sinks,
    trust boundaries, and framework signals aggregated into a high-level view.
    """
    import json as _json

    shared_brain_path = (
        Path.home()
        / "Shared"
        / "bounty_recon"
        / _sanitize_program_name(program)
        / "ghost"
        / "shared_brain"
        / "index.json"
    )
    if not shared_brain_path.exists():
        return f"\n\n[shared_brain index not found at {shared_brain_path} — no app map generated]"

    try:
        with shared_brain_path.open("r", encoding="utf-8", errors="replace") as f:
            raw = _json.load(f)
    except Exception as e:
        return f"\n\n[shared_brain index unreadable: {e}]"

    if not isinstance(raw, dict) or "files" not in raw:
        return "\n\n[shared_brain index has unexpected format — skipping app map]"

    files: dict = raw["files"]

    # Aggregate signals
    all_entries: list[str] = []
    all_sinks: list[str] = []
    all_trust: list[str] = []
    frameworks: set[str] = set()
    class_scores: dict[str, float] = {}

    for path, data in files.items():
        signals = data.get("signals", {})
        roles = data.get("roles", [])
        lang = data.get("lang", "?")

        # Entry points
        for entry in signals.get("entries", []):
            text = entry.get("text", "")[:120]
            kind = entry.get("kind", "")
            all_entries.append(f"  [{kind}] {path}: {text}")

        # Dangerous sinks
        for sink in signals.get("sinks", []):
            classes = sink.get("class_hints", [])
            text = sink.get("text", "")[:120]
            all_sinks.append(f"  [{','.join(classes)}] {path}: {text}")

        # Trust boundaries
        for tb in signals.get("trust_boundaries", []):
            all_trust.append(f"  {path}: {tb.get('text', '')[:120]}")

        # Frameworks detected
        for role in roles:
            if any(kw in role.lower() for kw in ["electron", "chrome", "browser", "node", "python", "java", "dotnet"]):
                frameworks.add(role)

        # Vulnerability class scores
        for cls, score in signals.get("class_scores", {}).items():
            if cls not in class_scores:
                class_scores[cls] = 0.0
            class_scores[cls] = max(class_scores[cls], float(score))

    lines = [
        f"\n\n=== APPLICATION MAP (from shared_brain) ===",
        f"Files indexed: {len(files)}",
    ]

    if frameworks:
        lines.append(f"Frameworks detected: {', '.join(sorted(frameworks))}")

    if class_scores:
        lines.append("\nTop vulnerability classes by score:")
        for cls, score in sorted(class_scores.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"  [{score:.1f}] {cls}")

    if all_entries:
        lines.append(f"\nEntry points ({len(all_entries)} total, top 15):")
        lines.extend(all_entries[:15])

    if all_sinks:
        lines.append(f"\nDangerous sinks ({len(all_sinks)} total, top 20):")
        lines.extend(all_sinks[:20])

    if all_trust:
        lines.append(f"\nTrust boundaries ({len(all_trust)} total, top 10):")
        lines.extend(all_trust[:10])

    return "\n".join(lines)[:6000]  # Cap at ~6000 chars to keep prompt manageable


def _load_state(program: str) -> dict:
    """Load collaboration state for incremental exploration."""
    state_path = (
        Path.home()
        / "Shared"
        / "bounty_recon"
        / _sanitize_program_name(program)
        / "ghost"
        / "collaboration"
        / "state.json"
    )
    if state_path.exists():
        try:
            import json
            return json.loads(state_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "areas_explored": [],
        "unexplored_vectors": [
            "authentication/bypass",
            "authorization/idor",
            "api/security",
            "session/handling",
            "file_processing",
            "crypto/misuse",
            " Injection (XSS/SQL/CMD)",
            "redress/composition",
            "webSocket/security",
            "graphql/security",
            "cache/poisoning",
            "Race conditions",
            "prototype pollution",
        ],
        "ideas_kept": [],
        "ideas_rejected": [],
        "runs": 0,
    }


def _save_state(program: str, state: dict) -> None:
    """Save collaboration state after each run."""
    state_path = (
        Path.home()
        / "Shared"
        / "bounty_recon"
        / _sanitize_program_name(program)
        / "ghost"
        / "collaboration"
    )
    state_path.mkdir(parents=True, exist_ok=True)
    state["runs"] = state.get("runs", 0) + 1
    import json
    (state_path / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")


def _extract_bullet_section(text: str, header: str) -> list[str]:
    """Extract bullet items under a header from a plain-text agent update block."""
    lines = text.splitlines()
    items: list[str] = []
    capturing = False
    for raw in lines:
        line = raw.strip()
        if not capturing:
            if line == header:
                capturing = True
            continue

        if not line:
            if items:
                break
            continue

        if line.startswith("- "):
            items.append(line[2:].strip())
            continue

        # Stop when the next section or marker begins.
        if line.endswith(":") or line.startswith("==="):
            break

    return items


def _apply_synthesizer_state_update(workdir: Path, state: dict) -> bool:
    """Apply an explicit synthesizer coverage update from shared_context/state.txt."""
    state_file = workdir / "shared_context" / "state.txt"
    if not state_file.exists():
        return False

    text = state_file.read_text(encoding="utf-8", errors="replace")
    start_marker = "=== SYNTHESIZER RUN UPDATE ==="
    end_marker = "=== END SYNTHESIZER RUN UPDATE ==="
    if start_marker not in text or end_marker not in text:
        return False

    update_text = text.split(start_marker)[-1].split(end_marker)[0]
    targeted = _extract_bullet_section(update_text, "Vectors targeted this run:")
    confirmed = _extract_bullet_section(update_text, "Vectors confirmed explored this run:")
    remaining = _extract_bullet_section(update_text, "Vectors still unexplored after this run:")
    kept = _extract_bullet_section(update_text, "Ideas kept this run:")

    explored = state.setdefault("areas_explored", [])
    unexplored = state.setdefault("unexplored_vectors", [])

    for vector in targeted + confirmed:
        if vector and vector not in explored:
            explored.append(vector)
        if vector in unexplored:
            unexplored.remove(vector)

    if remaining:
        deduped_remaining: list[str] = []
        for vector in remaining:
            if vector and vector not in explored and vector not in deduped_remaining:
                deduped_remaining.append(vector)
        state["unexplored_vectors"] = deduped_remaining

    if kept:
        ideas_kept = state.setdefault("ideas_kept", [])
        for idea in kept:
            if idea and idea not in ideas_kept:
                ideas_kept.append(idea)

    return True


def _sanitize(s: str) -> str:
    """Basic slug sanitization."""
    return s.lower().replace(" ", "-").replace("/", "-").replace(".", "-")


def _collab_dir(program: str) -> Path:
    """Get the collaboration output directory."""
    today = date.today().strftime("%d-%m-%Y")
    return (
        Path.home()
        / "Shared"
        / "bounty_recon"
        / _sanitize(program)
        / "ghost"
        / "collaboration"
        / today
    )


def _sanitize_program_name(program: str) -> str:
    return program.lower().replace(" ", "-").replace("/", "-").replace(".", "-").replace(":", "-")


# ═══════════════════════════════════════════════════════════════════════════════
# STAGES
# ═══════════════════════════════════════════════════════════════════════════════

def stage_creative(workdir: Path, logger: Optional[SubagentLogger] = None) -> bool:
    """Stage 1: Spawn Creative Chaos Agent (gpt-4.1)."""
    stage_dir = workdir / "creative"
    stage_dir.mkdir(parents=True, exist_ok=True)

    findings_file = stage_dir / "findings.txt"

    # Load state for unexplored vectors
    state_text = ""
    state_file = workdir / "shared_context" / "state.txt"
    if state_file.exists():
        state_text = f"\n\n=== INCREMENTAL EXPLORATION STATE ===\n{state_file.read_text(encoding='utf-8', errors='replace')[:2000]}"

    # Load app map
    app_map = _load_app_map(workdir)

    prompt = f"""WORKING DIRECTORY: {workdir}
CURRENT STAGE: Creative Chaos Agent

{CREATIVE_PROMPT}

{state_text}
{app_map}

Working in: {workdir}
ABSOLUTELY write your output to: {findings_file}
Write DONE signal to: {stage_dir}/done.txt

IMPORTANT: Use the write tool to write your ideas to {findings_file}"""
    if logger:
        logger.step("Spawning Creative Chaos Agent (gpt-4.1)...")

    stdout, code = _call_codex(prompt, workdir, model="gpt-4.1", timeout=600)
    if logger:
        logger.step(f"Creative agent done (exit={code})")

    # Check if it wrote findings — also fall back to stdout if file is empty
    if findings_file.exists() and findings_file.stat().st_size > 100:
        if logger:
            logger.result(f"Creative agent wrote {findings_file.stat().st_size} bytes of wild ideas")
        return True
    elif stdout and len(stdout.strip()) > 100:
        # Fallback: codex wrote to stdout instead of file
        findings_file.write_text(stdout, encoding="utf-8")
        if logger:
            logger.result(f"Creative agent wrote {len(stdout)} bytes to stdout (file fallback)")
        return True
    else:
        if logger:
            logger.error(f"Creative agent produced no output (stdout: {len(stdout) if stdout else 0} bytes)")
        return False


def stage_analyst(workdir: Path, logger: Optional[SubagentLogger] = None) -> bool:
    """Stage 2: Spawn Analyst Agent (gpt-5.4)."""
    stage_dir = workdir / "analyst"
    stage_dir.mkdir(parents=True, exist_ok=True)

    # Load creative findings to inject them
    creative_findings = workdir / "creative" / "findings.txt"
    creative_text = ""
    if creative_findings.exists():
        creative_text = creative_findings.read_text(encoding="utf-8", errors="replace")

    filtered_file = stage_dir / "filtered.txt"
    state_text = ""
    state_file = workdir / "shared_context" / "state.txt"
    if state_file.exists():
        state_text = f"\n\n=== INCREMENTAL EXPLORATION STATE ===\n{state_file.read_text(encoding='utf-8', errors='replace')[:2000]}"
    app_map = _load_app_map(workdir)

    prompt = f"""WORKING DIRECTORY: {workdir}
CURRENT STAGE: Analyst Agent — Filtering Creative Ideas

ANALYTICAL TASK:
{ANALYST_PROMPT}

{state_text}
{app_map}

CREATIVE AGENT OUTPUT (for filtering):
---
{creative_text[:5000] if creative_text else "NO OUTPUT FROM CREATIVE AGENT"}
---

Working in: {workdir}
ABSOLUTELY write your filtered results to: {filtered_file}
Write DONE signal to: {stage_dir}/done.txt

IMPORTANT: Use the write tool to write your filtered ideas to {filtered_file}"""
    if logger:
        logger.step("Spawning Analyst Agent (gpt-5.4)...")

    stdout, code = _call_codex(prompt, workdir, model="gpt-5.4", timeout=600)
    if logger:
        logger.step(f"Analyst agent done (exit={code})")

    if filtered_file.exists() and filtered_file.stat().st_size > 50:
        if logger:
            logger.result(f"Analyst filtered down to {filtered_file.stat().st_size} bytes")
        return True
    elif stdout and len(stdout.strip()) > 50:
        filtered_file.write_text(stdout, encoding="utf-8")
        if logger:
            logger.result(f"Analyst wrote {len(stdout)} bytes to stdout (file fallback)")
        return True
    else:
        if logger:
            logger.error(f"Analyst agent produced no output")
        return False


def stage_synthesizer(workdir: Path, program: str, logger: Optional[SubagentLogger] = None) -> bool:
    """Stage 3: Spawn Synthesizer Agent (gpt-5.4)."""
    stage_dir = workdir / "synthesizer"
    stage_dir.mkdir(parents=True, exist_ok=True)

    # Load context
    analyst_text = ""
    analyst_filtered = workdir / "analyst" / "filtered.txt"
    if analyst_filtered.exists():
        analyst_text = analyst_filtered.read_text(encoding="utf-8", errors="replace")

    today = date.today().strftime("%d-%m-%Y")
    chains_file = stage_dir / "chains.md"
    state_text = ""
    state_file = workdir / "shared_context" / "state.txt"
    if state_file.exists():
        state_text = f"\n\n=== INCREMENTAL EXPLORATION STATE ===\n{state_file.read_text(encoding='utf-8', errors='replace')[:2000]}"
    app_map = _load_app_map(workdir)

    prompt = f"""WORKING DIRECTORY: {workdir}
CURRENT STAGE: Synthesizer Agent — Building Novel Chains

SYNTHESIS TASK:
{SYNTHESIZER_PROMPT}

{state_text}
{app_map}

FILTERED CREATIVE IDEAS (for synthesis):
---
{analyst_text[:5000] if analyst_text else "NO FILTERED IDEAS"}
---

Working in: {workdir}
ABSOLUTELY write your chains to: {chains_file}
Write DONE signal to: {stage_dir}/done.txt

IMPORTANT: Use the write tool to write your chains to {chains_file}"""
    if logger:
        logger.step("Spawning Synthesizer Agent (gpt-5.4)...")

    stdout, code = _call_codex(prompt, workdir, model="gpt-5.4", timeout=600)
    if logger:
        logger.step(f"Synthesizer agent done (exit={code})")

    if chains_file.exists() and chains_file.stat().st_size > 100:
        if logger:
            logger.result(f"Synthesizer produced {chains_file.stat().st_size} bytes of chains")
        return True
    elif stdout and len(stdout.strip()) > 100:
        chains_file.write_text(stdout, encoding="utf-8")
        if logger:
            logger.result(f"Synthesizer wrote {len(stdout)} bytes to stdout (file fallback)")
        return True
    else:
        if logger:
            logger.error(f"Synthesizer produced no output")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Retard Collaboration — Creative 3-agent brainstorming harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agents/retard_collaboration.py evernote --source ~/Shared/bounty_recon/evernote/0day_team/
  python agents/retard_collaboration.py evernote --source ~/Shared/bounty_recon/evernote/0day_team/ --target ~/source/

Workflow: zero_day_team -> retard_collaboration -> chainer
        """,
    )
    parser.add_argument("program", help="Bug bounty program name")
    parser.add_argument(
        "--source",
        dest="source",
        required=True,
        help="Path to zero_day_team output directory (contains findings.jsonl)",
    )
    parser.add_argument(
        "--target",
        dest="target",
        default=None,
        help="Optional: path to source code being analyzed",
    )
    parser.add_argument(
        "--skip-creative",
        action="store_true",
        help="Skip creative agent (use if creative output already exists)",
    )
    parser.add_argument(
        "--skip-analyst",
        action="store_true",
        help="Skip analyst agent",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print raw stdout from agents",
    )
    args = parser.parse_args()

    program = _sanitize_program_name(args.program)
    source_path = Path(args.source).expanduser().resolve()
    target_path = Path(args.target).expanduser().resolve() if args.target else None

    # Logger
    logger: Optional[SubagentLogger] = None
    if _HAS_LOGGER:
        try:
            logger = SubagentLogger("retard_collab", program)
            logger.start(target=f"source={source_path}", source=args.source)
        except Exception:
            logger = None

    # Working directory — unique per run to avoid stale file contamination
    import uuid
    today = date.today().strftime("%d-%m-%Y")
    run_id = uuid.uuid4().hex[:8]
    workdir = Path(f"/tmp/collab_{program}_{today.replace('-', '')}_{run_id}")
    workdir.mkdir(parents=True, exist_ok=True)

    # Subdirectories
    creative_dir = workdir / "creative"
    analyst_dir = workdir / "analyst"
    synthesizer_dir = workdir / "synthesizer"
    shared_dir = workdir / "shared_context"
    for d in [creative_dir, analyst_dir, synthesizer_dir, shared_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # Copy/populate shared context
    findings_jsonl = source_path / FINDINGS_FILENAME
    if findings_jsonl.exists():
        findings = _load_jsonl(findings_jsonl)
        text = _render_findings_for_prompt(findings)
        (shared_dir / "zero_day_findings.txt").write_text(text, encoding="utf-8")
        # Also copy the raw JSONL
        import shutil
        shutil.copy(findings_jsonl, shared_dir / "zero_day_findings.jsonl")
        print(f"[+] Loaded {len(findings)} zero-day findings from {findings_jsonl}")
        if logger:
            logger.step(f"Loaded {len(findings)} zero-day findings from source")
    else:
        print(f"[!] WARNING: {findings_jsonl} not found — creative agent will have no context")
        if logger:
            logger.step("WARNING: findings.jsonl not found in source")

    # Copy app_map if found, otherwise auto-generate from shared_brain
    app_map_candidates = [
        source_path / "app_map.txt",
        source_path.parent / "app_map.txt",
        source_path.parent.parent / "app_map.txt",
    ]
    app_map_written = False
    for candidate in app_map_candidates:
        if candidate.exists():
            import shutil
            shutil.copy(candidate, shared_dir / "app_map.txt")
            print(f"[+] Copied app_map from {candidate}")
            app_map_written = True
            break

    if not app_map_written:
        # Auto-generate app map from shared_brain index
        app_map_text = _generate_app_map_from_shared_brain(program)
        (shared_dir / "app_map.txt").write_text(app_map_text, encoding="utf-8")
        print(f"[+] Auto-generated app_map from shared_brain ({len(app_map_text)} chars)")

    # Load and persist collaboration state for incremental exploration
    state = _load_state(program)
    unexplored = state.get("unexplored_vectors", [])
    explored = state.get("areas_explored", [])
    state_text = (
        f"COLLABORATION STATE (for incremental exploration)\n"
        f"Runs so far: {state.get('runs', 0)}\n"
        f"\nAreas already explored ({len(explored)}): {', '.join(explored) if explored else 'none yet'}\n"
        f"\nUnexplored vectors to focus on ({len(unexplored)}):\n"
        + "\n".join(f"  - {v}" for v in unexplored)
    )
    (shared_dir / "state.txt").write_text(state_text, encoding="utf-8")
    print(f"[+] Collaboration state loaded ({state.get('runs', 0)} previous runs)")

    # Write task.txt
    task_parts = [f"Program: {program}", f"Source: {source_path}"]
    if target_path:
        task_parts.append(f"Target source: {target_path}")
    task_parts.append(f"Date: {today}")
    task_parts.append("\nGoal: Generate novel attack chains that neither zero_day_team nor creative chaos found alone.")
    (shared_dir / "task.txt").write_text("\n".join(task_parts), encoding="utf-8")

    print(f"\n[*] Working directory: {workdir}")
    print(f"[*] Stages: Creative(gpt-4.1) → Analyst(gpt-5.4) → Synthesizer(gpt-5.4)")
    print()

    # ── Stage 1: Creative ────────────────────────────────────────────────────
    if args.skip_creative:
        print("[*] Skipping creative (--skip-creative)")
        if logger:
            logger.step("Skipped creative agent (--skip-creative)")
    else:
        creative_ok = stage_creative(workdir, logger)
        if not creative_ok:
            print("[!] Creative stage produced no output — continuing anyway")
        print()

    # ── Stage 2: Analyst ─────────────────────────────────────────────────────
    if args.skip_analyst:
        print("[*] Skipping analyst (--skip-analyst)")
        if logger:
            logger.step("Skipped analyst agent (--skip-analyst)")
    else:
        analyst_ok = stage_analyst(workdir, logger)
        if not analyst_ok:
            print("[!] Analyst stage produced no output")
        print()

    # ── Stage 3: Synthesizer ─────────────────────────────────────────────────
    synth_ok = stage_synthesizer(workdir, program, logger)
    if not synth_ok:
        print("[!] Synthesizer stage produced no output")
        if logger:
            logger.error("Synthesizer produced no output")
        print()
        return

    # ── Update collaboration state ─────────────────────────────────────────────
    state = _load_state(program)

    # Parse ideas from creative + analyst outputs to update state
    creative_file = creative_dir / "findings.txt"
    analyst_file = analyst_dir / "filtered.txt"
    chains_file = synthesizer_dir / "chains.md"

    explicit_state_update = _apply_synthesizer_state_update(workdir, state)

    if not explicit_state_update and creative_file.exists():
        # Fallback heuristic when the synthesizer did not write a state update block.
        creative_text = creative_file.read_text(encoding="utf-8", errors="replace").lower()
        for vector in list(state.get("unexplored_vectors", [])):
            normalized = vector.lower().replace("/", " ").replace("-", " ").strip()
            if normalized and normalized in creative_text:
                if vector not in state.get("areas_explored", []):
                    state.setdefault("areas_explored", []).append(vector)
                if vector in state.get("unexplored_vectors", []):
                    state["unexplored_vectors"].remove(vector)

    if not explicit_state_update and analyst_file.exists():
        analyst_text = analyst_file.read_text(encoding="utf-8", errors="replace")
        if len(analyst_text.strip()) > 50:
            state.setdefault("ideas_kept", []).append(analyst_text[:300])

    if not explicit_state_update and chains_file.exists():
        chains_text = chains_file.read_text(encoding="utf-8", errors="replace")
        if len(chains_text.strip()) > 50:
            state.setdefault("ideas_kept", []).append(chains_text[:500])

    _save_state(program, state)
    print(f"[+] State updated: {len(state.get('areas_explored', []))} areas explored, {len(state.get('unexplored_vectors', []))} unexplored vectors remaining")

    # ── Copy output to canonical location ────────────────────────────────────
    output_dir = _collab_dir(program)
    output_dir.mkdir(parents=True, exist_ok=True)

    import shutil
    chains_src = synthesizer_dir / "chains.md"
    output_path = output_dir / "collaborative_chains.md"
    shutil.copy(chains_src, output_path)

    # Copy the full stage outputs too
    try:
        shutil.copytree(creative_dir, output_dir / "creative", dirs_exist_ok=True)
        shutil.copytree(analyst_dir, output_dir / "analyst", dirs_exist_ok=True)
        shutil.copytree(synthesizer_dir, output_dir / "synthesizer", dirs_exist_ok=True)
    except Exception as e:
        print(f"[!] Warning: could not copy stage outputs: {e}")

    print(f"\n[+] OUTPUT: {output_dir}")
    print(f"[+] Chains: {output_path}")

    if logger:
        logger.result(f"Output: {output_path}")
        logger.finish(success=True, summary=f"Collaborative chains → {output_path}")

    print(f"\n[*] Feed to chainer: python agents/chainer.py {program} --source {output_dir.parent}")


if __name__ == "__main__":
    main()
