#!/usr/bin/env python3
"""
Solo Deep-Dive APK Hunter
==========================
Single-agent 3-pass progressive analysis of an extracted APK.

Pass 1 — Surface Scout:     Rank all surfaces by exploit potential
Pass 2 — Deep Strike:       Codex-powered deep dive on top-ranked surfaces
Pass 3 — Chain Forge:       Build exploit chains connecting Pass 2 findings

PTE tracking: each Codex call is instrumented with token estimation and SPAN logging.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ── path bootstrap ──────────────────────────────────────────────────────────
_AGENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _AGENT_DIR.parent
for _p in (_PROJECT_ROOT, Path.home() / "projects" / "bounty-tools"):
    if _p.as_posix() not in (x.as_posix() for x in map(Path, sys.path)):
        sys.path.insert(0, _p.as_posix())

# ── ledger imports (lazy so we don't break if not available) ─────────────────
try:
    from agents.ledger_v2 import VersionedFindingsLedger
    from agents.snapshot_identity import get_snapshot_identity
    from agents.apk_surface_registry import ApkSurfaceRegistry
except ImportError:
    VersionedFindingsLedger = None
    get_snapshot_identity = None
    ApkSurfaceRegistry = None

# ── logging + PTE ─────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _estimate_tokens(text: str | bytes | None) -> int:
    if text is None:
        return 0
    size = len(text) if isinstance(text, bytes) else len(str(text).encode("utf-8", errors="replace"))
    return max(0, math.ceil(size / 4))

def _compute_pte(prompt_tokens: int, completion_tokens: int, tool_output_tokens: int = 0) -> int:
    return prompt_tokens + completion_tokens + tool_output_tokens

def _log(msg: str, emoji: str = "🤖") -> None:
    print(f"{emoji} [{_now_iso()}] {msg}", flush=True)

def _safe_log_span(
    logger: Any,
    span_type: str,
    level: str,
    message: str,
    **fields: Any,
) -> None:
    span = {"ts": _now_iso(), "type": span_type, "level": level, "message": message, **fields}
    print(f"  SPAN {json.dumps(span)}", flush=True)
    if logger is not None:
        try:
            logger.log_span(span_type=span_type, level=level, message=message, **fields)
        except Exception:
            pass

# ── Codex runner with PTE tracking ────────────────────────────────────────────
def _call_codex(
    prompt: str,
    workdir: Path,
    model: str = "gpt-5.4",
    timeout: int = 480,
    logger: Any = None,
    label: str = "codex",
) -> tuple[str, int]:
    """Run Codex CLI with PTE tracking and stdin redirect."""
    task_file = workdir / ".codex_task.txt"
    task_file.write_text(prompt, encoding="utf-8")
    cmd = [
        "bash", "-lc",
        f"codex exec -s danger-full-access --skip-git-repo-check -C '{workdir}' < '{task_file}'"
    ]
    if model != "gpt-5.4":
        cmd[2] = cmd[2].replace("codex exec", f"codex exec -m {model}")

    prompt_tokens = _estimate_tokens(prompt)
    start = time.time()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(workdir))
    finally:
        try:
            task_file.unlink(missing_ok=True)
        except Exception:
            pass

    response = result.stdout or result.stderr or ""
    duration_ms = int((time.time() - start) * 1000)
    completion_tokens = _estimate_tokens(response)
    output_bytes = len(response.encode("utf-8", errors="replace"))
    tool_output_tokens = max(0, math.ceil(output_bytes / 4))
    pte = _compute_pte(prompt_tokens, completion_tokens, tool_output_tokens)

    _safe_log_span(
        logger,
        span_type="model",
        level="STEP",
        message=f"[{label}] {model} call",
        model_name=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        tool_output_tokens=tool_output_tokens,
        pte_lite=pte,
        latency_ms=duration_ms,
        output_bytes=output_bytes,
        success=result.returncode == 0,
    )
    return result.stdout or "", result.returncode


# ── helpers ─────────────────────────────────────────────────────────────────
def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")

def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path

# ── Pass 1: Surface Scout ────────────────────────────────────────────────────
def _pass1_surface_scout(
    extracted_root: Path,
    registry_path: Path,
    logger: Any = None,
) -> dict[str, Any]:
    """Rank surfaces from the registry by exploit potential."""
    _safe_log_span(logger, "phase", "START", "Pass 1: Surface Scout", target=str(registry_path))
    t0 = time.time()

    registry = ApkSurfaceRegistry.load(registry_path)
    payload = registry.payload

    surfaces: list[dict[str, Any]] = []
    all_components: list[dict[str, Any]] = list(payload.get("components", []))
    content_providers: list[dict[str, Any]] = list(payload.get("content_providers", []))
    webview_classes: list[dict[str, Any]] = list(payload.get("webview_classes", []))

    def _norm(comp: dict[str, Any], surf_type: str) -> dict[str, Any]:
        name = comp.get("class_name", comp.get("name", ""))
        metadata = comp.get("metadata", {}) or {}
        return {
            "type": surf_type,
            "name": name,
            "exported": comp.get("exported", False),
            "permissions": metadata.get("permissions", []) or [],
            "intent_filters": metadata.get("intent_filters", []) or [],
            "file": comp.get("file_path", comp.get("file", "")),
            "score": 0,
            "reasons": [],
            "metadata": metadata,
        }

    dangerous = {
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_CONTACTS", "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO", "android.permission.SEND_SMS",
    }

    for comp in all_components:
        surf = _norm(comp, comp.get("component_type", "component"))
        if surf["exported"] and not surf["permissions"]:
            surf["score"] += 3
            surf["reasons"].append("exported with no permission")
        for perm in surf["permissions"]:
            if perm in dangerous:
                surf["score"] += 2
                surf["reasons"].append(f"dangerous permission: {perm}")
        for iff in surf["intent_filters"]:
            for action in iff.get("actions", []):
                if any(x in action.lower() for x in ["view", "send", "pick", "process"]):
                    surf["score"] += 1
                    surf["reasons"].append(f"interesting action: {action}")
        if "webview" in surf["name"].lower():
            surf["score"] += 2
            surf["reasons"].append("WebView surface")
        if surf["type"] == "provider":
            surf["score"] += 2
            surf["reasons"].append("content provider")
        if surf["score"] > 0:
            surfaces.append(surf)

    for provider in content_providers:
        surf = _norm(provider, "provider")
        surf["score"] += 2
        surf["reasons"].append("content provider")
        surfaces.append(surf)

    for webview in webview_classes:
        surf = _norm(webview, "webview")
        surf["score"] += 2
        surf["reasons"].append("WebView class")
        surfaces.append(surf)

    surfaces.sort(key=lambda x: x["score"], reverse=True)

    elapsed = int((time.time() - t0) * 1000)
    _safe_log_span(
        logger, "phase", "RESULT",
        f"Surface Scout: {len(surfaces)} surfaces ranked, top score={surfaces[0]['score'] if surfaces else 0}",
        surface_count=len(surfaces),
        top_score=surfaces[0]["score"] if surfaces else 0,
        latency_ms=elapsed,
    )

    return {
        "all_surfaces": surfaces,
        "top_surfaces": surfaces,  # caller slices
        "registry_stats": registry.stats if hasattr(registry, "stats") else {},
    }


# ── Pass 2: Deep Strike ──────────────────────────────────────────────────────
def _pass2_deep_strike(
    top_surfaces: list[dict[str, Any]],
    extracted_root: Path,
    findings_path: Path,
    program: str,
    logger: Any = None,
) -> list[dict[str, Any]]:
    """Deep-dive on each surface using Codex with full PTE tracking."""
    _safe_log_span(logger, "phase", "START", f"Pass 2: Deep Strike on {len(top_surfaces)} surfaces")
    t0 = time.time()

    findings: list[dict[str, Any]] = []
    workdir = extracted_root if extracted_root.exists() else Path("/tmp")

    for i, surface in enumerate(top_surfaces):
        surf_type = surface["type"]
        surf_name = surface["name"]
        file_path = surface.get("file", "")

        prompt = f"""You are a senior Android security researcher doing DEEP ANALYSIS on a single app surface.

## TARGET
- Program: {program}
- Surface type: {surf_type}
- Component: {surf_name}
- File: {file_path}
- Exported: {surface['exported']}
- Permissions: {', '.join(surface['permissions']) or 'none'}
- Why interesting: {', '.join(surface.get('reasons', [])) or 'score-ranked high-value surface'}

## APK SOURCE: {extracted_root}

## YOUR TASK
Deep code analysis. Go beyond surface-level hints.

1. Read the relevant smali/java files for this component
2. Trace the full call chain: entrypoint → attacker-controlled input → security gate → sink
3. Identify what's broken: missing checks, weak gates, unsafe defaults
4. Look for: missing permission checks, unsafe reflection, unsecured IPC, deep-link injection, WebView JS execution, native lib loading from untrusted paths, SQL injection, SSRF, IDOR
5. For each vuln found, document:
   - Exact file + line (smali offset or method name)
   - Attacker's control point
   - Missing/flawed security gate
   - Concrete impact in 2 sentences
   - PoC steps (pseudocode is fine)

## OUTPUT
Respond ONLY with JSON:
{{
  "surface_analysis": {{"component": "{surf_name}", "surface_type": "{surf_type}", "summary": "..."}},
  "findings": [
    {{
      "type": "missing_permission_check|unsafe_reflection|ssrf|xss|idor|auth_bypass|webview_rce|native_injection|provider_sql|other",
      "title": "short title",
      "severity": "HIGH|MEDIUM|LOW",
      "file": "path/to/file.smali",
      "description": "what's wrong",
      "attacker_control": "where attacker controls data",
      "gate": "missing or flawed gate",
      "impact": "concrete impact",
      "poc_steps": ["step1", "step2"]
    }}
  ]
}}

If no vulns: {{"surface_analysis": {{...}}, "findings": []}}"""

        label = f"deep_strike[{i+1}/{len(top_surfaces)}]"
        try:
            stdout, rc = _call_codex(prompt, workdir, model="gpt-5.4", timeout=600, logger=logger, label=label)
        except subprocess.TimeoutExpired:
            _safe_log_span(logger, "phase", "WARN", f"Timeout after 600s for {surf_name}", surface=surf_name)
            continue

        if rc != 0:
            _safe_log_span(logger, "phase", "WARN", f"Codex exited {rc} for {surf_name}", surface=surf_name)
            continue

        try:
            # Find JSON block
            match = re.search(r"\{[\s\S]*\}", stdout)
            parsed = json.loads(match.group()) if match else json.loads(stdout.strip())
            surf_findings = parsed.get("findings", [])
            for f in surf_findings:
                f["agent"] = f"deep_dive.{surf_type}"
                f["surface"] = surf_name
                f["source"] = "codex_deep_strike"
                f["review_tier"] = "deep_dive"
            findings.extend(surf_findings)
            _safe_log_span(logger, "phase", "STEP", f"[{label}] {len(surf_findings)} findings", surface=surf_name, finding_count=len(surf_findings))
        except json.JSONDecodeError:
            _safe_log_span(logger, "phase", "WARN", f"JSON parse error for {surf_name}", surface=surf_name, raw=stdout[:200])

    elapsed = int((time.time() - t0) * 1000)
    _safe_log_span(logger, "phase", "RESULT", f"Deep Strike: {len(findings)} raw findings", finding_count=len(findings), latency_ms=elapsed)
    return findings


# ── Pass 3: Chain Forge ─────────────────────────────────────────────────────
def _pass3_chain_forge(
    findings: list[dict[str, Any]],
    extracted_root: Path,
    program: str,
    output_dir: Path,
    logger: Any = None,
) -> list[dict[str, Any]]:
    """Chain Pass 2 findings into multi-step exploit scenarios."""
    _safe_log_span(logger, "phase", "START", "Pass 3: Chain Forge")
    t0 = time.time()

    if not findings:
        _safe_log_span(logger, "phase", "SKIP", "No findings to chain")
        return []

    real = [f for f in findings if f.get("type") not in ("parse_error", "info")]
    if len(real) < 2:
        _safe_log_span(logger, "phase", "SKIP", f"Only {len(real)} findings — need 2+ to chain")
        return []

    brief = "\n".join(
        f"- [{f.get('severity','?')}] {f.get('title','?')} ({f.get('type','?')}) on {f.get('surface','?')} — {f.get('impact','?')[:80]}"
        for f in real
    )

    prompt = f"""You are an exploit developer. Given findings from an Android app audit, chain them into multi-step attacks.

## PROGRAM: {program}
## APK SOURCE: {extracted_root}

## FINDINGS
{brief}

## YOUR TASK
Find pairs/groups that combine into worse attacks than either alone.

Patterns to look for:
- Info leak → Auth bypass via leaked tokens
- Exported surface + no perms → WebView RCE via injected content
- SSRF → Internal service access
- Broadcast spoofing → State manipulation
- File-provider + WebView → Arbitrary file read
- Custom URL scheme → Deeplink injection → Activity hijack
- Native lib loading → ROP via downloaded .so

For each valid chain:
- Describe the attack narrative step by step
- Explain why chaining is worse than each finding alone
- Note gaps: what's unknown/missing for full exploit
- Give pseudocode for the full chain

## OUTPUT
Respond ONLY with JSON:
{{
  "chains": [
    {{
      "id": "chain_1",
      "title": "Descriptive chain name",
      "findings_used": ["title1", "title2"],
      "severity": "HIGH|MEDIUM|LOW",
      "steps": [
        {{"step": 1, "action": "what attacker does", "finding": "enabling finding"}}
      ],
      "narrative": "attack story",
      "cumulative_impact": "why this is worse chained",
      "gaps": ["gap1", "gap2"],
      "poc_sketch": "pseudocode"
    }}
  ]
}}

If no valid chains: {{"chains": []}}"""

    workdir = extracted_root if extracted_root.exists() else Path("/tmp")
    stdout, rc = _call_codex(prompt, workdir, model="gpt-4.1", timeout=300, logger=logger, label="chain_forge")

    chains: list[dict[str, Any]] = []
    if rc == 0:
        try:
            match = re.search(r"\{[\s\S]*\}", stdout)
            parsed = json.loads(match.group()) if match else json.loads(stdout.strip())
            chains = parsed if isinstance(parsed, list) else parsed.get("chains", [])
        except json.JSONDecodeError:
            _safe_log_span(logger, "phase", "WARN", "Chain Forge JSON parse error")

    if chains:
        chains_file = output_dir / f"chains_{_now_iso().replace(':', '-')}.json"
        chains_file.write_text(json.dumps(chains, indent=2), encoding="utf-8")
        _safe_log_span(logger, "phase", "RESULT", f"Chain Forge: {len(chains)} chains saved", chain_count=len(chains), path=str(chains_file))
    else:
        _safe_log_span(logger, "phase", "RESULT", "Chain Forge: no valid chains found")

    elapsed = int((time.time() - t0) * 1000)
    return chains


# ── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="Solo Deep-Dive APK Hunter")
    parser.add_argument("program", help="Bug bounty program name")
    parser.add_argument("--apk", help="Path to APK or already-extracted source")
    parser.add_argument("--registry", help="Path to surface_registry.json")
    parser.add_argument("--output-dir", help="Output directory")
    parser.add_argument("--max-surfaces", type=int, default=5, help="Surfaces for Pass 2 (default: 5)")
    parser.add_argument("--force", action="store_true", help="Re-run even if complete")
    args = parser.parse_args()

    program = args.program
    apk_path = Path(args.apk) if args.apk else None

    _AGENT_DIR = Path(__file__).resolve().parent
    _PROJECT_ROOT = _AGENT_DIR.parent
    SHARED_ROOT = Path.home() / "Shared" / "bounty_recon" / program

    run_id = datetime.now(timezone.utc).strftime("%d-%m-%Y")
    output_dir = Path(args.output_dir) if args.output_dir else _ensure_dir(SHARED_ROOT / "ghost" / "deep_dive" / run_id)

    if not args.force and (output_dir / "COMPLETE").exists():
        _log(f"Already complete: {output_dir}. Use --force to re-run.", "⏭️")
        return
    _ensure_dir(output_dir)

    # Resolve extracted source
    if apk_path:
        extracted_root = apk_path if not apk_path.is_file() else Path("/tmp") / f"{program}_dd"
    else:
        candidates = list(Path("/home/ryushe/source").glob(f"{program}*"))
        extracted_root = candidates[0] if candidates else None
        if not extracted_root:
            _log(f"No APK or extraction found for {program}. Use --apk.", "❌")
            sys.exit(1)

    # Resolve surface registry
    if args.registry:
        registry_path = Path(args.registry)
    else:
        for candidate in [
            SHARED_ROOT / "surface_registry.json",
            Path.home() / "Shared" / "bounty_recon" / "surface_registry.json",
        ]:
            if candidate.exists():
                registry_path = candidate
                break
        else:
            _log("No surface_registry.json. Run apk_team first.", "❌")
            sys.exit(1)

    findings_path = _ensure_dir(output_dir / "findings")

    # Init logger
    logger = None
    try:
        from subagent_logger import SubagentLogger
        logger = SubagentLogger("deep_dive", program)
        logger.start(target=program, mode="deep_dive")
    except Exception:
        pass

    # Init ledger — matches apk_team dedup so findings merge across both tools
    ledger = None
    if VersionedFindingsLedger and get_snapshot_identity:
        try:
            snapshot_identity = get_snapshot_identity(extracted_root)
            version_label = str(snapshot_identity.get("version_label") or registry_path.parent.name or "")
            ledger = VersionedFindingsLedger(
                program,
                target_root=extracted_root,
                version_label=version_label,
                snapshot_identity=snapshot_identity,
                agent="deep-dive",
            )
        except Exception as exc:
            _log(f"Ledger init failed (will run without dedup): {exc}", "⚠️")

    # Init/update surface registry for progressive finding tracking
    registry = None
    if ApkSurfaceRegistry:
        try:
            registry = ApkSurfaceRegistry.load(registry_path)
        except Exception as exc:
            _log(f"Surface registry init failed: {exc}", "⚠️")

    _log(f"🎯 Deep Dive: {program} | Source: {extracted_root} | Registry: {registry_path}", "🚀")

    # ── Pass 1 ──
    p1_start = time.time()
    p1_result = _pass1_surface_scout(extracted_root, registry_path, logger)
    top_surfaces = p1_result["top_surfaces"][:args.max_surfaces]
    p1_time = time.time() - p1_start

    p1_file = output_dir / "pass1_surface_scout.json"
    p1_file.write_text(json.dumps(p1_result, indent=2), encoding="utf-8")

    if not top_surfaces:
        _log("No interesting surfaces found. Aborting.", "❌")
        return

    # ── Pass 2 ──
    p2_start = time.time()
    findings = _pass2_deep_strike(top_surfaces, extracted_root, findings_path, program, logger)
    p2_time = time.time() - p2_start

    # Feed findings through the shared ledger (deduplicates with apk_team findings)
    deduplicated_count = 0
    for f in findings:
        if ledger is not None:
            try:
                before_fid = f.get("fid")
                updated = ledger.update(f)
                is_new = (before_fid is None) and bool(updated.get("fid"))
                if is_new:
                    deduplicated_count += 1
                else:
                    _safe_log_span(logger, "phase", "STEP",
                        f" Deduped: {f.get('title', f.get('type', 'unknown'))}")
            except Exception as exc:
                _safe_log_span(logger, "phase", "WARN",
                    f"Ledger update failed: {exc}", finding=f.get("title", "unknown"))
        if registry is not None:
            registry.record_progressive_finding(f, requested_by="deep_dive")

    if findings:
        with (findings_path / "findings.jsonl").open("w", encoding="utf-8") as f:
            for finding in findings:
                f.write(json.dumps(finding, ensure_ascii=False) + "\n")
        (output_dir / "pass2_deep_strike.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")

    # ── Pass 3 ──
    p3_start = time.time()
    chains = _pass3_chain_forge(findings, extracted_root, program, output_dir, logger)
    p3_time = time.time() - p3_start

    # ── Summary ──
    _log("", "=")
    _log(f"DEEP DIVE COMPLETE — {program}", "🏁")
    _log(f"  Pass 1 (Surface Scout): {p1_time:.1f}s — {len(top_surfaces)} surfaces", "📊")
    _log(f"  Pass 2 (Deep Strike):   {p2_time:.1f}s — {len(findings)} raw, {deduplicated_count} new to ledger", "💣")
    _log(f"  Pass 3 (Chain Forge):   {p3_time:.1f}s — {len(chains)} chains", "⛓️")
    _log(f"  Output: {output_dir}", "📤")
    _log("", "=")

    (output_dir / "COMPLETE").write_text(
        f"Completed at {_now_iso()}\n"
        f"Raw findings: {len(findings)}\n"
        f"New to ledger: {deduplicated_count}\n"
        f"Chains: {len(chains)}\n",
        encoding="utf-8"
    )

    if logger is not None:
        try:
            logger.finish(success=True)
        except Exception:
            pass

    _safe_log_span(logger, "tool", "COMPLETE", f"deep_dive {program}",
                   tool_name="apk_deep_dive", tool_category="apk", target=program,
                   params={"max_surfaces": args.max_surfaces},
                   result={"raw_findings": len(findings), "new_to_ledger": deduplicated_count,
                           "chains": len(chains), "output": str(output_dir)},
                   success=True)


if __name__ == "__main__":
    main()
