"""Generic AppMap/research hypothesis generation helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents.appmap_research import sanitize_key

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class HypothesisOptions:
    category: str
    max_hypotheses: int | None = None
    surface_kinds: tuple[str, ...] = ()
    require_appmap_ref: bool = False
    include_low_confidence: bool = False


@dataclass(frozen=True)
class HypothesisResult:
    hypotheses: list[dict[str, Any]]
    report: str
    brainstorm_spec: str | None
    summary: dict[str, Any]


def generate_hypotheses(
    *,
    campaign_root: Path,
    appmap_run_root: Path,
    manifest: dict[str, Any],
    seed_path: Path,
    options: HypothesisOptions,
    brainstorm_spec: bool = False,
) -> HypothesisResult:
    seed = _read_seed(seed_path)
    appmap = _read_appmap_run(appmap_run_root)
    category = options.category or _default_category(manifest, seed)
    target_keys = _target_keys(appmap.target_profile, manifest)
    surface_filter = {sanitize_key(item, fallback="") for item in options.surface_kinds if sanitize_key(item, fallback="")}

    candidates = _candidate_rows(appmap.candidates, surface_filter)
    hypotheses = _hypotheses_from_candidates(candidates, seed, appmap, category, target_keys)
    if options.include_low_confidence:
        hypotheses.extend(_hypotheses_from_surfaces(appmap.surfaces, seed, appmap, category, target_keys, surface_filter))

    hypotheses = _dedupe_hypotheses(hypotheses)
    if options.require_appmap_ref:
        hypotheses = [
            item
            for item in hypotheses
            if item.get("appmap_candidate_refs") or item.get("appmap_surface_refs")
        ]
    if not options.include_low_confidence:
        hypotheses = [item for item in hypotheses if float(item.get("confidence") or 0.0) >= 0.45]

    hypotheses = sorted(
        hypotheses,
        key=lambda item: (
            -float(item.get("confidence") or 0.0),
            str(item.get("category") or ""),
            str(item.get("mapping_signature") or ""),
            str(item.get("id") or ""),
        ),
    )
    if options.max_hypotheses is not None:
        hypotheses = hypotheses[: max(0, options.max_hypotheses)]
    hypotheses = [_with_stable_id(item, index) for index, item in enumerate(hypotheses, start=1)]

    summary = {
        "schema_version": SCHEMA_VERSION,
        "campaign_root": str(campaign_root),
        "appmap_run_root": str(appmap_run_root),
        "category": category,
        "candidate_count": len(appmap.candidates),
        "surface_count": len(appmap.surfaces),
        "hypothesis_count": len(hypotheses),
        "surface_filter": sorted(surface_filter),
        "network_access": False,
    }
    report = render_hypothesis_report(hypotheses, seed=seed, appmap=appmap, summary=summary)
    spec = render_brainstorm_spec(hypotheses, seed=seed, appmap=appmap, summary=summary, manifest=manifest) if brainstorm_spec else None
    return HypothesisResult(hypotheses=hypotheses, report=report, brainstorm_spec=spec, summary=summary)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def render_hypothesis_report(
    hypotheses: list[dict[str, Any]],
    *,
    seed: dict[str, Any],
    appmap: "_AppMapRun",
    summary: dict[str, Any],
) -> str:
    lines = [
        "# AppMap Research Hypotheses",
        "",
        f"- Category: {summary['category']}",
        f"- AppMap run: {summary['appmap_run_root']}",
        f"- Candidates read: {summary['candidate_count']}",
        f"- Surfaces read: {summary['surface_count']}",
        f"- Hypotheses emitted: {summary['hypothesis_count']}",
        "- Network access: false",
        "",
        "## Validated Research",
    ]
    sources = _dict_rows(seed.get("sources"))
    techniques = _dict_rows(seed.get("technique_packs") or seed.get("techniques"))
    if sources:
        for source in sources[:20]:
            source_id = _identifier(source, "S")
            title = _text(source.get("title") or source.get("name") or source_id)
            url = _text(source.get("url") or source.get("local_path") or "")
            suffix = f" - {url}" if url else ""
            lines.append(f"- {source_id}: {title}{suffix}")
    else:
        lines.append("- No validated sources were available.")
    lines.append("")
    if techniques:
        lines.append("## Technique Packs")
        for technique in techniques[:20]:
            technique_id = _identifier(technique, "T")
            title = _text(technique.get("title") or technique.get("name") or technique_id)
            surfaces = ", ".join(_string_list(technique.get("applicable_surface_kinds") or technique.get("surface_kinds"))) or "-"
            lines.append(f"- {technique_id}: {title} (surfaces: {surfaces})")
        lines.append("")
    lines.append("## Hypotheses")
    if not hypotheses:
        lines.extend(
            [
                "No hypotheses were generated.",
                "",
                "Likely gaps: no AppMap candidates matched the validated technique packs, surface filters removed all candidates, or the AppMap run lacks candidate evidence.",
                "",
            ]
        )
        return "\n".join(lines)
    for item in hypotheses:
        lines.extend(
            [
                f"### {item['id']} - {item['title']}",
                f"- Category: {item['category']}",
                f"- Confidence: {item['confidence']}",
                f"- Source: {item['source']}",
                f"- Boundary: {item['boundary']}",
                f"- Flow: {item['flow']}",
                f"- Sink: {item['sink']}",
                f"- AppMap candidates: {', '.join(item['appmap_candidate_refs']) or '-'}",
                f"- AppMap surfaces: {', '.join(item['appmap_surface_refs']) or '-'}",
                f"- Research refs: {', '.join(item['research_refs']) or '-'}",
                f"- Technique packs: {', '.join(item['technique_pack_refs']) or '-'}",
                f"- Focus files: {', '.join(item['focus_files']) or '-'}",
                f"- Suggested agents: {', '.join(item['suggested_agents']) or '-'}",
                f"- Agent prompt: {item['agent_prompt']}",
                f"- Gaps: {', '.join(item['gaps']) or '-'}",
                f"- Mapping signature: {item['mapping_signature']}",
                "",
            ]
        )
    return "\n".join(lines)


def render_brainstorm_spec(
    hypotheses: list[dict[str, Any]],
    *,
    seed: dict[str, Any],
    appmap: "_AppMapRun",
    summary: dict[str, Any],
    manifest: dict[str, Any],
) -> str:
    program = _text(manifest.get("program") or appmap.target_profile.get("program") or "appmap-target")
    run_id = _text(appmap.manifest.get("run_id") or Path(summary["appmap_run_root"]).name)
    target_kind = _text(appmap.target_profile.get("target_kind") or manifest.get("target_kind") or "auto")
    source_count = len(_dict_rows(seed.get("sources")))
    technique_count = len(_dict_rows(seed.get("technique_packs") or seed.get("techniques")))
    lines = [
        f"# {program} AppMap Research Hypotheses",
        "",
        "## Metadata",
        f"- Program: {program}",
        "- Family: appmap",
        "- Lane: research-hypothesis",
        f"- Target kind: {target_kind}",
        "- Target path: .",
        "- Status: active",
        f"- AppMap run id: {run_id}",
        f"- AppMap run root: {summary['appmap_run_root']}",
        f"- Category: {summary['category']}",
        "",
        "## Target mental model",
        f"Validated local research ({source_count} sources, {technique_count} technique packs) was joined with AppMap candidate and surface artifacts. No network calls or target execution were performed.",
        "",
    ]
    if appmap.architecture.strip():
        lines.extend(["## AppMap architecture excerpt", appmap.architecture.strip()[:1200], ""])
    lines.extend(
        [
            "## Hypotheses",
        ]
    )
    for index, item in enumerate(hypotheses, start=1):
        hid = f"H{index:03d}"
        evidence = [*(f"appmap-{ref}" for ref in item["appmap_candidate_refs"]), *(f"appmap-{ref}" for ref in item["appmap_surface_refs"])]
        evidence.extend(f"research:{ref}" for ref in item["research_refs"])
        evidence.extend(f"research-technique:{ref}" for ref in item["technique_pack_refs"])
        lines.extend(
            [
                f"### {hid} - {item['title']}",
                item["agent_prompt"],
                "- Status: untested",
                "- Priority: high" if float(item["confidence"]) >= 0.75 else "- Priority: medium",
                f"- Surface: {item['category']}",
                f"- Entry point: {item['source']}",
                f"- Expected chain: {item['flow']}",
                "- Suggested agents:",
                *[f"  - {agent}" for agent in item["suggested_agents"]],
                "- Focus files:",
                *[f"  - {path}" for path in item["focus_files"]],
                f"- Tags: {', '.join(_tags_for(item))}",
                "- Evidence:",
                *[f"  - {ref}" for ref in evidence],
                f"- Notes: Original hypothesis {item['id']}; {item['why_relevant']} Gaps: {', '.join(item['gaps']) or '-'}; mapping_signature={item['mapping_signature']}",
                "",
            ]
        )
    lines.extend(
        [
            "## Coverage log",
            "| Hypothesis | Agent | Status | Result | Linked FIDs | Run ID | Notes |",
            "|---|---|---|---|---|---|---|",
            "",
        ]
    )
    return "\n".join(lines)


@dataclass(frozen=True)
class _AppMapRun:
    root: Path
    manifest: dict[str, Any]
    candidates: list[dict[str, Any]]
    surfaces: list[dict[str, Any]]
    target_profile: dict[str, Any]
    architecture: str


def _read_appmap_run(root: Path) -> _AppMapRun:
    if not root.exists() or not root.is_dir():
        raise ValueError(f"--appmap-run must be an existing directory: {root}")
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"--appmap-run is missing manifest.json: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"failed to parse AppMap manifest {manifest_path}: {exc.msg}") from exc
    if not isinstance(manifest, dict):
        raise ValueError(f"AppMap manifest must be a JSON object: {manifest_path}")
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), dict) else {}
    candidates_path = _artifact_path(root, artifacts, "candidates", "candidates.jsonl")
    surfaces_path = _artifact_path(root, artifacts, "surfaces", "surfaces.jsonl")
    target_profile_path = _artifact_path(root, artifacts, "target_profile", "target_profile.json")
    architecture_path = _artifact_path(root, artifacts, "architecture", "architecture.md")
    candidates = _read_jsonl(candidates_path)
    surfaces = _read_jsonl(surfaces_path)
    if not candidates_path.is_file() and not surfaces_path.is_file():
        raise ValueError(
            "AppMap run must contain at least one candidate or surface artifact "
            f"({candidates_path} or {surfaces_path})"
        )
    return _AppMapRun(
        root=root,
        manifest=manifest,
        candidates=candidates,
        surfaces=surfaces,
        target_profile=_read_json(target_profile_path, default={}),
        architecture=architecture_path.read_text(encoding="utf-8") if architecture_path.is_file() else "",
    )


def _artifact_path(root: Path, artifacts: dict[str, Any], key: str, default: str) -> Path:
    value = artifacts.get(key) or default
    relpath = Path(str(value))
    if relpath.is_absolute():
        raise ValueError(f"AppMap manifest artifact {key!r} must be relative: {value}")
    if any(part == ".." for part in relpath.parts):
        raise ValueError(f"AppMap manifest artifact {key!r} must not contain '..': {value}")
    root_resolved = root.resolve(strict=True)
    path = (root / relpath).resolve(strict=False)
    try:
        path.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"AppMap manifest artifact {key!r} escapes --appmap-run: {value}") from exc
    return path


def _read_seed(path: Path) -> dict[str, Any]:
    payload = _read_json(path, default={"sources": [], "technique_packs": []})
    if isinstance(payload, list):
        sources: list[dict[str, Any]] = []
        techniques: list[dict[str, Any]] = []
        for row in payload:
            if not isinstance(row, dict):
                continue
            row_type = str(row.get("type") or row.get("record_type") or "").strip()
            if row_type == "source":
                sources.append(row)
            elif row_type in {"technique", "technique_pack"} or "vulnerability_pack" in row:
                techniques.append(row)
        return {"sources": sources, "technique_packs": techniques}
    return payload if isinstance(payload, dict) else {"sources": [], "technique_packs": []}


def _read_json(path: Path, *, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"failed to parse JSON artifact {path}: {exc.msg}") from exc


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"failed to parse JSONL artifact {path} line {line_number}: {exc.msg}") from exc
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _candidate_rows(candidates: list[dict[str, Any]], surface_filter: set[str]) -> list[dict[str, Any]]:
    rows = [item for item in candidates if isinstance(item, dict)]
    if not surface_filter:
        return rows
    return [item for item in rows if _candidate_kind_keys(item) & surface_filter]


def _hypotheses_from_candidates(
    candidates: list[dict[str, Any]],
    seed: dict[str, Any],
    appmap: _AppMapRun,
    category: str,
    target_keys: set[str],
) -> list[dict[str, Any]]:
    techniques = _dict_rows(seed.get("technique_packs") or seed.get("techniques"))
    sources_by_id = {_identifier(source, "S"): source for source in _dict_rows(seed.get("sources"))}
    hypotheses: list[dict[str, Any]] = []
    for candidate in candidates:
        matching_techniques = [
            technique
            for technique in techniques
            if _technique_matches(technique, category=category, target_keys=target_keys, surface_kinds=_candidate_kind_keys(candidate))
        ]
        if not matching_techniques:
            continue
        hint = _chain_hint(candidate)
        technique_ids = [_identifier(item, "T") for item in matching_techniques]
        research_refs = _research_refs(matching_techniques, sources_by_id)
        source = candidate.get("source") if isinstance(candidate.get("source"), dict) else {}
        boundary = candidate.get("boundary") if isinstance(candidate.get("boundary"), dict) else {}
        transform = candidate.get("transform") if isinstance(candidate.get("transform"), dict) else {}
        sink = candidate.get("sink") if isinstance(candidate.get("sink"), dict) else {}
        focus_files = _focus_files(candidate)
        appmap_surface_refs = _surface_refs(candidate)
        appmap_candidate_refs = [_explicit_identifier(candidate)] if _explicit_identifier(candidate) else []
        confidence = _confidence(candidate, matching_techniques, hint)
        signature = _mapping_signature(category, candidate, technique_ids, hint["key"])
        hypotheses.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": "",
                "status": "draft",
                "category": _category_name(category, hint),
                "title": hint["title"],
                "source": hint["source"] or _surface_label(source),
                "boundary": hint["boundary"] or _surface_label(boundary),
                "flow": hint["flow"] or _flow_label(source, boundary, transform, sink),
                "sink": hint["sink"] or _surface_label(sink),
                "why_relevant": _why_relevant(hint, matching_techniques),
                "appmap_refs": [*(f"candidate:{ref}" for ref in appmap_candidate_refs), *(f"surface:{ref}" for ref in appmap_surface_refs)],
                "appmap_surface_refs": appmap_surface_refs,
                "appmap_candidate_refs": appmap_candidate_refs,
                "research_refs": research_refs,
                "source_ids": research_refs,
                "technique_pack_refs": technique_ids,
                "focus_files": focus_files,
                "suggested_agents": [_agent_key(appmap, category, hint, candidate)],
                "agent_prompt": _agent_prompt(hint, candidate, matching_techniques),
                "confidence": confidence,
                "gaps": _gaps(hint, candidate),
                "mapping_signature": signature,
            }
        )
    return hypotheses


def _hypotheses_from_surfaces(
    surfaces: list[dict[str, Any]],
    seed: dict[str, Any],
    appmap: _AppMapRun,
    category: str,
    target_keys: set[str],
    surface_filter: set[str],
) -> list[dict[str, Any]]:
    techniques = _dict_rows(seed.get("technique_packs") or seed.get("techniques"))
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for surface in surfaces:
        if not isinstance(surface, dict):
            continue
        kind = sanitize_key(str(surface.get("kind") or ""), fallback="")
        if not kind or (surface_filter and kind not in surface_filter):
            continue
        by_kind.setdefault(kind, []).append(surface)
    hypotheses: list[dict[str, Any]] = []
    for kind, kind_surfaces in sorted(by_kind.items()):
        matching_techniques = [
            technique
            for technique in techniques
            if _technique_matches(technique, category=category, target_keys=target_keys, surface_kinds={kind})
        ]
        if not matching_techniques:
            continue
        first = sorted(kind_surfaces, key=lambda item: (_text(item.get("file")), int(item.get("line") or 0), _identifier(item, "S")))[0]
        pseudo_candidate = {"id": f"SURFACE-{_identifier(first, 'S')}", "source": first, "boundary": {}, "transform": {}, "sink": first, "score": 0.3}
        hint = _chain_hint(pseudo_candidate)
        technique_ids = [_identifier(item, "T") for item in matching_techniques]
        surface_ref = _explicit_identifier(first)
        hypotheses.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": "",
                "status": "draft",
                "category": _category_name(category, hint),
                "title": f"Review {kind} surface against validated {category} techniques",
                "source": _surface_label(first),
                "boundary": "No complete AppMap candidate boundary was observed.",
                "flow": f"{kind} surface requires manual source/boundary/sink completion",
                "sink": _surface_label(first),
                "why_relevant": _why_relevant(hint, matching_techniques),
                "appmap_refs": [f"surface:{surface_ref}"] if surface_ref else [],
                "appmap_surface_refs": [surface_ref] if surface_ref else [],
                "appmap_candidate_refs": [],
                "research_refs": _research_refs(matching_techniques, {_identifier(source, 'S'): source for source in _dict_rows(seed.get("sources"))}),
                "source_ids": _research_refs(matching_techniques, {_identifier(source, 'S'): source for source in _dict_rows(seed.get("sources"))}),
                "technique_pack_refs": technique_ids,
                "focus_files": [_text(first.get("file")) or "."],
                "suggested_agents": [_agent_key(appmap, category, hint, pseudo_candidate)],
                "agent_prompt": f"Manually inspect the {kind} AppMap surface and determine whether validated {category} research describes a reachable chain from attacker-controlled input to impact.",
                "confidence": 0.35,
                "gaps": ["No complete AppMap candidate chain was available for this surface."],
                "mapping_signature": _mapping_signature(category, pseudo_candidate, technique_ids, f"surface-{kind}"),
            }
        )
    return hypotheses


def _technique_matches(
    technique: dict[str, Any],
    *,
    category: str,
    target_keys: set[str],
    surface_kinds: set[str],
) -> bool:
    applies_to_all = _bool_value(technique.get("applies_to_all"))
    vuln_pack = sanitize_key(str(technique.get("vulnerability_pack") or technique.get("focus") or ""), fallback="")
    category_key = sanitize_key(category, fallback="")
    if category_key and vuln_pack and category_key != vuln_pack and vuln_pack not in category_key and category_key not in vuln_pack:
        searchable = " ".join(
            [
                str(technique.get("id") or ""),
                str(technique.get("title") or ""),
                str(technique.get("summary") or ""),
                " ".join(_string_list(technique.get("categories"))),
            ]
        )
        if category_key not in sanitize_key(searchable, fallback=""):
            return False
    target_pack_keys = {sanitize_key(item, fallback="") for item in _string_list(technique.get("target_pack_keys") or technique.get("target_packs"))}
    if not applies_to_all and target_pack_keys and not (target_pack_keys & target_keys):
        return False
    applicable = {sanitize_key(item, fallback="") for item in _string_list(technique.get("applicable_surface_kinds") or technique.get("surface_kinds"))}
    if not applies_to_all and applicable and not (applicable & surface_kinds):
        return False
    return True


def _chain_hint(candidate: dict[str, Any]) -> dict[str, str]:
    kinds = _candidate_kind_keys(candidate)
    source_kind = _kind(candidate.get("source"))
    sink_kind = _kind(candidate.get("sink"))
    if source_kind in {"config", "config-file"} and sink_kind == "process-exec":
        return {
            "key": "config-to-exec",
            "title": "Config-controlled value may reach process execution or unsafe loader",
            "source": "attacker-influenced config, project file, environment, or update metadata",
            "boundary": "config parse/load and sanitization boundary before privileged executor or loader code",
            "flow": "config load -> validation/sanitization check -> command, argv, environment, working directory, or DLL/library load decision -> executor",
            "sink": "process execution, updater/installer launch, unsafe load path, or DLL search-order hijack primitive",
            "why": "config-to-exec chains often hinge on whether config values are normalized before executor, loader, or DLL search-path decisions.",
            "prompt": "Trace config parsing, sanitization, load-path construction, executor arguments, environment/cwd control, and DLL hijack or unsafe loader opportunities.",
        }
    if source_kind == "ipc" and sink_kind in {"process-exec", "dynamic-code"}:
        return {
            "key": "ipc-to-exec",
            "title": "IPC-controlled message may reach an executor or code-evaluation sink",
            "source": "renderer, plugin, local client, or lower-privilege process IPC input",
            "boundary": "IPC authorization, sender/origin validation, schema validation, and dispatch boundary",
            "flow": "IPC message -> handler/schema boundary -> privileged method dispatch -> executor or dynamic code sink",
            "sink": "process execution or dynamic-code evaluation reachable from privileged IPC handling",
            "why": "IPC-to-exec chains require careful review of sender trust, schema enforcement, and privileged dispatch.",
            "prompt": "Trace IPC sender/origin validation, message schema checks, dispatch tables, and whether attacker-controlled fields influence executor or dynamic-code arguments.",
        }
    if "dynamic-code" in kinds:
        return {
            "key": "dynamic-code",
            "title": "Mapped input may reach dynamic code evaluation",
            "source": "mapped attacker-controlled or lower-trust input",
            "boundary": "parser, template, expression, script, or policy boundary before evaluation",
            "flow": "input -> parser/transform boundary -> dynamic code evaluation",
            "sink": "eval, Function, template execution, script compiler, or equivalent dynamic-code sink",
            "why": "dynamic-code sinks are high-impact when input is insufficiently constrained to a safe expression language.",
            "prompt": "Determine whether the mapped input can alter evaluated code, template bodies, expressions, globals, or imported modules.",
        }
    if "unsafe-deserialization" in kinds or "deserialization" in kinds:
        return {
            "key": "deserialization",
            "title": "Mapped input may reach unsafe deserialization",
            "source": "serialized data, request body, cache entry, file import, or message payload",
            "boundary": "type validation, signature, allowlist, or parser boundary before object reconstruction",
            "flow": "serialized input -> validation boundary -> deserializer -> gadget-capable object or code path",
            "sink": "unsafe deserialization with gadget execution, object injection, or privileged method invocation",
            "why": "deserialization chains depend on whether trusted type/signature checks happen before object reconstruction.",
            "prompt": "Review type allowlists, signatures, parser mode, class/gadget availability, and whether untrusted serialized data reaches the deserializer.",
        }
    if kinds & {"protocol", "custom-scheme", "shell-open", "file-path"}:
        return {
            "key": "path-protocol-open",
            "title": "Path, protocol, or shell-open surface may cross a trust boundary",
            "source": "URL, custom scheme, file path, dropped file, import/export path, or navigation input",
            "boundary": "scheme allowlist, canonicalization, path normalization, and OS handler boundary",
            "flow": "path or URL input -> normalization/allowlist boundary -> protocol, file, shell, or navigation sink",
            "sink": "shell.openExternal/openPath, custom protocol handler, file read/write, launcher, or OS scheme handler",
            "why": "path and protocol chains often fail through canonicalization mistakes, custom scheme confusion, or unsafe OS handler launches.",
            "prompt": "Inspect URL/scheme parsing, path canonicalization, allowlists, shell-open calls, custom protocol handlers, and file read/write destinations.",
        }
    if kinds & {"auth", "session", "cookie", "token"}:
        return {
            "key": "auth-session",
            "title": "Mapped auth or session surface may cross a privilege boundary",
            "source": "token, cookie, session state, account identifier, or auth callback input",
            "boundary": "authentication, authorization, tenant, sender, or session binding boundary",
            "flow": "auth/session input -> trust or ownership boundary -> privileged action or sensitive state",
            "sink": "session mutation, token use, privileged account action, or cross-user data access",
            "why": "auth/session chains depend on whether identity and ownership checks are preserved across boundaries.",
            "prompt": "Trace session binding, token origin, ownership checks, tenant scoping, and any privileged action reachable after the mapped boundary.",
        }
    return {
        "key": f"{source_kind or 'source'}-to-{sink_kind or 'sink'}",
        "title": "Mapped AppMap candidate may form a validated research chain",
        "source": "",
        "boundary": "",
        "flow": "",
        "sink": "",
        "why": "validated research and AppMap evidence overlap on the mapped surface kinds.",
        "prompt": "Trace the mapped source through boundary and transform evidence into the sink, then verify exploitability preconditions from the validated technique packs.",
    }


def _confidence(candidate: dict[str, Any], techniques: list[dict[str, Any]], hint: dict[str, str]) -> float:
    candidate_score = float(candidate.get("score") or candidate.get("confidence") or 0.5)
    trust_scores = [float(item.get("trust_score")) for item in techniques if isinstance(item.get("trust_score"), int | float)]
    research_score = sum(trust_scores) / len(trust_scores) if trust_scores else 0.7
    hint_bonus = 0.05 if hint["key"] in {"config-to-exec", "ipc-to-exec", "dynamic-code", "deserialization", "path-protocol-open"} else 0.0
    return round(max(0.0, min(0.98, candidate_score * 0.78 + research_score * 0.17 + hint_bonus)), 2)


def _candidate_kind_keys(candidate: dict[str, Any]) -> set[str]:
    kinds: set[str] = set()
    for key in ("source", "boundary", "transform", "sink"):
        value = candidate.get(key)
        if isinstance(value, dict):
            kind = sanitize_key(str(value.get("kind") or ""), fallback="")
            if kind:
                kinds.add(kind)
            role = sanitize_key(str(value.get("role") or ""), fallback="")
            if role:
                kinds.add(role)
    return kinds


def _target_keys(target_profile: dict[str, Any], manifest: dict[str, Any]) -> set[str]:
    values: list[str] = [
        str(target_profile.get("target_kind") or ""),
        str(manifest.get("target_kind") or ""),
        str(manifest.get("focus") or ""),
    ]
    for key in ("detected_kinds", "frameworks", "languages", "target_pack_keys"):
        value = target_profile.get(key)
        if isinstance(value, dict):
            values.extend(str(item) for item in value.keys())
        else:
            values.extend(_string_list(value))
    return {sanitize_key(item, fallback="") for item in values if sanitize_key(item, fallback="")}


def _research_refs(techniques: list[dict[str, Any]], sources_by_id: dict[str, dict[str, Any]]) -> list[str]:
    refs: list[str] = []
    for technique in techniques:
        refs.extend(_string_list(technique.get("source_ids") or technique.get("sources")))
    return sorted({ref for ref in refs if ref in sources_by_id or ref})


def _surface_refs(candidate: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ("source", "boundary", "transform", "sink"):
        surface = candidate.get(key)
        if isinstance(surface, dict):
            ref = _explicit_identifier(surface)
            if ref:
                refs.append(ref)
    return list(dict.fromkeys(refs))


def _focus_files(candidate: dict[str, Any]) -> list[str]:
    files: set[str] = set()
    for key in ("source", "boundary", "transform", "sink"):
        surface = candidate.get(key)
        if isinstance(surface, dict) and str(surface.get("file") or "").strip():
            files.add(str(surface["file"]))
    return sorted(files)[:8] or ["."]


def _mapping_signature(category: str, candidate: dict[str, Any], technique_ids: list[str], hint_key: str) -> str:
    parts = [
        sanitize_key(category, fallback="category"),
        hint_key,
        _identifier(candidate, "C"),
        _kind(candidate.get("source")),
        _kind(candidate.get("boundary")),
        _kind(candidate.get("transform")),
        _kind(candidate.get("sink")),
        ",".join(sorted(technique_ids)),
    ]
    raw = "|".join(parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]
    return f"{sanitize_key(raw, fallback='mapping')[:90]}-{digest}"


def _dedupe_hypotheses(hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for item in hypotheses:
        signature = str(item.get("mapping_signature") or "")
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(item)
    return unique


def _with_stable_id(item: dict[str, Any], index: int) -> dict[str, Any]:
    copied = dict(item)
    copied["id"] = f"HYP{index:03d}"
    return copied


def _category_name(category: str, hint: dict[str, str]) -> str:
    base = sanitize_key(category, fallback="vulnerability")
    hint_key = sanitize_key(hint["key"], fallback="")
    return f"{base}-{hint_key}" if hint_key and hint_key not in base else base


def _agent_key(appmap: _AppMapRun, category: str, hint: dict[str, str], candidate: dict[str, Any]) -> str:
    program = sanitize_key(str(appmap.target_profile.get("program") or appmap.manifest.get("program") or "appmap"), fallback="appmap")
    candidate_id = sanitize_key(_identifier(candidate, "C"), fallback="candidate").lower()
    return sanitize_key(f"{program}-{category}-{hint['key']}-{candidate_id}", fallback="appmap-hypothesis")[:96]


def _agent_prompt(hint: dict[str, str], candidate: dict[str, Any], techniques: list[dict[str, Any]]) -> str:
    technique_titles = "; ".join(_text(item.get("title") or item.get("id")) for item in techniques[:3])
    base = hint.get("prompt") or "Trace the mapped chain and verify exploitability preconditions."
    flow = _flow_label(
        candidate.get("source") if isinstance(candidate.get("source"), dict) else {},
        candidate.get("boundary") if isinstance(candidate.get("boundary"), dict) else {},
        candidate.get("transform") if isinstance(candidate.get("transform"), dict) else {},
        candidate.get("sink") if isinstance(candidate.get("sink"), dict) else {},
    )
    return f"{base} AppMap mapped: {flow}. Validated techniques: {technique_titles or '-'}."


def _why_relevant(hint: dict[str, str], techniques: list[dict[str, Any]]) -> str:
    summaries = " ".join(_text(item.get("summary")) for item in techniques[:3] if _text(item.get("summary")))
    return f"{hint.get('why') or 'AppMap and validated research overlap.'} {summaries}".strip()


def _gaps(hint: dict[str, str], candidate: dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    if not candidate.get("source"):
        gaps.append("Need a concrete attacker-controlled source.")
    if not candidate.get("boundary"):
        gaps.append("Need boundary validation details.")
    if hint["key"] == "config-to-exec":
        gaps.append("Need proof config values control command, path, argv, env, cwd, or loader/DLL search behavior.")
    elif hint["key"] == "ipc-to-exec":
        gaps.append("Need method-level sender/origin/schema validation review.")
    elif hint["key"] == "path-protocol-open":
        gaps.append("Need canonicalization and scheme/path allowlist review.")
    return gaps


def _flow_label(source: dict[str, Any], boundary: dict[str, Any], transform: dict[str, Any], sink: dict[str, Any]) -> str:
    parts = [_surface_kind_label(source, "source"), _surface_kind_label(boundary, "boundary")]
    if transform:
        parts.append(_surface_kind_label(transform, "transform"))
    parts.append(_surface_kind_label(sink, "sink"))
    return " -> ".join(part for part in parts if part)


def _surface_kind_label(surface: dict[str, Any], fallback: str) -> str:
    if not surface:
        return fallback
    return f"{surface.get('kind') or fallback} {fallback}"


def _surface_label(surface: dict[str, Any]) -> str:
    if not surface:
        return "unknown"
    location = f"{surface.get('file')}:{surface.get('line')}" if surface.get("file") and surface.get("line") else _text(surface.get("file") or "")
    kind = _text(surface.get("kind") or surface.get("role") or "surface")
    desc = _text(surface.get("description") or surface.get("name") or "")
    suffix = f" ({location})" if location else ""
    return f"{kind}{suffix}: {desc}".strip(": ")


def _tags_for(item: dict[str, Any]) -> list[str]:
    tags = ["appmap", "research-hypothesis", sanitize_key(str(item.get("category") or ""), fallback="category")]
    tags.extend(sanitize_key(ref, fallback="") for ref in item.get("technique_pack_refs") or [])
    return [tag for tag in dict.fromkeys(tags) if tag]


def _default_category(manifest: dict[str, Any], seed: dict[str, Any]) -> str:
    categories = _string_list(manifest.get("category"))
    if categories:
        return categories[0]
    focus = _text(manifest.get("focus"))
    if focus:
        return focus
    techniques = _dict_rows(seed.get("technique_packs") or seed.get("techniques"))
    for technique in techniques:
        if _text(technique.get("vulnerability_pack")):
            return _text(technique["vulnerability_pack"])
    return "vulnerability"


def _identifier(row: dict[str, Any], fallback_prefix: str) -> str:
    value = str(row.get("id") or row.get("key") or row.get("source_id") or row.get("technique_id") or "").strip()
    if value:
        return value
    digest = hashlib.sha1(json.dumps(row, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:8]
    return f"{fallback_prefix}{digest}"


def _explicit_identifier(row: dict[str, Any]) -> str:
    return str(row.get("id") or row.get("key") or row.get("source_id") or row.get("technique_id") or "").strip()


def _kind(value: Any) -> str:
    return sanitize_key(str(value.get("kind") or ""), fallback="") if isinstance(value, dict) else ""


def _text(value: Any) -> str:
    return str(value or "").strip()


def _dict_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


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
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}
