#!/usr/bin/env python3
"""Build offline JavaScript fanout campaigns for zero_day_team.

This adapter keeps /js responsible for JavaScript-specific inventory and packet
shaping, then hands a local, no-network campaign to zero_day_team through a
generated brainstorm spec.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
MAPSTORE_CANDIDATES_FILENAME = "mapstore_candidates.jsonl"
MAPSTORE_CANDIDATE_SCHEMA_FILENAME = "mapstore_candidate_schema.json"


@dataclass(frozen=True)
class JsOfflineLane:
    key: str
    title: str
    surface: str
    tags: tuple[str, ...]
    priority: str
    purpose: str
    expected_chain: str
    trigger_hints: tuple[str, ...] = ()


LANES: tuple[JsOfflineLane, ...] = (
    JsOfflineLane(
        key="general-map",
        title="Class-agnostic JavaScript cartography",
        surface="js-application-map",
        tags=("js", "cartography", "routes", "trust-boundaries"),
        priority="high",
        purpose="Map app areas, routes, request builders, objects, trust boundaries, hidden state, feature flags, and integrations without committing to one vuln class.",
        expected_chain="JS packet evidence -> app/flow/trust-boundary map -> specialist routing and synthesis",
    ),
    JsOfflineLane(
        key="request-shape",
        title="Request builder and endpoint shape review",
        surface="js-request-shape",
        tags=("js", "request-shape", "endpoints", "graphql"),
        priority="high",
        purpose="Extract API clients, request builders, headers, content types, GraphQL operations, route templates, and request fields for endpoint-analysis handoffs.",
        expected_chain="JS request builder -> endpoint contract or object/action field -> scoped follow-up handoff",
        trigger_hints=("graphql", "request"),
    ),
    JsOfflineLane(
        key="dom-xss",
        title="DOM source-to-sink review",
        surface="js-dom-xss",
        tags=("js", "dom-xss", "sources", "sinks"),
        priority="high",
        purpose="Trace URL/hash/search/storage/message/form/bootstrap state into DOM writes, script creation, navigation, template rendering, or eval-like sinks.",
        expected_chain="attacker-controlled browser source -> transform/check -> DOM/script/navigation sink -> browser proof hypothesis",
        trigger_hints=("dom_write", "script_create", "navigation", "eval", "location", "storage", "message"),
    ),
    JsOfflineLane(
        key="access-control",
        title="Client-visible authorization and role assumptions",
        surface="js-access-control",
        tags=("js", "access-control", "roles", "permissions"),
        priority="high",
        purpose="Inspect role, permission, admin, team, tenant, workspace, entitlement, invite, and ownership logic for server-enforced boundary questions.",
        expected_chain="client-visible authorization object or gate -> server request/flow -> owned-account access-control hypothesis",
        trigger_hints=("access_control", "object_ids"),
    ),
    JsOfflineLane(
        key="idor",
        title="Object identifier and tenant boundary review",
        surface="js-idor",
        tags=("js", "idor", "object-ids", "tenant"),
        priority="high",
        purpose="Map design/project/folder/file/media/template/comment/user/team/invoice/subscription identifiers and object-boundary assumptions.",
        expected_chain="object identifier in JS/request shape -> ownership boundary question -> controlled cross-account comparison hypothesis",
        trigger_hints=("object_ids", "access_control"),
    ),
    JsOfflineLane(
        key="auth-ato",
        title="Auth, recovery, invite, and identity-binding review",
        surface="js-auth-ato",
        tags=("js", "auth", "ato", "oauth", "session"),
        priority="high",
        purpose="Inspect login, reset, invite, OAuth/SSO/SAML, captcha/risk, session binding, identity linking, and account-change flows.",
        expected_chain="auth/session JS flow -> identity or token boundary -> ATO/password-reset/OAuth handoff",
        trigger_hints=("auth",),
    ),
    JsOfflineLane(
        key="payment",
        title="Billing and paid-entitlement review",
        surface="js-payment",
        tags=("js", "payment", "billing", "entitlements"),
        priority="medium",
        purpose="Inspect checkout, coupons, credits, invoices, subscriptions, refunds, plans, pricing, and paid entitlement object fields.",
        expected_chain="billing JS field/request -> paid state or entitlement boundary -> zero-dollar-first payment-testing hypothesis",
        trigger_hints=("payment",),
    ),
    JsOfflineLane(
        key="ssrf-import",
        title="URL importer, webhook, preview, and server-fetch review",
        surface="js-ssrf-import",
        tags=("js", "ssrf", "import", "webhook", "preview"),
        priority="medium",
        purpose="Inspect URL importers, preview/fetch resolvers, webhooks, embed/media/favicons, remote URL fields, and server-side fetch hints.",
        expected_chain="URL-like field or importer -> server-side resolver hint -> controlled SSRF/import handoff",
        trigger_hints=("server_fetch", "upload_import_export"),
    ),
    JsOfflineLane(
        key="business-logic",
        title="Workflow state and client-trust review",
        surface="js-business-logic",
        tags=("js", "business-logic", "workflow", "client-trust"),
        priority="medium",
        purpose="Inspect workflow state machines, feature gates, install/connect flows, publish/share/import/export controls, and unsafe client assumptions.",
        expected_chain="client-side workflow assumption -> server action or state transition -> business-logic hypothesis",
        trigger_hints=("feature_flag", "upload_import_export", "realtime"),
    ),
    JsOfflineLane(
        key="postmessage",
        title="postMessage and frame boundary review",
        surface="js-postmessage",
        tags=("js", "postmessage", "frames", "origin"),
        priority="medium",
        purpose="Inspect postMessage listeners/senders, origin checks, frame/embed flows, window opener relationships, and message schema trust.",
        expected_chain="message/event source -> origin/schema gate -> privileged action or data exposure hypothesis",
        trigger_hints=("message",),
    ),
    JsOfflineLane(
        key="storage-session",
        title="Browser storage, session, and bootstrap state review",
        surface="js-storage-session",
        tags=("js", "storage", "session", "bootstrap-state"),
        priority="medium",
        purpose="Inspect localStorage/sessionStorage/cookies/indexedDB, hydration globals, hidden state, and state restoration logic for trust-boundary mistakes.",
        expected_chain="stored/bootstrap value -> auth/session/UI/request influence -> controlled state-manipulation hypothesis",
        trigger_hints=("storage", "hidden_state", "auth"),
    ),
    JsOfflineLane(
        key="worker-messaging",
        title="Worker and background-message review",
        surface="js-worker-messaging",
        tags=("js", "workers", "messages", "background"),
        priority="medium",
        purpose="Inspect web workers, service workers, broadcast channels, background sync, and worker message schemas for confused trust boundaries.",
        expected_chain="worker/background message -> parser/action boundary -> controlled worker behavior hypothesis",
        trigger_hints=("realtime", "message"),
    ),
    JsOfflineLane(
        key="graphql",
        title="GraphQL operation and object-boundary review",
        surface="js-graphql",
        tags=("js", "graphql", "operations", "object-boundaries"),
        priority="medium",
        purpose="Inspect GraphQL operations, variables, fragments, mutations, object IDs, authorization fields, and hidden operation names.",
        expected_chain="GraphQL operation/variable -> object/action boundary -> endpoint-analysis or IDOR hypothesis",
        trigger_hints=("graphql",),
    ),
    JsOfflineLane(
        key="feature-flags",
        title="Feature flag, experiment, and beta-gate review",
        surface="js-feature-flags",
        tags=("js", "feature-flags", "experiments", "beta"),
        priority="medium",
        purpose="Inspect feature flags, experiments, rollout gates, beta-only controls, admin toggles, and client-visible entitlement switches.",
        expected_chain="client-visible gate/flag -> hidden action or entitlement path -> access-control/business-logic hypothesis",
        trigger_hints=("feature_flag",),
    ),
    JsOfflineLane(
        key="upload-import-export",
        title="Upload, import, export, and file-flow review",
        surface="js-upload-import-export",
        tags=("js", "upload", "import", "export", "files"),
        priority="medium",
        purpose="Inspect file upload/import/export/download/media flows, transform options, filenames, MIME/metadata fields, and server-side processing hints.",
        expected_chain="file/media JS flow -> parser/storage/transform boundary -> upload/import/export handoff",
        trigger_hints=("upload_import_export",),
    ),
    JsOfflineLane(
        key="secrets",
        title="Usable secret and integration identifier review",
        surface="js-secrets",
        tags=("js", "secrets", "tokens", "integrations"),
        priority="low",
        purpose="Inspect concrete keys, tokens, signed URLs, provider IDs, public/private config leakage, and integration pivots; downgrade generic secret words.",
        expected_chain="concrete secret-like value or integration identifier -> scope-expanding impact path -> sanitized evidence handoff",
    ),
    JsOfflineLane(
        key="cors-header-trust",
        title="Header, origin, CORS, and client trust review",
        surface="js-header-origin-trust",
        tags=("js", "cors", "headers", "origin"),
        priority="low",
        purpose="Inspect client-side origin/header assumptions, custom headers, CSRF/header names, CORS-related config, and proxy/header trust hints.",
        expected_chain="client-visible header/origin assumption -> server trust boundary -> headers/access-control hypothesis",
    ),
    JsOfflineLane(
        key="cache-state",
        title="Cache, offline state, and stale-data review",
        surface="js-cache-state",
        tags=("js", "cache", "offline", "stale-state"),
        priority="low",
        purpose="Inspect service-worker caches, local caches, stale state reuse, request caching keys, and offline behavior that may cross user or tenant boundaries.",
        expected_chain="cache/offline state key -> cross-user or stale authorization boundary -> cache/state hypothesis",
    ),
    JsOfflineLane(
        key="parser-confusion",
        title="Parser, encoding, and normalization review",
        surface="js-parser-confusion",
        tags=("js", "parser", "encoding", "normalization"),
        priority="low",
        purpose="Inspect URL/path/query/body parsers, encoders/decoders, sanitizers, schema coercion, and normalization helpers for differential behavior.",
        expected_chain="controlled encoded/typed value -> parser/normalizer boundary -> request-exploration hypothesis",
    ),
    JsOfflineLane(
        key="anomaly-hunter",
        title="Classless anomaly and weirdness review",
        surface="js-anomaly",
        tags=("js", "anomaly", "weirdness", "classless"),
        priority="high",
        purpose="Ignore vuln-class labels and hunt for surprising code, odd trust assumptions, rare modules, dead routes, debug/admin hints, custom parsers, strange state machines, and anything the classifier missed.",
        expected_chain="unexpected JS behavior or trust assumption -> new hypothesis, MapStore gadget, or specialist handoff",
    ),
)


MODE_LANES: dict[str, tuple[str, ...]] = {
    "quick": ("general-map", "request-shape", "dom-xss", "anomaly-hunter"),
    "look": (
        "general-map",
        "request-shape",
        "dom-xss",
        "access-control",
        "idor",
        "auth-ato",
        "business-logic",
        "anomaly-hunter",
    ),
    "deep": tuple(lane.key for lane in LANES),
    "full": tuple(lane.key for lane in LANES),
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"expected JSON object in {path}")
    return payload


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid JSONL in {path}:{line_no}: {exc}") from exc
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def stable_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        value = str(value or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def selected_lanes(mode: str, metadata_rows: list[dict]) -> list[JsOfflineLane]:
    lane_by_key = {lane.key: lane for lane in LANES}
    keys = list(MODE_LANES[mode])
    if mode == "look":
        hints = collect_signal_hints(metadata_rows)
        for lane in LANES:
            if lane.key in keys:
                continue
            if any(hint in hints for hint in lane.trigger_hints):
                keys.insert(-1, lane.key)
    return [lane_by_key[key] for key in stable_unique(keys)]


def collect_signal_hints(metadata_rows: list[dict]) -> set[str]:
    hints: set[str] = set()
    for row in metadata_rows:
        for field in ("flow_hints", "sources", "sinks"):
            values = row.get(field)
            if isinstance(values, list):
                hints.update(str(value) for value in values)
        if row.get("hidden_state_hints"):
            hints.add("hidden_state")
        if row.get("graphql_operations"):
            hints.add("graphql")
    return hints


def copy_packets(js_run_root: Path, target_root: Path, packet_rows: list[dict]) -> list[dict]:
    packet_target = target_root / "packets"
    packet_target.mkdir(parents=True, exist_ok=True)
    copied_rows: list[dict] = []
    for index, row in enumerate(packet_rows, 1):
        source_path = Path(str(row.get("packet_path") or "")).expanduser()
        if not source_path.is_absolute():
            source_path = js_run_root / source_path
        if not source_path.is_file():
            continue
        name = f"{index:04d}-{source_path.name}"
        dest_path = packet_target / name
        shutil.copy2(source_path, dest_path)
        copied = dict(row)
        copied["original_packet_path"] = str(source_path)
        copied["campaign_packet_path"] = str(dest_path)
        copied["campaign_packet_relpath"] = str(dest_path.relative_to(target_root.parent))
        copied_rows.append(copied)
    return copied_rows


def build_target_index(
    *,
    program: str,
    js_run_root: Path,
    target_root: Path,
    inventory_manifest: dict,
    metadata_rows: list[dict],
    copied_packets: list[dict],
) -> dict:
    index = {
        "schema": "js-offline-target.v1",
        "program": program,
        "source_js_run_root": str(js_run_root),
        "source_manifest": str(js_run_root / "manifest.json"),
        "created_at": utc_now(),
        "inventory": {
            "run_id": inventory_manifest.get("run_id"),
            "target_host": inventory_manifest.get("target_host"),
            "scope_hosts": inventory_manifest.get("scope_hosts") or [],
            "js_downloaded": inventory_manifest.get("js_downloaded"),
            "packets": inventory_manifest.get("packets"),
        },
        "metadata_rows": len(metadata_rows),
        "packet_rows": len(copied_packets),
        "packets": copied_packets,
        "source_files": {
            "metadata_jsonl": str(js_run_root / "metadata.jsonl"),
            "packets_jsonl": str(js_run_root / "packets.jsonl"),
            "provenance_jsonl": str(js_run_root / "js_provenance.jsonl"),
            "external_integrations_jsonl": str(js_run_root / "external_integrations.jsonl"),
        },
    }
    write_json(target_root / "index.json", index)
    return index


def mapstore_candidate_schema() -> dict:
    return {
        "schema": "js-offline-mapstore-candidate.v1",
        "required_fields": [
            "kind",
            "surface",
            "scope",
            "tags",
            "title",
            "body",
            "evidence_refs",
            "promote_reason",
            "dedupe_hint",
        ],
        "fields": {
            "kind": "Always mapstore_candidate.",
            "surface": "MapStore surface or JS lane, for example js/access-control.",
            "scope": "One of app, surface, or url.",
            "url": "Full URL when the observation is URL-specific; omit for app/surface scope.",
            "tags": "Search tags such as js, gadget, access-control, needs-live-validation, negative.",
            "title": "Short durable observation title.",
            "body": "Concise reusable app behavior, primitive, negative result, or validation-state note.",
            "evidence_refs": "Local packet, manifest, provenance, or report paths that support the candidate.",
            "promote_reason": "Why future agents should see this in MapStore.",
            "dedupe_hint": "Stable hint for merging similar candidates before durable MapStore promotion.",
            "linked_fids": "Optional reviewed ledger FIDs if the candidate later maps to a finding.",
        },
        "notes": [
            "Agents append proposed durable observations here; they do not write recon/maps directly.",
            "A synthesis/promoter pass dedupes these rows against MapStore before promotion.",
            "Missing MapStore matches mean the lead is new-to-current-index, not globally novel.",
        ],
    }


def create_candidate_files(campaign_root: Path) -> tuple[Path, Path]:
    candidates_path = campaign_root / MAPSTORE_CANDIDATES_FILENAME
    schema_path = campaign_root / MAPSTORE_CANDIDATE_SCHEMA_FILENAME
    candidates_path.parent.mkdir(parents=True, exist_ok=True)
    candidates_path.write_text("", encoding="utf-8")
    write_json(schema_path, mapstore_candidate_schema())
    return candidates_path, schema_path


def spec_header(
    *,
    program: str,
    campaign_root: Path,
    target_root: Path,
    mode: str,
    inventory_manifest: dict,
    mapstore_candidates_path: Path,
    mapstore_schema_path: Path,
) -> list[str]:
    target_rel = target_root.relative_to(campaign_root)
    created = datetime.now(UTC).strftime("%Y-%m-%d")
    candidates_rel = mapstore_candidates_path.relative_to(campaign_root)
    schema_rel = mapstore_schema_path.relative_to(campaign_root)
    return [
        f"# Brainstorm Spec: {program} JavaScript Offline Fanout",
        "",
        "## Metadata",
        f"- Program: {program}",
        "- Family: web_bounty",
        "- Lane: web",
        "- Target kind: web-js",
        f"- Target path: {target_rel}",
        f"- Created: {created}",
        "- Status: active",
        "- Execution mode: offline",
        "- Live requests allowed: false",
        f"- JS inventory run id: {inventory_manifest.get('run_id') or 'unknown'}",
        f"- JS offline mode: {mode}",
        f"- MapStore candidates path: {candidates_rel}",
        f"- MapStore candidate schema: {schema_rel}",
        "",
        "## Target mental model",
        "This is an offline JavaScript artifact campaign. Agents review local packet files produced by /js inventory, not the live target. "
        "The classifier accelerates routing but never excludes a class. Report concrete findings only when packet evidence is strong; otherwise produce hypotheses, MapStore gadget candidates, endpoint handoffs, or live-validation plans.",
        "",
        "MapStore is available as lazy retrieval, not mandatory prompt baggage. When your current evidence gives you a concrete URL, surface, field, or tag set, query MapStore before calling a lead a duplicate or a durable primitive. If MapStore has no match, treat the lead as unlinked/new-to-current-index and continue analysis normally; do not overclaim global novelty from a missing query result.",
        "",
        "Do not write durable MapStore entries directly. Proposed reusable app memory, gadgets, negative observations, and live-validation state should be appended as JSONL candidates to:",
        f"- {candidates_rel}",
        f"Use the schema at {schema_rel}. A later synthesis/promoter pass dedupes and promotes selected rows.",
        "",
        "## Impact primitives",
        "### P001 - Offline JavaScript packet evidence",
        "- Source: local JS inventory packets",
        "- Impact: packets can reveal routes, request builders, object boundaries, client trust assumptions, and candidate exploit chains",
        f"- Evidence: {target_rel}/index.json",
        "- Status: active",
        "",
        "## Hypotheses",
    ]


def hypothesis_block(index: int, lane: JsOfflineLane, target_rel: Path, mapstore_candidates_rel: Path) -> list[str]:
    hid = f"H{index:03d}"
    agent_key = f"js-{lane.key}"
    tags = ", ".join(lane.tags)
    return [
        f"### {hid} - {lane.title}",
        lane.purpose,
        "- Status: untested",
        f"- Priority: {lane.priority}",
        f"- Surface: {lane.surface}",
        "- Entry point: local JavaScript inventory packets and provenance generated by /js",
        f"- Expected chain: {lane.expected_chain}",
        "- Suggested agents:",
        f"  - {agent_key}",
        "- Focus files:",
        f"  - {target_rel}/index.json",
        f"  - {target_rel}/packets/*.md",
        f"- Tags: {tags}",
        "- Evidence:",
        f"  - {target_rel}/index.json",
        "- Notes: Stay offline. Do not make live requests. Preserve packet/provenance references. Specialists should stay in-lane but include unexpected off-lane primitives in a peripheral-vision field. Query MapStore lazily only when concrete evidence gives you a URL, surface, field, or tag set. Missing MapStore context means new-to-current-index, not proven globally novel. Append reusable gadget, negative-test, or live-validation memory proposals to "
        f"{mapstore_candidates_rel}; do not write durable MapStore entries directly.",
        "",
    ]


def build_spec(
    *,
    program: str,
    campaign_root: Path,
    target_root: Path,
    lanes: list[JsOfflineLane],
    mode: str,
    inventory_manifest: dict,
    mapstore_candidates_path: Path,
    mapstore_schema_path: Path,
) -> Path:
    brainstorm_dir = campaign_root / "brainstorm"
    spec_path = brainstorm_dir / "spec.md"
    target_rel = target_root.relative_to(campaign_root)
    candidates_rel = mapstore_candidates_path.relative_to(campaign_root)
    lines = spec_header(
        program=program,
        campaign_root=campaign_root,
        target_root=target_root,
        mode=mode,
        inventory_manifest=inventory_manifest,
        mapstore_candidates_path=mapstore_candidates_path,
        mapstore_schema_path=mapstore_schema_path,
    )
    for index, lane in enumerate(lanes, 1):
        lines.extend(hypothesis_block(index, lane, target_rel, candidates_rel))
    lines.extend(
        [
            "## Coverage log",
            "| Hypothesis | Agent | Status | Result | Linked FIDs | Run ID | Notes |",
            "|---|---|---|---|---|---|---|",
            "",
        ]
    )
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text("\n".join(lines), encoding="utf-8")
    return spec_path


def zero_day_command(*, program: str, target_root: Path, spec_path: Path, parallel: bool) -> list[str]:
    command = [
        sys.executable,
        str(REPO_ROOT / "agents" / "zero_day_team.py"),
        program,
        str(target_root),
        "--hunt-type",
        "web",
        "--target-kind",
        "web-js",
        "--brainstorm-spec",
        str(spec_path),
        "--brainstorm-only",
    ]
    if parallel:
        command.append("--parallel")
    return command


def shell_join(command: list[str]) -> str:
    return " ".join(sh_quote(part) for part in command)


def sh_quote(value: str) -> str:
    if not value:
        return "''"
    safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-=.,/:"
    if all(char in safe for char in value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def command_prepare(args: argparse.Namespace) -> int:
    js_run_root = Path(args.js_run_root).expanduser().resolve(strict=False)
    manifest_path = js_run_root / "manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"JS inventory manifest not found: {manifest_path}")
    inventory_manifest = read_json(manifest_path)
    program = args.program or str(inventory_manifest.get("program") or "").strip()
    if not program:
        raise SystemExit("program is required when manifest lacks program")

    metadata_rows = read_jsonl(js_run_root / "metadata.jsonl")
    packet_rows = read_jsonl(js_run_root / "packets.jsonl")
    if not packet_rows:
        raise SystemExit(f"no JS packet rows found in {js_run_root / 'packets.jsonl'}")

    campaign_root = (
        Path(args.campaign_root).expanduser().resolve(strict=False)
        if args.campaign_root
        else js_run_root / "offline_campaign"
    )
    if campaign_root.exists() and any(campaign_root.iterdir()) and not args.force:
        raise SystemExit(f"campaign root already exists and is not empty: {campaign_root} (use --force)")
    if campaign_root.exists() and args.force:
        shutil.rmtree(campaign_root)
    target_root = campaign_root / "offline_target"
    target_root.mkdir(parents=True, exist_ok=True)
    mapstore_candidates_path, mapstore_schema_path = create_candidate_files(campaign_root)

    copied_packets = copy_packets(js_run_root, target_root, packet_rows)
    if not copied_packets:
        raise SystemExit("no packet files could be copied into the offline target")
    target_index = build_target_index(
        program=program,
        js_run_root=js_run_root,
        target_root=target_root,
        inventory_manifest=inventory_manifest,
        metadata_rows=metadata_rows,
        copied_packets=copied_packets,
    )
    lanes = selected_lanes(args.mode, metadata_rows)
    spec_path = build_spec(
        program=program,
        campaign_root=campaign_root,
        target_root=target_root,
        lanes=lanes,
        mode=args.mode,
        inventory_manifest=inventory_manifest,
        mapstore_candidates_path=mapstore_candidates_path,
        mapstore_schema_path=mapstore_schema_path,
    )
    command = zero_day_command(
        program=program,
        target_root=target_root,
        spec_path=spec_path,
        parallel=not args.no_parallel,
    )
    manifest = {
        "schema": "js-offline-campaign.v1",
        "program": program,
        "mode": args.mode,
        "created_at": utc_now(),
        "execution_mode": "offline",
        "live_requests_allowed": False,
        "js_run_root": str(js_run_root),
        "campaign_root": str(campaign_root),
        "target_root": str(target_root),
        "target_index": str(target_root / "index.json"),
        "brainstorm_spec": str(spec_path),
        "mapstore_candidates": str(mapstore_candidates_path),
        "mapstore_candidate_schema": str(mapstore_schema_path),
        "lanes": [asdict(lane) for lane in lanes],
        "packet_count": len(copied_packets),
        "metadata_rows": len(metadata_rows),
        "zero_day_command": command,
        "zero_day_command_text": shell_join(command),
        "target": {
            "inventory_run_id": target_index["inventory"]["run_id"],
            "target_host": target_index["inventory"]["target_host"],
            "scope_hosts": target_index["inventory"]["scope_hosts"],
        },
    }
    write_json(campaign_root / "manifest.json", manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def command_run(args: argparse.Namespace) -> int:
    if args.js_run_root:
        prepare_args = argparse.Namespace(
            js_run_root=args.js_run_root,
            campaign_root=args.campaign_root,
            program=args.program,
            mode=args.mode,
            force=args.force,
            no_parallel=args.no_parallel,
        )
        command_prepare(prepare_args)
        campaign_root = (
            Path(args.campaign_root).expanduser().resolve(strict=False)
            if args.campaign_root
            else Path(args.js_run_root).expanduser().resolve(strict=False) / "offline_campaign"
        )
    elif args.campaign_root:
        campaign_root = Path(args.campaign_root).expanduser().resolve(strict=False)
    else:
        raise SystemExit("run requires --js-run-root or --campaign-root")
    manifest = read_json(campaign_root / "manifest.json")
    command = [str(part) for part in manifest.get("zero_day_command") or []]
    if not command:
        raise SystemExit(f"zero_day_command missing from {campaign_root / 'manifest.json'}")
    if args.execute:
        return subprocess.call(command, cwd=REPO_ROOT)
    print(shell_join(command))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build offline JS fanout campaigns for zero_day_team")
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare", help="Create offline target, brainstorm spec, and manifest")
    prepare.add_argument("--js-run-root", required=True, help="Existing js_analyzer.py inventory run root")
    prepare.add_argument("--campaign-root", help="Output campaign root. Defaults to <js-run-root>/offline_campaign")
    prepare.add_argument("--program", help="Program override if manifest lacks program")
    prepare.add_argument("--mode", choices=sorted(MODE_LANES), default="deep")
    prepare.add_argument("--force", action="store_true", help="Replace an existing campaign root")
    prepare.add_argument("--no-parallel", action="store_true", help="Do not include --parallel in the generated zero_day_team command")
    prepare.set_defaults(func=command_prepare)

    run = sub.add_parser("run", help="Print or execute the generated zero_day_team command")
    run.add_argument("--js-run-root", help="Prepare from this JS run before printing/executing")
    run.add_argument("--campaign-root", help="Existing or output campaign root")
    run.add_argument("--program", help="Program override when preparing from --js-run-root")
    run.add_argument("--mode", choices=sorted(MODE_LANES), default="deep")
    run.add_argument("--force", action="store_true", help="Replace an existing campaign root when preparing")
    run.add_argument("--no-parallel", action="store_true", help="Do not include --parallel in the generated zero_day_team command")
    run.add_argument("--execute", action="store_true", help="Actually run zero_day_team. Without this, print the command only.")
    run.set_defaults(func=command_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
