#!/usr/bin/env python3
"""Initialize canonical Shared and mounted-artifact lanes for a bounty program.

The initializer is deliberately idempotent: it creates missing directories and
front-door metadata but never removes or overwrites existing program state.
Scope is required by default; pass either ``--platform`` (to pull it) or
``--skip-scope`` (to record that the program needs a manual scope source).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# Direct execution sets sys.path to scripts/, not the harness root.
HARNESS_ROOT = Path(__file__).resolve().parents[1]
if str(HARNESS_ROOT) not in sys.path:
    sys.path.insert(0, str(HARNESS_ROOT))

from agents.scope_puller import canonical_program_slug, pull_scope
from agents.scope_seed_files import recon_seed_lines
from agents.scope_manager import ScopeManager
from agents.storage_resolver import (
    BINARIES_FAMILY,
    WEB_FAMILY,
    ensure_layout,
    normalize_program,
    resolve_storage,
)

DEFAULT_ARTIFACT_ROOT = Path(os.environ.get("BOUNTY_ARTIFACT_ROOT", "/mnt/bounty"))
LANE_FAMILIES = {
    "web": WEB_FAMILY,
    "api": WEB_FAMILY,
    "apk": BINARIES_FAMILY,
    "exe": BINARIES_FAMILY,
    "mac": BINARIES_FAMILY,
}


def _mkdirs(paths: Iterable[Path], *, dry_run: bool) -> list[str]:
    created: list[str] = []
    for path in paths:
        if not path.exists():
            created.append(str(path))
            if not dry_run:
                path.mkdir(parents=True, exist_ok=True)
    return created


def _write_once(path: Path, text: str, *, dry_run: bool) -> bool:
    if path.exists():
        return False
    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return True


def _artifact_paths(program: str, lane: str, root: Path) -> list[Path]:
    program_root = root / program
    if lane in {"web", "api"}:
        surface = program_root / lane
        return [
            surface / "recon" / "fuzzing",
            surface / "recon" / "subdomains" / "runs",
            surface / "recon" / "javascript" / "urls",
            surface / "recon" / "javascript" / "downloads" / "by-host",
            surface / "recon" / "javascript" / "downloads" / "by-sha256",
            surface / "recon" / "javascript" / "sourcemaps",
            surface / "recon" / "javascript" / "chunks",
            surface / "recon" / "javascript" / "indexes",
            surface / "recon" / "javascript" / "runs",
            surface / "recon" / "pages",
            surface / "recon" / "api",
            surface / "screenshots" / "admin",
            surface / "screenshots" / "auth",
            surface / "screenshots" / "billing",
            surface / "screenshots" / "settings",
            surface / "screenshots" / "unknown",
            surface / "screenshots" / "runs",
            surface / "proxy" / "flows",
            surface / "proxy" / "har",
            surface / "proxy" / "runs",
            surface / "videos",
            surface / "browser-profiles",
            surface / "cdp-traces",
            surface / "reports-heavy",
        ]
    surface = program_root / lane
    return [
        surface / "static" / "decompile",
        surface / "static" / "jadx" / "runs",
        surface / "static" / "apktool",
        surface / "dynamic" / "traces",
        surface / "dynamic" / "frida",
        surface / "dynamic" / "screenshots",
        surface / "runs",
        surface / "reports-heavy",
    ]


def _shared_lane_paths(layout) -> list[Path]:
    paths = [
        layout.recon_root / "_meta",
        layout.recon_root / "_batches",
        layout.recon_root / "_runs",
        layout.recon_root / "_archive",
        layout.recon_root / "_scratch",
        layout.lane_root / "findings",
        layout.lane_root / "scripts",
    ]
    return [path for path in paths if path is not None]


def _read_scope(program: str) -> tuple[set[str], set[str]]:
    scope = ScopeManager(program)
    return scope.domains, scope.urls


def _preserve_existing(paths: Iterable[Path]) -> dict[Path, bytes]:
    """Keep Bounty Core's create-only setup from replacing curated files."""
    return {path: path.read_bytes() for path in paths if path.exists()}


def _restore_existing(saved: dict[Path, bytes]) -> None:
    for path, content in saved.items():
        path.write_bytes(content)


def _seed_recon_files(recon_root: Path, domains: set[str], urls: set[str], *, dry_run: bool) -> dict[str, int]:
    url_lines, wild_lines = recon_seed_lines(domains, urls)
    seeds = {
        "urls": len(url_lines),
        "wildcards": len(wild_lines),
    }
    for name, lines in (("urls.txt", url_lines), ("wild.txt", wild_lines)):
        body = "\n".join(lines) + ("\n" if lines else "")
        _write_once(recon_root / name, body, dry_run=dry_run)
    return seeds

def _collection_handoff(program: str, domains: set[str], urls: set[str], *, mode: str, include_docs: bool) -> dict[str, object]:
    """Stable dependency packets for an agent coordinator, not scanner commands."""
    seeds, wildcards = recon_seed_lines(domains, urls)
    scope = {"source": "saved platform scope", "domains": sorted(domains),
             "urls": sorted(urls), "url_seeds": seeds, "wildcard_seeds": wildcards}

    def packet(key: str, owner: str, depends_on: list[str], task: str, output: str) -> dict[str, object]:
        return {"id": key, "owner": owner, "depends_on": depends_on,
                "status": "pending-scope-rate-review" if not depends_on else "pending-prerequisites",
                "task": task, "expected_receipt": output}

    stages = [packet("full-recon", "/recon", [],
                     "Inspect comparable baseline freshness and scope first. Reuse a verified current baseline, run a targeted delta for a named gap, or run all eligible /recon baseline lanes if missing or stale. For explicit full, do not silently downgrade collection. Assess request-level destinations and aggregate rate across workers; Recon-Ry owns archive promotion. Publish scope-checked new page/host discoveries to the JS worker without waiting for the entire broad run.",
                     "Completed comparable baseline/reuse or delta receipt with manifests, scope/rate decision, gaps and completed Recon-Ry receipt when launched")]
    stages.append(packet("js-url-acquisition", "/js-pull + /live-map", [] if mode == "full" else ["full-recon"],
                         "For full, start beside /recon on approved seeds within a shared rate budget and consume newly validated scoped page/host URLs as they arrive; for focused modes, first ensure a usable /recon receipt. Reuse current content-addressed JS or fetch missing/stale scoped scripts, including runtime chunks and bounded source maps. A page/flow with no JS is an explicit negative coverage receipt, not a blocker to mapping other evidence. Do not mistake URL inventory for downloaded or reviewed JS.",
                         "JS URL/content-hash and page/flow provenance, failures, no-JS surfaces and bounded collection checkpoint/coverage gaps"))
    if mode in {"full", "api", "params"}:
        stages.append(packet("katana-endpoints", "/bounty-tools + /focused-recon", ["js-url-acquisition"],
                             "After the JS checkpoint, run bounded scoped Katana -jc on approved page/JS inputs if request-level redirects/rate and resources permit; check installed help, preserve raw source-attributed output. Record a skipped receipt if unsafe or unavailable. Do not duplicate Recon-Ry archives.",
                             "Raw Katana manifest and candidates or explicit skip reason"))
    if include_docs:
        stages.append(packet("public-docs", "/recon-docs → /docs", [],
                             "Discover bounded public program/product/developer documentation from provider-compliant sources. Docs are source claims, not target scope or server behavior; quarantine third-party and out-of-scope links.",
                             "Source-attributed docs and reviewed topics or explicit skip reason"))
    if mode in {"full", "api", "params"}:
        api_dependencies = ["js-url-acquisition", "katana-endpoints"]
        if mode != "full":
            api_dependencies.insert(0, "full-recon")
        if include_docs:
            api_dependencies.append("public-docs")
        stages.append(packet("api-mapping", "/api-surface-mapping", api_dependencies,
                             "Reconcile scoped JS/source declarations, authorized runtime requests and completed docs/spec receipts into API operations and context. In full mode, begin from approved initial seeds and the JS checkpoint while broad /recon continues; refresh affected operation records if later recon discoveries change the surface before final reconciliation. A no-JS receipt permits runtime/spec mapping; do not invoke candidate operations as a discovery test.",
                             "Attributed API operation map, declared versus observed distinctions and bounded evidence-linked handoffs; final refresh after any material later recon discovery"))
    if mode == "full":
        stages.append(packet("api-reconciliation", "/js-pull + /api-surface-mapping", ["full-recon", "api-mapping"],
                             "Compare final /recon discoveries to the API-map input manifests. Refresh affected JS/API operation records where a new scoped surface is material, or record no change with evidence. Keep the full baseline completion distinct from the earlier API mapping checkpoint.",
                             "Final recon-to-API diff and refreshed operation/JS input pointers or evidence-backed no-change receipt"))
    if mode in {"full", "params"}:
        dependencies = ["full-recon", "js-url-acquisition", "api-reconciliation" if mode == "full" else "api-mapping"]
        if include_docs:
            dependencies.append("public-docs")
        stages.append(packet("parameter-mining", "/parameter-mining", dependencies,
                             "Correlate query/path/body/header/form/GraphQL fields with specific scoped routes and operations from recon, JS request builders, API map, runtime observations and docs. Distinguish observed from declared or name-only candidates; do not automatically fuzz or claim server acceptance. Reuse current evidence and fill bounded gaps.",
                             "Source-attributed parameter/operation records, confidence, unresolved fields and coverage gaps"))
    sources = [str(stage["id"]) for stage in stages]
    stages.extend([
        packet("recon-bus-promotion", "/recon-corpus-write-policy + Recon Bus", sources,
               "At each completed producer checkpoint, scope-check and promote reusable full URLs, parameterized URLs, JavaScript URLs, hosts and content paths through Recon Bus append or promote-run; preserve raw manifests, provenance and quarantine. Recon Bus URL promotion probes new URLs by default: include those requests in the aggregate rate budget and enforce request-level destination/redirect containment, or deliberately use record-only --liveness unknown / --no-probe until authorized. Query canonical aggregate for downstream input. This final receipt reconciles all selected producer promotions; never hand-edit aggregates or repeat Recon-Ry's archive promotion. Name-only field vocabulary stays in attributed parameter artifacts until tied to an eligible URL/route.",
               "Per-producer and final Recon Bus promotion receipts/counts, source references and quarantined candidates"),
        packet("url-ingest-review", "/url-ingest", ["recon-bus-promotion"],
               "Review promoted URL sets and prior per-lane coverage; hand off bounded next packets without marking collection as testing.",
               "URL Ingest queue/coverage receipt and remaining gaps"),
    ])
    return {"schema_version": 2, "program": program, "mode": mode,
            "execution_boundary": "plan-only; this CLI does not spawn Hermes subagents or make target requests",
            "scope": scope,
            "gates": ["Read published program scope and rules, saved scope and permitted aggregate rate budget before dispatch.",
                      "Apply general-security-testing-policy, program-testing-policy and live-testing-policy before traffic; owning skills govern accounts, browsers, tools and writes.",
                      "Wildcard/shared IP/archive/docs do not authorize a destination; enforce restricted origins/paths at request time or defer broad active scanning.",
                      "Stop on challenge, repeated 429, instability, scope ambiguity or unavailable rate authorization."],
            "completion_rule": "Every selected producer needs an evidence-backed completed/reused/skipped or blocked receipt; dependencies wait for completion, not launch. Scope-filtered Recon Bus promotion and URL review are required. A pending/blocked stage means this mode is not complete.",
            "stages": stages}


def initialize_program(
    program: str,
    *,
    lanes: list[str],
    shared_root: Path,
    artifact_root: Path,
    platform: str | None,
    skip_scope: bool,
    dry_run: bool,
    mode: str = "basic",
    include_docs: bool | None = None,
) -> dict[str, object]:
    slug = canonical_program_slug(program) if platform else normalize_program(program)
    if platform and skip_scope:
        raise ValueError("--platform and --skip-scope cannot be used together")
    if not platform and not skip_scope:
        raise ValueError("scope is required: provide --platform or explicitly use --skip-scope")
    if mode not in {"basic", "full", "js", "api", "params"}:
        raise ValueError("mode must be basic, full, js, api or params")
    if include_docs and mode == "basic":
        raise ValueError("--include-docs requires a non-basic mode")
    if include_docs is None:
        include_docs = mode in {"full", "api", "params"}
    if mode != "basic" and (skip_scope or not platform):
        raise ValueError(f"{mode} mode requires --platform and saved scope; --skip-scope is not eligible")
    if mode != "basic" and not any(lane in {"web", "api"} for lane in lanes):
        raise ValueError(f"{mode} mode requires a web or api lane")
    # pull_scope and ScopeManager both use ~/Shared/scopes. Reject an alternate
    # layout before the network pull rather than claiming its scope is aligned.
    if mode != "basic" and shared_root.expanduser().resolve() != (Path.home() / "Shared").resolve():
        raise ValueError("--shared-root is not supported with non-basic initialization: scope pull and reads use ~/Shared/scopes")

    if platform and not dry_run:
        pulled_scope = pull_scope(program, platform)
        if pulled_scope is None:
            raise RuntimeError("scope pull failed; no program layout was created")

    scope_state = "skipped" if skip_scope else "pulled" if platform else "unknown"
    if mode != "basic" and dry_run:
        scope_state = "saved"
    domains, urls = _read_scope(slug) if not dry_run else (set(), set())
    if mode != "basic" and dry_run:
        # Dry runs do not pull scope, but must still have an existing saved grant.
        domains, urls = _read_scope(slug)
    if mode != "basic" and not (domains or urls):
        raise ValueError(f"{mode} mode requires non-empty saved scope; no layout or handoff created")
    handoff = _collection_handoff(slug, domains, urls, mode=mode, include_docs=include_docs) if mode != "basic" else None
    created: list[str] = []
    refreshed: list[str] = []
    shared_lanes: dict[str, str] = {}

    for lane in lanes:
        layout = resolve_storage(
            slug,
            family=LANE_FAMILIES[lane],
            lane=lane,
            root_override=shared_root,
            create=False,
        )
        protected_paths = [
            layout.context_root / "target_profile.json",
            layout.context_root / "me_context.md",
            layout.recon_root / "urls.txt",
            layout.recon_root / "wild.txt",
        ]
        if not dry_run:
            preserved = _preserve_existing(protected_paths)
            ensure_layout(layout)
            _restore_existing(preserved)
        created.extend(_mkdirs(_shared_lane_paths(layout), dry_run=dry_run))
        shared_lanes[lane] = str(layout.lane_root)

        if lane in {"web", "api"}:
            seeds = _seed_recon_files(layout.recon_root, domains, urls, dry_run=dry_run)
        else:
            seeds = {"urls": 0, "wildcards": 0}
        created.extend(_mkdirs(_artifact_paths(slug, lane, artifact_root), dry_run=dry_run))

        manifest = {
            "program": slug,
            "lane": lane,
            "scope_state": scope_state,
            "scope_domains": len(domains),
            "scope_urls": len(urls),
            "recon_seeds": seeds,
            "artifact_root": str(artifact_root / slug / lane),
            "initialized_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        manifest_path = layout.recon_root / "_meta" / "program-init.json"
        if _write_once(manifest_path, json.dumps(manifest, indent=2) + "\n", dry_run=dry_run):
            created.append(str(manifest_path))
        artifact_map = layout.recon_root / "artifact-map.md"
        if _write_once(
            artifact_map,
            f"# {slug} {lane} artifact map\n\n"
            f"Heavy non-secret artifacts: `{artifact_root / slug / lane}`\n\n"
            "Update machine-readable per-artifact maps when a persistent corpus is created.\n",
            dry_run=dry_run,
        ):
            created.append(str(artifact_map))

    handoff_path = None
    if handoff is not None:
        handoff_lane = "web" if "web" in lanes else "api"
        handoff_root = shared_root / WEB_FAMILY / slug / handoff_lane / "recon" / "_meta"
        handoff_path = handoff_root / ("full-recon-handoff.json" if mode == "full" else f"init-{mode}-handoff.json")
        body = json.dumps(handoff, indent=2, sort_keys=True) + "\n"
        if not handoff_path.exists():
            if not dry_run:
                handoff_path.write_text(body, encoding="utf-8")
            created.append(str(handoff_path))
        elif handoff_path.read_text(encoding="utf-8") != body:
            if not dry_run:
                handoff_path.write_text(body, encoding="utf-8")
            refreshed.append(str(handoff_path))

    result = {
        "program": slug,
        "lanes": shared_lanes,
        "artifact_root": str(artifact_root / slug),
        "scope_state": scope_state,
        "scope_domains": len(domains),
        "scope_urls": len(urls),
        "created": created,
        "refreshed": refreshed,
        "dry_run": dry_run,
    }
    if handoff is not None:
        result["mode"] = mode
        result["handoff_path"] = str(handoff_path)
        result["handoff"] = handoff
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program", help="Program slug or platform handle")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--platform", choices=["hackerone", "bugcrowd", "intigriti"], help="Pull published scope from this platform")
    scope.add_argument("--skip-scope", action="store_true", help="Initialize only and record that a manual scope source is still required")
    parser.add_argument("--lane", dest="lanes", choices=sorted(LANE_FAMILIES), action="append", help="Initialize a surface lane (repeatable; defaults to web)")
    parser.add_argument("--mode", choices=["basic", "full", "js", "api", "params"], default="basic", help="Basic bootstrap (default), or an agent-facing recon + discovery handoff (CLI does not dispatch)")
    parser.add_argument("--include-docs", action="store_true", default=None, help="Bounded public docs; included by default in full, api and params")
    parser.add_argument("--shared-root", type=Path, default=Path.home() / "Shared", help="Shared base root (default: ~/Shared)")
    parser.add_argument("--artifact-root", type=Path, default=DEFAULT_ARTIFACT_ROOT, help="Mounted non-secret artifact root (default: /mnt/bounty)")
    parser.add_argument("--dry-run", action="store_true", help="Show the initialization plan without creating files")
    parser.add_argument("--json", action="store_true", help="Print the result as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = initialize_program(
            args.program,
            lanes=args.lanes or ["web"],
            shared_root=args.shared_root.expanduser(),
            artifact_root=args.artifact_root.expanduser(),
            platform=args.platform,
            skip_scope=args.skip_scope,
            dry_run=args.dry_run,
            mode=args.mode,
            include_docs=args.include_docs,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}")
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Initialized {result['program']} ({result['scope_state']})")
        for lane, path in result["lanes"].items():
            print(f"  Shared {lane}: {path}")
        print(f"  Mounted artifacts: {result['artifact_root']}")
        label = "Planned" if result["dry_run"] else "Created"
        print(f"  {label}: {len(result['created'])} path(s)")
        print(f"  {'Would refresh' if result['dry_run'] else 'Refreshed'}: {len(result['refreshed'])} path(s)")
        if result.get("handoff_path"):
            print(f"  Pending {result['mode']} handoff: {result['handoff_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
