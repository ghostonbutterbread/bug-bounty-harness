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

def _full_handoff(program: str, domains: set[str], urls: set[str], *, include_docs: bool) -> dict[str, object]:
    """Stable packets for an agent coordinator, not runnable scanner commands."""
    seeds, wildcards = recon_seed_lines(domains, urls)
    scope = {"source": "platform-pulled saved scope", "domains": sorted(domains),
             "urls": sorted(urls), "url_seeds": seeds, "wildcard_seeds": wildcards}

    def packet(key: str, owner: str, depends_on: list[str], task: str, output: str) -> dict[str, object]:
        return {"id": key, "owner": owner, "depends_on": depends_on,
                "status": "pending-scope-rate-review" if not depends_on else "pending-prerequisites",
                "task": task, "expected_receipt": output}

    stages = [
        packet("full-recon", "/recon", [],
               "Independently execute the full-platform recon workflow against saved scope; assess each active producer's request-level scope and aggregate rate budget first. Recon-Ry owns its own stages and archive promotion. Do not infer coverage from a plan.",
               "Full-recon collection manifests, coverage gaps, scope/rate decision and Recon-Ry completion receipt"),
        packet("js-url-acquisition", "/js-pull + /live-map", [],
               "Comprehensively collect scoped JavaScript URL candidates from canonical aggregate, authorized runtime pages/flows, and source-attributed history; dedupe, preserve provenance and fetch only after live-policy approval. Do not silently treat a URL list as downloaded JS or deep review.",
               "JS URL inventory, content hashes, source/page provenance, failures and coverage gaps"),
        packet("katana-endpoints", "/bounty-tools + /focused-recon", ["js-url-acquisition"],
               "Only after the JS collection receipt, evaluate a bounded, scoped Katana endpoint extraction pass using the approved JS/page inputs. Validate request-level destinations and rate; if unsafe, record a skipped receipt. Do not repeat Recon-Ry archive producers.",
               "Raw Katana run manifest and source-attributed endpoint candidates or explicit skip reason"),
        packet("api-mapping", "/api-surface-mapping", ["js-url-acquisition", "katana-endpoints"],
               "Reconcile JS/source-declared routes with authorized runtime observations as separate evidence classes; map methods, auth context, and unknowns without testing operations.",
               "API operation map and bounded evidence-linked handoffs"),
    ]
    if include_docs:
        stages.append(packet("public-docs", "/recon-docs → /docs", [],
                             "Explicit full-only discovery of bounded public program/product/developer documentation from provider-compliant sources. Public docs are source claims, not target scope or observed behavior; quarantine third-party and out-of-scope links; do not crawl indiscriminately.",
                             "Source-attributed public docs list and candidate Program Docs topics or skip reason"))
    sources = ["full-recon", "js-url-acquisition", "katana-endpoints", "api-mapping"]
    if include_docs:
        sources.append("public-docs")
    stages.extend([
        packet("recon-bus-promotion", "/recon-corpus-write-policy + Recon Bus", sources,
               "Review raw producer receipts, filter each candidate against saved scope, retain rejected candidates in quarantine, and promote attributed reusable evidence through Recon Bus only; never hand-edit aggregates or duplicate Recon-Ry completion promotion.",
               "Recon Bus promotion receipts and quarantined candidate references"),
        packet("url-ingest-review", "/url-ingest", ["recon-bus-promotion"],
               "Ingest promoted URL sets into a review queue, inspect prior per-lane coverage, and hand off bounded next packets; do not mark URLs tested by collection alone.",
               "URL Ingest queue/coverage receipt and pending review gaps"),
    ])
    return {"schema_version": 1, "program": program, "mode": "full",
            "execution_boundary": "plan-only; this CLI does not spawn Hermes subagents or make target requests",
            "scope": scope,
            "gates": ["Read published program scope and rules, saved scope and permitted rate budget before dispatch.",
                      "Apply general-security-testing-policy, program-testing-policy and live-testing-policy before traffic; owning skills govern accounts, browsers, tools and writes.",
                      "A wildcard, shared IP, archive result or public doc is not authorization. Restricted origin/path grants require request-level enforcement; defer active broad scans if unresolved.",
                      "Stop on challenge, repeated 429, instability, scope ambiguity or unavailable rate authorization."],
            "completion_rule": "All selected receipts, scope-filtered promotion and URL review queue required; every stage remains pending until an agent records evidence.",
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
    if mode not in {"basic", "full"}:
        raise ValueError("mode must be basic or full")
    if include_docs and mode != "full":
        raise ValueError("--include-docs requires --mode full")
    if include_docs is None:
        include_docs = mode == "full"
    if mode == "full" and (skip_scope or not platform):
        raise ValueError("full mode requires --platform and saved scope; --skip-scope is not eligible")
    if mode == "full" and not any(lane in {"web", "api"} for lane in lanes):
        raise ValueError("full mode requires a web or api lane")
    # pull_scope and ScopeManager both use ~/Shared/scopes. Reject an alternate
    # layout before the network pull rather than claiming its scope is aligned.
    if mode == "full" and shared_root.expanduser().resolve() != (Path.home() / "Shared").resolve():
        raise ValueError("--shared-root is not supported with full initialization: scope pull and reads use ~/Shared/scopes")

    if platform and not dry_run:
        pulled_scope = pull_scope(program, platform)
        if pulled_scope is None:
            raise RuntimeError("scope pull failed; no program layout was created")

    scope_state = "skipped" if skip_scope else ("pulled" if platform else "unknown")
    domains, urls = _read_scope(slug) if not dry_run else (set(), set())
    if mode == "full" and dry_run:
        # Dry runs do not pull scope, but must still have an existing saved grant.
        domains, urls = _read_scope(slug)
    if mode == "full" and not (domains or urls):
        raise ValueError("full mode requires non-empty saved scope; no layout or handoff created")
    handoff = _full_handoff(slug, domains, urls, include_docs=include_docs) if mode == "full" else None
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
        handoff_path = handoff_root / "full-recon-handoff.json"
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
        result["mode"] = "full"
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
    parser.add_argument("--mode", choices=["basic", "full"], default="basic", help="Basic bootstrap (default) or full agent-facing handoff (CLI does not dispatch)")
    parser.add_argument("--include-docs", action="store_true", default=None, help="Compatibility option; bounded public docs are included in full by default")
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
            print(f"  Pending full-recon handoff: {result['handoff_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
