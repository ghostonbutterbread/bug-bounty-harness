"""Plan-first coordinator for a composable full reconnaissance pass.

This module deliberately plans and records focused lanes.  It does not launch
network tools, browsers, or child agents: their owning skills retain scope,
authentication, rate, and lifecycle authority.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from bounty_core.recon import start_run, write_manifest

ReconMode = Literal["baseline-full", "full", "delta", "map-only"]
REQUESTED_MODES = {"auto", "full", "delta", "map-only"}


@dataclass(frozen=True, slots=True)
class FullReconConfig:
    program: str
    target: str
    requested_mode: str = "auto"
    baseline_manifest: str | None = None
    auth_alias: str | None = None
    include_proxy_history: bool = False
    family: str = "web_bounty"
    lane: str = "web"
    root: str | Path | None = None
    run_id: str | None = None


@dataclass(frozen=True, slots=True)
class ReconLane:
    key: str
    owner: str
    purpose: str
    trigger: str
    status: str
    writes: tuple[str, ...]
    command: tuple[str, ...] = ()
    account_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["writes"] = list(self.writes)
        payload["command"] = list(self.command)
        return payload


def resolve_mode(requested_mode: str, baseline_manifest: str | None) -> ReconMode:
    if requested_mode not in REQUESTED_MODES:
        raise ValueError(f"unsupported recon mode: {requested_mode!r}")
    if requested_mode != "auto":
        return requested_mode  # type: ignore[return-value]
    return "delta" if baseline_manifest else "baseline-full"


def build_plan(config: FullReconConfig) -> dict[str, Any]:
    mode = resolve_mode(config.requested_mode, config.baseline_manifest)
    collection = mode != "map-only"
    full = mode in {"baseline-full", "full"}
    target = config.target
    auth = config.auth_alias

    lanes = [
        ReconLane(
            key="recon-ry",
            owner="/recon-ry",
            purpose="Durable broad collection; its completion handler owns Recon Bus promotion.",
            trigger="full collection" if collection else "existing collector only",
            status="planned" if collection else "not-requested",
            writes=("recon-ry run capsule", "aggregated evidence via existing completion handler"),
            command=("python3", "agents/recon_ry.py", "start", config.program, "--url", target, "--profile", "full") if collection else (),
            account_required=False,
        ),
        ReconLane(
            key="runtime-live-collection",
            owner="/live-map",
            purpose="Collect browser/proxy-observed routes, loaded JS, API and GraphQL shapes through normal workflows.",
            trigger="baseline/full" if full else "changed authenticated/runtime question",
            status="planned" if full else "deferred",
            writes=("application-map observations", "source-attributed Recon Bus proposals"),
            account_required=bool(auth),
        ),
        ReconLane(
            key="js-inventory",
            owner="/js",
            purpose="Acquire, hash, dedupe, and cheaply inventory JavaScript from aggregate and runtime provenance.",
            trigger="baseline/full" if full else "new or changed JS inventory",
            status="planned" if full else "deferred",
            writes=("content-addressed JS library", "JS provenance/observations", "source-attributed Recon Bus proposals"),
            command=("python3", "agents/js_analyzer.py", "inventory", config.program, "--input", "<Recon-Bus jsfiles path>", "--target-host", target),
        ),
        ReconLane(
            key="developer-docs",
            owner="/recon-docs → /docs",
            purpose="Collect public product/developer/API/SDK/integration documentation signals without creating a second docs store.",
            trigger="baseline/full" if full else "new feature, integration, or technology signal",
            status="planned" if full else "deferred",
            writes=("developer-doc source artifact", "Program Doc proposal when justified"),
        ),
    ]
    if config.include_proxy_history:
        lanes.append(
            ReconLane(
                key="proxy-history-intake",
                owner="/caido or /pwnfox → /live-map",
                purpose="Normalize bounded existing proxy observations; never bulk-copy raw traffic into prompts.",
                trigger="explicit source-history availability",
                status="planned",
                writes=("application-map observations", "source-attributed Recon Bus proposals"),
                account_required=bool(auth),
            )
        )
    lanes.extend(
        [
            ReconLane(
                key="surface-synthesis",
                owner="/focused-recon",
                purpose="Cluster canonical aggregate evidence and emit bounded target packets and coverage state.",
                trigger="after collection receipts are available",
                status="blocked-on-collection" if collection else "planned",
                writes=("recon/map target packets", "coverage receipt"),
            ),
            ReconLane(
                key="recon-signal-triage",
                owner="MapStore + Hypothesis Ledger",
                purpose="Persist concrete observations and recon-tagged candidate questions with evidence pointers; no automatic testing.",
                trigger="while collecting and after synthesis",
                status="planned",
                writes=("MapStore observations", "Hypothesis Ledger candidates tagged recon"),
            ),
        ]
    )
    return {
        "schema_version": 1,
        "program": config.program,
        "target": target,
        "mode": mode,
        "baseline_manifest": config.baseline_manifest,
        "auth_alias": auth,
        "execution_boundary": "plan-only; each lane's owning skill controls live action and account use",
        "completion_rule": "full collection is pending until every applicable lane has a receipt; Recon-Ry may remain running while offline lanes proceed",
        "lanes": [lane.to_dict() for lane in lanes],
    }


def write_plan(config: FullReconConfig) -> Path:
    plan = build_plan(config)
    run = start_run(
        tool="full-recon",
        target=config.target,
        program=config.program,
        family=config.family,
        lane=config.lane,
        run_id=config.run_id,
        root_override=config.root,
    )
    plan_path = run.run_dir / "plan.json"
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    run.command_path.write_text("full-recon plan-only coordinator\n", encoding="utf-8")
    run.stdout_path.write_text("", encoding="utf-8")
    run.stderr_path.write_text("", encoding="utf-8")
    return write_manifest(
        run,
        {
            "status": "planned",
            "exit_code": 0,
            "mode": plan["mode"],
            "artifact_files": [str(plan_path)],
            "raw_files": [],
            "parsed_files": [str(plan_path)],
            "counts": {"lanes": len(plan["lanes"]), "planned_lanes": sum(item["status"] == "planned" for item in plan["lanes"])},
            "promotion_policy": "No direct aggregate, MapStore, or hypothesis writes; owners receive bounded lane contracts.",
            "next_action": "Dispatch planned lanes through their owning skills after normal scope/auth/live-policy gates.",
        },
    )
