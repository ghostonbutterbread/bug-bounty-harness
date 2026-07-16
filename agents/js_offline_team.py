#!/usr/bin/env python3
"""File-tool-only worker runner for local JavaScript deep review.

Workers receive local packet/spec paths and are launched with Hermes' ``file``
toolset only. This runner never invokes a target, browser, proxy, terminal, or
zero_day_team.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

PLANNER_LANES = ("general-map", "anomaly-hunter")


@dataclass(frozen=True)
class WorkerResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[..., WorkerResult]


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid campaign manifest: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"invalid campaign manifest: {path} must contain an object")
    return value


def _manifest(campaign_root: Path) -> dict:
    return _read_json(campaign_root / "manifest.json")


def _lane_ids(manifest: dict) -> dict[str, str]:
    return {str(lane["key"]): f"H{index:03d}" for index, lane in enumerate(manifest.get("lanes") or [], 1) if isinstance(lane, dict) and lane.get("key")}


def worker_command(campaign_root: Path, lane: str, hypothesis_id: str) -> list[str]:
    manifest = _manifest(campaign_root)
    target = str(Path(manifest["offline_target"]).resolve())
    spec = str(Path(manifest["brainstorm_spec"]).resolve())
    report = campaign_root / "reviews" / "instructions" / f"{lane}.md"
    prompt = (
        "You are a local JavaScript review worker. Review only the local JS artifacts below. "
        "Do not make network requests, invoke commands, browse, use a proxy, or test a target. "
        "Write a concise evidence-grounded review to the requested report path using exact packet citations.\n\n"
        f"Lane: {lane}\nHypothesis: {hypothesis_id}\nLocal packet root: {target}\n"
        f"Local brainstorm spec: {spec}\nReport path: {report}\n"
        "Include: lead, evidence, source-to-sink/request trace, controllability, confidence, and any separately gated live-validation hypothesis."
    )
    return ["hermes", "chat", "-q", "--toolsets", "file", "--quiet", prompt]


def _default_runner(command: list[str], **_kwargs: object) -> WorkerResult:
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    return WorkerResult(completed.returncode, completed.stdout, completed.stderr)


def _approval_path(root: Path) -> Path:
    return root / "reviews" / "follow_up_approval.json"


def approve_follow_up(campaign_root: Path, lanes: Sequence[str]) -> dict:
    manifest = _manifest(campaign_root)
    known = _lane_ids(manifest)
    selected = list(dict.fromkeys(str(lane).strip() for lane in lanes if str(lane).strip()))
    if not selected:
        raise SystemExit("approval requires at least one follow-up lane")
    unknown = [lane for lane in selected if lane not in known or lane in PLANNER_LANES]
    if unknown:
        raise SystemExit(f"unknown or planner follow-up lane(s): {', '.join(unknown)}")
    payload = {"schema": "js-offline-follow-up-approval.v1", "approved_lanes": selected}
    path = _approval_path(campaign_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _approved_lanes(root: Path) -> list[str]:
    path = _approval_path(root)
    if not path.exists():
        raise SystemExit("follow-up execution requires a persisted approval; run approve after reviewing planner reports")
    value = _read_json(path)
    return [str(item) for item in value.get("approved_lanes") or []]


def run_stage(campaign_root: Path, *, stage: str, lanes: Sequence[str] | None = None, runner: Runner = _default_runner) -> dict:
    root = campaign_root.expanduser().resolve()
    manifest = _manifest(root)
    ids = _lane_ids(manifest)
    if stage == "planner":
        selected = [lane for lane in PLANNER_LANES if lane in ids]
    elif stage == "follow-up":
        selected = list(lanes or [])
        if not selected:
            raise SystemExit("follow-up execution requires selected lanes")
        approved = set(_approved_lanes(root))
        denied = [lane for lane in selected if lane not in approved]
        if denied:
            raise SystemExit(f"follow-up lane(s) lack approval: {', '.join(denied)}")
    else:
        raise SystemExit(f"unknown stage: {stage}")
    unknown = [lane for lane in selected if lane not in ids]
    if unknown:
        raise SystemExit(f"unknown lane(s): {', '.join(unknown)}")

    workers: list[dict] = []
    report_root = root / "reviews" / stage
    report_root.mkdir(parents=True, exist_ok=True)
    for lane in selected:
        result = runner(worker_command(root, lane, ids[lane]))
        report_path = report_root / f"{lane}.md"
        report_path.write_text((result.stdout.rstrip() or "Worker produced no report.") + "\n", encoding="utf-8")
        workers.append({"lane": lane, "hypothesis_id": ids[lane], "report": str(report_path), "returncode": result.returncode})
    payload = {"schema": "js-offline-stage-result.v1", "stage": stage, "status": "completed" if all(item["returncode"] == 0 for item in workers) else "failed", "workers": workers}
    (report_root / "result.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run file-tool-only local JavaScript review workers")
    sub = parser.add_subparsers(dest="command", required=True)
    approve = sub.add_parser("approve", help="Persist selected follow-up lanes after planner review")
    approve.add_argument("--campaign-root", required=True)
    approve.add_argument("--lane", action="append", required=True)
    run = sub.add_parser("run", help="Run local-only mapper or approved specialist workers")
    run.add_argument("--campaign-root", required=True)
    run.add_argument("--stage", choices=("planner", "follow-up"), required=True)
    run.add_argument("--lane", action="append", default=[])
    args = parser.parse_args(argv)
    root = Path(args.campaign_root)
    result = approve_follow_up(root, args.lane) if args.command == "approve" else run_stage(root, stage=args.stage, lanes=args.lane)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status", "completed") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
