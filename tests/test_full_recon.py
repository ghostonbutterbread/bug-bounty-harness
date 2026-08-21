from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.recon.full import FullReconConfig, build_plan, resolve_mode, write_plan


def lane(plan: dict[str, object], key: str) -> dict[str, object]:
    return next(item for item in plan["lanes"] if item["key"] == key)  # type: ignore[index]


def test_auto_uses_baseline_full_without_comparable_receipt() -> None:
    plan = build_plan(FullReconConfig(program="demo", target="https://app.example.com"))

    assert plan["mode"] == "baseline-full"
    assert lane(plan, "recon-ry")["status"] == "planned"
    assert lane(plan, "runtime-live-collection")["status"] == "planned"
    assert lane(plan, "developer-docs")["owner"] == "/recon-docs → /docs"
    assert "completion handler owns" in str(lane(plan, "recon-ry")["purpose"])


def test_auto_uses_delta_with_baseline_and_full_forces_collection() -> None:
    baseline = "/evidence/baseline.json"
    delta = build_plan(FullReconConfig(program="demo", target="example.com", baseline_manifest=baseline))
    full = build_plan(FullReconConfig(program="demo", target="example.com", requested_mode="full", baseline_manifest=baseline))

    assert delta["mode"] == "delta"
    assert lane(delta, "runtime-live-collection")["status"] == "deferred"
    assert full["mode"] == "full"
    assert lane(full, "runtime-live-collection")["status"] == "planned"


def test_map_only_does_not_start_collection_and_proxy_is_explicit() -> None:
    plan = build_plan(FullReconConfig(program="demo", target="example.com", requested_mode="map-only", include_proxy_history=True))

    assert lane(plan, "recon-ry")["status"] == "not-requested"
    assert lane(plan, "proxy-history-intake")["status"] == "planned"
    assert lane(plan, "surface-synthesis")["status"] == "planned"


def test_plan_receipt_writes_without_live_action(tmp_path: Path) -> None:
    manifest_path = write_plan(FullReconConfig(program="demo", target="example.com", root=tmp_path, run_id="unit"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["tool"] == "full-recon"
    assert manifest["status"] == "planned"
    plan = json.loads((manifest_path.parent / "plan.json").read_text(encoding="utf-8"))
    assert plan["execution_boundary"].startswith("plan-only")


def test_cli_dry_run_prints_plan() -> None:
    result = subprocess.run(
        [sys.executable, "agents/recon_full.py", "demo", "--target", "example.com", "--dry-run"],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=True,
    )

    assert json.loads(result.stdout)["mode"] == "baseline-full"
    assert resolve_mode("full", "/receipt.json") == "full"
