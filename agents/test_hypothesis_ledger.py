from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "agents" / "hypothesis_ledger.py"


def run_cli(tmp_path: Path, *args: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(CLI), "--root", str(tmp_path), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": ""},
        check=True,
    )
    return json.loads(result.stdout)


def prepare_mapstore_root(tmp_path: Path, program: str) -> None:
    lane_root = tmp_path / "web_bounty" / program / "web"
    recon_root = lane_root / "recon"
    recon_root.mkdir(parents=True)
    for name in ("context", "notes", "ledgers", "reports"):
        (lane_root / name).mkdir(parents=True, exist_ok=True)
    profile = {
        "program": program,
        "family": "web_bounty",
        "lane": "web",
        "root_mode": "shared-default",
        "base_root": str(tmp_path),
        "family_root": str(tmp_path / "web_bounty"),
        "program_root": str(tmp_path / "web_bounty" / program),
        "canonical_root": str(lane_root),
        "reports_root": str(lane_root / "reports"),
        "ledger_root": str(lane_root / "ledgers"),
        "working_root": str(lane_root / "working"),
        "context_root": str(lane_root / "context"),
        "notes_root": str(lane_root / "notes"),
        "shared_root": str(tmp_path / "web_bounty" / program / "shared"),
        "recon_root": str(recon_root),
        "input_root": "",
        "allow_lane_autocreate": True,
    }
    (lane_root / "context" / "target_profile.json").write_text(json.dumps(profile), encoding="utf-8")


def test_cli_captures_private_hypothesis_and_exposes_only_owner_view(tmp_path):
    created = run_cli(
        tmp_path,
        "create", "demo",
        "--agent-id", "agent-a", "--run-id", "run-a",
        "--title", "Signed URL export worker", "--surface", "export",
        "--url", "https://app.example/export", "--tag", "worker", "--tag", "pdf",
    )

    owner_view = run_cli(tmp_path, "list", "demo", "--agent-id", "agent-a", "--run-id", "run-a", "--surface", "export")
    other_view = run_cli(tmp_path, "list", "demo", "--agent-id", "agent-b", "--run-id", "run-b")
    checkpoint = run_cli(tmp_path, "continuation", "demo", "--agent-id", "agent-a", "--run-id", "run-a", "--surface", "export")

    assert owner_view["hypotheses"][0]["id"] == created["id"]
    assert other_view == {"hypotheses": []}
    assert checkpoint == {"private_unresolved_count": 1, "active_count": 0, "surface": "export"}


def test_cli_can_transition_an_owned_hypothesis_to_active(tmp_path):
    created = run_cli(
        tmp_path, "create", "demo", "--agent-id", "agent-a", "--run-id", "run-a",
        "--title", "Signed URL export worker", "--surface", "export",
    )

    active = run_cli(
        tmp_path, "transition", "demo", created["id"], "--agent-id", "agent-a", "--run-id", "run-a", "--status", "active",
    )
    checkpoint = run_cli(tmp_path, "continuation", "demo", "--agent-id", "agent-a", "--run-id", "run-a", "--surface", "export")

    assert active["status"] == "active"
    assert checkpoint == {"private_unresolved_count": 1, "active_count": 1, "surface": "export"}


def test_cli_lead_followup_returns_released_context_without_broadening_list(tmp_path):
    created = run_cli(
        tmp_path, "create", "demo", "--agent-id", "agent-a", "--run-id", "run-a",
        "--title", "Export worker authorization seam", "--surface", "export",
        "--lead-id", "lead-export-worker",
    )

    released = run_cli(
        tmp_path, "release", "demo", created["id"],
        "--agent-id", "agent-a", "--run-id", "run-a",
    )
    ordinary_list = run_cli(tmp_path, "list", "demo", "--agent-id", "agent-b", "--run-id", "run-b")
    result = subprocess.run(
        [
            sys.executable, str(CLI), "--root", str(tmp_path), "lead-followup", "demo",
            "--agent-id", "agent-b", "--run-id", "run-b", "--lead-id", "lead-export-worker",
        ],
        cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ""},
    )

    assert released["context_state"] == "released"
    assert ordinary_list == {"hypotheses": []}
    assert result.returncode != 0
    assert "exact public MapStore lead ID/path" in result.stderr


def test_cli_lead_followup_requires_a_public_lead_and_returns_its_card(tmp_path):
    program = "demo"
    prepare_mapstore_root(tmp_path, program)
    lead_result = subprocess.run(
        [
            sys.executable, str(ROOT / "agents" / "leads.py"), "create",
            "--program", program, "--root", str(tmp_path), "--relative-id",
            "--class", "authz", "--surface", "export", "--title", "Export authorization seam",
            "--observed-basis", "Owned export starts a worker.",
            "--candidate-chain", "export -> worker -> authorization boundary",
            "--exact-unknown", "Whether the worker rechecks authorization.",
            "--next-discriminator", "Owned two-account export comparison.",
            "--evidence-ref", "mapstore:export-worker",
        ],
        cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ""}, check=True,
    )
    lead_id = lead_result.stdout.strip()
    created = run_cli(
        tmp_path, "create", program, "--agent-id", "agent-a", "--run-id", "run-a",
        "--title", "Worker authorization branch", "--surface", "export", "--lead-id", lead_id,
    )
    run_cli(tmp_path, "release", program, created["id"], "--agent-id", "agent-a", "--run-id", "run-a")

    followup = run_cli(
        tmp_path, "lead-followup", program, "--agent-id", "agent-b", "--run-id", "run-b", "--lead-id", lead_id,
    )

    assert followup["lead"]["path"] == lead_id
    assert followup["lead"]["title"] == "Export authorization seam"
    assert [item["id"] for item in followup["hypotheses"]] == [created["id"]]


def test_leads_create_preserves_legacy_absolute_path_output(tmp_path):
    program = "demo"
    prepare_mapstore_root(tmp_path, program)

    result = subprocess.run(
        [
            sys.executable, str(ROOT / "agents" / "leads.py"), "create",
            "--program", program, "--root", str(tmp_path),
            "--class", "authz", "--surface", "export", "--title", "Export authorization seam",
            "--observed-basis", "Owned export starts a worker.",
            "--candidate-chain", "export -> worker -> authorization boundary",
            "--exact-unknown", "Whether the worker rechecks authorization.",
            "--next-discriminator", "Owned two-account export comparison.",
            "--evidence-ref", "mapstore:export-worker",
        ],
        cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ""}, check=True,
    )

    absolute_path = result.stdout.strip()
    assert Path(absolute_path).is_absolute()

    updated = subprocess.run(
        [
            sys.executable, str(ROOT / "agents" / "leads.py"), "update-status",
            "--program", program, "--root", str(tmp_path), "--path", absolute_path,
            "--status", "needs_recheck", "--reason", "fixture pending",
        ],
        cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ""}, check=True,
    )

    assert not Path(updated.stdout.strip()).is_absolute()


def test_cli_lead_followup_accepts_legacy_absolute_lead_path(tmp_path):
    program = "demo"
    prepare_mapstore_root(tmp_path, program)
    lead_result = subprocess.run(
        [
            sys.executable, str(ROOT / "agents" / "leads.py"), "create",
            "--program", program, "--root", str(tmp_path), "--relative-id",
            "--class", "authz", "--surface", "export", "--title", "Export authorization seam",
            "--observed-basis", "Owned export starts a worker.",
            "--candidate-chain", "export -> worker -> authorization boundary",
            "--exact-unknown", "Whether the worker rechecks authorization.",
            "--next-discriminator", "Owned two-account export comparison.",
            "--evidence-ref", "mapstore:export-worker",
        ],
        cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ""}, check=True,
    )
    relative_lead_id = lead_result.stdout.strip()
    legacy_absolute_lead_id = str(tmp_path / "web_bounty" / program / "web" / "recon" / "maps" / relative_lead_id)
    created = run_cli(
        tmp_path, "create", program, "--agent-id", "agent-a", "--run-id", "run-a",
        "--title", "Worker authorization branch", "--surface", "export", "--lead-id", legacy_absolute_lead_id,
    )
    run_cli(tmp_path, "release", program, created["id"], "--agent-id", "agent-a", "--run-id", "run-a")

    followup = run_cli(
        tmp_path, "lead-followup", program, "--agent-id", "agent-b", "--run-id", "run-b", "--lead-id", legacy_absolute_lead_id,
    )

    assert followup["lead"]["path"] == relative_lead_id
    assert [item["id"] for item in followup["hypotheses"]] == [created["id"]]
