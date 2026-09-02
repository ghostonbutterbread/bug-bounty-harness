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


def run_cli_result(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI), "--root", str(tmp_path), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": ""},
    )


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


def test_cli_lead_followup_canonicalizes_relative_storage_for_legacy_absolute_lookup(tmp_path):
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
    absolute_lead_id = str(tmp_path / "web_bounty" / program / "web" / "recon" / "maps" / relative_lead_id)
    legacy_created = run_cli(
        tmp_path, "create", program, "--agent-id", "agent-a", "--run-id", "run-a",
        "--title", "Legacy worker authorization branch", "--surface", "export", "--lead-id", absolute_lead_id,
    )
    run_cli(tmp_path, "release", program, legacy_created["id"], "--agent-id", "agent-a", "--run-id", "run-a")
    created = run_cli(
        tmp_path, "create", program, "--agent-id", "agent-a", "--run-id", "run-a",
        "--title", "Worker authorization branch", "--surface", "export", "--lead-id", relative_lead_id,
    )
    run_cli(tmp_path, "release", program, created["id"], "--agent-id", "agent-a", "--run-id", "run-a")

    absolute_followup = run_cli(
        tmp_path, "lead-followup", program, "--agent-id", "agent-b", "--run-id", "run-b", "--lead-id", absolute_lead_id,
    )
    relative_followup = run_cli(
        tmp_path, "lead-followup", program, "--agent-id", "agent-b", "--run-id", "run-b", "--lead-id", relative_lead_id,
    )

    assert absolute_followup["lead"]["path"] == relative_lead_id
    expected_ids = [legacy_created["id"], created["id"]]
    assert [item["id"] for item in absolute_followup["hypotheses"]] == expected_ids
    assert [item["id"] for item in relative_followup["hypotheses"]] == expected_ids


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


def test_cli_peer_surface_review_is_explicit_and_limited_to_the_exact_surface_url(tmp_path):
    program = "demo"
    peer_match = run_cli(
        tmp_path, "create", program, "--agent-id", "agent-a", "--run-id", "run-a",
        "--title", "Matching export peer", "--surface", "export",
        "--url", "https://app.example/export", "--tag", "worker",
    )
    run_cli(
        tmp_path, "create", program, "--agent-id", "agent-b", "--run-id", "run-b",
        "--title", "Different export URL", "--surface", "export",
        "--url", "https://app.example/other", "--tag", "worker",
    )
    run_cli(
        tmp_path, "create", program, "--agent-id", "agent-c", "--run-id", "run-c",
        "--title", "Different surface", "--surface", "billing",
        "--url", "https://app.example/export", "--tag", "worker",
    )

    private_list = run_cli(tmp_path, "list", program, "--agent-id", "agent-d", "--run-id", "run-d")
    missing_scope = run_cli_result(
        tmp_path, "peer-surface-review", program, "--agent-id", "agent-d", "--run-id", "run-d",
    )
    wrong_intent = run_cli_result(
        tmp_path, "peer-surface-review", program, "--agent-id", "agent-d", "--run-id", "run-d",
        "--surface", "export", "--url", "https://app.example/export", "--review-intent", "wrong",
    )
    invalid_limit = run_cli_result(
        tmp_path, "peer-surface-review", program, "--agent-id", "agent-d", "--run-id", "run-d",
        "--surface", "export", "--url", "https://app.example/export",
        "--review-intent", "current-surface-peer-history", "--limit", "51",
    )
    reviewed = run_cli(
        tmp_path, "peer-surface-review", program, "--agent-id", "agent-d", "--run-id", "run-d",
        "--surface", "export", "--url", "https://app.example/export",
        "--review-intent", "current-surface-peer-history", "--tag", "worker", "--limit", "1",
    )

    assert private_list == {"hypotheses": []}
    assert missing_scope.returncode != 0
    assert wrong_intent.returncode != 0
    assert invalid_limit.returncode != 0
    assert reviewed["review_scope"] == "peer-current-surface"
    assert reviewed["review_intent"] == "current-surface-peer-history"
    assert reviewed["query"] == {
        "surface": "export", "url": "https://app.example/export", "tags": ["worker"],
        "statuses": ["active", "blocked", "candidate", "deferred", "queued"],
    }
    assert reviewed["limit"] == 1
    assert reviewed["returned_count"] == 1
    assert reviewed["total_matching_count"] == 1
    assert [item["id"] for item in reviewed["results"]] == [peer_match["id"]]
    assert reviewed["has_more"] is False
    assert reviewed["cursor"] is None


def test_cli_operator_app_review_requires_explicit_operator_request_and_intent(tmp_path):
    program = "demo"
    first = run_cli(
        tmp_path, "create", program, "--agent-id", "agent-a", "--run-id", "run-a",
        "--title", "Export peer", "--surface", "export", "--url", "https://app.example/export",
    )
    second = run_cli(
        tmp_path, "create", program, "--agent-id", "agent-b", "--run-id", "run-b",
        "--title", "Billing peer", "--surface", "billing", "--url", "https://app.example/billing",
    )

    missing_request = run_cli_result(
        tmp_path, "operator-app-review", program, "--agent-id", "operator", "--run-id", "review-1",
        "--operator-intent", "application-thinking-review",
    )
    wrong_intent = run_cli_result(
        tmp_path, "operator-app-review", program, "--agent-id", "operator", "--run-id", "review-1",
        "--operator-request-id", "operator-request-7", "--operator-intent", "wrong",
    )
    invalid_limit = run_cli_result(
        tmp_path, "operator-app-review", program, "--agent-id", "operator", "--run-id", "review-1",
        "--operator-request-id", "operator-request-7", "--operator-intent", "application-thinking-review",
        "--limit", "101",
    )
    reviewed = run_cli(
        tmp_path, "operator-app-review", program, "--agent-id", "operator", "--run-id", "review-1",
        "--operator-request-id", "operator-request-7", "--operator-intent", "application-thinking-review",
        "--limit", "2",
    )

    assert missing_request.returncode != 0
    assert wrong_intent.returncode != 0
    assert invalid_limit.returncode != 0
    assert reviewed["review_scope"] == "operator-app-wide"
    assert reviewed["operator_request_id"] == "operator-request-7"
    assert reviewed["operator_intent"] == "application-thinking-review"
    assert reviewed["query"] == {"statuses": ["active", "blocked", "candidate", "deferred", "queued"]}
    assert reviewed["limit"] == 2
    assert reviewed["returned_count"] == 2
    assert reviewed["total_matching_count"] == 2
    assert {item["id"] for item in reviewed["results"]} == {first["id"], second["id"]}
    assert reviewed["surface_counts"] == {"billing": 1, "export": 1}
    assert reviewed["has_more"] is False
    assert reviewed["cursor"] is None
