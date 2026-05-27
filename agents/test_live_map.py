from __future__ import annotations

import json
from pathlib import Path

from agents.live_map import (
    build_handoffs,
    ensure_map,
    ingest_observations,
    map_paths,
    read_jsonl,
)


def test_live_map_ingests_routes_and_derives_access_control_handoff(tmp_path: Path) -> None:
    counts = ingest_observations(
        "demo",
        [
            {
                "type": "route",
                "method": "GET",
                "url": "https://target.example/my-account?id=wiener",
                "status": 200,
                "auth_state": "user:wiener",
                "title": "My account",
            }
        ],
        source="browser",
        shared_base=tmp_path,
        run_id="browser-smoke",
    )

    paths = map_paths("demo", shared_base=tmp_path)

    assert counts["routes"] == 1
    routes = read_jsonl(paths.routes)
    assert routes[0]["tags"] == ["object-reference"]
    objects = read_jsonl(paths.objects)
    assert objects[0]["kind"] == "id"
    hypotheses = read_jsonl(paths.hypotheses)
    assert hypotheses[0]["lane"] == "access-control:horizontal"

    packets = build_handoffs("demo", shared_base=tmp_path)

    assert len(packets) == 1
    payload = json.loads(packets[0].read_text(encoding="utf-8"))
    assert payload["skill"] == "access-control"
    assert payload["routes"][0]["url"] == "https://target.example/my-account?id=wiener"
    assert payload["instructions"][0] == "Do not assume the vulnerability class is proven."


def test_live_map_dedupes_same_route_auth_state(tmp_path: Path) -> None:
    observations = [
        {
            "type": "route",
            "method": "GET",
            "url": "https://target.example/projects/123?workspace_id=abc",
            "auth_state": "user:a",
        }
    ]

    ingest_observations("demo", observations, source="proxy", shared_base=tmp_path)
    ingest_observations("demo", observations, source="proxy", shared_base=tmp_path)

    paths = ensure_map("demo", shared_base=tmp_path)
    assert len(read_jsonl(paths.routes)) == 1
    hypotheses = read_jsonl(paths.hypotheses)
    lanes = {row["lane"] for row in hypotheses}
    assert "access-control:horizontal" in lanes
    assert "access-control:tenant" in lanes


def test_live_map_accepts_manual_flow_records(tmp_path: Path) -> None:
    counts = ingest_observations(
        "demo",
        [
            {
                "type": "flow",
                "name": "login",
                "flow_type": "auth",
                "entry_url": "https://target.example/login",
                "auth_state": "anonymous",
            }
        ],
        source="manual",
        shared_base=tmp_path,
    )

    paths = map_paths("demo", shared_base=tmp_path)

    assert counts["flows"] == 1
    flow = read_jsonl(paths.flows)[0]
    assert flow["id"] == "F0001"
    assert flow["source"] == "manual"


def test_live_map_blind_mode_redacts_route_hints_and_adds_browser_redaction(tmp_path: Path) -> None:
    ingest_observations(
        "demo",
        [
            {
                "type": "route",
                "method": "GET",
                "url": "https://target.example/admin",
                "status": 200,
                "auth_state": "user:wiener",
                "title": "Lab: Multi-step process with no access control on one step",
                "notes": "Top-left lab banner exposed the expected vulnerability.",
            },
            {
                "type": "hypothesis",
                "lane": "access-control:vertical",
                "summary": "Observed an administrator-only route while authenticated as low privilege.",
                "recommended_skill": "access-control",
                "recommended_pack": "vertical",
                "source_route_ids": ["R0001"],
                "source_object_ids": [],
                "status": "candidate",
            },
        ],
        source="browser",
        shared_base=tmp_path,
    )

    packets = build_handoffs("demo", shared_base=tmp_path, blind_mode=True)

    payload = json.loads(packets[0].read_text(encoding="utf-8"))
    route = payload["routes"][0]
    assert payload["blind_mode"]["enabled"] is True
    assert "document.title" in payload["blind_mode"]["browser_redaction_js"]
    assert payload["instructions"][0].startswith("Blind mode is active")
    assert route["blind_mode_redacted"] is True
    assert "title" not in route
    assert "notes" not in route
