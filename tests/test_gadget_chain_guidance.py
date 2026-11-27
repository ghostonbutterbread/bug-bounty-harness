"""Offline gadget-card handoff and route contract; no target traffic."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agents.map_store import MapStore


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/map-store/SKILL.md"
REFERENCE = ROOT / "skills/map-store/references/map-store-reference.md"


def test_gadget_guidance_keeps_missing_link_and_finding_boundary() -> None:
    skill = " ".join(SKILL.read_text(encoding="utf-8").split())
    detail = " ".join(REFERENCE.read_text(encoding="utf-8").split())
    assert "--tags gadget --intent gadget --limit 20" in skill
    assert "query returns pointers, not a semantic chain matcher" in skill
    assert "matching words alone do not establish a usable supplier" in skill
    assert "independently verified, ingest that vulnerability through `/ledger`" in skill
    assert "a local header rewrite proves only header-conditional execution" in detail
    assert "one named independent capability missing" in detail
    assert "not a new field, finding status" in detail


def test_confirmed_gadgets_remain_queryable_for_manual_composition(tmp_path: Path) -> None:
    """Exercise the real MapStore write/query path in a synthetic program."""
    store = MapStore("synthetic", root=str(tmp_path))
    sink = store.write(
        url="https://app.example.test/view",
        surface="xss",
        title="Header-conditional script sink",
        body=(
            "Capability:\n"
            "- grants: script execution only when the document lacks CSP\n"
            "- requires: victim document navigation carries exact X-Requested-With token\n"
            "- crosses: client->browser\n"
            "- chain_status: ready\n"
            "- chain_watch: an attacker-reachable writer for victim document headers\n"
            "Checked: no writer yet; next: examine first-party navigation paths.\n"
        ),
        tags=["gadget", "confirmed"],
    )
    decoy = store.write(
        url="https://app.example.test/api",
        surface="api",
        title="XHR-only header setter",
        body=(
            "Capability:\n"
            "- grants: sets the token on XHR requests only\n"
            "- requires: XHR caller\n"
            "- crosses: client->server\n"
            "- chain_status: ready\n"
            "- chain_watch: a consumer of XHR response data\n"
        ),
        tags=["gadget", "confirmed"],
    )
    query = subprocess.run(
        [
            sys.executable, str(ROOT / "agents/map_store.py"), "query",
            "--program", "synthetic", "--root", str(tmp_path),
            "--tags", "gadget", "--intent", "gadget", "--limit", "20", "--json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    rows = json.loads(query.stdout)["observations"]
    assert {row["title"] for row in rows} == {
        "Header-conditional script sink", "XHR-only header setter",
    }
    assert {row["path"] for row in rows} == {
        str(sink.relative_to(store.maps_root)),
        str(decoy.relative_to(store.maps_root)),
    }
    assert "victim document navigation" in sink.read_text(encoding="utf-8")
    assert "XHR requests only" in decoy.read_text(encoding="utf-8")
    assert not (tmp_path / "web_bounty/synthetic/web/ledgers/ledger.json").exists()
