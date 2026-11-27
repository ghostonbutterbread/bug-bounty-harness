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
    assert "For gadget matching and promotion, load `references/map-store-reference.md`" in skill
    assert "gadget query returns pointers, not a semantic chain matcher" in detail
    assert "Matching words alone do not establish a usable supplier" in detail
    assert "independently verified, ingest through `/ledger`" in detail
    assert "sanitized `/leads` projection linked to the MapStore card" in detail
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
    payload = json.loads(query.stdout)
    rows = payload["observations"]
    assert payload["has_more"] is False
    assert {row["title"] for row in rows} == {
        "Header-conditional script sink", "XHR-only header setter",
    }
    assert {row["path"] for row in rows} == {
        str(sink.relative_to(store.maps_root)),
        str(decoy.relative_to(store.maps_root)),
    }
    assert "victim document navigation" in sink.read_text(encoding="utf-8")
    assert "XHR requests only" in decoy.read_text(encoding="utf-8")
    # A bounded public Lead projects the exact missing link without moving the
    # conditional sink into the Findings ledger.
    lead = subprocess.run(
        [
            sys.executable, str(ROOT / "agents/leads.py"), "create",
            "--program", "synthetic", "--root", str(tmp_path),
            "--class", "xss", "--surface", "xss",
            "--url", "https://app.example.test/view",
            "--title", "Needs victim document header writer",
            "--observed-basis", "header-conditional execution on owned fixture",
            "--candidate-chain", "writer -> document request -> execution",
            "--exact-unknown", "Can a victim navigation carry the token?",
            "--next-discriminator", "Check a distinct first-party navigation writer",
            "--wake-condition", "new document-request header writer observed",
            "--evidence-ref", sink.relative_to(store.maps_root).as_posix(),
            "--relative-id",
        ],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    lead_card = store.read_obs(lead.stdout.strip())
    assert lead_card is not None
    assert "Exact unknown: Can a victim navigation carry the token?" in lead_card
    assert sink.relative_to(store.maps_root).as_posix() in lead_card
    search = subprocess.run(
        [sys.executable, str(ROOT / "agents/leads.py"), "search",
         "--program", "synthetic", "--root", str(tmp_path), "--class", "xss"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    assert "Needs victim document header writer" in search.stdout
    assert not (tmp_path / "web_bounty/synthetic/web/ledgers/ledger.json").exists()


def test_gadget_query_reports_more_matches_after_a_bounded_window(tmp_path: Path) -> None:
    store = MapStore("synthetic", root=str(tmp_path))
    for index in range(21):
        store.write(
            url=f"https://app.example.test/g/{index}", surface="xss",
            title=f"gadget {index:02d}", body="Capability:\n- grants: observed effect\n",
            tags=["gadget"],
        )
    # A newer non-gadget cannot consume the limit ahead of gadget filtering.
    store.write(
        url="https://app.example.test/unrelated", surface="api",
        title="unrelated fact", body="Unrelated observation", tags=["observed"],
    )
    argv = [
        sys.executable, str(ROOT / "agents/map_store.py"), "query",
        "--program", "synthetic", "--root", str(tmp_path),
        "--intent", "gadget", "--limit", "20", "--json",
    ]
    result = subprocess.run(argv, cwd=ROOT, check=True, capture_output=True, text=True)
    payload = json.loads(result.stdout)
    assert len(payload["observations"]) == 20
    assert payload["has_more"] is True
    assert "narrow filters or raise --limit" in result.stderr
    assert all("gadget" in row["tags"] for row in payload["observations"])

    # Even without an explicit limit, the text display only prints ten pointers.
    text = subprocess.run(argv[:-3], cwd=ROOT, check=True, capture_output=True, text=True)
    assert "more matches; narrow filters or raise --limit" in text.stdout
