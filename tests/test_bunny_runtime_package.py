"""Discovery contracts for the canonical Bunny roles (no model calls)."""
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_pi_package_exports_the_existing_role_definitions():
    manifest = ROOT / "skills/bunny/package.json"
    if not manifest.exists():
        return
    package = json.loads(manifest.read_text())
    roots = package["pi"]["subagents"]["agents"]
    assert roots == ["./agents"]
    roles = {}
    for directory in roots:
        for path in (manifest.parent / directory).glob("*.md"):
            _, header, body = path.read_text().split("---", 2)
            metadata = yaml.safe_load(header)
            roles[metadata["name"]] = (metadata, body)
    assert set(roles) == {"bunny-hunter", "bunny-recon", "bunny-verifier", "bunny-reporter"}
    for metadata, body in roles.values():
        assert metadata.get("advertise") is True
        assert "bunny-collaborative" in body
        assert "Do not allocate other workers" in body


def test_router_loads_the_team_dispatch_contract():
    bunny = ROOT / "skills/bunny"
    router = (bunny / "SKILL.md").read_text()
    assert "(references/dispatch.md)" in router
    dispatch = bunny / "references/dispatch.md"
    assert dispatch.is_file()
    text = dispatch.read_text()
    for phrase in [
        "ordinary subagent tools",
        "do not build or require a harness-specific",
        "Bunny talks with recon",
        "Bunny talks with the hunter",
        "Recon and the hunter talk with each other",
        "Bunny relays",
    ]:
        assert phrase in text
    assert "PI_SUBAGENT_EXTRA_AGENT_DIRS" not in text
    assert "subagent({" not in text


def test_dispatch_does_not_load_collaborative_roles_for_offhand_workers():
    text = (ROOT / "skills/bunny/references/dispatch.md").read_text()
    assert "explicit offhand" in text
    assert "ordinary scoped workers" in text
    assert "do not launch these collaborative role files" in text


def test_dispatch_does_not_prescribe_a_harness():
    text = (ROOT / "skills/bunny/references/dispatch.md").read_text()
    assert "current harness" in text
    assert "ordinary subagent tools" in text


def test_store_handoff_is_pointer_based_and_acknowledged():
    text = (ROOT / "skills/bunny-collaborative/SKILL.md").read_text()
    for phrase in ["Pointer handoffs", "recipient acknowledges", "read-back", "existing stores", "do not copy"]:
        assert phrase in text


def test_team_messages_are_direct_with_explicit_relay_fallback():
    text = (ROOT / "skills/bunny/references/dispatch.md").read_text()
    assert "Recon and the hunter talk with each other" in text
    assert "Bunny relays" in text


def test_operations_and_evidence_ownership_stay_separate():
    text = (ROOT / "skills/bunny-collaborative/SKILL.md").read_text()
    assert "Coordinator-owned operational support" in text
    assert "designated worker identity" in text
    assert "unrelated productive work" in text
    assert "Evidence authorship stays with the producer" in text
    assert "not an implicit surface-lease transfer" in text


def test_investigative_runs_keep_worker_autonomy():
    text = (ROOT / "skills/bunny-collaborative/SKILL.md").read_text()
    assert "does not expand authority" in text


def test_continuity_keeps_the_investigator_and_distinguishes_stop_causes():
    text = (ROOT / "skills/bunny-collaborative/SKILL.md").read_text()
    for phrase in ["A new question", "same investigator", "harness deadline", "provider/process failure", "new segment ID"]:
        assert phrase in text
    role = (ROOT / "agents/bunny-hunter.md").read_text()
    assert "choose and revise your investigative theory" in role


def test_blunt_challenge_is_not_followed_by_motivational_disclaimers():
    text = (ROOT / "skills/bunny-collaborative/SKILL.md").read_text()
    assert "Do not append a motivational disclaimer" in text
    assert "internal evidence rule" in text
