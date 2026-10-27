"""Discovery contracts for the canonical Bunny roles (no model calls)."""
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_pi_package_exports_the_existing_role_definitions():
    manifest = ROOT / "skills/bunny/package.json"
    assert manifest.is_file(), "Bunny roles need a Pi package export, not worker aliases"
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


def test_router_loads_the_runtime_dispatch_contract():
    bunny = ROOT / "skills/bunny"
    router = (bunny / "SKILL.md").read_text()
    assert "(references/dispatch.md)" in router
    dispatch = bunny / "references/dispatch.md"
    assert dispatch.is_file()
    text = dispatch.read_text()
    assert "PI_SUBAGENT_EXTRA_AGENT_DIRS" in text
    assert 'agent: "bunny-hunter"' in text
    assert "resolved role file" in text
    assert "not a generic `worker`" in text
    assert "read back" in text
    assert "delegate_task" in text


def test_dispatch_does_not_load_collaborative_roles_for_offhand_workers():
    text = (ROOT / "skills/bunny/references/dispatch.md").read_text()
    assert "explicit offhand" in text
    assert "ordinary scoped workers" in text
    assert "do not launch these collaborative role files" in text


def test_read_only_pi_parent_keeps_native_coordination_tools():
    text = (ROOT / "skills/bunny/references/dispatch.md").read_text()
    assert "--tools" in text
    assert "subagent,bg_wait,subagent_supervisor" in text
    assert "allowlist replaces" in text


def test_store_handoff_is_pointer_based_and_acknowledged():
    text = (ROOT / "skills/bunny-collaborative/SKILL.md").read_text()
    for phrase in ["Pointer handoffs", "recipient acknowledges", "read-back", "existing stores", "do not copy"]:
        assert phrase in text


def test_pi_handoff_workers_have_independent_async_completion():
    text = (ROOT / "skills/bunny/references/dispatch.md").read_text()
    assert "individual async runs" in text
    assert "aggregate completion" in text
    assert "replyTo" in text
    assert 'action: "get", agent: "bunny-hunter"' in text


def test_operations_and_evidence_ownership_stay_separate():
    text = (ROOT / "skills/bunny-collaborative/SKILL.md").read_text()
    assert "Coordinator-owned operational support" in text
    assert "designated worker identity" in text
    assert "unrelated productive work" in text
    assert "Evidence authorship stays with the producer" in text
    assert "not an implicit surface-lease transfer" in text


def test_investigative_pi_runs_do_not_infer_coding_acceptance():
    text = (ROOT / "skills/bunny/references/dispatch.md").read_text()
    assert "acceptance: false" in text
    assert "does not disable an assigned verification gate" in text


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
