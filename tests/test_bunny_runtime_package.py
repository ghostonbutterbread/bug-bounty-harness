"""Discovery contracts for the canonical Bunny roles (no model calls)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_role_instructions_are_read_before_workers_act():
    text = (ROOT / "skills/bunny/references/dispatch.md").read_text()
    assert "read the canonical role file" in text
    assert "before acting" in text


def test_collaborative_workers_confirm_role_and_mode_before_target_actions():
    text = " ".join((ROOT / "skills/bunny/references/dispatch.md").read_text().split())
    assert "selected checkout's `bunny-collaborative`" in text
    assert "wait for Bunny's go-ahead" in text
    assert "before any target action" in text


def test_verifier_and_reporter_are_spawned_only_when_needed():
    text = (ROOT / "skills/bunny-collaborative/SKILL.md").read_text()
    assert "`bunny-verifier` for a credible candidate" in text
    assert "`bunny-reporter` after verified evidence" in text


def test_collaborative_routes_dispatch_through_owning_bunny_skill():
    text = (ROOT / "skills/bunny-collaborative/SKILL.md").read_text()
    assert "`bunny` skill's `references/dispatch.md`" in text
    assert "../bunny/references/dispatch.md" not in text


def test_router_loads_dispatch_only_for_collaborative_mode():
    router = (ROOT / "skills/bunny/SKILL.md").read_text()
    assert "Before collaborative dispatch, load [Bunny team dispatch]" in router


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
    text = " ".join((ROOT / "skills/bunny/references/dispatch.md").read_text().lower().split())
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
    assert "share one team browser by default" in text
    assert "one active controller at a time" in text
    assert "owner remains its driver" in text
    assert "another browser" in text
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
