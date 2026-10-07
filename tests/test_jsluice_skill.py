from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_js_tool_map_routes_to_registered_jsluice_skill() -> None:
    js = (ROOT / "skills/js/SKILL.md").read_text(encoding="utf-8")
    registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
    playbook = (ROOT / "prompts/js-playbook.md").read_text(encoding="utf-8")

    assert "## Tool Map" in js
    assert "**JSLuice**" in js
    assert "Load `/jsluice`" in js
    assert "skills/jsluice/SKILL.md" in registry
    assert "load `/jsluice`" in playbook
    assert "jsluice urls" not in js  # Tool details belong to the focused skill.


def test_jsluice_skill_has_local_modes_and_proof_limits() -> None:
    skill = (ROOT / "skills/jsluice/SKILL.md").read_text(encoding="utf-8")

    assert skill.startswith("---\nname: jsluice\ndescription:")
    assert "jsluice urls \"$LOCAL_JS_FILE\"" in skill
    assert "jsluice secrets \"$LOCAL_JS_FILE\"" in skill
    assert "jsluice query -q '(string) @matches' \"$LOCAL_JS_FILE\"" in skill
    for field in ("artifact_path", "sha256", "run_id", "provenance"):
        assert field in skill
    assert "never an HTTP URL" in skill
    assert "not proof of a sink or vulnerability" in skill
    assert "BBH wrapper" in skill
