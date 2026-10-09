from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_js_routes_broad_and_focused_hunts_without_losing_legacy_entrypoints() -> None:
    router = text("skills/js/SKILL.md")
    registry = text("SKILL_REGISTRY.md")
    assert "name: js\n" in router
    assert "`/js-pull`" in router and "`/js-hunt`" in router
    assert '"hunt the JavaScript"' in router
    assert "--focus" in router
    assert "`analyze`" in router and "`deep`" in router
    assert "`offline-fanout`" in router and "`generate`" in router
    assert "**JSLuice**" in router and "Load `/jsluice`" in router
    assert "skills/js-pull/SKILL.md" in registry
    assert "skills/js-hunt/SKILL.md" in registry
    assert "legacy analyze/deep/offline-fanout/generate remain supported" in registry


def test_pull_preserves_existing_inventory_and_scope_contract() -> None:
    pull = text("skills/js-pull/SKILL.md")
    for required in (
        "agents/js_analyzer.py inventory",
        "--target-host",
        "source_map_modules.jsonl",
        "metadata.jsonl",
        "packets.jsonl",
        "js_info.sqlite",
        "prompts/js-playbook.md",
    ):
        assert required in pull
    assert "not a finding" in pull
    assert "inline" in pull


def test_hunt_is_adaptive_and_evidence_led_not_a_class_matrix() -> None:
    hunt = text("skills/js-hunt/SKILL.md")
    playbook = text("prompts/js-playbook.md")
    fanout = text("skills/js/references/offline-fanout.md")
    for required in (
        "broad behavior map",
        "request builders",
        "state",
        "secrets",
        "anomal",
        "prioritize",
        "deep trace",
        "missing proof",
        "coverage",
        "--focus endpoints",
        "--focus params",
        "--focus secrets",
        "--focus application-logic",
        "--focus dataflows",
        "native_fanout",
    ):
        assert required.lower() in hunt.lower()
    assert "no fixed" in hunt.lower()
    assert "live validation" in hunt.lower()
    assert "`/js-hunt`" in playbook
    assert "`/js-hunt`" in fanout
    assert "three complementary review roles" in playbook
    assert "no more than three active JS-review subagents" in playbook
    assert "select only evidence-supported broad follow-up categories" not in " ".join(playbook.split())
    assert "at most three active JS-review subagents" in fanout


def test_hunt_handoff_names_evidence_and_separate_validation() -> None:
    hunt = text("skills/js-hunt/SKILL.md")
    for required in (
        "JS URL",
        "sha256",
        "packet path",
        "page/flow",
        "controllability",
        "observed",
        "hypothesis",
        "next discriminator",
        "`/analyze-endpoint`",
        "`/url-ingest`",
        "`/map-store`",
    ):
        assert required.lower() in hunt.lower()
    assert "third-party" in hunt
    assert "owned" in hunt
