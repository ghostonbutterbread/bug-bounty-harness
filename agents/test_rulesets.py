from __future__ import annotations

from pathlib import Path

from agents.hunt_pipeline.rulesets import hunting_policy_view, resolve_ruleset


def test_desktop_baseline_does_not_imply_electron_overlay(tmp_path: Path) -> None:
    ruleset = resolve_ruleset("auto", target_kind="desktop", target_path=tmp_path)

    assert ruleset.selected_rulesets == ("desktop-baseline",)
    assert ruleset.overlays == ()
    assert "electron" not in ruleset.app_kinds


def test_electron_auto_composes_desktop_baseline_and_electron_overlay(tmp_path: Path) -> None:
    ruleset = resolve_ruleset("auto", target_kind="electron", target_path=tmp_path)

    assert ruleset.base_id == "desktop-baseline"
    assert ruleset.overlays == ("electron-overlay",)
    assert ruleset.selected_rulesets == ("desktop-baseline", "electron-overlay")
    assert ruleset.hypothesis_guidance["surface_family_map"]["ipc"] == "ipc-bridge"
    assert ruleset.policy_hints["policy_id"] == "electron-application-first-loose"


def test_compatibility_alias_resolves_to_ruleset_view_and_policy_hint(tmp_path: Path) -> None:
    ruleset = resolve_ruleset("electron-application-first-loose", target_kind="desktop", target_path=tmp_path)
    policy = hunting_policy_view(ruleset)

    assert ruleset.id == "electron-application-first-loose"
    assert ruleset.compatibility_alias == "electron-application-first-loose"
    assert ruleset.selected_rulesets == ("desktop-baseline", "electron-overlay")
    assert policy.id == "electron-application-first-loose"
