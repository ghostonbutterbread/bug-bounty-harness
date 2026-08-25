#!/usr/bin/env python3
"""Regression coverage for the cross-run leads skill contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_leads_skill_is_registered_as_cross_run_and_class_neutral() -> None:
    skill = (ROOT / "skills" / "leads" / "SKILL.md").read_text()
    registry = (ROOT / "SKILL_REGISTRY.md").read_text()

    assert "name: leads" in skill
    assert "cross-run" in skill
    assert "not a live-testing lane" in skill
    assert "not XSS-specific" in skill
    assert "`/leads <program> [--class <vuln-class>]`" in registry


def test_leads_skill_uses_mapstore_projection_and_private_hypotheses() -> None:
    skill = (ROOT / "skills" / "leads" / "SKILL.md").read_text()

    assert "MapStore" in skill
    assert "Hypothesis Ledger" in skill
    assert "`lead`" in skill
    assert "--needs-you" in skill
    assert "Do not expose another live agent's private hypotheses" in skill
    assert "Every lead touched during a run receives a disposition" in skill
