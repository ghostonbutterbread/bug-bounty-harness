"""Keep operator guidance aligned with the installed CLI/Core contracts."""

import argparse
from pathlib import Path
import re

from bounty_core.error_store import VALID_CHANNELS, VALID_LAYERS

from agents.error_store import build_parser
from agents.manual_hunter import EDITABLE_FINDING_FIELDS
from agents.map_store import VALID_STATUSES


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"


def _skill(name: str) -> str:
    return (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")


def _documented_values(text: str, label: str) -> set[str]:
    line = next(line for line in text.splitlines() if line.startswith(f"- **{label}"))
    return {value for value in re.findall(r"`([^`]+)`", line) if not value.startswith("--")}


def test_error_store_guidance_matches_record_contract():
    guide = _skill("error-intelligence")
    goal = _skill("bug-goals")
    subcommands = next(
        action for action in build_parser()._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    record = subcommands.choices["record"]
    flags = {flag for action in record._actions for flag in action.option_strings}

    assert {"--signal", "--class"}.isdisjoint(flags)
    assert "not structured Error Store fields" in guide
    assert "not Error Store fields or query filters" in goal
    assert _documented_values(guide, "Layer") == set(VALID_LAYERS)
    assert _documented_values(guide, "Channel") == set(VALID_CHANNELS)


def test_map_store_distinguishes_proof_tag_from_lifecycle_status():
    guide = _skill("map-store")
    assert "confirmed" not in VALID_STATUSES
    assert "`confirmed` is a proof **tag**, not a lifecycle status" in guide
    assert "`--tags confirmed`" in guide


def test_finding_edit_guidance_excludes_derived_severity_label():
    guide = _skill("manual-hunter")
    fields = guide.split("Editable fields are ", 1)[1].split(". `severity_label`", 1)[0]
    assert set(re.findall(r"`([^`]+)`", fields)) == EDITABLE_FINDING_FIELDS
    assert "severity_label" not in EDITABLE_FINDING_FIELDS
