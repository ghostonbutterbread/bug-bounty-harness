"""Prove the release-gate route checks reject missing links, not just names."""
from pathlib import Path
import shutil

import pytest

from agents import test_agent_context_routing as context
from agents import test_shared_skill_adoption as adoption
from agents import test_xss_defense_signal_routing as defense
from agents import test_xss_skill_clarity as clarity
from tests import test_script_policy as policy

ROOT = Path(__file__).resolve().parents[1]


def fixture_files(tmp_path, paths):
    for name in paths:
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)


def remove(path, token):
    content = path.read_text(encoding="utf-8")
    assert token in content
    path.write_text(content.replace(token, "REMOVED"), encoding="utf-8")


@pytest.mark.parametrize("path,token", [
    ("agents/index.md", "Load `/data-store-guidance` early"),
    ("skills/data-store-guidance/SKILL.md", "owner/run-private candidates and their lifecycle. Owner: `/hypothesis-ledger`"),
])
def test_private_hypothesis_route_rejects_a_missing_link(tmp_path, monkeypatch, path, token):
    paths = ["agents/index.md", "AGENTS.md", "INSTRUCTIONS.md", "skills/data-store-guidance/SKILL.md", "skills/hypothesis-ledger/SKILL.md"]
    fixture_files(tmp_path, paths)
    remove(tmp_path / path, token)
    monkeypatch.setattr(context, "ROOT", tmp_path)
    with pytest.raises(AssertionError):
        context.test_root_instructions_point_to_compact_agent_entry_card()


@pytest.mark.parametrize("path,token", [
    ("skills/data-store-guidance/SKILL.md", "/bounty-storage"),
    ("SKILL_REGISTRY.md", "skills/huge-ingest/SKILL.md"),
    ("agents/index.md", "/vulnerability-patch-research"),
])
def test_shared_skill_discovery_rejects_a_missing_link(tmp_path, monkeypatch, path, token):
    paths = ["README.md", "SKILL_REGISTRY.md", "agents/index.md", "skills/data-store-guidance/SKILL.md"]
    paths += [f"skills/{name}/SKILL.md" for name in ("bounty-storage", "huge-ingest", "vulnerability-patch-research")]
    fixture_files(tmp_path, paths)
    remove(tmp_path / path, token)
    monkeypatch.setattr(adoption, "ROOT", tmp_path)
    with pytest.raises(AssertionError):
        adoption.SharedSkillAdoptionTests().test_discovery_docs_and_skills_do_not_reference_source_repo()


@pytest.mark.parametrize("token", [
    "keep pressure on that same vector",
    "Sanitizer behavior: load `xss-technology-research` and `xss-payload-engineering`",
    "WAF/filter behavior: load `waf-live-policy`",
    "inherited safety or stop boundary",
])
def test_defense_route_rejects_missing_safety_or_continuation(tmp_path, monkeypatch, token):
    path = "skills/xss/SKILL.md"
    fixture_files(tmp_path, [path])
    remove(tmp_path / path, token)
    monkeypatch.setattr(defense, "ROOT", tmp_path)
    with pytest.raises(AssertionError):
        defense.test_xss_defense_signals_continue_the_same_consumer_path()


@pytest.mark.parametrize("path,token", [
    ("skills/xss/references/source-acquisition.md", "`js` → `js-pull`"),
    ("skills/js/references/analysis-lens.md", "forward from the value and backward from its final\nconsumer"),
    ("skills/xss/references/source-acquisition.md", "framework raw-HTML/template/trust APIs"),
])
def test_xss_js_route_rejects_missing_acquisition_trace_or_stack_review(tmp_path, monkeypatch, path, token):
    paths = ["skills/xss/SKILL.md", "skills/xss/references/source-acquisition.md", "skills/js/SKILL.md", "skills/js/references/analysis-lens.md", "agents/xss_source_sites.py", "agents/xss_sink_sites.py", "skills/xss/scripts/README.md"]
    fixture_files(tmp_path, paths)
    remove(tmp_path / path, token)
    monkeypatch.setattr(clarity, "ROOT", tmp_path)
    monkeypatch.setattr(clarity, "XSS", tmp_path / "skills/xss/SKILL.md")
    monkeypatch.setattr(clarity, "SOURCE", tmp_path / "skills/xss/references/source-acquisition.md")
    with pytest.raises(AssertionError):
        clarity.test_xss_routes_live_js_loading_and_stack_specific_source_sink_review()


def test_script_index_rejects_missing_required_record_field(tmp_path, monkeypatch):
    script_dir = tmp_path / "scripts"
    script_dir.mkdir()
    (script_dir / "example.py").write_text("# fixture\n", encoding="utf-8")
    index = script_dir / "README.md"
    index.write_text("## `example.py`\n" + "\n".join(policy.REQUIRED_RECORD_FIELDS[:-1]), encoding="utf-8")
    monkeypatch.setattr(policy, "ROOT", tmp_path)
    with pytest.raises(AssertionError, match="Last verified"):
        policy.assert_index_covers_scripts(script_dir, index)
