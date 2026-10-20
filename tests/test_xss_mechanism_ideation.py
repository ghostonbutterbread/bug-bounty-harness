"""The XSS idea layer remains reachable without replacing lane proof or cards."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_router_reaches_incremental_ideation_without_replacing_lanes() -> None:
    router = read("skills/xss/SKILL.md")
    payload = read("skills/xss-payload-engineering/SKILL.md")
    research = read("skills/xss-technology-research/SKILL.md")
    reference = ROOT / "skills/xss-payload-engineering/references/mechanism-ideation.md"
    assert reference.is_file()
    for lane in ("reflected-xss", "stored-xss", "dom-xss", "blind-xss"):
        assert lane in router
    assert "xss-payload-engineering" in router
    assert "mechanism-ideation.md" in router
    assert "mechanism-ideation.md" in payload
    assert "mechanism-ideation.md" in research
    assert "selected lane still owns proof" in router


def test_nonfire_and_sanitizer_branch_preserve_causal_controls() -> None:
    router = read("skills/xss/SKILL.md")
    payload = read("skills/xss-payload-engineering/SKILL.md")
    ideation = read("skills/xss-payload-engineering/references/mechanism-ideation.md")
    assert "consumer mounted" in router and "inert control rendered" in router
    assert "do not infer that a sanitizer held" in router
    assert "Build candidates **backward from the final interpreter**" in payload
    for distinction in (
        "Mutation XSS (mXSS)",
        "Fragmentation/reassembly",
        "Double decode / entity / Unicode",
        "Sanitizer output vs safe use",
    ):
        assert distinction in ideation
    assert "Same safe tree after all real parses" in ideation
    assert "Assembly happens before the sanitizer" in ideation
    assert "Backend rejects the variant before storage" in ideation
    assert "a permissive default policy" in ideation
    assert "A local fixture can teach that contrast but never proves" in ideation
    assert "target facts in MapStore" in ideation


def test_research_trigger_stays_evidence_specific() -> None:
    research = read("skills/xss-technology-research/SKILL.md")
    assert "exact\nmissing parser or composition edge" in research
    assert "not a generic \"mXSS bypass\"" in research
    assert "External material is hypothesis input, never target proof" in research
