"""The ledger's severity route must resolve to a program-first skill."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/program-severity-scoring/SKILL.md"
LEDGER = ROOT / "skills/ledger/SKILL.md"
REGISTRY = ROOT / "SKILL_REGISTRY.md"


def test_route_resolves_to_local_registered_skill_with_metadata() -> None:
    ledger = LEDGER.read_text(encoding="utf-8")
    assert "load the `program-severity-scoring` skill" in ledger
    entry = "| **program-severity-scoring** | `/program-severity-scoring {program}` | `skills/program-severity-scoring/SKILL.md` |"
    assert entry in REGISTRY.read_text(encoding="utf-8")
    content = SKILL.read_text(encoding="utf-8")
    match = re.match(r"\A---\n(?P<header>.*?)\n---\n\s*(?P<body>\S.*)", content, re.DOTALL)
    assert match, "skill requires nonempty body and frontmatter"
    assert re.search(r"^name: program-severity-scoring$", match["header"], re.MULTILINE)
    assert re.search(r"^description: .+", match["header"], re.MULTILINE)


def test_scoring_contract_does_not_invent_a_rating() -> None:
    content = SKILL.read_text(encoding="utf-8")
    for required in (
        "published program", "program-policy.md", "platform rubric", "CVSS",
        "demonstrated", "cap", "UNKNOWN", "Scoring Authority",
        "Severity Rationale", "Program Constraint", "unproven",
    ):
        assert required in content
    assert "P1 =" not in content
    assert "P1 is" not in content
    assert "Do not assign a provisional high severity" in content
    assert "normalization is not scoring" in content
    assert content.index("published program's specific overrides") < content.index("platform rubric")
    assert "only when the program requires\n   CVSS" in content
    assert "If the controlling program policy or delegated rubric is inaccessible" in content
    assert "leave report readiness blocked" in content
