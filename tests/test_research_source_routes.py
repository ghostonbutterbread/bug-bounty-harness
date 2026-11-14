"""Verify the research-source guide is discoverable and packaged."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
ENTRY_ROUTES = (
    "hunt", "bug-goals", "waf", "xss-technology-research",
    "rce-technology-research", "vulnerability-patch-research",
)


def route_errors(root: Path) -> list[str]:
    skills = root / "skills"
    entry = skills / "research-knowledge-management" / "SKILL.md"
    intake = skills / "research-source-intake" / "SKILL.md"
    mapping = skills / "research-knowledge-management" / "references" / "research-source-map.md"
    registry = root / "SKILL_REGISTRY.md"
    paths = [skills / name / "SKILL.md" for name in ENTRY_ROUTES]
    receipt = skills / "research-knowledge-management/references/source-evaluations/hexbrain.md"
    required = [entry, intake, mapping, registry, receipt, *paths]
    missing = [str(p.relative_to(root)) for p in required if not p.is_file()]
    if missing:
        return missing
    e, i, m, r = (p.read_text(encoding="utf-8") for p in required[:4])
    errors = []
    for token, text in (
        ("`references/research-source-map.md`", e),
        ("`research-source-intake`", e),
        ("name: research-source-intake", i),
        ("`references/research-source-map.md`", i),
        ("`research-knowledge-management`", i),
        ("| **research-source-intake** |", r),
        ("research-source-intake", m),
        ("references/source-evaluations/hexbrain.md", m),
    ):
        if token not in text:
            errors.append(token)
    for path in paths:
        text = " ".join(path.read_text(encoding="utf-8").split())
        if "`research-knowledge-management` and its source map" not in text and "`research-knowledge-management` and its on-demand source map" not in text:
            errors.append(str(path.relative_to(root)))
    return errors


class ResearchSourceRoutesTest(unittest.TestCase):
    def test_source_map_and_intake_are_discoverable(self):
        self.assertEqual(route_errors(ROOT), [])
        entry = (SKILLS / "research-knowledge-management" / "SKILL.md").read_text()
        goal = (SKILLS / "bug-goals" / "SKILL.md").read_text()
        self.assertIn("`research-knowledge-management` and its on-demand source map", goal)
        for ref in re.findall(r"`(references/[^`]+\.md)`", entry):
            self.assertTrue((SKILLS / "research-knowledge-management" / ref).is_file(), ref)

    def test_missing_map_fails_route_validation(self):
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            fixture = Path(d)
            for rel in (
                "SKILL_REGISTRY.md",
                "skills/research-knowledge-management/SKILL.md",
                "skills/research-source-intake/SKILL.md",
                "skills/research-knowledge-management/references/research-source-map.md",
                "skills/research-knowledge-management/references/source-evaluations/hexbrain.md",
                *(f"skills/{name}/SKILL.md" for name in ENTRY_ROUTES),
            ):
                dest = fixture / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / rel, dest)
            self.assertEqual(route_errors(fixture), [])
            (fixture / "skills/research-knowledge-management/references/research-source-map.md").unlink()
            self.assertTrue(route_errors(fixture))

    def test_missing_upstream_hunt_pointer_fails_route_validation(self):
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            fixture = Path(d)
            for rel in (
                "SKILL_REGISTRY.md", "skills/research-knowledge-management/SKILL.md",
                "skills/research-source-intake/SKILL.md",
                "skills/research-knowledge-management/references/research-source-map.md",
                "skills/research-knowledge-management/references/source-evaluations/hexbrain.md",
                *(f"skills/{name}/SKILL.md" for name in ENTRY_ROUTES),
            ):
                dest = fixture / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / rel, dest)
            self.assertEqual(route_errors(fixture), [])
            hunt = fixture / "skills/hunt/SKILL.md"
            hunt.write_text(hunt.read_text().replace("`research-knowledge-management` and its source map", "research"))
            self.assertIn("skills/hunt/SKILL.md", route_errors(fixture))

    def test_use_cases_access_and_boundaries_are_present(self):
        mapping = " ".join((SKILLS / "research-knowledge-management/references/research-source-map.md").read_text().split())
        for text in (
            "MapStore", "ResearchMap", "HexBrain", "Preview", "PortSwigger",
            "PayloadsAllTheThings", "program-finder", "technology-research",
            "authenticated", "have not been verified", "safe-fetch",
            "not target safety", "Applicable policy still owns research and closure",
        ):
            self.assertIn(text, mapping)
        intake = (SKILLS / "research-source-intake/SKILL.md").read_text()
        for text in ("at least", "existing resource", "needs-access", "needs-verification", "private reports", "not target proof"):
            self.assertIn(text, intake)


if __name__ == "__main__":
    unittest.main()
