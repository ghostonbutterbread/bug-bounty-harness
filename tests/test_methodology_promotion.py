"""Offline guards for the methodology routes selectively promoted into BBH."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"


def body(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class MethodologyPromotionTest(unittest.TestCase):
    def test_public_program_shortlist_has_canonical_entry_and_no_auth_claim(self):
        finder = body("skills/program-finder/SKILL.md")
        self.assertTrue(finder.startswith("---\nname: program-finder\n"))
        self.assertIn("| **program-finder** |", body("SKILL_REGISTRY.md"))
        self.assertIn("load `/program-finder`", body("agents/index.md"))
        for phrase in ("not reconnaissance", "not testing permission", "JavaScript Lens — not applicable", "unknown"):
            self.assertIn(phrase, finder)
        self.assertFalse((SKILLS / "program-finder" / "references" / "live-target-list.md").exists())

    def test_capability_route_keeps_runtime_map_and_behavior_distinct(self):
        entry = body("skills/live-map/SKILL.md")
        playbook = body("prompts/live-map-playbook.md")
        map_ref = body("skills/map-store/references/map-store-reference.md")
        for text in (entry, playbook):
            self.assertIn("MapStore", text)
            self.assertIn("Behavior", text)
            self.assertIn("unknown", text)
        self.assertIn("prints an absolute path", map_ref)
        self.assertIn("complete existing-plus-new", map_ref)
        self.assertIn("named, factual\n   Application Behaviors", body("agents/index.md"))
        self.assertFalse((SKILLS / "application-surface-mapping").exists())

    def test_scanner_qualification_has_bounded_nonblocking_truth(self):
        skill = body("skills/bounty-tools/SKILL.md")
        playbook = body("prompts/bounty-tools-playbook.md")
        xss = body("skills/xss/references/tool-assisted-discovery.md")
        self.assertIn("Long-running startup qualification", skill)
        self.assertIn("does **not** implement a mid-run progress", skill)
        self.assertIn("`tool-run` is synchronous", playbook)
        self.assertIn("A source and sink mentioned in the\nsame static bundle are not a proven data-flow edge", xss)
        self.assertFalse((SKILLS / "scanner-startup-validation").exists())

    def test_research_synthesis_is_on_demand_and_recon_schedule_is_inactive(self):
        research = body("skills/research-knowledge-management/SKILL.md")
        synthesis = body("skills/research-knowledge-management/references/functionality-first-writeup-synthesis.md")
        recon = body("skills/recon/SKILL.md")
        maintenance = body("skills/bounty-tools/references/recon-maintenance-automation.md")
        self.assertIn("For an explicit product-class", research)
        self.assertIn("case-admission", research)
        self.assertIn("only a narrow, reviewed portable mechanism", synthesis)
        self.assertIn("consult `/bounty-tools`", recon)
        self.assertIn("offline-review-only", maintenance)
        self.assertIn("does **not** implement", maintenance)
        self.assertIn("never execute a stored `command`", maintenance)
        self.assertFalse((SKILLS / "recon-automation").exists())


if __name__ == "__main__":
    unittest.main()
