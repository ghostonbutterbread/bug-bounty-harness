from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "bunny" / "SKILL.md"


class BunnySkillTests(unittest.TestCase):
    def test_opt_in_mode_and_role_boundary(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertIn("name: bunny", text)
        self.assertIn("opt-in", text)
        self.assertIn("Keep `hunt-orchestration`", text)
        for role in ("Hunter/steward", "Recon", "Verifier", "Reporter"):
            self.assertIn(role, text)
        self.assertIn("persistent coordinator", text)

    def test_account_and_evidence_guards(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertIn("not as a universal start gate", text)
        self.assertIn("A logout is a diagnostic event", text)
        self.assertIn("never a factual finding", text)
        self.assertIn("verified reportable finding", text)

    def test_role_visible_agent_names(self):
        text = SKILL.read_text(encoding="utf-8")
        for role in ("hunter", "recon", "verifier", "reporter"):
            self.assertIn(f"bunny-{role}-", text)
        self.assertIn("Claude Code's Agent tool", text)
        self.assertIn("unique, short `name`", text)
        self.assertIn("role written only inside the prompt does not rename", text)
        self.assertIn("alongside the ordinary scoped `description` and full task packet", text)

    def test_registered(self):
        registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
        self.assertIn("| **bunny** |", registry)
        self.assertIn("`skills/bunny/SKILL.md`", registry)


if __name__ == "__main__":
    unittest.main()
