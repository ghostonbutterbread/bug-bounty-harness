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
            name = f"bunny-{role}"
            self.assertIn(f"`{name}`", text)
            agent = SKILL.parent / "agents" / f"{name}.md"
            body = agent.read_text(encoding="utf-8")
            self.assertTrue(body.startswith(f"---\nname: {name}\n"))
            self.assertIn("description:", body)
            self.assertIn("Follow the coordinator's scoped task packet", body)
        self.assertIn("role written only in the prompt or `description`", text)
        self.assertIn("instead of silently launching `general-purpose`", text)

    def test_registered(self):
        registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
        self.assertIn("| **bunny** |", registry)
        self.assertIn("`skills/bunny/SKILL.md`", registry)


if __name__ == "__main__":
    unittest.main()
