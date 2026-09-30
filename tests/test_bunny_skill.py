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

    def test_native_worker_names(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertIn("current harness's native subagent", text)
        self.assertIn("Set the native worker name when supported", text)
        self.assertIn("If native naming is unavailable", text)
        self.assertIn("task title/description and scoped packet", text)
        self.assertIn("harness's available agent type", text)
        self.assertNotIn("Claude Code", text)
        self.assertNotIn("subagent_type", text)
        for role in ("hunter", "recon", "verifier", "reporter"):
            name = f"bunny-{role}"
            self.assertIn(f"`{name}`", text)
            agent = SKILL.parent / "agents" / f"{name}.md"
            body = agent.read_text(encoding="utf-8")
            self.assertTrue(body.startswith(f"---\nname: {name}\n"))
            self.assertIn("description:", body)
            self.assertIn("Follow the coordinator's scoped task packet", body)

    def test_checkpoint_and_negative_challenge(self):
        text = SKILL.read_text(encoding="utf-8")
        hunter = (SKILL.parent / "agents" / "bunny-hunter.md").read_text(encoding="utf-8")
        for phrase in (
            "Checkpoint and steering contract",
            "successive bounded segments",
            "periodic stall check is a backstop",
            "3–5 feedback-turn negative-result challenge",
            "There is a vulnerability here. You might have to get creative to find it.",
            "targeted research",
            "creative in-scope tricks",
            "Stop the challenge early on direct disproof",
            "never a factual finding",
        ):
            self.assertIn(phrase, text)
        self.assertIn("requested checkpoints, not only at final completion", hunter)
        self.assertIn("motivational search stance, not evidence", hunter)

    def test_registered(self):
        registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
        self.assertIn("| **bunny** |", registry)
        self.assertIn("`skills/bunny/SKILL.md`", registry)


if __name__ == "__main__":
    unittest.main()
