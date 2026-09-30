from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
ROUTER = SKILLS / "bunny" / "SKILL.md"
COLLABORATIVE = SKILLS / "bunny-collaborative" / "SKILL.md"
OFFHAND = SKILLS / "bunny-offhand" / "SKILL.md"


class BunnySkillTests(unittest.TestCase):
    def test_default_route_and_explicit_offhand(self):
        router = ROUTER.read_text(encoding="utf-8")
        self.assertIn("name: bunny\n", router)
        self.assertIn("opt-in", router)
        self.assertIn("Keep `hunt-orchestration`", router)
        self.assertIn("Default: collaborative", router)
        self.assertIn("load `bunny-collaborative` before dispatch", router)
        self.assertIn("coordinator and each collaborative worker must load", router)
        self.assertIn("Explicit: offhand", router)
        self.assertIn("load `bunny-offhand` in the coordinator", router)
        self.assertIn("not** a Bunny mode skill", router)
        self.assertIn("Do not silently fall back", router)
        self.assertIn("mode change occurs at an evidence checkpoint", router)

    def test_shared_account_and_evidence_guards(self):
        router = ROUTER.read_text(encoding="utf-8")
        self.assertIn("not as a universal start gate", router)
        self.assertIn("A logout is a diagnostic event", router)
        self.assertIn("Independently verify credible candidates", router)
        self.assertIn("aggregate", router)
        self.assertIn("do not automatically submit externally", router)

    def test_collaborative_worker_roles_and_load(self):
        text = COLLABORATIVE.read_text(encoding="utf-8")
        self.assertIn("name: bunny-collaborative\n", text)
        self.assertIn("Both the coordinator and every collaborative worker load", text)
        self.assertIn("Load bunny-collaborative before acting", text)
        self.assertIn("native subagent facility", text)
        for role in ("hunter", "recon", "verifier", "reporter"):
            name = f"bunny-{role}"
            self.assertIn(f"`{name}`", text)
            body = (SKILLS / "bunny" / "agents" / f"{name}.md").read_text(encoding="utf-8")
            self.assertTrue(body.startswith(f"---\nname: {name}\n"))
            self.assertIn("load `bunny-collaborative`", body)

    def test_checkpoint_and_negative_challenge(self):
        text = COLLABORATIVE.read_text(encoding="utf-8")
        hunter = (SKILLS / "bunny" / "agents" / "bunny-hunter.md").read_text(encoding="utf-8")
        for phrase in (
            "send the coordinator a bounded checkpoint",
            "observed result **versus** interpretation",
            "successive bounded segments",
            "periodic stall check is a backstop",
            "3–5 coordinator feedback turns",
            "There is a vulnerability here. You might have to get creative to find it.",
            "Research the observed technology",
            "creative in-scope tricks",
            "Stop the challenge early on direct disproof",
            "never a factual finding",
        ):
            self.assertIn(phrase, text)
        self.assertIn("requested checkpoints, not only at final completion", hunter)
        self.assertIn("motivational search stance, not evidence", hunter)

    def test_offhand_requires_no_worker_mode(self):
        text = OFFHAND.read_text(encoding="utf-8")
        self.assertIn("name: bunny-offhand\n", text)
        self.assertIn("Only the coordinator loads this mode skill", text)
        self.assertIn("Do not instruct workers to load a Bunny mode skill", text)
        self.assertIn("final bounded result", text)
        self.assertIn("never choose it as the default", text)

    def test_registered(self):
        registry = (ROOT / "SKILL_REGISTRY.md").read_text(encoding="utf-8")
        for name in ("bunny", "bunny-collaborative", "bunny-offhand"):
            self.assertIn(f"| **{name}** |", registry)
            self.assertIn(f"`skills/{name}/SKILL.md`", registry)


if __name__ == "__main__":
    unittest.main()
