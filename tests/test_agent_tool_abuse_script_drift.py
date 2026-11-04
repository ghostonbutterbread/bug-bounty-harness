"""Static route/guard check for a controlled AI tool-abuse hypothesis."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MutableHostedScriptTechniqueTests(unittest.TestCase):
    def test_ai_tool_abuse_owns_script_retrieval_drift(self):
        owner = (ROOT / "skills/agent-tool-abuse/SKILL.md").read_text(encoding="utf-8")
        entry = (ROOT / "skills/ai-tester/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("/agent-tool-abuse", entry)
        for cue in (
            "inspects a hosted script, repairs an apparent bug",
            "inspection and initial reproduction",
            "later retrieval automatically",
            "distinct **inert canary**",
            "earlier refusal does not authorize changed code",
            "Do not use\na malicious payload",
            "authorized owned endpoint",
            "each response's digest, retrieval order",
            "Distinguish a pinned local snapshot from a\nnew fetch",
            "A proposed command or model claim is not execution",
            "action boundaries to any live target",
        ):
            with self.subTest(cue=cue):
                self.assertIn(cue, owner)


if __name__ == "__main__":
    unittest.main()
