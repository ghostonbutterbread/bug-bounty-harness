"""Static route/guard check for a controlled AI tool-abuse hypothesis."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MutableHostedScriptTechniqueTests(unittest.TestCase):
    def test_ai_tool_abuse_owns_script_retrieval_drift(self):
        owner = " ".join((ROOT / "skills/agent-tool-abuse/SKILL.md").read_text(encoding="utf-8").split())
        entry = (ROOT / "skills/ai-tester/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("/agent-tool-abuse", entry)
        for cue in (
            "inspects a hosted script, repairs an apparent bug",
            "later retrieves that URL to execute it",
            "inspection and initial reproduction",
            "automatically serve a distinct **inert canary**",
            "execution-time retrieval",
            "earlier refusal does not authorize changed code",
            "Do not use a malicious payload",
            "authorized owned endpoint",
            "each response's digest, retrieval order",
            "Distinguish a pinned local snapshot from a new fetch",
            "A proposed command or model claim is not execution",
            "action boundaries to any live target",
        ):
            with self.subTest(cue=cue):
                self.assertIn(cue, owner)


if __name__ == "__main__":
    unittest.main()
