"""Static AI policy-routing regressions, not an agent-behavior evaluation."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "skills/ai-tester/references/action-boundaries.md"
DOCUMENTS = (
    "skills/ai-tester/SKILL.md",
    "skills/ai-action-chain/SKILL.md",
    "skills/agent-tool-abuse/SKILL.md",
    "skills/prompt-injection/SKILL.md",
    "skills/indirect-injection/SKILL.md",
    "prompts/ai-action-chain-playbook.md",
    "prompts/agent-tool-abuse-playbook.md",
    "prompts/prompt-injection-playbook.md",
    "prompts/indirect-injection-playbook.md",
)


class AIActionGuardTests(unittest.TestCase):
    def test_ai_entries_resolve_one_guard_adapter_and_retain_host_protection(self):
        self.assertTrue(REFERENCE.is_file(), "Missing shared AI action-boundary adapter")
        reference = " ".join(REFERENCE.read_text(encoding="utf-8").split())
        for owner in (
            "general-security-testing-policy", "live-testing-policy",
            "program-testing-policy", "account-testing-policy", "rce-validation",
            "attempt-recording-policy",
        ):
            with self.subTest(owner=owner):
                self.assertIn(f"`{owner}`", reference)
        for boundary in (
            "does not grant permission", "owned disposable application fixture",
            "does not confer ownership of the server", "pre-existing server files",
            "Do not delete, overwrite, or replace", "reverse shells",
            "service disruption", "unexpected unapproved side effect",
            "explicit restrictions remain binding", "non-sensitive canaries",
            "Pause when permission is unclear",
        ):
            with self.subTest(boundary=boundary):
                self.assertIn(boundary, reference)

        for name in DOCUMENTS:
            with self.subTest(document=name):
                path = ROOT / name
                text = path.read_text(encoding="utf-8")
                links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", text)
                routes = [link for link in links if link.endswith("action-boundaries.md")]
                self.assertTrue(routes, f"{name} does not route to the shared adapter")
                for link in routes:
                    self.assertEqual((path.parent / link).resolve(), REFERENCE.resolve())
                for stale_rule in (
                    "Do not send messages, invite users, publish, purchase, delete, refund",
                    "Do not make purchases, send messages, edit customer/vendor data, delete content, or trigger external requests without explicit approval.",
                    "Stop before real messages, destructive edits, purchases, account changes",
                    "Stop before destructive edits, spam, purchases, account changes",
                    "unless Ryushe explicitly approved that exact action or it is the stated objective of an authorized lab",
                ):
                    self.assertNotIn(stale_rule, " ".join(text.split()))


if __name__ == "__main__":
    unittest.main()
