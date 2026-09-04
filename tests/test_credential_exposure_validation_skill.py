from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "credential-exposure-validation" / "SKILL.md"
JS_SKILL = ROOT / "skills" / "js" / "SKILL.md"
REGISTRY = ROOT / "SKILL_REGISTRY.md"


class CredentialExposureValidationSkillTests(unittest.TestCase):
    def test_skill_preserves_the_disclosed_credential_and_brute_force_boundary(self) -> None:
        content = SKILL.read_text(encoding="utf-8")

        self.assertIn("generic \"do not brute force\"", content)
        self.assertIn("complete username/password pair already exposed", content)
        self.assertIn("once to each relevant in-scope first-party login panel", content)
        self.assertIn("at most five likely default/admin credential pairs", content)
        self.assertIn("Use one to five pairs only", content)
        self.assertIn("each username/password combination is supported", content)
        self.assertEqual(content.count("Submit one pair at a time at the program's stated login rate"), 2)
        self.assertIn("immediately for every discovered in-scope admin", content)
        self.assertIn("generic password wordlist", content)
        self.assertIn("If authentication testing or default-password guessing is prohibited", content)
        self.assertIn("Every pair must be supported by product/version/panel documentation", content)
        self.assertIn("documentation or observed in-scope target configuration evidence", content)
        self.assertNotIn("likely default/common passwords", content)
        self.assertNotIn("closely related common/default passwords", content)
        self.assertIn("panel-specific restriction wins", content)
        self.assertIn("resource-safety-policy", content)
        self.assertIn("## JavaScript Lens", content)

    def test_skill_requires_minimal_proof_and_secret_redaction(self) -> None:
        content = SKILL.read_text(encoding="utf-8")

        self.assertIn("do not navigate, call APIs, read records, change settings", content)
        self.assertIn("Never retain raw passwords, tokens, cookies", content)
        self.assertIn("one redacted Attempt per submitted pair", content)

    def test_registry_and_js_handoff_route_exposed_pairs_to_this_skill(self) -> None:
        self.assertIn(
            "| **credential-exposure-validation** | `/credential-exposure-validation {program} {panel-or-source}` | `skills/credential-exposure-validation/SKILL.md` |",
            REGISTRY.read_text(encoding="utf-8"),
        )
        self.assertIn(
            "Route a complete exposed username/password pair with in-scope provenance to\n   `/credential-exposure-validation`; do not turn it into a wordlist candidate.",
            JS_SKILL.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
