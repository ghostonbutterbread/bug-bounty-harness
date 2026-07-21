import unittest

from agents.smart_fuzzing import build_deterministic_evidence_pack


class TestDeterministicEvidencePack(unittest.TestCase):
    def test_route_tokens_are_scoped_normalized_and_source_attributed(self):
        pack = build_deterministic_evidence_pack(
            program="demo",
            target_host="app.example.test",
            sources={
                "katana": [
                    "https://app.example.test/api/v2/projects/123/export",
                    "https://outside.example.test/admin",
                ],
                "javascript": ["/settings/billing", "/api/v2/templates"],
            },
            allowed_hosts={"app.example.test"},
        )

        by_candidate = {item["candidate"]: item for item in pack}
        self.assertIn("projects", by_candidate)
        self.assertIn("billing", by_candidate)
        self.assertIn("templates", by_candidate)
        self.assertNotIn("admin", by_candidate)
        self.assertEqual(by_candidate["projects"]["target_host"], "app.example.test")
        self.assertIn("katana", by_candidate["projects"]["sources"])
        self.assertIn("javascript", by_candidate["templates"]["sources"])


if __name__ == "__main__":
    unittest.main()
