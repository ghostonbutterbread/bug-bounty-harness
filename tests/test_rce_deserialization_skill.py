"""Offline packaging and routing regressions for deserialization reasoning."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


def text(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


class DeserializationSkillTest(unittest.TestCase):
    def test_entry_mapping_and_exploration_route_to_packaged_skill(self):
        for name in ("rce", "rce-surface-mapping", "rce-exploration"):
            self.assertIn("`rce-deserialization`", text(f"skills/{name}/SKILL.md"))
        self.assertIn("| **rce-deserialization** |", text("SKILL_REGISTRY.md"))
        skill = text("skills/rce-deserialization/SKILL.md")
        self.assertTrue(skill.startswith("---\nname: rce-deserialization\n"))
        description_match = re.search(r'description: "([^"]+)"', skill)
        self.assertIsNotNone(description_match)
        assert description_match is not None
        description = description_match.group(1)
        self.assertLessEqual(len(description), 60)
        self.assertTrue(description.endswith("."))
        related_match = re.search(r"related_skills: \[([^\]]+)\]", skill)
        self.assertIsNotNone(related_match)
        assert related_match is not None
        for name in related_match.group(1).split(", "):
            self.assertTrue((ROOT / "skills" / name / "SKILL.md").is_file(), name)
        refs = re.findall(r"`(references/[^`]+\.md)`", skill)
        self.assertTrue(refs)
        for ref in refs:
            self.assertTrue((ROOT / "skills/rce-deserialization" / ref).is_file())

    def test_carrier_lens_is_general_not_a_pickle_only_check(self):
        mapping = text("skills/rce-surface-mapping/SKILL.md")
        for phrase in ("Headers and cookies", "round-tripped server-issued state",
                       "merely readable state", "header-driven parser/error paths"):
            self.assertIn(phrase, mapping)
        self.assertNotIn("pickle.loads", mapping)

    def test_reasoning_keeps_control_and_reconstruction_separate(self):
        skill = " ".join(text("skills/rce-deserialization/SKILL.md").split())
        for phrase in ("outer serializer", "readability does not imply forgery",
                       "verification order", "permitted types", "failing later",
                       "first dangerous consumer", "not server-side reachability",
                       "synthetic-only boundary", "does not provide a live-cookie adapter",
                       "not as a fixed probe sequence", "observed, source-supported, inferred, or unknown"):
            self.assertIn(phrase, skill)
        self.assertIn("never use `pickle.load`, `pickle.loads`, or `python -m pickle`", skill)
        self.assertIn("without executing them", skill)
        self.assertIn("`rce-validation`", skill)

    def test_case_separates_framework_default_from_application_behavior(self):
        case = " ".join(text("skills/rce-deserialization/references/session-object-case.md").split())
        for phrase in ("tagged JSON serializer, not pickle", "reused as the session signing key",
                       "unpickled by the callback", "not standing permission",
                       "not the target's consumer", "Primary sources and capture provenance"):
            self.assertIn(phrase, case)
        for host in ("simonkoeck.com", "flask.palletsprojects.com", "docs.python.org"):
            self.assertIn(host, case)
        self.assertEqual(len(re.findall(r"SHA-256: [a-f0-9]{64}", case)), 4)

    def test_new_packet_stays_portable_and_has_no_executable_payload(self):
        for path in ("skills/rce-deserialization/SKILL.md",
                     "skills/rce-deserialization/references/session-object-case.md"):
            content = text(path)
            self.assertNotIn("/home/", content)
            self.assertNotIn("__reduce__", content)
            self.assertNotIn("time.sleep(", content)
            self.assertNotIn("subprocess", content)


if __name__ == "__main__":
    unittest.main()
