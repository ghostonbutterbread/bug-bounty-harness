"""Static, device-free checks for the Android hierarchy guidance."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/android-adb/SKILL.md"


class AndroidHierarchyGuidanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SKILL.read_text(encoding="utf-8")
        cls.section = cls.text.split("## UI Hierarchy Output Safety\n", 1)[1].split(
            "\n## ", 1
        )[0]

    def test_output_boundary_precedes_transport_examples(self):
        self.assertLess(
            self.text.index("## UI Hierarchy Output Safety"),
            self.text.index("## Abommie / WSL"),
        )
        for phrase in (
            "sensitive dynamic values",
            "accessibility password metadata is false",
            "do not emit or persist raw hierarchy XML or copied values",
            "tool results, stdout, errors, logs, or artifacts",
            "verified pre-output sanitization",
            "fixed safe schema",
            "fail closed",
            "does not assert that such a sanitizer exists",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.section)

    def test_manual_alternative_does_not_presume_screenshot_safety(self):
        for phrase in (
            "inspect the emulator screen manually",
            "without copying displayed values",
            "Screenshots can also",
            "do not assume they are safe to capture or share",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.section)

    def test_authorized_transport_examples_remain(self):
        for command in (
            "adb -s emulator-5554 shell getprop ro.product.model",
            "adb connect 127.0.0.1:5555",
            "adb -s 127.0.0.1:5555 shell getprop ro.product.model",
            "emu-adb-tailscale --tunnel",
        ):
            with self.subTest(command=command):
                self.assertIn(command, self.text)
        self.assertIn("Never run\n`adb kill-server`", self.text)


if __name__ == "__main__":
    unittest.main()
