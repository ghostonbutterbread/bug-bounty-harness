"""Form workflows defer CAPTCHA decisions to the canonical policy."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FormCaptchaRoutingTests(unittest.TestCase):
    def test_form_captcha_routes_browser_solving_and_preserves_verification_boundary(self):
        text = " ".join((ROOT / "skills/form-submission-testing/SKILL.md").read_text().split())
        self.assertIn("load `captcha-policy`", text)
        self.assertIn("normal browser", text)
        self.assertIn("verification values", text)
        self.assertNotIn("Do not bypass it, rotate IPs, automate solving", text)


if __name__ == "__main__":
    unittest.main()
