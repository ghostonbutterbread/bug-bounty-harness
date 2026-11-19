"""Offline checks that error triage routes CAPTCHA to its canonical owner."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def text(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


class ErrorTriageCaptchaRoutingTests(unittest.TestCase):
    def test_captcha_body_takes_precedence_over_status_403(self):
        for path in ("skills/error-triage/SKILL.md",
                     "skills/error-triage/references/technique-packs/access-errors.md",
                     "prompts/error-triage-playbook.md"):
            with self.subTest(path=path):
                content = text(path)
                self.assertIn("CAPTCHA-bearing `403`", content)
                self.assertIn("before `/403`", content)
                self.assertIn("`captcha-policy`", content)

    def test_entry_and_rate_pack_route_to_canonical_owner_without_overriding_stops(self):
        for path in ("skills/error-triage/SKILL.md",
                     "skills/error-triage/references/technique-packs/rate-limit-waf.md"):
            with self.subTest(path=path):
                content = text(path)
                self.assertIn("`captcha-policy`", content)
                self.assertIn("429", content)
                self.assertIn("operator_review", content)
                self.assertIn("do not resume blocked automation", content)
                self.assertNotIn("Stop on CAPTCHA", content)
                self.assertNotIn("bot protection, CAPTCHA, out-of-scope", content)
                self.assertNotIn("browser challenge/CAPTCHA -> `/chromium-handoff`", content)

    def test_selected_auth_and_unhandled_packs_defer_captcha_and_preserve_stops(self):
        for path in ("skills/error-triage/references/technique-packs/auth-errors.md",
                     "skills/error-triage/references/technique-packs/unhandled-errors.md"):
            with self.subTest(path=path):
                content = text(path)
                self.assertIn("CAPTCHA", content)
                self.assertIn("`captcha-policy`", content)
                self.assertIn("429 cooldown", content)
                self.assertIn("`operator_review`", content)
                self.assertNotIn("WAF/CAPTCHA/rate limiting", content)
                self.assertNotIn("anti-abuse, CAPTCHA, WAF", content)

    def test_unhandled_pack_does_not_override_captcha_decision_with_anti_abuse_stop(self):
        content = text("skills/error-triage/references/technique-packs/unhandled-errors.md")
        stop = content.split("## Stop", 1)[1]
        self.assertIn("For CAPTCHA, follow `captcha-policy`", stop)
        self.assertIn("other applicable stops", stop)

    def test_playbook_defers_captcha_before_anti_abuse_stop(self):
        stop = text("prompts/error-triage-playbook.md").split("## Stop Conditions", 1)[1]
        self.assertIn("non-CAPTCHA anti-abuse", stop)
        self.assertIn("For CAPTCHA, follow `captcha-policy`", stop)
        self.assertIn("other applicable stops", stop)

    def test_loaded_context_and_playbook_do_not_preempt_captcha_policy(self):
        for path in ("prompts/error-triage-context-pack.md", "prompts/error-triage-playbook.md"):
            with self.subTest(path=path):
                content = text(path)
                self.assertIn("`captcha-policy`", content)
                self.assertNotIn("bot protection, CAPTCHA, and explicit", content)
                self.assertNotIn("`429`, CAPTCHA, WAF page | `/waf`, manual handoff, or stop", content)


if __name__ == "__main__":
    unittest.main()
