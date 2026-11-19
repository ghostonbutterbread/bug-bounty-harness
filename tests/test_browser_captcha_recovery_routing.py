"""Offline regression checks for browser specialist policy boundaries."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def skill(name):
    return " ".join((ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8").split())


class BrowserCaptchaRecoveryRoutingTests(unittest.TestCase):
    def test_chromium_routes_captcha_recovery_without_blanket_rotation_ban(self):
        text = skill("chromium-test")
        self.assertIn("load `captcha-policy` for CAPTCHA recovery decisions", text)
        self.assertNotIn("CAPTCHA-solving services, or IP rotation — those remain prohibited", text)
        self.assertIn("proxy_cert_status.status: trusted", text)
        self.assertIn("Do not use a stale non-graphical browser", text)

    def test_handoff_preserves_session_and_rejects_interrupted_challenge(self):
        text = skill("chromium-handoff")
        for phrase in ("load `captcha-policy`", "interrupted challenge is ineligible",
                       "existing proxy/effective egress IP", "display_fallback",
                       "proxy_cert_status.status: trusted", "Pause automation"):
            self.assertTrue(phrase in text, f"missing handoff boundary: {phrase}")
        self.assertNotIn("CAPTCHA-solving services, IP rotation, or challenge-bypass loops", text)

    def test_nebula_keeps_human_and_privacy_gates_and_defers_manager_detection(self):
        text = skill("nebula-browser-lane")
        for phrase in ("Ryushe is at Nebula's screen", "Never drop Mullvad",
                       "mullvad_exit_ip: true", "Firefox is off-limits",
                       "Never open or copy", "Single-owner lock",
                       "Manager detection", "stop and report"):
            self.assertTrue(phrase in text, f"missing device boundary: {phrase}")
        self.assertNotIn("mullvad relay set location", text)
        self.assertNotIn("standalone daemon, e.g.", text)

    def test_nebula_preserves_eligible_human_controlled_screen_flow(self):
        text = skill("nebula-browser-lane")
        self.assertIn("human-controlled physical-screen flow", text)
        self.assertIn("human performs the egress check and target interactions", text)
        self.assertIn("not an unattended device capability", text)

    def test_nebula_prefers_proxy_but_permits_verified_vpn_direct(self):
        text = skill("nebula-browser-lane")
        self.assertIn("Prefer a task-scoped MITM", text)
        self.assertIn("do not make it mandatory", text)
        self.assertIn("may use the verified VPN directly, even if a proxy is available", text)
        self.assertIn("record that traffic is unproxied", text)
        self.assertIn("Nebula-only exception", text)
        self.assertIn("actual browser proxy route and exact CA trust", text)
        self.assertIn("remote proxy can change the exit IP", text)
        self.assertIn("429 cooldown", text)
        self.assertIn("still prohibits the corresponding target interaction", text)
        self.assertIn("launch command below does not establish or verify", text)
        for stale_gate in ("do not drive network traffic without the agent-proxy gate",
                           "Before any agent-driven target interaction",
                           "requires the task proxy and CA gate"):
            self.assertNotIn(stale_gate, text)

    def test_nebula_managed_lease_and_handoff_survive_reconciliation(self):
        text = skill("nebula-browser-lane")
        for phrase in ("hold_lane.py renew --receipt", "hold_lane.py begin-handoff --receipt",
                       "hold_lane.py complete-handoff --receipt", "hold_lane.py browser-start --receipt",
                       "hold_lane.py browser-stop --receipt", "hold_lane.py release --receipt",
                       "Never clear it based on elapsed time", "Apply the proxy or direct-VPN decision above"):
            self.assertIn(phrase, text)
        self.assertNotIn('pkill -f', text)

    def test_captcha_handoff_precedes_terminal_cleanup_and_rate_stop_remains(self):
        text = skill("chromium-test")
        for phrase in ("Do not revisit a CAPTCHA before following `captcha-policy`",
                       "preserve the eligible browser for handoff",
                       "429", "operator_review", "do not resume blocked automation"):
            self.assertTrue(phrase in text, f"missing lifecycle boundary: {phrase}")

    def test_ip_incident_is_independent_of_captcha_recovery(self):
        text = skill("chromium-test")
        self.assertIn("CAPTCHA alone is not evidence of an IP-related block", text)
        self.assertIn("independent evidence makes an IP-related block plausible", text)
        self.assertIn("load `mullvad`", text)
        self.assertNotIn("If `captcha-policy` selects an egress comparison", text)
        self.assertIn("preserve the eligible browser", text)

    def test_same_task_handoff_retains_named_profile_lease(self):
        text = skill("chromium-test")
        self.assertIn("A same-task operator handoff is not terminal", text)
        self.assertNotIn("terminal completion, handoff, or cancellation", text)
        self.assertIn("renew", text)

    def test_generic_challenge_workflow_defers_captcha_before_revisit(self):
        text = skill("chromium-test")
        workflow = text.split("## Workflow", 1)[1]
        self.assertIn("For CAPTCHA, follow `captcha-policy` before any revisit", workflow)
        gpu = text.split("### GPU/WebGL in-page verification", 1)[1].split("### Remote CDP", 1)[0]
        self.assertIn("CAPTCHA handling is governed by `captcha-policy`, not this GPU workflow", gpu)
        self.assertIn("Do not make WebGL verification a prerequisite", gpu)

    def test_resume_keeps_existing_browser_and_proxy(self):
        text = skill("chromium-handoff")
        self.assertTrue("On resume, retain the task browser" in text,
                        "handoff resume must retain the existing browser")
        self.assertTrue("its display, and proxy" in text,
                        "handoff resume must retain display and proxy")
        self.assertNotIn("On resume/end, first withdraw", text)

    def test_missing_webgl_does_not_destroy_an_eligible_captcha_handoff(self):
        text = skill("chromium-test")
        self.assertTrue("For a CAPTCHA, preserve the eligible browser" in text,
                        "WebGL failure must not preempt eligible CAPTCHA handoff")


if __name__ == "__main__":
    unittest.main()
