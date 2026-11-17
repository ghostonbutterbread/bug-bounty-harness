from pathlib import Path
import unittest


SKILL = Path(__file__).resolve().parents[1] / "skills/mullvad/SKILL.md"


class MullvadInspectRoutingTest(unittest.TestCase):
    def test_optional_snapshot_routes_to_general_skill_without_weakening_preflight(self):
        text = " ".join(SKILL.read_text(encoding="utf-8").split())
        preflight = text.split("## Identify and preserve the current VPN manager", 1)[1]
        preflight = preflight.split("## Choose one VPN manager per host", 1)[0]
        self.assertIn("`script-manager`", preflight)
        self.assertIn("`scripts/README.md`", preflight)
        self.assertIn("`egress_inspect.py`", preflight)
        self.assertIn("read-only IPv4 local snapshot", preflight)
        self.assertIn("If the helper is unavailable, continue the existing inspection commands", preflight)
        self.assertIn("do not infer that a manager is absent", preflight)
        self.assertIn("does not verify DNS, IPv6, fail-closed protection, or ISP exposure", preflight)
        for command in ("`tailscale get exit-node`", "`tailscale status --json`", "`mullvad status -v`"):
            self.assertIn(command, preflight)
        self.assertIn("If manager state is unknown or conflicting, stop external traffic and ask Ryushe.", preflight)
        self.assertIn("Never silently fall back to ISP egress.", preflight)
        self.assertIn("use the existing Tailscale exit if selected and active, or the existing standalone Mullvad tunnel if connected with no Tailscale exit selected", preflight)


if __name__ == "__main__":
    unittest.main()
