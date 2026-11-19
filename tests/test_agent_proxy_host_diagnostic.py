"""The agent proxy route defers only the approved host-IP diagnostic."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AgentProxyHostDiagnosticTests(unittest.TestCase):
    def test_target_traffic_stays_on_proxy(self):
        text = " ".join((ROOT / "skills/agent-proxy/SKILL.md").read_text().split())
        self.assertIn("host-direct IP diagnostic", text)
        self.assertIn("`proxy-routing-policy`", text)
        self.assertIn("does not authorize sending target traffic outside the task proxy", text)
        self.assertIn("browser: --proxy-server=http://127.0.0.1:<leased-port>", text)

    def test_mullvad_records_and_compares_agent_owned_baseline(self):
        text = " ".join((ROOT / "skills/mullvad/SKILL.md").read_text().split())
        self.assertIn("`egress_snapshot.py`", text)
        self.assertIn('python3 "$HOME/.hermes/synced-skills/script-manager/scripts/egress_snapshot.py"', text)
        self.assertIn("Load General Skills `script-manager`", text)
        self.assertIn("Do not assume this provider revision is installed", text)
        self.assertIn("manually and optionally run", text)
        self.assertIn("already changed host IP does not trigger another switch", text)
        self.assertIn("same-city West Coast exit of the verified current manager", text)
        self.assertIn("not automatic, guaranteed to switch, or a manager change", text)
        self.assertIn("stable, private, opaque run-owned incident key", text)
        for command in ("`record KEY`", "`check KEY`", "`refresh KEY`"):
            self.assertIn(command, text)
        self.assertIn("Continue other permitted investigation", text)
        self.assertIn("CAPTCHA or 403 alone is not an IP-block classification", text)
        self.assertIn("point-in-time post-block host-direct IPv4 observation", text)
        self.assertIn("cannot establish the blocked IP if a switch happened before capture", text)
        self.assertIn("Do not log raw IPs", text)
        self.assertIn("regardless of whether a host baseline can be captured", text)
        self.assertIn("non-secret incident context in the run record", text)
        self.assertIn("helper is unavailable or recording fails", text)
        self.assertIn("baseline is unknown", text)
        self.assertIn("refresh deduplicates only the host-direct path", text)
        self.assertIn("cannot establish whether a remote proxy path changed", text)
        self.assertIn("not proof that the target unblocked", text)
        self.assertIn("Do not force rotation", text)
        self.assertIn("`same` or `unknown` is not permission to rotate", text)


if __name__ == "__main__":
    unittest.main()
