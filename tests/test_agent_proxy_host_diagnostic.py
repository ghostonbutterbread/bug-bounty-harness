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
        self.assertIn("Verify the installed help and execute on the actual egress machine", text)
        self.assertIn("optionally run `check KEY` or `refresh KEY`", text)
        self.assertIn("reports `already_refreshed` if the host IP changed", text)
        self.assertIn("same-city West Coast exit of the current manager", text)
        self.assertIn("same UID and shared filesystem view, not other users or VPN tools", text)
        self.assertIn("uncertain or interrupted switch can leave a persistent latch", text)
        self.assertIn("Do not remove it or retry a switch speculatively", text)
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

    def test_manual_procedures_remain_routed_and_guarded(self):
        skill = (ROOT / "skills/mullvad/SKILL.md").read_text()
        playbook = (ROOT / "prompts/mullvad-playbook.md").read_text()
        normalized = " ".join(skill.split())
        for link, heading in (
            ("#choose-the-path-on-each-host", "## Choose the path on each host"),
            ("#preflight-gate-for-a-remote-handoff", "## Preflight gate for a remote handoff"),
            ("#tailscale-rotation-preferred-once-migrated", "## Tailscale rotation (preferred once migrated)"),
            ("#standalone-cli-fallback--rotation", "## Standalone CLI fallback / rotation"),
        ):
            with self.subTest(link=link):
                self.assertIn("../../prompts/mullvad-playbook.md" + link, skill)
                self.assertIn(heading, playbook)
        for gate in (
            "Do not bypass a missing incident baseline with manual rotation",
            "Check public Mullvad egress and rule out the ISP address",
            "change, including a successful incident refresh, verify manager, relay and intended route, DNS, relevant IPv6, independent remote access and affected workloads",
            "A manager change requires explicit direction",
            "never silently change lockdown, layer managers, or clear a selected Tailscale exit",
            "verification probes remain subject to the local route and DNS gate above",
        ):
            self.assertIn(gate, normalized)
        self.assertIn("agent/tool transcripts or logs", playbook)
        standalone = playbook.split("## Standalone CLI fallback / rotation", 1)[1].split("## Boot/restart checks", 1)[0]
        self.assertIn("public IP is not the normal ISP IP", standalone)
        self.assertIn("`mullvad_exit_ip: true`", standalone)
        self.assertNotIn("curl -4fsS --max-time 10 https://ip.me", playbook)
        self.assertNotIn("curl -6fsS --max-time 10 https://ip.me", playbook)


if __name__ == "__main__":
    unittest.main()
