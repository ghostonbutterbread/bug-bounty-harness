"""Offline checks of the documented handoff route cleanup contract."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills/chromium-handoff/scripts/handoff_transport.sh"
SKILL = ROOT / "skills/chromium-handoff/SKILL.md"


class HandoffCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.log = self.dir / "tailscale.log"
        for name, body in {
            "tailscale": 'printf "%s\\n" "$*" >> "$STUB_LOG"\n',
            "curl": 'printf 200\n',
        }.items():
            stub = self.dir / name
            stub.write_text("#!/bin/sh\n" + body)
            stub.chmod(0o755)
        self.env = {
            "PATH": str(self.dir) + ":/usr/bin:/bin",
            "HOME": str(self.dir),
            "STUB_LOG": str(self.log),
        }

    def run_helper(self, action, **env):
        return subprocess.run(["/bin/bash", str(SCRIPT), action], cwd=ROOT,
                              env={**self.env, **env}, text=True, capture_output=True)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_documented_stop_examples_match_their_published_route(self):
        workflow = SKILL.read_text().split("6. On resume", 1)[1].split("## Failure", 1)[0]
        blocks = re.findall(r"```bash\n(.*?)\n\s*```", workflow, re.S)
        stops = [block for block in blocks if "handoff_transport.sh\" stop" in block]
        self.assertEqual(len(stops), 2, "cleanup must provide independent screenshot and KasmVNC stop examples")
        replacements = {"<handoff_port>": "9501", "<kasmvnc_web_port>": "8463",
                        "<unique_tailnet_https_port>": "9502"}
        expected = {
            "serve --https=443 --set-path=/handoff/9501 off",
            "serve --https=9502 off",
        }
        for block in stops:
            command = block.strip()
            for placeholder, value in replacements.items():
                command = command.replace(placeholder, value)
            # Examples must not inherit another handoff's transport selection.
            polluted_env = {**self.env, "HANDOFF_HTTPS_PORT": "9555",
                            "HANDOFF_PATH": "/handoff/other",
                            "HANDOFF_PORT_MIN": "8463", "HANDOFF_PORT_MAX": "8499",
                            "HANDOFF_HOST": "0.0.0.0"}
            result = subprocess.run(["/bin/bash", "-c", command], cwd=ROOT,
                                    env=polluted_env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({call for call in self.calls() if call.endswith(" off")}, expected)

    def test_documented_kasmvnc_start_stop_ignore_polluted_host(self):
        text = SKILL.read_text()
        start_text = text.split("3. For a KasmVNC Chromium run", 1)[1].split("4. For a screenshot handoff", 1)[0]
        stop_text = text.split("For a KasmVNC root route", 1)[1].split("If publication used", 1)[0]
        start_match = re.search(r"```bash\n(.*?)\n\s*```", start_text, re.S)
        stop_match = re.search(r"```bash\n(.*?)\n\s*```", stop_text, re.S)
        assert start_match is not None and stop_match is not None
        polluted = {**self.env, "HANDOFF_HOST": "0.0.0.0", "HANDOFF_PATH": "/handoff/other"}
        for match in (start_match, stop_match):
            command = match.group(1).strip().replace("<kasmvnc_web_port>", "8463").replace("<unique_tailnet_https_port>", "9502")
            result = subprocess.run(["/bin/bash", "-c", command], cwd=ROOT,
                                    env=polluted, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [
            "serve --bg --https=9502 http://127.0.0.1:8463", "serve status",
            "serve --https=9502 off", "serve status",
        ])

    def test_documented_screenshot_start_then_stop_ignores_polluted_transport(self):
        text = SKILL.read_text()
        screenshot = text.split("4. For a screenshot handoff", 1)[1].split("4. Always", 1)[0]
        cleanup = text.split("6. On resume", 1)[1].split("For a KasmVNC root route", 1)[0]
        start_match = re.search(r"```bash\n(.*?)\n\s*```", screenshot, re.S)
        stop_match = re.search(r"```bash\n(.*?)\n\s*```", cleanup, re.S)
        assert start_match is not None and stop_match is not None
        start, stop = start_match.group(1), stop_match.group(1)
        for port_min, port_max in (("9501", "9599"), ("8463", "8499")):
            with self.subTest(inherited_range=(port_min, port_max)):
                self.log.unlink(missing_ok=True)
                polluted = {**self.env, "HANDOFF_HTTPS_PORT": "9555",
                            "HANDOFF_PATH": "/handoff/other", "HANDOFF_PORT_MIN": port_min,
                            "HANDOFF_PORT_MAX": port_max, "HANDOFF_HOST": "localhost"}
                for block in (start, stop):
                    command = "set -e\n" + block.strip().replace("<handoff_port>", "9501")
                    result = subprocess.run(["/bin/bash", "-c", command], cwd=ROOT,
                                            env=polluted, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.calls(), [
                    "serve --bg --https=443 --set-path=/handoff/9501 http://127.0.0.1:9501",
                    "serve status", "serve status",
                    "serve --https=443 --set-path=/handoff/9501 off", "serve status",
                ])

    def test_helper_validation_and_routes_with_offline_stub(self):
        cases = [
            ({"HANDOFF_PORT": "9501"}, "serve --bg --https=443 --set-path=/handoff/9501 http://127.0.0.1:9501", "serve --https=443 --set-path=/handoff/9501 off"),
            ({"HANDOFF_PORT": "8463", "HANDOFF_PORT_MIN": "8463", "HANDOFF_PORT_MAX": "8499", "HANDOFF_HTTPS_PORT": "9502"}, "serve --bg --https=9502 http://127.0.0.1:8463", "serve --https=9502 off"),
            ({"HANDOFF_PORT": "9501", "HANDOFF_PATH": "/handoff/custom"}, "serve --bg --https=443 --set-path=/handoff/custom http://127.0.0.1:9501", "serve --https=443 --set-path=/handoff/custom off"),
        ]
        for env, start, stop in cases:
            with self.subTest(env=env):
                self.log.unlink(missing_ok=True)
                for action in ("start", "stop"):
                    result = self.run_helper(action, **env)
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.calls(), [start, "serve status", stop, "serve status"])
        for env in ({"HANDOFF_PORT": "8463", "HANDOFF_HTTPS_PORT": "9502"},
                    {"HANDOFF_PORT": "9501", "HANDOFF_HTTPS_PORT": "443"},
                    {"HANDOFF_PORT": "9501", "HANDOFF_PATH": "/../bad"},
                    {"HANDOFF_PORT": "9501", "HANDOFF_HOST": "0.0.0.0"}):
            with self.subTest(invalid=env):
                self.log.unlink(missing_ok=True)
                result = self.run_helper("stop", **env)
                self.assertEqual(result.returncode, 64, result.stderr)
                self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
