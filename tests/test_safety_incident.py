"""Checkout-local safety incident CLI integration, without external delivery."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from bounty_core.safety_incidents import SafetyIncidentStore

ROOT = Path(__file__).resolve().parents[1]


class SafetyIncidentCliTests(unittest.TestCase):
    def test_record_persists_in_explicit_lane_and_can_be_read_back(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bbh-safety-", dir=os.environ.get("TMPDIR")) as directory:
            storage_root = Path(directory)
            env = os.environ.copy()
            env.pop("DISCORD_SAFETY_WEBHOOK_URL", None)
            completed = subprocess.run(
                [
                    str(ROOT / "scripts/bbh"), "scripts/safety_incident.py",
                    "--program", "fixture-program", "--lane", "web",
                    "--root", str(storage_root), "record",
                    "--producer", "fixture-test", "--run-id", "fixture-run",
                    "--category", "other", "--action", "Stopped local fixture task",
                    "--subject", "Owned local fixture", "--impact", "None observed",
                    "--containment", "No further action", "--no-notify",
                ],
                cwd=ROOT, env=env, text=True, capture_output=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            incident = result["incident"]
            self.assertIsNone(result["notification"])
            self.assertEqual(incident["program"], "fixture-program")
            self.assertEqual(incident["lane"], "web")
            self.assertEqual(incident["run_id"], "fixture-run")
            store = SafetyIncidentStore("fixture-program", lane="web", root_override=storage_root)
            events = [json.loads(line) for line in store.events_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(events, [incident])
            self.assertEqual(store.get(incident["incident_id"]), incident)
            self.assertFalse(store.notifications_path.exists())
            self.assertEqual(store.events_path, storage_root / "web_bounty/fixture-program/web/safety_incidents/events.jsonl")


if __name__ == "__main__":
    unittest.main()
