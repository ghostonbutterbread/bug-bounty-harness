"""Checkout-local safety incident CLI integration, without external delivery."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from bounty_core.safety_incidents import SafetyIncidentStore
from bounty_core.storage import resolve_storage

ROOT = Path(__file__).resolve().parents[1]


class SafetyIncidentCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="bbh-safety-", dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / "nondefault-shared"
        self.layout = resolve_storage("fixture-program", family="web_bounty", lane="web", root_override=self.base)
        self.profile = self.layout.context_root / "target_profile.json"
        self.profile.parent.mkdir(parents=True)
        self.write_profile()
        self.env = os.environ.copy()
        self.env.pop("DISCORD_SAFETY_WEBHOOK_URL", None)
        self.env["HARNESS_SHARED_BASE"] = str(Path(self.temp.name) / "wrong-env-base")

    def write_profile(self, **overrides: str) -> None:
        profile = {"program": "fixture-program", "family": "web_bounty", "lane": "web",
                   "base_root": str(self.layout.base_root),
                   "canonical_root": str(self.layout.lane_root)}
        profile.update(overrides)
        self.profile.write_text(json.dumps(profile), encoding="utf-8")

    def run_client(self, *global_args: str, command: str = "record", profile: Path | None = None) -> subprocess.CompletedProcess[str]:
        args = [str(ROOT / "scripts/bbh"), "scripts/safety_incident.py",
                "--program", "fixture-program", "--lane", "web"]
        if profile is not None:
            args += ["--profile", str(profile)]
        args += list(global_args)
        if command == "record":
            args += ["record", "--producer", "fixture-test", "--run-id", "fixture-run",
                     "--category", "other", "--action", "Stopped local fixture task",
                     "--subject", "Owned local fixture", "--impact", "None observed",
                     "--containment", "No further action", "--no-notify"]
        else:
            args += ["notify", "absent-incident"]
        return subprocess.run(args, cwd=ROOT, env=self.env, text=True, capture_output=True, check=False)

    def assert_no_write(self) -> None:
        self.assertFalse((self.layout.lane_root / "safety_incidents").exists())
        self.assertFalse((Path(self.env["HARNESS_SHARED_BASE"]) / "web_bounty").exists())

    def test_record_persists_in_profile_lane_with_nondefault_shared_base(self) -> None:
        completed = self.run_client(profile=self.profile)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        incident = result["incident"]
        self.assertIsNone(result["notification"])
        self.assertEqual((incident["program"], incident["lane"], incident["run_id"]),
                         ("fixture-program", "web", "fixture-run"))
        store = SafetyIncidentStore("fixture-program", lane="web", root_override=self.base)
        events = [json.loads(line) for line in store.events_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(events, [incident])
        self.assertEqual(store.get(incident["incident_id"]), incident)
        self.assertFalse(store.notifications_path.exists())
        self.assertEqual(store.events_path, self.layout.lane_root / "safety_incidents/events.jsonl")
        self.assertFalse((Path(self.env["HARNESS_SHARED_BASE"]) / "web_bounty").exists())

    def test_missing_profile_or_missing_flag_fails_closed(self) -> None:
        for profile in (None, self.base / "web_bounty" / "missing" / "web" / "context" / "target_profile.json"):
            with self.subTest(profile=profile):
                result = self.run_client(profile=profile)
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_write()

    def test_wrong_identity_root_location_or_explicit_root_fails_closed(self) -> None:
        for field, value in (("program", "other"), ("family", "binaries"), ("lane", "api"),
                             ("base_root", str(Path(self.temp.name) / "other-base")),
                             ("canonical_root", str(self.layout.lane_root / "other"))):
            with self.subTest(field=field):
                self.write_profile(**{field: value})
                result = self.run_client(profile=self.profile)
                self.assertEqual(result.returncode, 2)
                self.assertIn("profile unavailable or inconsistent", result.stderr)
                self.assert_no_write()
        self.write_profile()
        result = self.run_client("--root", str(Path(self.temp.name) / "other-base"), profile=self.profile)
        self.assertEqual(result.returncode, 2)
        self.assert_no_write()
        result = self.run_client("--root", "relative-base", profile=self.profile)
        self.assertEqual(result.returncode, 2)
        self.assert_no_write()
        misplaced = Path(self.temp.name) / "target_profile.json"
        misplaced.write_text(self.profile.read_text(encoding="utf-8"), encoding="utf-8")
        result = self.run_client(profile=misplaced)
        self.assertEqual(result.returncode, 2)
        self.assert_no_write()

    def test_notify_also_requires_profile(self) -> None:
        result = self.run_client(command="notify")
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_write()

    def test_matching_explicit_root_is_accepted(self) -> None:
        result = self.run_client("--root", str(self.base), profile=self.profile)
        self.assertEqual(result.returncode, 0, result.stderr)
