"""Checkout-local safety incident CLI integration, without external delivery."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts import safety_incident
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
        self.env["HOME"] = str(Path(self.temp.name) / "home")
        self.env["HARNESS_SHARED_BASE"] = str(Path(self.temp.name) / "wrong-env-base")

    def write_webhook(self, value: str, mode: int = 0o600) -> Path:
        path = Path(self.env["HOME"]) / ".config/bounty-core/safety-webhook-url"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
        path.chmod(mode)
        return path

    def write_profile(self, **overrides: str) -> None:
        profile = {"program": "fixture-program", "family": "web_bounty", "lane": "web",
                   "base_root": str(self.layout.base_root),
                   "canonical_root": str(self.layout.lane_root)}
        profile.update(overrides)
        self.profile.write_text(json.dumps(profile), encoding="utf-8")

    def run_client(self, *global_args: str, command: str = "record", profile: Path | None = None,
                   no_notify: bool = True, severity: str | None = None) -> subprocess.CompletedProcess[str]:
        args = [str(ROOT / "scripts/bbh"), "scripts/safety_incident.py",
                "--program", "fixture-program", "--lane", "web"]
        if profile is not None:
            args += ["--profile", str(profile)]
        args += list(global_args)
        if command == "record":
            args += ["record", "--producer", "fixture-test", "--run-id", "fixture-run",
                     "--category", "other", "--action", "Stopped local fixture task",
                     "--subject", "Owned local fixture", "--impact", "None observed",
                     "--containment", "No further action"]
            if severity is not None:
                args += ["--severity", severity]
            if no_notify:
                args.append("--no-notify")
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

    def test_severity_and_terminal_summary_with_installed_provider(self) -> None:
        result = self.run_client(profile=self.profile, severity="critical")
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["incident"]["severity"], "critical")
        self.assertIn("Saved safety incident " + receipt["incident"]["incident_id"], result.stderr)
        self.assertIn("Stopped local fixture task", result.stderr)
        self.assertIsNone(receipt["notification"])

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

    def test_unavailable_or_insecure_secret_still_records_not_configured(self) -> None:
        secret = "https://discord.com/api/webhooks/123456/fake_fixture_only"
        path = Path(self.env["HOME"]) / ".config/bounty-core/safety-webhook-url"
        for case in ("absent", "public", "symlink", "invalid", "oversize"):
            with self.subTest(case=case):
                path.unlink(missing_ok=True)
                if case == "public":
                    self.write_webhook(secret, 0o644)
                elif case == "symlink":
                    target = Path(self.temp.name) / "symlink-target"
                    target.write_text(secret, encoding="utf-8")
                    target.chmod(0o600)
                    path.symlink_to(target)
                elif case == "invalid":
                    self.write_webhook(secret + "\nEXTRA")
                elif case == "oversize":
                    self.write_webhook("x" * 4097)
                result = self.run_client(profile=self.profile, no_notify=False)
                self.assertEqual(result.returncode, 1, result.stderr)
                receipt = json.loads(result.stdout)
                self.assertEqual(receipt["notification"]["state"], "not-configured")
                self.assertIn("webhook unavailable or insecure", result.stderr)
                self.assertNotIn(secret, result.stdout + result.stderr)
                store = SafetyIncidentStore("fixture-program", lane="web", root_override=self.base)
                self.assertEqual(store.get(receipt["incident"]["incident_id"]), receipt["incident"])

    def test_private_file_is_forwarded_only_inside_safety_cli_and_env_wins(self) -> None:
        secret = "https://discord.com/api/webhooks/123456/fake_fixture_only"
        self.write_webhook(secret + "\n")
        args = ["--program", "fixture-program", "--lane", "web", "--profile", str(self.profile),
                "record"]
        with patch.dict(os.environ, {"HOME": self.env["HOME"]}, clear=True):
            with patch.object(safety_incident, "provider_main", return_value=0) as provider:
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    self.assertEqual(safety_incident.main(args), 0)
                self.assertEqual(os.environ["DISCORD_SAFETY_WEBHOOK_URL"], secret)
                self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())
                self.assertEqual(stderr.getvalue(), "")
                self.assertNotIn("--profile", provider.call_args.args[0])
            os.environ["DISCORD_SAFETY_WEBHOOK_URL"] = "explicit-invalid-fixture"
            with patch.object(safety_incident, "provider_main", return_value=0):
                self.assertEqual(safety_incident.main(args), 0)
                self.assertEqual(os.environ["DISCORD_SAFETY_WEBHOOK_URL"], "explicit-invalid-fixture")

    def test_no_notify_skips_secret_even_if_private_file_exists(self) -> None:
        secret = "https://discord.com/api/webhooks/123456/fake_fixture_only"
        self.write_webhook(secret)
        result = self.run_client(profile=self.profile)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(json.loads(result.stdout)["notification"])
        self.assertIn("Saved safety incident", result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)
        store = SafetyIncidentStore("fixture-program", lane="web", root_override=self.base)
        self.assertFalse(store.notifications_path.exists())

    def test_explicit_env_does_not_read_file(self) -> None:
        secret = "https://discord.com/api/webhooks/123456/fake_fixture_only"
        self.write_webhook(secret, 0o644)
        self.env["DISCORD_SAFETY_WEBHOOK_URL"] = "explicit-invalid-fixture"
        result = self.run_client(profile=self.profile, no_notify=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["notification"]["state"], "invalid-configuration")
        self.assertIn("Saved safety incident", result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_different_owner_is_rejected(self) -> None:
        self.write_webhook("https://discord.com/api/webhooks/123456/fake_fixture_only")
        with patch.dict(os.environ, {"HOME": self.env["HOME"]}, clear=True), \
             patch.object(safety_incident.os, "getuid", return_value=os.getuid() + 1):
            self.assertIsNone(safety_incident._load_webhook_file())
