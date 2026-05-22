"""Focused tests for BaseTeam storage target identity routing."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents.base_team import AgentSpec, BaseTeam  # noqa: E402
from agents.base_team.storage import resolve_team_storage  # noqa: E402
from agents.storage_resolver import resolve_target_identity  # noqa: E402


class DummyTeam(BaseTeam):
    def get_static_profiles(self) -> list[AgentSpec]:
        return []

    def generate_dynamic_from_surfaces(
        self,
        surfaces: list[dict],
        *,
        snapshot_id: str,
    ) -> list[AgentSpec]:
        return []


class BaseTeamStorageIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)

    def test_legacy_team_type_fallback_remains_intact(self) -> None:
        with patch.object(Path, "home", return_value=self.tmp):
            storage = resolve_team_storage("demo", team_type="0day_team")

        self.assertEqual(storage.family, "web_bounty")
        self.assertEqual(storage.lane, "web")
        self.assertEqual(storage.lane_root, self.tmp / "Shared" / "web_bounty" / "demo" / "web")

    def test_apk_team_type_still_defaults_to_apk_lane(self) -> None:
        with patch.object(Path, "home", return_value=self.tmp):
            storage = resolve_team_storage("demo", team_type="apk")

        self.assertEqual(storage.family, "binaries")
        self.assertEqual(storage.lane, "apk")
        self.assertEqual(storage.lane_root, self.tmp / "Shared" / "binaries" / "demo" / "apk")

    def test_legacy_output_root_still_acts_as_base_root_without_identity_context(self) -> None:
        output_root = self.tmp / "custom-root"

        storage = resolve_team_storage("demo", team_type="apk", output_root=output_root)

        self.assertEqual(storage.family, "binaries")
        self.assertEqual(storage.lane, "apk")
        self.assertEqual(storage.lane_root, output_root / "binaries" / "demo" / "apk")

    def test_target_path_identity_context_overrides_legacy_team_lane(self) -> None:
        target = self.tmp / "android-src"
        target.mkdir()
        (target / "AndroidManifest.xml").write_text("<manifest />\n", encoding="utf-8")

        with patch.object(Path, "home", return_value=self.tmp):
            storage = resolve_team_storage("demo", team_type="0day_team", target_path=target)

        self.assertEqual(storage.family, "binaries")
        self.assertEqual(storage.lane, "apk")
        self.assertEqual(storage.lane_root, self.tmp / "Shared" / "binaries" / "demo" / "apk")

    def test_pre_resolved_identity_is_used_directly(self) -> None:
        identity = resolve_target_identity(program="demo", target_kind="api")

        with patch.object(Path, "home", return_value=self.tmp):
            storage = resolve_team_storage(
                "demo",
                team_type="0day_team",
                target_identity=identity,
            )

        self.assertEqual(storage.family, "web_bounty")
        self.assertEqual(storage.lane, "api")
        self.assertEqual(storage.lane_root, self.tmp / "Shared" / "web_bounty" / "demo" / "api")

    def test_base_team_accepts_explicit_identity_context(self) -> None:
        target = self.tmp / "target"
        target.mkdir()

        with patch.object(Path, "home", return_value=self.tmp):
            team = DummyTeam(
                "demo",
                "0day_team",
                target,
                target_kind="api",
                max_agents=1,
            )

        self.assertEqual(team.family, "web_bounty")
        self.assertEqual(team.lane, "api")
        self.assertEqual(team.team_dir, self.tmp / "Shared" / "web_bounty" / "demo" / "api")

    def test_base_team_injects_loaded_program_scope_into_agent_prompts(self) -> None:
        target = self.tmp / "target"
        target.mkdir()
        scope_dir = self.tmp / "Shared" / "scopes" / "demo"
        scope_dir.mkdir(parents=True)
        (scope_dir / "in-scope.txt").write_text(
            "# In-scope domains and URLs\n*.demo.example\nhttps://api.demo.example\n",
            encoding="utf-8",
        )
        (scope_dir / "rules-of-engagement.json").write_text(
            json.dumps(
                {
                    "platform": "bugcrowd",
                    "source_url": "https://bugcrowd.com/engagements/demo",
                    "source_brief_url": "https://bugcrowd.com/demo-brief.json",
                    "blocked_or_sensitive_classes": ["spam", "denial of service"],
                    "rules_text": "Do not spam users. Stay inside approved scope.",
                }
            ),
            encoding="utf-8",
        )

        with patch.object(Path, "home", return_value=self.tmp):
            team = DummyTeam("demo", "0day_team", target, max_agents=1)

        spec = AgentSpec(
            key="scope-check",
            vuln_class="xss",
            surface="web",
            prompt_template="Hunt {program}",
            focus_globs=["**/*"],
            code_patterns=[],
            program="demo",
            created_at="2026-05-21T00:00:00Z",
            snapshot_id="snapshot",
        )
        rendered = team._render_prompt(spec)

        self.assertIn("Program Scope And Rules Of Engagement", rendered)
        self.assertIn("Scope status: loaded.", rendered)
        self.assertIn("Platform: bugcrowd", rendered)
        self.assertIn("ScopeValidator(program).validate_or_fail(target)", rendered)
        self.assertIn("do not test or report it as a standalone bug", rendered)
        self.assertIn("normally out-of-scope or low-impact behavior may be considered", rendered)
        self.assertIn("record rejected amplifier candidates", rendered)
        self.assertIn("denial of service", rendered)
        self.assertIn("Rules text: Do not spam users. Stay inside approved scope.", rendered)

    def test_base_team_missing_program_scope_warns_agents_to_stay_offline(self) -> None:
        target = self.tmp / "target"
        target.mkdir()

        with patch.object(Path, "home", return_value=self.tmp):
            team = DummyTeam("demo", "0day_team", target, max_agents=1)

        spec = AgentSpec(
            key="scope-missing",
            vuln_class="xss",
            surface="web",
            prompt_template="Hunt {program}",
            focus_globs=["**/*"],
            code_patterns=[],
            program="demo",
            created_at="2026-05-21T00:00:00Z",
            snapshot_id="snapshot",
        )
        rendered = team._render_prompt(spec)

        self.assertIn("Scope status: not loaded.", rendered)
        self.assertIn("python3 agents/scope_puller.py demo --platform", rendered)
        self.assertIn("Do not send live requests", rendered)

    def test_base_team_load_ledger_normalizes_coverage_total_findings(self) -> None:
        target = self.tmp / "target"
        target.mkdir()

        with patch.object(Path, "home", return_value=self.tmp):
            team = DummyTeam("demo", "apk", target, max_agents=1)

        team.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        team.ledger_path.write_text(
            json.dumps({"coverage": {"total_findings": "3"}, "findings": [{"fid": "D01"}]}),
            encoding="utf-8",
        )

        ledger = team.load_ledger()

        self.assertEqual(ledger["coverage"]["total_findings"], 3)

    def test_canonical_apk_path_resolves_through_target_identity(self) -> None:
        target = self.tmp / "Shared" / "binaries" / "demo" / "apk" / "input" / "example.apk"
        target.parent.mkdir(parents=True)
        target.write_text("placeholder\n", encoding="utf-8")

        with patch.object(Path, "home", return_value=self.tmp):
            storage = resolve_team_storage("demo", team_type="apk", target_path=target)

        self.assertEqual(storage.family, "binaries")
        self.assertEqual(storage.lane, "apk")
        self.assertEqual(storage.lane_root, self.tmp / "Shared" / "binaries" / "demo" / "apk")

    def test_identity_context_prevents_canonical_output_root_nesting(self) -> None:
        lane_root = self.tmp / "Shared" / "binaries" / "demo" / "apk"
        target = lane_root / "input" / "example.apk"
        target.parent.mkdir(parents=True)
        target.write_text("placeholder\n", encoding="utf-8")

        with patch.object(Path, "home", return_value=self.tmp):
            storage = resolve_team_storage(
                "demo",
                team_type="apk",
                output_root=lane_root,
                target_path=target,
            )

        self.assertEqual(storage.lane_root, lane_root)

    def test_explicit_output_root_beats_canonical_target_path_storage_root(self) -> None:
        canonical_lane_root = self.tmp / "Shared" / "binaries" / "demo" / "exe"
        target = canonical_lane_root / "input" / "app.asar"
        target.parent.mkdir(parents=True)
        target.write_text("placeholder\n", encoding="utf-8")
        explicit_root = self.tmp / "explicit-output"

        with patch.object(Path, "home", return_value=self.tmp):
            storage = resolve_team_storage(
                "demo",
                team_type="0day_team",
                output_root=explicit_root,
                target_path=target,
            )

        self.assertEqual(storage.family, "binaries")
        self.assertEqual(storage.lane, "exe")
        self.assertEqual(storage.lane_root, explicit_root / "binaries" / "demo" / "exe")
        self.assertFalse((canonical_lane_root / "ledgers").exists())

    def test_base_team_canonical_lane_root_output_root_does_not_nest(self) -> None:
        lane_root = self.tmp / "Shared" / "binaries" / "demo" / "apk"
        target = lane_root / "input" / "example.apk"
        target.parent.mkdir(parents=True)
        target.write_text("placeholder\n", encoding="utf-8")

        with patch.object(Path, "home", return_value=self.tmp):
            team = DummyTeam(
                "demo",
                "apk",
                target,
                output_root=lane_root,
                infer_target_identity=True,
                max_agents=1,
            )

        self.assertEqual(team.family, "binaries")
        self.assertEqual(team.lane, "apk")
        self.assertEqual(team.team_dir, lane_root)
        self.assertFalse((lane_root / "binaries" / "demo" / "apk").exists())


if __name__ == "__main__":
    unittest.main()
