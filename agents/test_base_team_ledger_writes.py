from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

import agents.base_team as base_team_package
import agents.base_team.ledger as base_team_ledger
from agents.base_team import AgentSpec, BaseTeam
from agents.base_team.runtime import orchestrate as runtime_orchestrate
from agents.ledger import ledger_path


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


class BaseTeamLedgerWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)
        self.home = self.tmp / "home"
        self.home.mkdir(parents=True, exist_ok=True)
        self.home_patcher = patch.dict(os.environ, {"HOME": str(self.home)})
        self.home_patcher.start()
        self.addCleanup(self.home_patcher.stop)

        self.target = self.tmp / "target"
        self.target.mkdir()
        (self.target / "src").mkdir()
        (self.target / "src" / "MainActivity.java").write_text("class MainActivity {}\n", encoding="utf-8")
        self.output_root = self.tmp / "canonical-storage"
        self.team = DummyTeam("Acme App", "apk", self.target, output_root=self.output_root, max_agents=1)

    def _finding(self) -> dict:
        return {
            "agent": "ipc-agent",
            "category": "class",
            "class_name": "ipc-trust-boundary",
            "type": "Exported activity trust bypass",
            "file": "src/MainActivity.java",
            "line": 1,
            "description": "Exported activity consumes caller-controlled extras.",
            "severity": "HIGH",
        }

    def _payload(self) -> dict:
        return json.loads(self.team.ledger_path.read_text(encoding="utf-8"))

    def test_deduplicate_reserves_fid_through_canonical_ledger_at_explicit_root(self) -> None:
        reserved = self.team.deduplicate_findings([self._finding(), self._finding()], self.team.load_ledger())

        self.assertEqual(len(reserved), 1)
        self.assertEqual(reserved[0]["fid"], "D01")
        self.assertEqual(reserved[0]["team_type"], "apk")
        self.assertTrue(self.team.ledger_path.exists())
        self.assertFalse(
            ledger_path(
                self.team.program,
                lane=self.team.storage.lane,
                family=self.team.storage.family,
            ).exists()
        )

        payload = self._payload()
        self.assertEqual(len(payload["findings"]), 1)
        finding = payload["findings"][0]
        self.assertEqual(finding["fid"], "D01")
        self.assertEqual(finding["team_type"], "apk")
        self.assertEqual(finding["current"]["review_tier"], "PENDING_REVIEW")

    def test_reviewed_update_and_coverage_preserve_canonical_finding_state(self) -> None:
        reserved = self.team.deduplicate_findings([self._finding()], self.team.load_ledger())
        reviewed = {
            **reserved[0],
            "review_tier": "CONFIRMED",
            "tier": "CONFIRMED",
            "review_notes": "Confirmed reachable exported component.",
        }

        updated = self.team.update_reviewed_findings([reviewed])

        self.assertEqual(len(updated), 1)
        self.assertEqual(updated[0]["fid"], "D01")
        self.assertEqual(updated[0]["current"]["review_tier"], "CONFIRMED")

        payload = self._payload()
        payload["custom_metadata"] = {"owner": "base-team-test"}
        self.team.ledger_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

        self.team.update_coverage("ipc-agent", "android-ipc", 1)

        payload = self._payload()
        finding = payload["findings"][0]
        self.assertEqual(payload["custom_metadata"], {"owner": "base-team-test"})
        self.assertEqual(finding["current"]["review_tier"], "CONFIRMED")
        self.assertEqual(finding["review_tier"], "CONFIRMED")
        self.assertEqual(len(finding["sightings"]), 1)
        self.assertEqual(finding["sightings"][0]["review_tier"], "CONFIRMED")
        self.assertEqual(set(payload["coverage"]["agents_run"]), {"ipc-agent"})
        self.assertEqual(payload["coverage"]["surfaces_tested"], ["android-ipc"])
        self.assertEqual(payload["coverage"]["total_findings"], 1)

    def test_reviewed_identity_change_patches_same_fid_without_duplicate(self) -> None:
        reserved = self.team.deduplicate_findings([self._finding()], self.team.load_ledger())
        reviewed = {
            **reserved[0],
            "class_name": "exported-activity",
            "type": "Corrected exported activity bypass",
            "file": "src/CorrectedActivity.java",
            "line": 42,
            "review_tier": "CONFIRMED",
            "tier": "CONFIRMED",
            "review_notes": "Reviewer corrected the finding identity.",
        }

        updated = self.team.update_reviewed_findings([reviewed])

        self.assertEqual(updated[0]["fid"], "D01")
        payload = self._payload()
        self.assertEqual(len(payload["findings"]), 1)
        stored = payload["findings"][0]
        self.assertEqual(stored["fid"], "D01")
        self.assertEqual(stored["class_name"], "exported-activity")
        self.assertEqual(stored["type"], "Corrected exported activity bypass")
        self.assertEqual(stored["file"], "src/CorrectedActivity.java")
        self.assertEqual(stored["line"], 42)
        self.assertEqual(stored["current"]["review_tier"], "CONFIRMED")

    def test_reviewed_update_refreshes_report_and_indexes(self) -> None:
        reserved = self.team.deduplicate_findings([self._finding()], self.team.load_ledger())
        reviewed = {
            **reserved[0],
            "review_tier": "CONFIRMED",
            "tier": "CONFIRMED",
            "review_notes": "Confirmed reachable exported component.",
        }

        updated = self.team.update_reviewed_findings([reviewed])

        stored = updated[0]
        report_path = Path(stored["report_path"])
        self.assertTrue(report_path.exists())
        self.assertEqual(report_path.parent.parent.name, "findings")
        self.assertEqual(report_path.parent.name, "confirmed")
        self.assertEqual(report_path.name, f"{stored['fid']} - HIGH - Exported activity trust bypass.md")
        self.assertTrue((self.team.storage.ledgers_root / "indexes" / "by_status" / "confirmed.json").exists())
        self.assertTrue((self.team.storage.ledgers_root / "indexes" / "active_slice.json").exists())
        confirmed_index = self.team.storage.reports_root / "confirmed.md"
        self.assertTrue(confirmed_index.exists())
        self.assertIn("Exported activity trust bypass", confirmed_index.read_text(encoding="utf-8"))

    def test_partial_persistence_reserves_without_review_promotion(self) -> None:
        self.team._partial_findings = [self._finding()]

        self.team._persist_partial_results()

        payload = self._payload()
        self.assertEqual(len(payload["findings"]), 1)
        stored = payload["findings"][0]
        self.assertEqual(stored["fid"], "D01")
        self.assertEqual(stored["current"]["review_tier"], "PENDING_REVIEW")
        self.assertNotEqual(stored.get("review_tier"), "INCONCLUSIVE")
        self.assertNotIn("report_path", stored)
        self.assertFalse((self.team.storage.ledgers_root / "indexes" / "by_status" / "inconclusive.json").exists())

    def test_active_base_team_write_paths_do_not_expose_or_use_legacy_save_ledger(self) -> None:
        self.assertFalse(hasattr(base_team_package, "save_ledger"))
        self.assertFalse(hasattr(base_team_ledger, "save_ledger"))
        self.assertFalse(hasattr(BaseTeam, "save_ledger"))
        self.assertFalse(hasattr(self.team, "save_ledger"))

        reserved = self.team.deduplicate_findings([self._finding()], self.team.load_ledger())
        reviewed = {
            **reserved[0],
            "review_tier": "CONFIRMED",
            "tier": "CONFIRMED",
            "review_notes": "Confirmed reachable exported component.",
        }

        updated = self.team.update_reviewed_findings([reviewed])
        self.team.update_coverage("ipc-agent", "android-ipc", len(updated))
        self.team._partial_findings = [self._finding()]
        self.team._persist_partial_results()

        payload = self._payload()
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["findings"][0]["fid"], "D01")
        self.assertEqual(payload["findings"][0]["current"]["review_tier"], "CONFIRMED")
        self.assertEqual(payload["coverage"]["surfaces_tested"], ["android-ipc"])

    def test_runtime_review_path_uses_reviewed_update_instead_of_whole_ledger_save(self) -> None:
        reviewed = {**self._finding(), "fid": "D01", "review_tier": "CONFIRMED"}
        calls: list[str] = []

        confirmed, dormant, novel = runtime_orchestrate(
            parallel=True,
            agents_mode="static",
            install_signal_handlers=lambda: None,
            set_partial_findings=lambda findings: None,
            get_static_profiles=lambda: [],
            generate_dynamic_agents=lambda target, force: [],
            target_path=self.target,
            force_preflight=False,
            select_specs=lambda static, dynamic: [],
            load_shared_brain=lambda: {"files": {}},
            load_ledger=lambda: {"version": 2, "findings": []},
            set_last_loaded_ledger=lambda ledger: None,
            findings_path=self.team.findings_path,
            write_traces=lambda events: None,
            snapshot_id=lambda: "snap-runtime",
            spawn_agent=lambda prompt, agent_name, log_path: None,  # type: ignore[arg-type,return-value]
            agents_dir=self.team.agents_dir,
            slug=lambda value: value,
            trace_timestamp=lambda: "20260429T000000Z",
            sigterm_received=lambda: False,
            read_log_for_handle=lambda handle: "",
            cleanup_handle=lambda handle: None,
            collect_agent_findings=lambda spec, log_path: [],
            agent_timeout=1,
            deduplicate_findings=lambda raw, ledger: [reviewed],
            stage2_review=lambda findings, target: (findings, [], []),
            update_reviewed_findings=lambda findings: calls.append("updated") or findings,
            update_coverage=lambda agent_name, surface, finding_count: None,
            get_last_review_error=lambda: None,
            active_handles={},
            persist_partial_results=lambda: None,
            render_prompt=lambda spec: "",
        )

        self.assertEqual(calls, ["updated"])
        self.assertEqual(confirmed, [reviewed])
        self.assertEqual(dormant, [])
        self.assertEqual(novel, [])


if __name__ == "__main__":
    unittest.main()
