"""Focused tests for APK team orchestration."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents import apk_team  # noqa: E402
from agents.base_team.apk_compat import load_findings, run_agent_session  # noqa: E402


class FakeProcess:
    returncode = 0

    def wait(self) -> int:
        return 0


class ApkTeamOutputRootTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)

    def test_explicit_output_root_is_forwarded_to_storage_and_review(self) -> None:
        explicit_root = self.tmp / "explicit-root"
        expected_root = explicit_root.expanduser().resolve(strict=False)
        storage = SimpleNamespace(
            family="binaries",
            lane="apk",
            lane_root=self.tmp / "storage" / "lane",
            reports_root=self.tmp / "storage" / "reports",
            ledgers_root=self.tmp / "storage" / "ledgers",
            context_root=self.tmp / "storage" / "context",
            working_root=self.tmp / "storage" / "work",
        )
        registry = SimpleNamespace(
            extracted_root=self.tmp / "extracted-apk",
            registry_path=self.tmp / "surface_registry.json",
            payload={"package_name": "com.example.app", "version_name": "1.2.3", "stats": {}},
            record_progressive_finding=Mock(),
        )
        ledger = SimpleNamespace(
            path=storage.ledgers_root / "ledger.json",
            get_class_context=Mock(return_value=""),
            update=Mock(),
            run_id="run-1",
        )
        finding = {
            "fid": "D01",
            "type": "exec-sink-reachability",
            "file": "src/Main.java",
            "description": "Reviewed finding.",
        }

        with (
            patch.object(apk_team, "SubagentLogger", None),
            patch.object(apk_team, "BountyMemory", None),
            patch.object(apk_team, "resolve_team_storage", return_value=storage) as resolve_mock,
            patch.object(
                apk_team,
                "build_surface_registry",
                return_value={"surface_registry_path": str(registry.registry_path)},
            ),
            patch.object(apk_team.ApkSurfaceRegistry, "load", return_value=registry),
            patch.object(
                apk_team,
                "get_snapshot_identity",
                return_value={"snapshot_id": "snap-1", "version_label": "1.2.3"},
            ),
            patch.object(apk_team, "create_team_ledger_from_storage", return_value=ledger),
            patch.object(apk_team, "DynamicAgentBuilder") as builder_cls,
            patch.object(apk_team, "_select_profiles", return_value=[]),
            patch.object(apk_team, "load_findings", return_value=[finding]),
            patch.object(apk_team, "stage2_ghost_review", return_value=([finding], [], [])) as review_mock,
            patch.object(apk_team, "update_team_finding", return_value=finding) as update_mock,
            patch.object(apk_team, "pretty_print_findings"),
        ):
            builder_cls.return_value.run.return_value = []

            apk_team.orchestrate_apk_team(
                "Example Program",
                str(self.tmp / "example.apk"),
                output_root=explicit_root,
            )

        self.assertEqual(resolve_mock.call_args.kwargs["output_root"], expected_root)
        self.assertIsNone(resolve_mock.call_args.kwargs["target_kind"])
        self.assertEqual(resolve_mock.call_args.kwargs["target_path"], str(self.tmp / "example.apk"))
        self.assertEqual(review_mock.call_args.kwargs["output_root"], expected_root)
        update_mock.assert_called_once()
        self.assertEqual(update_mock.call_args.args[:2], ("Example_Program", finding))
        self.assertEqual(update_mock.call_args.kwargs["root_override"], expected_root)
        self.assertEqual(update_mock.call_args.kwargs["family"], "binaries")
        self.assertEqual(update_mock.call_args.kwargs["lane"], "apk")
        self.assertTrue(update_mock.call_args.kwargs["write_report"])
        self.assertTrue(update_mock.call_args.kwargs["refresh"])
        ledger.update.assert_not_called()

    def test_apk_load_findings_preserves_reserved_fid(self) -> None:
        findings_path = self.tmp / "findings.jsonl"
        findings_path.write_text(
            '{"agent":"provider-agent","class_name":"provider","description":"Reviewed finding.",'
            '"fid":"D01","file":"AndroidManifest.xml","severity":"HIGH","type":"exported-provider"}\n',
            encoding="utf-8",
        )

        self.assertEqual(load_findings(findings_path)[0]["fid"], "D01")

    def test_apk_agent_session_reserves_before_queueing_raw_jsonl(self) -> None:
        findings_path = self.tmp / "findings.jsonl"
        raw = {"type": "exported-provider", "file": "AndroidManifest.xml", "severity": "HIGH"}
        reserved = {**raw, "fid": "D01", "snapshot_id": "snap-1"}
        ledger = SimpleNamespace(check=Mock(return_value=(False, "D01", reserved)))
        session = SimpleNamespace(
            process=FakeProcess(),
            log_path=self.tmp / "agent.log",
            profile=SimpleNamespace(key="provider-agent"),
            workspace=self.tmp / "workspace",
            skip_ledger=False,
        )
        session.log_path.write_text("{}\n", encoding="utf-8")
        session.workspace.mkdir()

        exit_code = run_agent_session(
            session,
            findings_path,
            ledger,
            extract_findings_from_log=Mock(return_value=[raw]),
        )

        self.assertEqual(exit_code, 0)
        ledger.check.assert_called_once_with(raw)
        queued = findings_path.read_text(encoding="utf-8")
        self.assertIn('"fid": "D01"', queued)
        self.assertFalse(hasattr(ledger, "add_or_update"))

    def test_chainer_invocation_uses_canonical_reports_output(self) -> None:
        storage = SimpleNamespace(
            family="binaries",
            lane="apk",
            lane_root=self.tmp / "storage" / "lane",
            reports_root=self.tmp / "storage" / "reports",
            ledgers_root=self.tmp / "storage" / "ledgers",
            context_root=self.tmp / "storage" / "context",
            working_root=self.tmp / "storage" / "work",
        )
        registry = SimpleNamespace(
            extracted_root=self.tmp / "extracted-apk",
            registry_path=self.tmp / "surface_registry.json",
            payload={"package_name": "com.example.app", "version_name": "1.2.3", "stats": {}},
            record_progressive_finding=Mock(),
        )
        ledger = SimpleNamespace(
            path=storage.ledgers_root / "ledger.json",
            get_class_context=Mock(return_value=""),
            update=Mock(),
            run_id="run-1",
        )
        finding = {
            "fid": "D01",
            "type": "exec-sink-reachability",
            "file": "src/Main.java",
            "description": "Requires prior XSS to reach a command sink.",
        }
        chainer_module = SimpleNamespace(main=Mock(return_value=1))
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))

        with (
            patch.object(apk_team, "SubagentLogger", None),
            patch.object(apk_team, "BountyMemory", None),
            patch.object(apk_team, "resolve_team_storage", return_value=storage),
            patch.object(
                apk_team,
                "build_surface_registry",
                return_value={"surface_registry_path": str(registry.registry_path)},
            ),
            patch.object(apk_team.ApkSurfaceRegistry, "load", return_value=registry),
            patch.object(
                apk_team,
                "get_snapshot_identity",
                return_value={"snapshot_id": "snap-1", "version_label": "1.2.3"},
            ),
            patch.object(apk_team, "create_team_ledger_from_storage", return_value=ledger),
            patch.object(apk_team, "DynamicAgentBuilder") as builder_cls,
            patch.object(apk_team, "_select_profiles", return_value=[]),
            patch.object(apk_team, "load_findings", return_value=[finding]),
            patch.object(apk_team, "stage2_ghost_review", return_value=([finding], [], [])),
            patch.object(apk_team, "update_team_finding", return_value=finding),
            patch.object(apk_team, "build_chain_graph", return_value={"nodes": [], "edges": []}),
            patch.object(apk_team, "get_chainable_findings", return_value=[finding]),
            patch.object(apk_team.importlib.util, "spec_from_file_location", return_value=spec),
            patch.object(apk_team.importlib.util, "module_from_spec", return_value=chainer_module),
            patch.object(apk_team, "pretty_print_findings"),
        ):
            builder_cls.return_value.run.return_value = []

            apk_team.orchestrate_apk_team("Example Program", str(self.tmp / "example.apk"), chain=True)

        chainer_args = chainer_module.main.call_args.args[0]
        self.assertEqual(
            chainer_args[chainer_args.index("--output-dir") + 1],
            str(storage.reports_root / "chained"),
        )

    def test_raw_jsonl_findings_are_review_input_only(self) -> None:
        explicit_root = self.tmp / "explicit-root"
        expected_root = explicit_root.expanduser().resolve(strict=False)
        storage = SimpleNamespace(
            family="binaries",
            lane="apk",
            lane_root=self.tmp / "storage" / "lane",
            reports_root=self.tmp / "storage" / "reports",
            ledgers_root=self.tmp / "storage" / "ledgers",
            context_root=self.tmp / "storage" / "context",
            working_root=self.tmp / "storage" / "work",
        )
        registry = SimpleNamespace(
            extracted_root=self.tmp / "extracted-apk",
            registry_path=self.tmp / "surface_registry.json",
            payload={"package_name": "com.example.app", "version_name": "1.2.3", "stats": {}},
            record_progressive_finding=Mock(),
        )
        ledger = SimpleNamespace(
            path=storage.ledgers_root / "ledger.json",
            get_class_context=Mock(return_value=""),
            update=Mock(),
            run_id="run-1",
            root_override=expected_root,
        )
        raw_finding = {
            "fid": "RAW01",
            "type": "unreviewed-apk-jsonl-candidate",
            "file": "smali/com/example/MainActivity.smali",
            "description": "Loaded from raw findings.jsonl and rejected before persistence.",
        }

        with (
            patch.object(apk_team, "SubagentLogger", None),
            patch.object(apk_team, "BountyMemory", None),
            patch.object(apk_team, "resolve_team_storage", return_value=storage),
            patch.object(
                apk_team,
                "build_surface_registry",
                return_value={"surface_registry_path": str(registry.registry_path)},
            ),
            patch.object(apk_team.ApkSurfaceRegistry, "load", return_value=registry),
            patch.object(
                apk_team,
                "get_snapshot_identity",
                return_value={"snapshot_id": "snap-1", "version_label": "1.2.3"},
            ),
            patch.object(apk_team, "create_team_ledger_from_storage", return_value=ledger),
            patch.object(apk_team, "DynamicAgentBuilder") as builder_cls,
            patch.object(apk_team, "_select_profiles", return_value=[]),
            patch.object(apk_team, "load_findings", return_value=[raw_finding]) as load_mock,
            patch.object(apk_team, "stage2_ghost_review", return_value=([], [], [])) as review_mock,
            patch.object(apk_team, "update_team_finding") as update_mock,
            patch.object(apk_team, "pretty_print_findings"),
            patch("bounty_core.ledger.add_finding") as add_finding_mock,
        ):
            builder_cls.return_value.run.return_value = []

            apk_team.orchestrate_apk_team(
                "Example Program",
                str(self.tmp / "example.apk"),
                output_root=explicit_root,
            )

        load_mock.assert_called_once()
        self.assertEqual(review_mock.call_args.args[0], [raw_finding])
        self.assertEqual(review_mock.call_args.kwargs["output_root"], expected_root)
        update_mock.assert_not_called()
        ledger.update.assert_not_called()
        add_finding_mock.assert_not_called()
        registry.record_progressive_finding.assert_not_called()

    def test_canonical_lane_root_output_root_does_not_nest_storage(self) -> None:
        lane_root = self.tmp / "Shared" / "binaries" / "Example_Program" / "apk"
        apk_path = lane_root / "input" / "example.apk"
        apk_path.parent.mkdir(parents=True)
        apk_path.write_text("placeholder\n", encoding="utf-8")
        registry = SimpleNamespace(
            extracted_root=self.tmp / "extracted-apk",
            registry_path=self.tmp / "surface_registry.json",
            payload={"package_name": "com.example.app", "version_name": "1.2.3", "stats": {}},
            record_progressive_finding=Mock(),
        )
        ledger = SimpleNamespace(
            path=lane_root / "ledgers" / "ledger.json",
            get_class_context=Mock(return_value=""),
            update=Mock(),
            run_id="run-1",
        )

        with (
            patch.object(Path, "home", return_value=self.tmp),
            patch.object(apk_team, "SubagentLogger", None),
            patch.object(apk_team, "BountyMemory", None),
            patch.object(
                apk_team,
                "build_surface_registry",
                return_value={"surface_registry_path": str(registry.registry_path)},
            ) as registry_mock,
            patch.object(apk_team.ApkSurfaceRegistry, "load", return_value=registry),
            patch.object(
                apk_team,
                "get_snapshot_identity",
                return_value={"snapshot_id": "snap-1", "version_label": "1.2.3"},
            ),
            patch.object(apk_team, "create_team_ledger_from_storage", return_value=ledger) as ledger_mock,
            patch.object(apk_team, "DynamicAgentBuilder") as builder_cls,
            patch.object(apk_team, "_select_profiles", return_value=[]),
            patch.object(apk_team, "load_findings", return_value=[]),
            patch.object(apk_team, "stage2_ghost_review", return_value=([], [], [])) as review_mock,
            patch.object(apk_team, "pretty_print_findings"),
        ):
            builder_cls.return_value.run.return_value = []

            apk_team.orchestrate_apk_team(
                "Example Program",
                str(apk_path),
                output_root=lane_root,
            )

        storage = ledger_mock.call_args.kwargs["storage"]
        self.assertEqual(storage.lane_root, lane_root)
        self.assertEqual(registry_mock.call_args.kwargs["output_root"], lane_root)
        self.assertEqual(review_mock.call_args.kwargs["output_root"], lane_root)
        self.assertFalse((lane_root / "binaries" / "Example_Program" / "apk").exists())

    def test_cli_accepts_target_identity_routing_flags(self) -> None:
        args = apk_team._parse_cli_args(
            [
                "Example Program",
                str(self.tmp / "example.apk"),
                "--target-kind",
                "apk",
                "--intent-text",
                "Android APK review",
                "--family",
                "binaries",
                "--lane",
                "apk",
            ]
        )

        self.assertEqual(args.target_kind, "apk")
        self.assertEqual(args.intent_text, "Android APK review")
        self.assertEqual(args.family, "binaries")
        self.assertEqual(args.lane, "apk")


if __name__ == "__main__":
    unittest.main()
