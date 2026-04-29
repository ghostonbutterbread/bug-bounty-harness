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
        self.assertEqual(review_mock.call_args.kwargs["output_root"], expected_root)
        update_mock.assert_called_once()
        self.assertEqual(update_mock.call_args.args[:2], ("Example_Program", finding))
        self.assertEqual(update_mock.call_args.kwargs["root_override"], expected_root)
        self.assertEqual(update_mock.call_args.kwargs["family"], "binaries")
        self.assertEqual(update_mock.call_args.kwargs["lane"], "apk")
        self.assertFalse(update_mock.call_args.kwargs["write_report"])
        self.assertFalse(update_mock.call_args.kwargs["refresh"])
        ledger.update.assert_not_called()

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


if __name__ == "__main__":
    unittest.main()
