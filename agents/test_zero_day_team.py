"""Focused tests for zero-day team storage propagation."""

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

from agents import zero_day_team  # noqa: E402


class ZeroDayTeamOutputRootTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)

    def test_chainer_invocation_uses_canonical_reports_output(self) -> None:
        target = self.tmp / "target"
        target.mkdir()
        storage = SimpleNamespace(
            family="web",
            lane="0day_team",
            lane_root=self.tmp / "storage" / "lane",
            reports_root=self.tmp / "storage" / "reports",
            ledgers_root=self.tmp / "storage" / "ledgers",
            context_root=self.tmp / "storage" / "context",
            working_root=self.tmp / "storage" / "work",
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
            "file": "src/main.py",
            "description": "Requires prior XSS to reach a command sink.",
        }
        chainer_module = SimpleNamespace(main=Mock(return_value=1))
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))

        with (
            patch.object(zero_day_team, "SubagentLogger", None),
            patch.object(zero_day_team, "_resolve_zero_day_storage", return_value=storage),
            patch.object(
                zero_day_team,
                "get_snapshot_identity",
                return_value={"snapshot_id": "snap-1", "version_label": "1.2.3", "channel": "stable"},
            ),
            patch.object(zero_day_team, "create_team_ledger_from_storage", return_value=ledger),
            patch.object(zero_day_team, "DynamicAgentBuilder") as builder_cls,
            patch.object(zero_day_team, "_select_profiles", return_value=[]),
            patch.object(zero_day_team, "_load_findings", return_value=[finding]),
            patch.object(zero_day_team, "stage2_ghost_review", return_value=([finding], [], [])),
            patch.object(zero_day_team, "update_team_finding", return_value=finding) as update_mock,
            patch.object(zero_day_team, "build_chain_graph", return_value={"nodes": [], "edges": []}),
            patch.object(zero_day_team, "get_chainable_findings", return_value=[finding]),
            patch("importlib.util.spec_from_file_location", return_value=spec),
            patch("importlib.util.module_from_spec", return_value=chainer_module),
            patch.object(zero_day_team, "_pretty_print_findings"),
        ):
            builder_cls.return_value.run.return_value = []

            zero_day_team.orchestrate_zero_day_team(
                "Example Program",
                str(target),
                chain=True,
                no_preflight=True,
                no_shared_brain=True,
            )

        chainer_args = chainer_module.main.call_args.args[0]
        self.assertEqual(
            chainer_args[chainer_args.index("--output-dir") + 1],
            str(storage.reports_root / "chained"),
        )
        update_mock.assert_called_once()
        self.assertEqual(update_mock.call_args.args[:2], ("Example_Program", finding))
        self.assertEqual(update_mock.call_args.kwargs["family"], "web")
        self.assertEqual(update_mock.call_args.kwargs["lane"], "0day_team")
        self.assertFalse(update_mock.call_args.kwargs["write_report"])
        self.assertFalse(update_mock.call_args.kwargs["refresh"])
        ledger.update.assert_not_called()

    def test_raw_jsonl_findings_are_review_input_only(self) -> None:
        target = self.tmp / "target"
        target.mkdir()
        storage = SimpleNamespace(
            family="web",
            lane="0day_team",
            lane_root=self.tmp / "storage" / "lane",
            reports_root=self.tmp / "storage" / "reports",
            ledgers_root=self.tmp / "storage" / "ledgers",
            context_root=self.tmp / "storage" / "context",
            working_root=self.tmp / "storage" / "work",
        )
        ledger = SimpleNamespace(
            path=storage.ledgers_root / "ledger.json",
            get_class_context=Mock(return_value=""),
            update=Mock(),
            run_id="run-1",
            root_override=self.tmp / "storage-root",
        )
        raw_finding = {
            "fid": "RAW01",
            "type": "unreviewed-jsonl-candidate",
            "file": "src/main.py",
            "description": "Loaded from raw findings.jsonl and not approved by review.",
        }

        with (
            patch.object(zero_day_team, "SubagentLogger", None),
            patch.object(zero_day_team, "_resolve_zero_day_storage", return_value=storage),
            patch.object(
                zero_day_team,
                "get_snapshot_identity",
                return_value={"snapshot_id": "snap-1", "version_label": "1.2.3", "channel": "stable"},
            ),
            patch.object(zero_day_team, "create_team_ledger_from_storage", return_value=ledger),
            patch.object(zero_day_team, "DynamicAgentBuilder") as builder_cls,
            patch.object(zero_day_team, "_select_profiles", return_value=[]),
            patch.object(zero_day_team, "_load_findings", return_value=[raw_finding]) as load_mock,
            patch.object(zero_day_team, "stage2_ghost_review", return_value=([], [], [])) as review_mock,
            patch.object(zero_day_team, "update_team_finding") as update_mock,
            patch.object(zero_day_team, "_pretty_print_findings"),
            patch("bounty_core.ledger.add_finding") as add_finding_mock,
        ):
            builder_cls.return_value.run.return_value = []

            zero_day_team.orchestrate_zero_day_team(
                "Example Program",
                str(target),
                chain=False,
                no_preflight=True,
                no_shared_brain=True,
            )

        load_mock.assert_called_once()
        self.assertEqual(review_mock.call_args.args[0], [raw_finding])
        update_mock.assert_not_called()
        ledger.update.assert_not_called()
        add_finding_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
