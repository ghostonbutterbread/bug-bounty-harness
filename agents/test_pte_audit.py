"""Tests for the PTE audit module and additive trace logger fields."""

from __future__ import annotations

import contextlib
import importlib.util
import io
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

from agents.pte_audit import HarnessEfficiencyScorer, main


SUBAGENT_LOGGER_PATH = Path("/home/ryushe/projects/bounty-tools/subagent_logger.py")


def _load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PteAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)
        self.home = self.tmp / "home"
        self.home.mkdir(parents=True, exist_ok=True)
        self.home_patcher = patch.dict(os.environ, {"HOME": str(self.home)}, clear=False)
        self.home_patcher.start()
        self.addCleanup(self.home_patcher.stop)

    def _ghost_dir(self, program: str) -> Path:
        return self.home / "Shared" / "bounty_recon" / program / "ghost"

    def _write_jsonl(self, path: Path, rows: list[dict]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        text = "".join(json.dumps(row) + "\n" for row in rows)
        path.write_text(text, encoding="utf-8")

    def _write_ledger(self, program: str) -> None:
        payload = {
            "version": 2,
            "program": program,
            "updated_at": "2026-04-08T03:00:00Z",
            "findings": [
                {
                    "fid": "D01",
                    "type": "Reflected XSS",
                    "class_name": "dom-xss",
                    "category": "class",
                    "file": "app.js",
                    "line": 10,
                    "severity": "HIGH",
                    "sightings": [
                        {
                            "snapshot_id": "snap-a",
                            "version_label": "v1",
                            "run_id": "20260408T010000Z",
                            "seen_at": "2026-04-08T01:00:00Z",
                            "status": "confirmed",
                            "review_tier": "CONFIRMED",
                            "agent": "xss_hunter",
                            "allocated_pte_lite": 900,
                        },
                        {
                            "snapshot_id": "snap-a",
                            "version_label": "v1",
                            "run_id": "20260408T020000Z",
                            "seen_at": "2026-04-08T02:00:00Z",
                            "status": "confirmed",
                            "review_tier": "CONFIRMED",
                            "agent": "xss_framework",
                            "allocated_pte_lite": 1800,
                        },
                    ],
                    "current": {
                        "review_tier": "CONFIRMED",
                        "status": "confirmed",
                        "version_label": "v1",
                    },
                },
                {
                    "fid": "D02",
                    "type": "Stored XSS prerequisite",
                    "class_name": "dom-xss",
                    "category": "class",
                    "file": "profile.js",
                    "line": 22,
                    "severity": "MEDIUM",
                    "chain_enabler": True,
                    "sightings": [
                        {
                            "snapshot_id": "snap-a",
                            "version_label": "v1",
                            "run_id": "20260408T010000Z",
                            "seen_at": "2026-04-08T01:10:00Z",
                            "status": "pending-review",
                            "review_tier": "DORMANT_ACTIVE",
                            "agent": "xss_hunter",
                            "allocated_pte_lite": 900,
                        }
                    ],
                    "current": {
                        "review_tier": "DORMANT_ACTIVE",
                        "status": "pending-review",
                        "version_label": "v1",
                    },
                },
                {
                    "fid": "D03",
                    "type": "False positive",
                    "class_name": "dom-xss",
                    "category": "class",
                    "file": "legacy.js",
                    "line": 5,
                    "severity": "LOW",
                    "sightings": [
                        {
                            "snapshot_id": "snap-a",
                            "version_label": "v1",
                            "run_id": "20260408T020000Z",
                            "seen_at": "2026-04-08T02:20:00Z",
                            "status": "rejected",
                            "review_tier": "REJECTED",
                            "agent": "xss_framework",
                            "allocated_pte_lite": 2200,
                        }
                    ],
                    "current": {
                        "review_tier": "REJECTED",
                        "status": "rejected",
                        "version_label": "v1",
                    },
                },
            ],
        }
        ledger_path = self._ghost_dir(program) / "ledger.json"
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        ledger_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def _write_traces(self, program: str) -> None:
        traces_dir = self._ghost_dir(program) / "traces"
        run1 = [
            {
                "timestamp": "2026-04-08T01:00:00Z",
                "level": "START",
                "tool": "xss_hunter",
                "agent_id": "agent1",
                "run_id": "20260408T010000Z",
                "trace_id": "trace-run1",
                "span_type": "run",
                "phase": "agent_run",
                "agent_name": "xss_hunter",
                "message": "start",
            },
            {
                "timestamp": "2026-04-08T01:00:02Z",
                "level": "STEP",
                "tool": "xss_hunter",
                "agent_id": "agent1",
                "run_id": "20260408T010000Z",
                "trace_id": "trace-run1",
                "span_type": "tool",
                "tool_name": "wayback",
                "tool_category": "archive",
                "agent_name": "xss_hunter",
                "message": "history lookup",
                "output_bytes": 600,
            },
            {
                "timestamp": "2026-04-08T01:00:03Z",
                "level": "STEP",
                "tool": "xss_hunter",
                "agent_id": "agent1",
                "run_id": "20260408T010000Z",
                "trace_id": "trace-run1",
                "span_type": "tool",
                "tool_name": "browser",
                "tool_category": "browser",
                "agent_name": "xss_hunter",
                "message": "browser verify",
                "output_bytes": 800,
            },
            {
                "timestamp": "2026-04-08T01:00:05Z",
                "level": "RESULT",
                "tool": "xss_hunter",
                "agent_id": "agent1",
                "run_id": "20260408T010000Z",
                "trace_id": "trace-run1",
                "span_type": "model",
                "agent_name": "xss_hunter",
                "model_name": "gpt-5.4",
                "prompt_tokens": 1200,
                "completion_tokens": 300,
                "tool_output_tokens": 300,
                "context_tokens_after": 2500,
                "pte_lite": 1800,
                "message": "review complete",
            },
            {
                "timestamp": "2026-04-08T01:00:08Z",
                "level": "FINISH",
                "tool": "xss_hunter",
                "agent_id": "agent1",
                "run_id": "20260408T010000Z",
                "trace_id": "trace-run1",
                "span_type": "run",
                "phase": "agent_run",
                "agent_name": "xss_hunter",
                "duration_ms": 8000,
                "success": True,
                "message": "done",
            },
        ]
        run2 = [
            {
                "timestamp": "2026-04-08T02:00:00Z",
                "level": "START",
                "tool": "xss_framework",
                "agent_id": "agent2",
                "run_id": "20260408T020000Z",
                "trace_id": "trace-run2",
                "span_type": "run",
                "phase": "agent_run",
                "agent_name": "xss_framework",
                "message": "start",
            },
        ]
        tool_spans = [
            ("archive", "wayback"),
            ("fuzz", "ffuf"),
            ("browser", "playwright"),
            ("waf", "waf-bypass"),
            ("browser", "playwright"),
            ("fuzz", "ffuf"),
        ]
        for idx, (tool_category, tool_name) in enumerate(tool_spans, start=1):
            run2.append(
                {
                    "timestamp": f"2026-04-08T02:00:{idx:02d}Z",
                    "level": "STEP",
                    "tool": "xss_framework",
                    "agent_id": "agent2",
                    "run_id": "20260408T020000Z",
                    "trace_id": "trace-run2",
                    "span_type": "tool",
                    "tool_name": tool_name,
                    "tool_category": tool_category,
                    "agent_name": "xss_framework",
                    "message": tool_name,
                    "output_bytes": 1200,
                }
            )
        run2.extend(
            [
                {
                    "timestamp": "2026-04-08T02:00:10Z",
                    "level": "RESULT",
                    "tool": "xss_framework",
                    "agent_id": "agent2",
                    "run_id": "20260408T020000Z",
                    "trace_id": "trace-run2",
                    "span_type": "model",
                    "agent_name": "xss_framework",
                    "model_name": "gpt-5.4",
                    "prompt_tokens": 1800,
                    "completion_tokens": 500,
                    "tool_output_tokens": 700,
                    "context_tokens_after": 34000,
                    "context_overhang_tokens": 2000,
                    "pte_lite": 4000,
                    "message": "review complete",
                },
                {
                    "timestamp": "2026-04-08T02:00:14Z",
                    "level": "FINISH",
                    "tool": "xss_framework",
                    "agent_id": "agent2",
                    "run_id": "20260408T020000Z",
                    "trace_id": "trace-run2",
                    "span_type": "run",
                    "phase": "agent_run",
                    "agent_name": "xss_framework",
                    "duration_ms": 14000,
                    "success": True,
                    "message": "done",
                },
            ]
        )
        self._write_jsonl(traces_dir / "20260408T010000Z.jsonl", run1)
        self._write_jsonl(traces_dir / "20260408T020000Z.jsonl", run2)

    def test_subagent_logger_writes_trace_and_computes_pte_lite(self) -> None:
        module = _load_module(SUBAGENT_LOGGER_PATH, "subagent_logger_test")
        logger = module.SubagentLogger("xss_hunter", "demo")
        logger.start(target="https://example.test")
        logger.log_span(
            "model",
            level="RESULT",
            message="model review",
            prompt_tokens=1000,
            completion_tokens=100,
            tool_output_tokens=40,
            context_tokens_after=33050,
        )
        logger.finish(success=True, summary="done")

        trace_dir = self._ghost_dir("demo") / "traces"
        trace_files = list(trace_dir.glob("*.jsonl"))
        self.assertEqual(len(trace_files), 1)
        rows = [json.loads(line) for line in trace_files[0].read_text(encoding="utf-8").splitlines() if line.strip()]
        model_rows = [row for row in rows if row.get("span_type") == "model"]

        self.assertEqual(module.estimate_tokens(9), 3)
        self.assertEqual(module.compute_pte_lite(prompt_tokens=1000, completion_tokens=100, tool_output_tokens=40, context_tokens_after=33050), 2190)
        self.assertEqual(len(model_rows), 1)
        self.assertEqual(model_rows[0]["pte_lite"], 2190)
        self.assertTrue(rows[0]["trace_id"].startswith("xss_hunter_"))

    def test_harness_efficiency_scoring_and_cli_outputs(self) -> None:
        program = "demo"
        self._write_ledger(program)
        self._write_traces(program)

        scorer = HarnessEfficiencyScorer(program)
        run1 = scorer.compute_run_worth("20260408T010000Z")
        framework = scorer.score_agent_profile("xss_framework")
        report = scorer.generate_audit_report()
        patterns = scorer.get_inefficiency_patterns("xss_framework")

        self.assertEqual(run1["confirmed_unique"], 1)
        self.assertEqual(run1["dormant_active"], 1)
        self.assertEqual(run1["total_pte_lite"], 1800)
        self.assertAlmostEqual(run1["run_worth"], 0.9722, places=4)

        self.assertEqual(framework["duplicates"], 1)
        self.assertEqual(framework["rejected"], 1)
        self.assertEqual(framework["median_pte_lite"], 4000)
        self.assertLess(framework["profile_worth"], 0.0)
        self.assertIn("Confirmatory Tool Usage", patterns)
        self.assertIn("Tool-Mixing", patterns)
        self.assertIn("Lack of Tool Priors", patterns)
        self.assertIn("Tool Format Collapse", patterns)

        self.assertIn("| Agent | Runs | Median PTE | Confirmed | Dormant | Rejected | Dupes | FP Rate | Worth Score |", report)
        self.assertIn("xss_framework overlaps 75% with xss_hunter", report)

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(["--program", program, "--compare", "xss_hunter", "xss_framework"])
        compare_output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("| Metric | xss_hunter | xss_framework |", compare_output)


if __name__ == "__main__":
    unittest.main()
