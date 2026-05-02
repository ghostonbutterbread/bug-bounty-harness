"""Focused tests for zero-day team storage propagation."""

from __future__ import annotations

import sys
import tempfile
import unittest
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents import zero_day_team  # noqa: E402


class FakeProcess:
    def wait(self, timeout=None) -> int:
        return 0


class ZeroDayTeamOutputRootTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)

    def _brainstorm_spec_text(self) -> str:
        return """# Brainstorm Spec: Canva Desktop EXE

## Metadata
- Program: canva
- Family: binaries
- Lane: exe
- Target kind: electron-exe
- Target path: input/app_asar
- Status: active

## Target mental model
Electron desktop target.

## Impact primitives
### P001 - Renderer to bridge
- Source: renderer import
- Impact: bridge access
- Status: active

## Hypotheses
### H001 - SVG import can create renderer script execution
- Status: untested
- Priority: high
- Surface: import-upload-render
- Entry point: user imports SVG
- Expected chain: imported SVG -> renderer script execution -> ElectronBridge host RPC
- Suggested agents:
  - canva-svg-import-xss
- Focus files:
  - dist/**/*.js
- Tags: xss, import, renderer
- Evidence:
  - reports/dormant/index.md:12

### H002 - Retired idea
- Status: retired
- Priority: low
- Surface: retired
- Entry point: old path
- Expected chain: old -> path
- Suggested agents:
  - canva-retired-agent
- Tags: retired
"""

    def test_shared_binaries_target_routes_to_binary_lane_storage(self) -> None:
        target = self.tmp / "Shared" / "binaries" / "canva" / "exe" / "input" / "app_asar"
        target.parent.mkdir(parents=True)

        with patch.object(zero_day_team.Path, "home", return_value=self.tmp):
            storage = zero_day_team._resolve_zero_day_storage("canva", target_path=target)

        self.assertEqual(storage.family, "binaries")
        self.assertEqual(storage.lane, "exe")
        self.assertEqual(storage.lane_root, self.tmp / "Shared" / "binaries" / "canva" / "exe")

    def test_unrelated_target_preserves_legacy_web_storage(self) -> None:
        target = self.tmp / "source" / "canva"
        target.mkdir(parents=True)

        with patch.object(zero_day_team.Path, "home", return_value=self.tmp):
            storage = zero_day_team._resolve_zero_day_storage("canva", target_path=target)

        self.assertEqual(storage.family, "web_bounty")
        self.assertEqual(storage.lane, "web")
        self.assertEqual(storage.lane_root, self.tmp / "Shared" / "web_bounty" / "canva" / "web")

    def test_lane_root_output_root_does_not_nest_legacy_web_storage(self) -> None:
        lane_root = self.tmp / "Shared" / "binaries" / "canva" / "exe"
        target = lane_root / "input" / "app_asar"
        target.parent.mkdir(parents=True)

        with patch.object(zero_day_team.Path, "home", return_value=self.tmp):
            storage = zero_day_team._resolve_zero_day_storage(
                "canva",
                output_root=lane_root,
                target_path=target,
            )

        self.assertEqual(storage.family, "binaries")
        self.assertEqual(storage.lane, "exe")
        self.assertEqual(storage.lane_root, lane_root)
        self.assertFalse((lane_root / "web_bounty" / "canva" / "web").exists())

    def test_explicit_output_root_beats_canonical_target_storage_root(self) -> None:
        canonical_lane_root = self.tmp / "Shared" / "binaries" / "canva" / "exe"
        target = canonical_lane_root / "input" / "app_asar"
        target.parent.mkdir(parents=True)
        explicit_root = self.tmp / "explicit-output"

        with patch.object(zero_day_team.Path, "home", return_value=self.tmp):
            storage = zero_day_team._resolve_zero_day_storage(
                "canva",
                output_root=explicit_root,
                target_path=target,
            )

        self.assertEqual(storage.family, "binaries")
        self.assertEqual(storage.lane, "exe")
        self.assertEqual(storage.lane_root, explicit_root / "binaries" / "canva" / "exe")
        self.assertFalse((canonical_lane_root / "ledgers").exists())

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
        self.assertTrue(update_mock.call_args.kwargs["write_report"])
        self.assertTrue(update_mock.call_args.kwargs["refresh"])
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

    def test_fresh_raw_findings_reserve_fid_and_still_promote_duplicates(self) -> None:
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
        raw_finding = {
            "agent": "xss",
            "category": "class",
            "class_name": "xss",
            "type": "xss-sink",
            "file": "src/main.py",
            "line": 9,
            "description": "User input reaches innerHTML.",
            "severity": "HIGH",
            "source": "location.hash",
            "sink": "innerHTML",
        }
        reserved_finding = {**raw_finding, "fid": "D01"}
        ledger = SimpleNamespace(
            path=storage.ledgers_root / "ledger.json",
            get_class_context=Mock(return_value=""),
            check=Mock(return_value=(True, "D01", reserved_finding)),
            run_id="run-1",
            root_override=self.tmp / "storage-root",
        )

        def review_side_effect(findings, *_args, **_kwargs):
            return ([dict(findings[0], review_tier="CONFIRMED", tier="CONFIRMED")], [], [])

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
            patch.object(zero_day_team, "_load_findings", return_value=[raw_finding]),
            patch.object(zero_day_team, "stage2_ghost_review", side_effect=review_side_effect) as review_mock,
            patch.object(zero_day_team, "update_team_finding", side_effect=lambda _program, finding, **_kwargs: dict(finding)) as update_mock,
            patch.object(zero_day_team, "_pretty_print_findings"),
        ):
            builder_cls.return_value.run.return_value = []

            result = zero_day_team.orchestrate_zero_day_team(
                "Example Program",
                str(target),
                fresh=True,
                chain=False,
                no_preflight=True,
                no_shared_brain=True,
            )

        ledger.check.assert_called_once_with(raw_finding)
        reviewed_input = review_mock.call_args.args[0]
        self.assertEqual(reviewed_input[0]["fid"], "D01")
        update_mock.assert_called_once()
        self.assertEqual(update_mock.call_args.args[1]["fid"], "D01")
        self.assertEqual(result["by_tier"]["confirmed"], 1)

    def test_brainstorm_spec_wiring_runs_only_selected_profiles_and_writes_coverage(self) -> None:
        lane_root = self.tmp / "Shared" / "binaries" / "canva" / "exe"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = lane_root / "brainstorm" / "spec.md"
        spec_path.parent.mkdir(parents=True)
        spec_path.write_text(self._brainstorm_spec_text(), encoding="utf-8")
        storage = SimpleNamespace(
            family="binaries",
            lane="exe",
            lane_root=lane_root,
            reports_root=lane_root / "reports",
            ledgers_root=lane_root / "ledgers",
            context_root=lane_root / "context",
            working_root=lane_root / "work",
        )
        ledger = SimpleNamespace(
            path=storage.ledgers_root / "ledger.json",
            get_class_context=Mock(return_value=""),
            check=Mock(side_effect=lambda finding: (False, "D77", {**finding, "fid": "D77"})),
            run_id="run-1",
            root_override=None,
        )
        spawned_profiles = []

        class FakeProcess:
            pid = 4242

            def wait(self, timeout=None):
                return 0

        def fake_spawn(*, profile, agents_root, coverage_path=None, **_kwargs):
            spawned_profiles.append(profile)
            agents_root.mkdir(parents=True, exist_ok=True)
            log_path = agents_root / f"agent_{profile.key}_4242.log"
            raw_finding = {
                **profile.brainstorm_metadata,
                "agent": profile.brainstorm_metadata["brainstorm_agent_key"],
                "category": "class",
                "class_name": "xss",
                "type": "SVG import renderer script execution",
                "file": "dist/renderer.js",
                "line": 1,
                "description": "SVG preview rendering reaches script-capable renderer code.",
                "severity": "HIGH",
                "context": "renderSvg(uploaded)",
                "source": "user SVG import",
                "trust_boundary": "import to renderer",
                "flow_path": "import -> preview -> render",
                "sink": "renderSvg(uploaded)",
                "exploitability": "Victim imports attacker SVG.",
            }
            log_path.write_text(json.dumps(raw_finding) + "\n", encoding="utf-8")
            return zero_day_team.AgentSession(
                profile=profile,
                workspace=agents_root / profile.key,
                log_path=log_path,
                process=FakeProcess(),
                coverage_path=coverage_path,
            )

        def review_side_effect(findings, *_args, **_kwargs):
            return ([{**finding, "review_tier": "CONFIRMED", "tier": "CONFIRMED"} for finding in findings], [], [])

        def promote_side_effect(*_args, reviewed_groups, **_kwargs):
            reviewed = list(reviewed_groups["confirmed"])
            return {
                "confirmed": reviewed,
                "dormant": [],
                "novel": [],
                "reviewed": reviewed,
                "ledger_updates": len(reviewed),
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
            patch.object(zero_day_team, "_spawn_agent", side_effect=fake_spawn),
            patch.object(zero_day_team, "stage2_ghost_review", side_effect=review_side_effect),
            patch.object(zero_day_team, "promote_reviewed_findings", side_effect=promote_side_effect),
            patch.object(zero_day_team, "_pretty_print_findings"),
        ):
            builder_cls.return_value.run.return_value = []

            result = zero_day_team.orchestrate_zero_day_team(
                "canva",
                str(target),
                no_preflight=True,
                no_shared_brain=True,
                brainstorm_spec=str(spec_path),
                brainstorm_only=True,
                brainstorm_hypothesis="H001",
            )

        self.assertEqual(result["classes_run"], ["canva-svg-import-xss"])
        self.assertEqual(result["brainstorm"]["hypotheses"], ["H001"])
        self.assertEqual([profile.key for profile in spawned_profiles], ["canva-svg-import-xss"])
        self.assertIn("Hypothesis id: H001", spawned_profiles[0].prompt_addendum)
        self.assertIn("Expected chain: imported SVG", spawned_profiles[0].prompt_addendum)
        self.assertIn("brainstorm_agent_key", spawned_profiles[0].prompt_addendum)
        coverage_path = lane_root / "brainstorm" / "coverage.jsonl"
        events = [json.loads(line)["event"] for line in coverage_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(
            events,
            [
                "hypothesis_loaded",
                "agent_queued",
                "agent_spawned",
                "agent_completed_with_raw_findings",
                "review_promoted",
            ],
        )
        stored_finding = json.loads((storage.ledgers_root / zero_day_team.FINDINGS_FILENAME).read_text().splitlines()[0])
        self.assertEqual(stored_finding["hypothesis_id"], "H001")
        self.assertEqual(stored_finding["brainstorm_agent_key"], "canva-svg-import-xss")

    def test_brainstorm_profile_key_collision_fails_closed(self) -> None:
        builtin = next(iter(zero_day_team.CLASS_PROFILES.values()))
        profile = zero_day_team.VulnerabilityClassProfile(
            key=builtin.key,
            description="Brainstorm duplicate of built-in profile.",
            entry_questions=("Can SVG execute?",),
            cross_questions=("Does the chain reach the bridge?",),
            sink_categories=("renderSvg",),
            reasoning="collision regression test",
            brainstorm_metadata={
                "hypothesis_id": "H001",
                "brainstorm_agent_key": builtin.key,
            },
        )

        with self.assertRaisesRegex(ValueError, "conflicts with existing profile"):
            zero_day_team._reject_brainstorm_profile_collisions(
                [profile],
                list(zero_day_team.CLASS_PROFILES.values()),
            )

    def test_brainstorm_spawn_failure_writes_terminal_coverage_event(self) -> None:
        coverage_path = self.tmp / "brainstorm" / "coverage.jsonl"
        profile = zero_day_team.VulnerabilityClassProfile(
            key="canva-svg-import-xss",
            description="Brainstorm SVG import XSS profile.",
            entry_questions=("Can SVG execute?",),
            cross_questions=("Does the chain reach the bridge?",),
            sink_categories=("renderSvg",),
            reasoning="spawn failure regression test",
            brainstorm_metadata={
                "hypothesis_id": "H001",
                "hypothesis_title": "SVG import can create renderer script execution",
                "brainstorm_agent_key": "canva-svg-import-xss",
                "brainstorm_spec": str(self.tmp / "brainstorm" / "spec.md"),
            },
        )
        session = zero_day_team.AgentSession(
            profile=profile,
            workspace=self.tmp / "workspace",
            log_path=self.tmp / "spawn_error.log",
            process=None,
            coverage_path=coverage_path,
        )

        with patch.object(zero_day_team, "_spawn_agent", return_value=session):
            _profile, exit_code = zero_day_team._run_single_agent(
                profile,
                program="canva",
                target=self.tmp,
                findings_path=self.tmp / "findings.jsonl",
                agents_root=self.tmp / "agents",
                ledger=SimpleNamespace(check=Mock()),
                coverage_path=coverage_path,
            )

        self.assertEqual(exit_code, -1)
        events = [json.loads(line)["event"] for line in coverage_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(events, ["agent_crashed"])

    def test_cli_accepts_brainstorm_spec_flags(self) -> None:
        args = zero_day_team._parse_cli_args(
            [
                "canva",
                str(self.tmp / "target"),
                "--brainstorm-spec",
                str(self.tmp / "brainstorm" / "spec.md"),
                "--brainstorm-only",
                "--brainstorm-hypothesis",
                "H001",
            ]
        )

        self.assertEqual(args.brainstorm_spec, str(self.tmp / "brainstorm" / "spec.md"))
        self.assertTrue(args.brainstorm_only)
        self.assertEqual(args.brainstorm_hypothesis, "H001")

    def test_agent_session_queues_finding_when_ledger_reservation_fails(self) -> None:
        findings_path = self.tmp / "findings.jsonl"
        log_path = self.tmp / "agent.log"
        workspace = self.tmp / "workspace"
        workspace.mkdir()
        log_path.write_text(
            '{"agent":"xss","category":"class","class_name":"xss","description":"Reviewed finding.",'
            '"file":"src/main.py","severity":"HIGH","type":"xss-sink"}\n',
            encoding="utf-8",
        )
        session = SimpleNamespace(
            process=FakeProcess(),
            log_path=log_path,
            profile=SimpleNamespace(key="xss"),
            workspace=workspace,
            skip_ledger=False,
        )
        ledger = SimpleNamespace(check=Mock(side_effect=RuntimeError("reservation failed")))

        exit_code = zero_day_team._run_agent_session(session, findings_path, ledger)

        self.assertEqual(exit_code, 0)
        queued = findings_path.read_text(encoding="utf-8")
        self.assertIn('"ledger_reservation_error": "reservation failed"', queued)
        self.assertIn('"type": "xss-sink"', queued)

    def test_log_extraction_ignores_prompt_schema_examples(self) -> None:
        log_path = self.tmp / "agent.log"
        log_path.write_text(
            "Append every finding to findings.jsonl in JSONL format using one of these schemas:\n"
            "Class finding:\n"
            '{"agent":"xss","category":"class","class_name":"xss","type":"short vulnerability label",'
            '"file":"path","line":123,"description":"why this path is dangerous","severity":"HIGH",'
            '"context":"relevant code context and reasoning","source":"identified source",'
            '"trust_boundary":"what boundary is crossed","flow_path":"how the data moves",'
            '"sink":"dangerous sink category or concrete sink","exploitability":"why an attacker can or cannot trigger it"}\n'
            "Agent result follows:\n"
            '{"agent":"xss","category":"class","class_name":"xss","type":"xss-sink",'
            '"file":"src/main.py","line":9,"description":"User input reaches innerHTML.",'
            '"severity":"HIGH","source":"location.hash","sink":"innerHTML"}\n',
            encoding="utf-8",
        )

        findings = zero_day_team._extract_findings_from_log(log_path, default_agent="xss")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "xss-sink")
        self.assertEqual(findings[0]["file"], "src/main.py")

    def test_append_unique_findings_filters_prompt_templates(self) -> None:
        findings_path = self.tmp / "findings.jsonl"
        prompt_template = {
            "agent": "xss",
            "category": "class",
            "class_name": "xss",
            "type": "short vulnerability label",
            "file": "path",
            "line": 123,
            "description": "why this path is dangerous",
            "severity": "HIGH",
            "source": "identified source",
            "sink": "dangerous sink category or concrete sink",
        }
        real_finding = {
            "agent": "xss",
            "category": "class",
            "class_name": "xss",
            "type": "xss-sink",
            "file": "src/main.py",
            "line": 9,
            "description": "User input reaches innerHTML.",
            "severity": "HIGH",
            "source": "location.hash",
            "sink": "innerHTML",
        }

        zero_day_team._append_unique_findings(findings_path, [prompt_template, real_finding])

        rows = [json.loads(line) for line in findings_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["type"], "xss-sink")

    def test_giant_single_line_source_excerpt_is_bounded_around_focus_term(self) -> None:
        finding = {
            "agent": "xss",
            "category": "class",
            "class_name": "xss",
            "type": "xss-sink",
            "file": "dist/main.js",
            "line": 1,
            "description": "User input reaches a DOM sink.",
            "severity": "HIGH",
            "context": "",
            "source": "location.hash",
            "trust_boundary": "URL to DOM",
            "flow_path": "hash to render",
            "sink": "dangerousSink(userInput)",
            "exploitability": "attacker controls hash",
        }
        giant_line = "a" * 50_000 + "dangerousSink(userInput)" + "b" * 50_000

        excerpt = zero_day_team._source_excerpt(
            giant_line,
            1,
            focus_terms=(finding["source"], finding["sink"], finding["type"]),
        )
        prompt = zero_day_team._build_claude_review_prompt(
            finding=finding,
            target_path=self.tmp,
            source_path=self.tmp / "dist" / "main.js",
            excerpt=excerpt,
        )

        self.assertIn("[truncated line 1: original length", excerpt)
        self.assertIn("dangerousSink(userInput)", excerpt)
        self.assertLess(len(excerpt), 2_000)
        self.assertLess(len(prompt), 10_000)


if __name__ == "__main__":
    unittest.main()
