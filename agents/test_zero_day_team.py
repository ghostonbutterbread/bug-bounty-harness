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

    def test_direct_static_profile_generation_uses_timestamp_helper(self) -> None:
        target = self.tmp / "target"
        target.mkdir()
        team = zero_day_team.ZeroDayTeam(
            program="demo",
            team_type="0day_team",
            target_path=target,
            output_root=self.tmp / "storage",
            max_agents=3,
            family="binaries",
            lane="exe",
            target_kind="electron-exe",
            hunting_policy="off",
        )

        profiles = team.get_static_profiles()

        self.assertGreater(len(profiles), 0)
        self.assertTrue(all(profile.created_at.endswith("Z") for profile in profiles))
        self.assertIn("dom-xss", {profile.key for profile in profiles})

    def test_legacy_zero_day_prompt_accepts_program_scope_snippet(self) -> None:
        profile = zero_day_team.VulnerabilityClassProfile(
            key="scope-aware",
            description="scope aware test",
            entry_questions=("entry?",),
            cross_questions=("cross?",),
            sink_categories=("sink",),
            reasoning="trace scope behavior",
        )

        prompt = zero_day_team._build_prompt_base(
            profile=profile,
            program="demo",
            target_path=self.tmp / "target",
            findings_path=self.tmp / "findings.jsonl",
            program_scope_snippet="## Program Scope And Rules Of Engagement\nScope status: loaded.",
        )

        self.assertIn("Program Scope And Rules Of Engagement", prompt)
        self.assertIn("Scope status: loaded.", prompt)
        self.assertIn("Append every finding", prompt)

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

    def _appmap_brainstorm_spec_text(
        self,
        count: int = 1,
        *,
        agent_prefix: str = "canva-appmap-rce",
        static_agent_key: str | None = None,
        run_id: str = "appmap-run-1",
    ) -> str:
        primitives = []
        hypotheses = []
        for index in range(1, count + 1):
            hypothesis_id = f"H{index:03d}"
            candidate_id = f"C{index:04d}"
            agent_key = static_agent_key or f"{agent_prefix}-{index}"
            primitives.append(
                "\n".join(
                    [
                        f"### P{index:03d} - Process execution reachable from config evidence",
                        "- Source: project config",
                        "- Impact: config may reach process execution",
                        f"- Evidence: appmap-{candidate_id}",
                        "- Status: active",
                    ]
                )
            )
            hypotheses.append(
                "\n".join(
                    [
                        f"### {hypothesis_id} - Project config may influence process execution",
                        "- Status: untested",
                        "- Priority: high",
                        "- Surface: appmap-S0001-config",
                        "- Entry point: user-controlled project config",
                        "- Expected chain: config source -> project boundary -> child_process sink",
                        "- Suggested agents:",
                        f"  - {agent_key}",
                        "- Focus files:",
                        "  - src/**/*.js",
                        "- Tags: rce, appmap, static",
                        "- Evidence:",
                        f"  - appmap-{candidate_id}",
                        f"  - appmap-context:{hypothesis_id}:{candidate_id}:{agent_key}",
                        "  - flow-F0001",
                    ]
                )
            )
        return (
            "# Brainstorm Spec: Canva AppMap RCE\n\n"
            "## Metadata\n"
            "- Program: canva\n"
            "- Family: appmap\n"
            "- Lane: static\n"
            "- Target kind: electron-exe\n"
            "- Target path: input/app_asar\n"
            "- Status: active\n"
            + ("- Agent granularity: category-master\n" if static_agent_key else "")
            + f"- AppMap run id: {run_id}\n\n"
            "## Target mental model\n"
            "Static AppMap target.\n\n"
            "## Impact primitives\n"
            + "\n\n".join(primitives)
            + "\n\n"
            "## Hypotheses\n"
            + "\n\n".join(hypotheses)
            + "\n\n"
            "## Coverage log\n"
            "| Hypothesis | Agent | Status | Result | Linked FIDs | Run ID | Notes |\n"
            "|---|---|---|---|---|---|---|\n"
        )

    def _write_appmap_spec(
        self,
        lane_root: Path,
        count: int = 1,
        *,
        spec_path: Path | None = None,
        agent_prefix: str = "canva-appmap-rce",
        static_agent_key: str | None = None,
        run_id: str = "appmap-run-1",
        shared_source_sink: bool = False,
    ) -> Path:
        spec_path = spec_path or lane_root / "brainstorm" / "appmap-rce-spec.md"
        spec_path.parent.mkdir(parents=True, exist_ok=True)
        spec_path.write_text(
            self._appmap_brainstorm_spec_text(
                count=count,
                agent_prefix=agent_prefix,
                static_agent_key=static_agent_key,
                run_id=run_id,
            ),
            encoding="utf-8",
        )
        contexts_dir = spec_path.parent / "agent_contexts"
        contexts_dir.mkdir(parents=True, exist_ok=True)
        for index in range(1, count + 1):
            hypothesis_id = f"H{index:03d}"
            candidate_id = f"C{index:04d}"
            agent_key = static_agent_key or f"{agent_prefix}-{index}"
            packet = {
                "schema_version": 1,
                "run_id": run_id,
                "candidate": {
                    "id": candidate_id,
                    "map_ids": {"flow_id": f"F{index:04d}"},
                },
                "hypothesis_linkage": {
                    "hypothesis_id": hypothesis_id,
                    "agent_key": agent_key,
                },
                "target_profile": {"target_kind": "electron-exe"},
                "focus_files": ["src/**/*.js"],
                "evidence": {
                    "source": {
                        "file": "src/shared.js" if shared_source_sink else f"src/source{index}.js",
                        "line": 10 if shared_source_sink else index,
                        "kind": "config",
                    },
                    "sink": {
                        "file": "src/shared.js" if shared_source_sink else f"src/sink{index}.js",
                        "line": 80 if shared_source_sink else index + 100,
                        "kind": "process-exec",
                    },
                },
            }
            (contexts_dir / f"{hypothesis_id}-{candidate_id}-{agent_key}.json").write_text(
                json.dumps(packet, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return spec_path

    def _write_tag_only_appmap_spec(self, lane_root: Path) -> Path:
        spec_path = lane_root / "brainstorm" / "appmap-rce-spec.md"
        spec_path.parent.mkdir(parents=True, exist_ok=True)
        text = self._appmap_brainstorm_spec_text(count=1).replace(
            "  - appmap-C0001\n"
            "  - appmap-context:H001:C0001:canva-appmap-rce-1\n"
            "  - flow-F0001",
            "  - flow-F0001",
        )
        spec_path.write_text(text, encoding="utf-8")
        return spec_path

    def _append_appmap_coverage_row(
        self,
        lane_root: Path,
        spec_path: Path,
        event: str,
        **overrides,
    ) -> None:
        coverage_path = lane_root / "brainstorm" / "coverage.jsonl"
        coverage_path.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "event": event,
            "hypothesis_id": "H001",
            "agent_key": "canva-appmap-rce-1",
            "source_spec_path": str(spec_path.resolve(strict=False)),
            "brainstorm_spec": str(spec_path.resolve(strict=False)),
            "appmap_candidate_id": "C0001",
            "appmap_context_packet": str(
                (spec_path.parent / "agent_contexts" / "H001-C0001-canva-appmap-rce-1.json")
                .resolve(strict=False)
            ),
            "appmap_run_id": "appmap-run-1",
            "snapshot_id": "snap-1",
            "snapshot_version": "1.2.3",
        }
        row.update(overrides)
        with coverage_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    def _appmap_storage(self, lane_root: Path) -> SimpleNamespace:
        return SimpleNamespace(
            family="appmap",
            lane="static",
            lane_root=lane_root,
            reports_root=lane_root / "reports",
            ledgers_root=lane_root / "ledgers",
            context_root=lane_root / "context",
            working_root=lane_root / "work",
        )

    def _run_appmap_brainstorm(
        self,
        *,
        lane_root: Path,
        target: Path,
        spec_path,
        storage: SimpleNamespace,
        spawned_profiles: list,
        spec_dir: Path | None = None,
        fresh: bool = False,
        parallel: bool = False,
        brainstorm_hypothesis: str | None = None,
        brainstorm_cluster_size: int = 1,
        brainstorm_only: bool = True,
        hunting_policy: str | None = "off",
        triage_policy: str | None = None,
        no_triage_policy: bool = False,
        policy_config: str | None = None,
        target_kind: str | None = None,
        scheduler: str = "legacy",
        agent_wave_size: int | str | None = "all",
        max_per_surface_family: int = 2,
        max_amplifier_family_first_wave: int = 3,
        category_master_mode: bool = False,
        max_hypotheses_per_master_agent: int = 6,
        snapshot_id: str = "snap-1",
        snapshot_version: str = "1.2.3",
    ) -> dict:
        ledger = SimpleNamespace(
            path=storage.ledgers_root / "ledger.json",
            get_class_context=Mock(return_value=""),
            check=Mock(),
            run_id="run-1",
            root_override=None,
        )

        class NoFindingProcess:
            pid = 4242

            def wait(self, timeout=None):
                return 0

        def fake_spawn(*, profile, agents_root, coverage_path=None, **_kwargs):
            spawned_profiles.append(profile)
            agents_root.mkdir(parents=True, exist_ok=True)
            log_path = agents_root / f"agent_{profile.key}_{len(spawned_profiles)}.log"
            log_path.write_text("{}\n", encoding="utf-8")
            return zero_day_team.AgentSession(
                profile=profile,
                workspace=agents_root / profile.key,
                log_path=log_path,
                process=NoFindingProcess(),
                coverage_path=coverage_path,
            )

        def promote_side_effect(*_args, reviewed_groups, **_kwargs):
            return {
                "confirmed": list(reviewed_groups["confirmed"]),
                "dormant": list(reviewed_groups["dormant"]),
                "novel": list(reviewed_groups["novel"]),
                "reviewed": [],
                "ledger_updates": 0,
            }

        with (
            patch.object(zero_day_team, "SubagentLogger", None),
            patch.object(zero_day_team, "_resolve_zero_day_storage", return_value=storage),
            patch.object(
                zero_day_team,
                "get_snapshot_identity",
                return_value={"snapshot_id": snapshot_id, "version_label": snapshot_version, "channel": "stable"},
            ),
            patch.object(zero_day_team, "create_team_ledger_from_storage", return_value=ledger),
            patch.object(zero_day_team, "DynamicAgentBuilder") as builder_cls,
            patch.object(zero_day_team, "_spawn_agent", side_effect=fake_spawn),
            patch.object(zero_day_team, "stage2_ghost_review", return_value=([], [], [])),
            patch.object(zero_day_team, "promote_reviewed_findings", side_effect=promote_side_effect),
            patch.object(zero_day_team, "_pretty_print_findings"),
        ):
            builder_cls.return_value.run.return_value = []
            return zero_day_team.orchestrate_zero_day_team(
                "canva",
                str(target),
                no_preflight=True,
                no_shared_brain=True,
                brainstorm_spec=spec_path,
                brainstorm_spec_dir=spec_dir,
                brainstorm_only=brainstorm_only,
                brainstorm_hypothesis=brainstorm_hypothesis,
                brainstorm_cluster_size=brainstorm_cluster_size,
                fresh=fresh,
                parallel=parallel,
                hunting_policy=hunting_policy,
                triage_policy=triage_policy,
                no_triage_policy=no_triage_policy,
                policy_config=policy_config,
                target_kind=target_kind,
                scheduler=scheduler,
                agent_wave_size=agent_wave_size,
                max_per_surface_family=max_per_surface_family,
                max_amplifier_family_first_wave=max_amplifier_family_first_wave,
                category_master_mode=category_master_mode,
                max_hypotheses_per_master_agent=max_hypotheses_per_master_agent,
            )

    def test_zero_day_summary_suppresses_hunting_policy_when_policy_disabled(self) -> None:
        lane_root = self.tmp / "lane"
        target = self.tmp / "electron-target"
        target.mkdir()
        spec_path = self.tmp / "specs" / "policy-off-spec.md"
        spec_path.parent.mkdir()
        spec_path.write_text(self._brainstorm_spec_text(), encoding="utf-8")
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            no_triage_policy=True,
            target_kind="electron-exe",
        )

        self.assertNotIn("hunting_policy", result)

    def test_zero_day_summary_includes_hunting_policy_when_enabled(self) -> None:
        lane_root = self.tmp / "lane"
        target = self.tmp / "electron-target"
        target.mkdir()
        spec_path = self.tmp / "specs" / "policy-on-spec.md"
        spec_path.parent.mkdir()
        spec_path.write_text(self._brainstorm_spec_text(), encoding="utf-8")
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            target_kind="electron-exe",
            hunting_policy="auto",
        )

        self.assertEqual(result["hunting_policy"]["id"], "electron-application-first-loose")

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
        self.assertEqual(
            update_mock.call_args.args[:2],
            (
                "Example_Program",
                {
                    "fid": "D01",
                    "type": "exec-sink-reachability",
                    "file": "src/main.py",
                    "description": "Requires prior XSS to reach a command sink.",
                },
            ),
        )
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

    def test_non_fresh_raw_duplicates_promote_fid_bearing_finding(self) -> None:
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
        stale_raw = {
            "agent": "dom-xss",
            "category": "class",
            "class_name": "dom-xss",
            "type": "hash reaches html sink",
            "file": "src/main.js",
            "line": 42,
            "description": "User-controlled hash reaches an HTML interpretation sink.",
            "severity": "HIGH",
            "source": "location.hash",
            "sink": "innerHTML",
        }
        fid_raw = {**stale_raw, "fid": "D01"}
        ledger = SimpleNamespace(
            path=storage.ledgers_root / "ledger.json",
            get_class_context=Mock(return_value=""),
            check=Mock(return_value=(True, "D99", {**stale_raw, "fid": "D99", "ledger_reserved": True})),
            run_id="run-1",
            root_override=self.tmp / "storage-root",
        )
        reviewed_inputs: list[dict] = []

        def review_side_effect(finding, *_args, **_kwargs):
            reviewed_inputs.append(dict(finding))
            reviewed = dict(finding, review_tier="CONFIRMED", tier="CONFIRMED")
            return "CONFIRMED", reviewed, "confirmed"

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
            patch.object(zero_day_team, "_load_findings", return_value=[stale_raw, fid_raw]),
            patch.object(zero_day_team, "_review_single_finding", side_effect=review_side_effect),
            patch.object(zero_day_team, "update_team_finding", side_effect=lambda _program, finding, **_kwargs: dict(finding)) as update_mock,
            patch.object(zero_day_team, "_pretty_print_findings"),
        ):
            builder_cls.return_value.run.return_value = []

            result = zero_day_team.orchestrate_zero_day_team(
                "Example Program",
                str(target),
                fresh=False,
                chain=False,
                no_preflight=True,
                no_shared_brain=True,
            )

        ledger.check.assert_not_called()
        self.assertEqual(len(reviewed_inputs), 1)
        self.assertEqual(reviewed_inputs[0]["fid"], "D01")
        self.assertNotIn("ledger_reserved", reviewed_inputs[0])
        update_mock.assert_called_once()
        self.assertEqual(update_mock.call_args.args[1]["fid"], "D01")
        persisted = [json.loads(line) for line in (storage.ledgers_root / "findings.jsonl").read_text().splitlines() if line.strip()]
        self.assertEqual([item.get("fid") for item in persisted], ["D01", "D01"])
        self.assertEqual(result["by_tier"]["confirmed"], 1)

    def test_review_semantic_dedupe_ignores_random_fids(self) -> None:
        target = self.tmp / "target"
        target.mkdir()
        base_finding = {
            "agent": "dom-xss",
            "category": "class",
            "class_name": "dom-xss",
            "type": "hash reaches html sink",
            "file": "src/main.js",
            "line": 42,
            "description": "User-controlled hash reaches an HTML interpretation sink.",
            "severity": "HIGH",
            "source": "location.hash",
            "sink": "innerHTML",
        }
        reviewed_inputs: list[dict] = []

        def review_side_effect(finding, *_args, **_kwargs):
            reviewed_inputs.append(dict(finding))
            reviewed = dict(finding, review_tier="CONFIRMED", tier="CONFIRMED")
            return "CONFIRMED", reviewed, "confirmed"

        with patch.object(zero_day_team, "_review_single_finding", side_effect=review_side_effect):
            confirmed, dormant, novel = zero_day_team.stage2_ghost_review(
                [
                    {**base_finding, "fid": "RANDOM-FID-1"},
                    {**base_finding, "fid": "RANDOM-FID-2"},
                ],
                target,
                "Example_Program",
                "web",
                write_reports=False,
            )

        self.assertEqual(len(reviewed_inputs), 1)
        self.assertEqual(reviewed_inputs[0]["fid"], "RANDOM-FID-1")
        self.assertEqual([finding["fid"] for finding in confirmed], ["RANDOM-FID-1"])
        self.assertEqual(dormant, [])
        self.assertEqual(novel, [])

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

    def test_appmap_coverage_gate_first_run_queues_and_spawns(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "static"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
        )

        self.assertEqual(result["classes_run"], ["canva-appmap-rce-1"])
        self.assertEqual([profile.key for profile in spawned_profiles], ["canva-appmap-rce-1"])
        coverage_path = lane_root / "brainstorm" / "coverage.jsonl"
        rows = [json.loads(line) for line in coverage_path.read_text(encoding="utf-8").splitlines()]
        events = [row["event"] for row in rows]
        self.assertEqual(events, ["hypothesis_loaded", "agent_queued", "agent_spawned", "agent_completed_no_finding"])
        queued = next(row for row in rows if row["event"] == "agent_queued")
        self.assertEqual(queued["appmap_candidate_id"], "C0001")
        self.assertEqual(queued["appmap_run_id"], "appmap-run-1")
        self.assertEqual(queued["snapshot_id"], "snap-1")
        self.assertEqual(queued["source_spec_path"], str(spec_path.resolve(strict=False)))

    def test_appmap_agent_log_findings_flow_into_review_and_promotion(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "promoted"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []
        reviewed_inputs: list[dict] = []
        promoted_updates: list[dict] = []
        ledger = SimpleNamespace(
            path=storage.ledgers_root / "ledger.json",
            get_class_context=Mock(return_value=""),
            check=Mock(side_effect=lambda finding: (False, "D01", {**finding, "fid": "D01"})),
            run_id="run-1",
            root_override=self.tmp / "storage-root",
        )

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
                "agent": profile.key,
                "category": "class",
                "class_name": "rce",
                "type": "Project config reaches process execution",
                "file": "src/sink1.js",
                "line": 101,
                "description": "User-controlled project config reaches child_process execution.",
                "severity": "HIGH",
                "source": "project config",
                "sink": "child_process.exec",
                "context": "applyProjectConfig(config)",
                "trust_boundary": "project import to main process",
                "flow_path": "config -> bridge -> exec",
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
            reviewed_inputs.extend(dict(finding) for finding in findings)
            return ([{**finding, "review_tier": "CONFIRMED", "tier": "CONFIRMED"} for finding in findings], [], [])

        def update_side_effect(_program, finding, **_kwargs):
            updated = dict(finding, promoted=True)
            promoted_updates.append(updated)
            return updated

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
            patch.object(zero_day_team, "update_team_finding", side_effect=update_side_effect),
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
            )

        self.assertEqual([profile.key for profile in spawned_profiles], ["canva-appmap-rce-1"])
        self.assertEqual(len(reviewed_inputs), 1)
        self.assertEqual(reviewed_inputs[0]["fid"], "D01")
        self.assertEqual(reviewed_inputs[0]["hypothesis_id"], "H001")
        self.assertEqual(reviewed_inputs[0]["appmap_candidate_id"], "C0001")
        self.assertEqual(len(promoted_updates), 1)
        self.assertEqual(promoted_updates[0]["fid"], "D01")
        self.assertTrue(promoted_updates[0]["promoted"])
        persisted = [
            json.loads(line)
            for line in (storage.ledgers_root / zero_day_team.FINDINGS_FILENAME).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual([item["fid"] for item in persisted], ["D01"])
        self.assertEqual(result["by_tier"]["confirmed"], 1)

    def test_brainstorm_single_spec_usage_stays_backward_compatible(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "single"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=str(spec_path),
            storage=storage,
            spawned_profiles=spawned_profiles,
        )

        self.assertEqual(result["classes_run"], ["canva-appmap-rce-1"])
        self.assertEqual(result["brainstorm"]["spec"], str(spec_path.resolve(strict=False)))
        self.assertEqual(result["brainstorm"]["specs"], [str(spec_path.resolve(strict=False))])

    def test_brainstorm_repeatable_explicit_specs_run_as_one_campaign(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "repeatable"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_a = self._write_appmap_spec(lane_root, spec_path=lane_root / "brainstorm" / "a" / "spec.md")
        spec_b = self._write_appmap_spec(lane_root, spec_path=lane_root / "brainstorm" / "b" / "spec.md")
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=[str(spec_a), str(spec_b)],
            storage=storage,
            spawned_profiles=spawned_profiles,
        )

        self.assertEqual(result["classes_run"], ["canva-appmap-rce-1", "canva-appmap-rce-1"])
        self.assertEqual(result["brainstorm"]["hypotheses"], ["H001", "H001"])
        self.assertEqual(
            [item["source_spec_path"] for item in result["brainstorm"]["hypothesis_assignments"]],
            [str(spec_a.resolve(strict=False)), str(spec_b.resolve(strict=False))],
        )
        self.assertEqual(
            [item["source_spec_path"] for item in result["brainstorm"]["profile_assignments"]],
            [str(spec_a.resolve(strict=False)), str(spec_b.resolve(strict=False))],
        )
        self.assertEqual(
            result["brainstorm"]["specs"],
            [str(spec_a.resolve(strict=False)), str(spec_b.resolve(strict=False))],
        )
        self.assertEqual(
            [profile.brainstorm_metadata["source_spec_path"] for profile in spawned_profiles],
            [str(spec_a.resolve(strict=False)), str(spec_b.resolve(strict=False))],
        )

    def test_duplicate_hypothesis_and_agent_ids_are_separated_by_spec_path(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "duplicate-hids"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_a = self._write_appmap_spec(lane_root, spec_path=lane_root / "brainstorm" / "a" / "spec.md")
        spec_b = self._write_appmap_spec(lane_root, spec_path=lane_root / "brainstorm" / "b" / "spec.md")

        profiles, hypotheses, paths = zero_day_team._load_brainstorm_campaign_profiles(
            spec_paths=[spec_a, spec_b],
            program_slug="canva",
            version="1.2.3",
        )
        zero_day_team._reject_brainstorm_profile_collisions(profiles, [])

        self.assertEqual([hypothesis.id for hypothesis in hypotheses], ["H001", "H001"])
        self.assertEqual(paths, [spec_a.resolve(strict=False), spec_b.resolve(strict=False)])
        self.assertEqual(profiles[0].key, profiles[1].key)
        self.assertNotEqual(
            zero_day_team._brainstorm_profile_key(profiles[0]),
            zero_day_team._brainstorm_profile_key(profiles[1]),
        )


    def test_selected_class_returns_duplicate_brainstorm_keys_across_specs(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "selected-class"
        spec_a = self._write_appmap_spec(lane_root, spec_path=lane_root / "brainstorm" / "a" / "spec.md")
        spec_b = self._write_appmap_spec(lane_root, spec_path=lane_root / "brainstorm" / "b" / "spec.md")

        profiles, _, _ = zero_day_team._load_brainstorm_campaign_profiles(
            spec_paths=[spec_a, spec_b],
            program_slug="canva",
            version="1.2.3",
        )
        selected = zero_day_team._select_from_profiles("canva-appmap-rce-1", profiles)

        self.assertEqual(len(selected), 2)
        self.assertEqual(
            [profile.brainstorm_metadata["source_spec_path"] for profile in selected],
            [str(spec_a.resolve(strict=False)), str(spec_b.resolve(strict=False))],
        )

    def test_coverage_skip_in_one_spec_does_not_skip_same_assignment_in_another_spec(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "coverage-by-spec"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_a = self._write_appmap_spec(lane_root, spec_path=lane_root / "brainstorm" / "a" / "spec.md")
        spec_b = self._write_appmap_spec(lane_root, spec_path=lane_root / "brainstorm" / "b" / "spec.md")
        self._append_appmap_coverage_row(lane_root, spec_a, "agent_completed_no_finding")
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=[str(spec_a), str(spec_b)],
            storage=storage,
            spawned_profiles=spawned_profiles,
        )

        self.assertEqual(result["classes_run"], ["canva-appmap-rce-1"])
        self.assertEqual(result["brainstorm"]["coverage_skipped"], ["canva-appmap-rce-1"])
        self.assertEqual(
            result["brainstorm"]["coverage_skipped_assignments"][0]["source_spec_path"],
            str(spec_a.resolve(strict=False)),
        )
        self.assertEqual(len(spawned_profiles), 1)
        self.assertEqual(
            spawned_profiles[0].brainstorm_metadata["source_spec_path"],
            str(spec_b.resolve(strict=False)),
        )
        rows = [
            json.loads(line)
            for line in (lane_root / "brainstorm" / "coverage.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        queued_specs = [row["source_spec_path"] for row in rows if row["event"] == "agent_queued"]
        self.assertEqual(queued_specs, [str(spec_b.resolve(strict=False))])

    def test_clustered_completion_fails_closed_for_unassigned_findings(self) -> None:
        coverage_path = self.tmp / "coverage.jsonl"
        log_path = self.tmp / "agent.log"
        log_path.write_text('{"findings": []}\n', encoding="utf-8")
        spec_path = str((self.tmp / "spec.md").resolve(strict=False))
        assignments = [
            {
                "hypothesis_id": "H001",
                "hypothesis_title": "H001",
                "brainstorm_agent_key": "canva-appmap-rce-1",
                "source_spec_path": spec_path,
                "brainstorm_spec": spec_path,
                "appmap_candidate_id": "C0001",
                "appmap_run_id": "appmap-run-1",
                "_snapshot_version": "1.2.3",
                "brainstorm_cluster_id": "cluster-H001-H002",
            },
            {
                "hypothesis_id": "H002",
                "hypothesis_title": "H002",
                "brainstorm_agent_key": "canva-appmap-rce-2",
                "source_spec_path": spec_path,
                "brainstorm_spec": spec_path,
                "appmap_candidate_id": "C0002",
                "appmap_run_id": "appmap-run-1",
                "_snapshot_version": "1.2.3",
                "brainstorm_cluster_id": "cluster-H001-H002",
            },
        ]
        profile = zero_day_team.VulnerabilityClassProfile(
            key="cluster-profile",
            description="cluster",
            entry_questions=(),
            cross_questions=(),
            sink_categories=(),
            reasoning="cluster",
            brainstorm_metadata={**assignments[0], "brainstorm_cluster_assignments": assignments},
        )
        session = zero_day_team.AgentSession(
            profile=profile,
            workspace=self.tmp,
            log_path=log_path,
            process=None,
            coverage_path=coverage_path,
        )
        malformed = {
            "hypothesis_id": "H999",
            "brainstorm_agent_key": "unknown-agent",
            "brainstorm_spec": spec_path,
            "type": "rce",
            "file": "src/shared.js",
            "line": 80,
        }

        zero_day_team._append_brainstorm_completion(
            session,
            exit_code=0,
            initial_salvaged=[malformed],
            final_salvaged=[malformed],
        )

        rows = [json.loads(line) for line in coverage_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([row["event"] for row in rows], ["agent_invalid_output", "agent_invalid_output"])
        self.assertTrue(all(row["unassigned_raw_finding_count"] == 2 for row in rows))

    def test_clustered_completion_records_findings_per_assignment(self) -> None:
        coverage_path = self.tmp / "coverage.jsonl"
        log_path = self.tmp / "agent.log"
        log_path.write_text('{"findings": []}\n', encoding="utf-8")
        assignments = []
        for hypothesis_id, agent_key, candidate_id in (
            ("H001", "canva-appmap-rce-1", "C0001"),
            ("H002", "canva-appmap-rce-2", "C0002"),
        ):
            assignments.append(
                {
                    "hypothesis_id": hypothesis_id,
                    "hypothesis_title": hypothesis_id,
                    "brainstorm_agent_key": agent_key,
                    "source_spec_path": str((self.tmp / "spec.md").resolve(strict=False)),
                    "brainstorm_spec": str((self.tmp / "spec.md").resolve(strict=False)),
                    "appmap_candidate_id": candidate_id,
                    "appmap_run_id": "appmap-run-1",
                    "_snapshot_version": "1.2.3",
                    "brainstorm_cluster_id": "cluster-H001-H002",
                }
            )
        profile = zero_day_team.VulnerabilityClassProfile(
            key="cluster-profile",
            description="cluster",
            entry_questions=(),
            cross_questions=(),
            sink_categories=(),
            reasoning="cluster",
            brainstorm_metadata={
                **assignments[0],
                "brainstorm_cluster_assignments": assignments,
            },
        )
        session = zero_day_team.AgentSession(
            profile=profile,
            workspace=self.tmp,
            log_path=log_path,
            process=None,
            coverage_path=coverage_path,
        )
        finding = {
            "hypothesis_id": "H001",
            "brainstorm_agent_key": "canva-appmap-rce-1",
            "brainstorm_spec": str((self.tmp / "spec.md").resolve(strict=False)),
            "type": "rce",
            "file": "src/shared.js",
            "line": 80,
            "source": "config",
            "sink": "exec",
        }

        zero_day_team._append_brainstorm_completion(
            session,
            exit_code=0,
            initial_salvaged=[finding],
            final_salvaged=[finding],
        )

        rows = [json.loads(line) for line in coverage_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(
            [(row["event"], row["hypothesis_id"]) for row in rows],
            [("agent_completed_with_raw_findings", "H001"), ("agent_completed_no_finding", "H002")],
        )
        self.assertIn("raw_finding_signatures", rows[0])
        self.assertNotIn("raw_finding_signatures", rows[1])

    def test_appmap_brainstorm_cluster_size_does_not_merge_different_source_sink(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "no-cluster"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root, count=2, shared_source_sink=False)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=str(spec_path),
            storage=storage,
            spawned_profiles=spawned_profiles,
            brainstorm_cluster_size=2,
        )

        self.assertEqual(len(spawned_profiles), 2)
        self.assertEqual(result["classes_run"], ["canva-appmap-rce-1", "canva-appmap-rce-2"])
        self.assertEqual(result["brainstorm"]["clusters"], [])

    def test_appmap_brainstorm_cluster_size_merges_shared_source_sink_assignments(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "cluster"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root, count=2, shared_source_sink=True)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=str(spec_path),
            storage=storage,
            spawned_profiles=spawned_profiles,
            brainstorm_cluster_size=2,
        )

        self.assertEqual(len(spawned_profiles), 1)
        self.assertEqual(result["classes_run"], [spawned_profiles[0].key])
        self.assertEqual(result["brainstorm"]["cluster_size"], 2)
        self.assertEqual(len(result["brainstorm"]["clusters"]), 1)
        self.assertEqual(
            [member["hypothesis_id"] for member in result["brainstorm"]["clusters"][0]["members"]],
            ["H001", "H002"],
        )
        rows = [
            json.loads(line)
            for line in (lane_root / "brainstorm" / "coverage.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        queued = [row for row in rows if row["event"] == "agent_queued"]
        self.assertEqual([row["hypothesis_id"] for row in queued], ["H001", "H002"])
        self.assertTrue(all(row.get("brainstorm_cluster_id") for row in queued))

    def test_category_master_spec_groups_static_category_agent_without_scheduler_mode(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "category-master-spec"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(
            lane_root,
            count=2,
            static_agent_key="exec-sink-reachability",
        )
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            scheduler="legacy",
        )

        self.assertEqual(result["classes_run"], ["exec-sink-reachability"])
        self.assertEqual(len(spawned_profiles), 1)
        master = spawned_profiles[0]
        self.assertEqual(master.key, "exec-sink-reachability")
        self.assertEqual(master.entry_questions, zero_day_team.CLASS_PROFILES["exec-sink-reachability"].entry_questions)
        self.assertTrue(master.brainstorm_metadata["category_master"])
        self.assertEqual(
            {item["hypothesis_id"] for item in master.brainstorm_metadata["brainstorm_cluster_assignments"]},
            {"H001", "H002"},
        )
        self.assertIn("Category-master member metadata", master.prompt_addendum)
        rows = [
            json.loads(line)
            for line in (lane_root / "brainstorm" / "coverage.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        queued = [row for row in rows if row.get("event") == "agent_queued"]
        self.assertEqual({row.get("hypothesis_id") for row in queued}, {"H001", "H002"})
        self.assertEqual({row.get("agent_key") for row in queued}, {"exec-sink-reachability"})

    def test_canonical_ownership_demotes_off_category_novel_duplicates(self) -> None:
        owner = {
            "category": "class",
            "class_name": "exec-sink-reachability",
            "agent": "exec-sink-reachability",
            "file": "src/main.js",
            "source": "userCommand from ipcMain.handle('run-tool')",
            "sink": "child_process.exec(userCommand)",
            "type": "IPC command execution reaches child_process.exec",
        }
        off_category = {
            "category": "novel",
            "class_name": "novel",
            "agent": "ssrf",
            "file": "src/main.js",
            "source": "renderer IPC message userCommand",
            "sink": "OS command execution via child_process.exec",
            "type": "IPC command injection to child_process.exec",
        }
        off_owner_class = {
            "category": "class",
            "class_name": "ipc-trust-boundary",
            "agent": "ipc-trust-boundary",
            "file": "src/main.js",
            "source": "renderer IPC message userCommand",
            "sink": "OS command execution via child_process.exec",
            "type": "renderer IPC command execution",
        }
        distinct = {
            "category": "novel",
            "class_name": "novel",
            "agent": "ssrf",
            "file": "src/net.js",
            "source": "URL import parameter",
            "sink": "server-side HTTP request",
            "type": "SSRF via import URL",
        }

        confirmed, dormant, novel, demoted = zero_day_team._triage_canonical_ownership(
            [owner, off_owner_class], [], [off_category, distinct]
        )

        self.assertEqual(confirmed, [owner])
        self.assertEqual(dormant, [])
        self.assertEqual(novel, [distinct])
        self.assertEqual(len(demoted), 2)
        self.assertEqual({item["canonical_owner_class"] for item in demoted}, {"exec-sink-reachability"})
        self.assertTrue(all("off-category duplicate" in item["rejected_reason"] for item in demoted))

    def test_canonical_ownership_keeps_novel_when_owner_class_did_not_report(self) -> None:
        off_category = {
            "category": "novel",
            "class_name": "novel",
            "agent": "ssrf",
            "file": "src/main.js",
            "source": "renderer IPC message userCommand",
            "sink": "OS command execution via child_process.exec",
            "type": "IPC command injection to child_process.exec",
        }

        _confirmed, _dormant, novel, demoted = zero_day_team._triage_canonical_ownership(
            [], [], [off_category]
        )

        self.assertEqual(novel, [off_category])
        self.assertEqual(demoted, [])

    def test_category_master_spec_merges_into_static_profile_in_full_run(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "category-master-full-run"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(
            lane_root,
            count=2,
            static_agent_key="exec-sink-reachability",
        )
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            brainstorm_only=False,
            scheduler="legacy",
        )

        self.assertIn("exec-sink-reachability", result["classes_run"])
        self.assertEqual(result["classes_run"].count("exec-sink-reachability"), 1)
        merged = [profile for profile in spawned_profiles if profile.key == "exec-sink-reachability"]
        self.assertEqual(len(merged), 1)
        self.assertTrue(merged[0].brainstorm_metadata["category_master"])
        self.assertEqual(
            {item["hypothesis_id"] for item in result["brainstorm"]["profile_assignments"]},
            {"H001", "H002"},
        )
        queued = [
            json.loads(line)
            for line in (lane_root / "brainstorm" / "coverage.jsonl").read_text(encoding="utf-8").splitlines()
            if json.loads(line).get("event") == "agent_queued"
        ]
        self.assertEqual({row.get("hypothesis_id") for row in queued}, {"H001", "H002"})
        self.assertEqual({row.get("agent_key") for row in queued}, {"exec-sink-reachability"})

    def test_selected_hypothesis_across_multiple_specs(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "selected"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_a = self._write_appmap_spec(lane_root, spec_path=lane_root / "brainstorm" / "a" / "spec.md")
        spec_b = self._write_appmap_spec(lane_root, count=2, spec_path=lane_root / "brainstorm" / "b" / "spec.md")
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=[str(spec_a), str(spec_b)],
            storage=storage,
            spawned_profiles=spawned_profiles,
            brainstorm_hypothesis="H002",
        )

        self.assertEqual(result["classes_run"], ["canva-appmap-rce-2"])
        self.assertEqual(result["brainstorm"]["hypotheses"], ["H002"])
        self.assertEqual(
            spawned_profiles[0].brainstorm_metadata["source_spec_path"],
            str(spec_b.resolve(strict=False)),
        )
        with self.assertRaisesRegex(ValueError, "H999.*not found or is retired"):
            self._run_appmap_brainstorm(
                lane_root=lane_root,
                target=target,
                spec_path=[str(spec_a), str(spec_b)],
                storage=storage,
                spawned_profiles=[],
                brainstorm_hypothesis="H999",
            )

    def test_brainstorm_spec_dir_discovery_is_deterministic_and_non_recursive(self) -> None:
        spec_dir = self.tmp / "specs"
        spec_dir.mkdir()
        (spec_dir / "notes.md").write_text("# Notes\n", encoding="utf-8")
        (spec_dir / "zeta-spec.md").write_text("# Zeta\n", encoding="utf-8")
        (spec_dir / "spec.md").write_text("# Main\n", encoding="utf-8")
        nested = spec_dir / "nested"
        nested.mkdir()
        (nested / "alpha-spec.md").write_text("# Nested\n", encoding="utf-8")

        paths = zero_day_team._discover_brainstorm_spec_dir(spec_dir)

        self.assertEqual([path.name for path in paths], ["spec.md", "zeta-spec.md"])

    def test_brainstorm_spec_dir_rejects_symlinked_specs(self) -> None:
        spec_dir = self.tmp / "spec-symlink"
        outside = self.tmp / "outside"
        spec_dir.mkdir()
        outside.mkdir()
        outside_spec = outside / "outside-spec.md"
        outside_spec.write_text("# Outside\n", encoding="utf-8")
        (spec_dir / "evil-spec.md").symlink_to(outside_spec)

        with self.assertRaisesRegex(ValueError, "must not be a symlink"):
            zero_day_team._discover_brainstorm_spec_dir(spec_dir)

    def test_brainstorm_spec_dir_appmap_flat_dir_stays_non_recursive(self) -> None:
        spec_dir = self.tmp / "appmap-run-rce"
        nested = spec_dir / "nested"
        nested.mkdir(parents=True)
        (nested / "spec.md").write_text("# Nested\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "contains no spec.md"):
            zero_day_team._discover_brainstorm_spec_dir(spec_dir)

    def test_appmap_coverage_gate_skips_duplicate_snapshot_hypothesis_candidate_agent(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "static"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        first = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
        )
        second = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
        )

        self.assertEqual(first["classes_run"], ["canva-appmap-rce-1"])
        self.assertEqual(second["classes_run"], [])
        self.assertEqual(second["brainstorm"]["coverage_skipped"], ["canva-appmap-rce-1"])
        self.assertEqual([profile.key for profile in spawned_profiles], ["canva-appmap-rce-1"])
        rows = [json.loads(line) for line in (lane_root / "brainstorm" / "coverage.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(sum(1 for row in rows if row["event"] == "agent_queued"), 1)
        self.assertEqual(sum(1 for row in rows if row["event"] == "agent_spawned"), 1)

    def test_appmap_coverage_gate_does_not_skip_stale_queued_or_spawned(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "stale"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root)
        self._append_appmap_coverage_row(lane_root, spec_path, "agent_queued")
        self._append_appmap_coverage_row(lane_root, spec_path, "agent_spawned")
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
        )

        self.assertEqual(result["classes_run"], ["canva-appmap-rce-1"])
        self.assertEqual(result["brainstorm"]["coverage_skipped"], [])
        self.assertEqual([profile.key for profile in spawned_profiles], ["canva-appmap-rce-1"])

    def test_appmap_coverage_gate_does_not_skip_after_timeout_or_crash(self) -> None:
        for event in ("agent_timeout", "agent_crashed"):
            with self.subTest(event=event):
                lane_root = self.tmp / "Shared" / "appmap" / "canva" / event
                target = lane_root / "input" / "app_asar"
                target.mkdir(parents=True)
                spec_path = self._write_appmap_spec(lane_root)
                self._append_appmap_coverage_row(lane_root, spec_path, event)
                storage = self._appmap_storage(lane_root)
                spawned_profiles: list = []

                result = self._run_appmap_brainstorm(
                    lane_root=lane_root,
                    target=target,
                    spec_path=spec_path,
                    storage=storage,
                    spawned_profiles=spawned_profiles,
                )

                self.assertEqual(result["classes_run"], ["canva-appmap-rce-1"])
                self.assertEqual(result["brainstorm"]["coverage_skipped"], [])

    def test_appmap_coverage_gate_does_not_skip_tag_only_appmap_profile(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "tag-only"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_tag_only_appmap_spec(lane_root)
        self._append_appmap_coverage_row(lane_root, spec_path, "agent_completed_no_finding")
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
        )

        self.assertEqual(result["classes_run"], ["canva-appmap-rce-1"])
        self.assertEqual(result["brainstorm"]["coverage_skipped"], [])

    def test_appmap_coverage_gate_does_not_skip_run_id_mismatch(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "run-mismatch"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root)
        self._append_appmap_coverage_row(
            lane_root,
            spec_path,
            "agent_completed_no_finding",
            appmap_run_id="other-run",
        )
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
        )

        self.assertEqual(result["classes_run"], ["canva-appmap-rce-1"])
        self.assertEqual(result["brainstorm"]["coverage_skipped"], [])

    def test_appmap_coverage_gate_does_not_skip_changed_snapshot(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "changed-snapshot"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root)
        self._append_appmap_coverage_row(
            lane_root,
            spec_path,
            "agent_completed_no_finding",
            snapshot_id="older-snapshot",
        )
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
        )

        self.assertEqual(result["classes_run"], ["canva-appmap-rce-1"])
        self.assertEqual(result["brainstorm"]["coverage_skipped"], [])

    def test_appmap_coverage_gate_fresh_bypasses_duplicate_skip(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "static"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
        )
        fresh = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            fresh=True,
        )

        self.assertEqual(fresh["classes_run"], ["canva-appmap-rce-1"])
        self.assertEqual(fresh["brainstorm"]["coverage_skipped"], [])
        self.assertEqual([profile.key for profile in spawned_profiles], ["canva-appmap-rce-1", "canva-appmap-rce-1"])
        rows = [json.loads(line) for line in (lane_root / "brainstorm" / "coverage.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(sum(1 for row in rows if row["event"] == "agent_queued"), 2)
        self.assertEqual(sum(1 for row in rows if row["event"] == "agent_spawned"), 2)

    def test_appmap_parallel_scheduling_keeps_hard_cap_at_ten(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "static"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root, count=12)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []
        executor_caps: list[int] = []
        real_executor = zero_day_team.ThreadPoolExecutor

        class CapturingExecutor(real_executor):
            def __init__(self, *args, **kwargs):
                if "max_workers" in kwargs:
                    executor_caps.append(kwargs["max_workers"])
                elif args:
                    executor_caps.append(args[0])
                super().__init__(*args, **kwargs)

        with patch.object(zero_day_team, "ThreadPoolExecutor", CapturingExecutor):
            result = self._run_appmap_brainstorm(
                lane_root=lane_root,
                target=target,
                spec_path=spec_path,
                storage=storage,
                spawned_profiles=spawned_profiles,
                parallel=True,
            )

        self.assertEqual(executor_caps, [zero_day_team.MAX_PARALLEL_AGENTS])
        self.assertEqual(zero_day_team.MAX_PARALLEL_AGENTS, 10)
        self.assertEqual(len(spawned_profiles), 12)
        self.assertEqual(len(result["classes_run"]), 12)

    def test_policy_aware_scheduler_agent_wave_size_limits_spawned_profiles(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "static"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root, count=12)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            scheduler="policy-aware",
            agent_wave_size=4,
        )

        self.assertEqual(len(spawned_profiles), 4)
        self.assertEqual(len(result["classes_run"]), 4)
        self.assertEqual(result["scheduler"]["mode"], "policy-aware")
        self.assertEqual(result["scheduler"]["selected"], 4)
        self.assertEqual(result["scheduler"]["deferred"], 8)
        decisions_path = Path(result["scheduler"]["decisions_path"])
        self.assertTrue(decisions_path.exists())
        decisions = [json.loads(line) for line in decisions_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(sum(1 for row in decisions if row["event"] == "agent_selected"), 4)
        self.assertEqual(sum(1 for row in decisions if row["event"] == "agent_deferred"), 8)

    def test_policy_aware_scheduler_keeps_parallel_executor_cap_as_concurrency_only(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "static"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root, count=12)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []
        executor_caps: list[int] = []
        real_executor = zero_day_team.ThreadPoolExecutor

        class CapturingExecutor(real_executor):
            def __init__(self, *args, **kwargs):
                if "max_workers" in kwargs:
                    executor_caps.append(kwargs["max_workers"])
                elif args:
                    executor_caps.append(args[0])
                super().__init__(*args, **kwargs)

        with patch.object(zero_day_team, "ThreadPoolExecutor", CapturingExecutor):
            result = self._run_appmap_brainstorm(
                lane_root=lane_root,
                target=target,
                spec_path=spec_path,
                storage=storage,
                spawned_profiles=spawned_profiles,
                parallel=True,
                scheduler="policy-aware",
                agent_wave_size=6,
            )

        self.assertEqual(executor_caps, [6])
        self.assertEqual(zero_day_team.MAX_PARALLEL_AGENTS, 10)
        self.assertEqual(len(spawned_profiles), 6)
        self.assertEqual(len(result["classes_run"]), 6)

    def test_policy_aware_scheduler_resumes_persisted_deferred_assignments(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "static"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root, count=4)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        first = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            scheduler="policy-aware",
            agent_wave_size=2,
        )
        second = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            scheduler="policy-aware",
            agent_wave_size=2,
        )

        self.assertEqual(first["scheduler"]["deferred"], 2)
        coverage_rows = [
            json.loads(line)
            for line in (lane_root / "brainstorm" / "coverage.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        deferred_coverage = [row for row in coverage_rows if row.get("scheduler_event") == "agent_deferred"]
        self.assertEqual(len(deferred_coverage), 2)
        self.assertEqual({row.get("status") for row in deferred_coverage}, {"untested"})
        self.assertNotIn("agent_key", deferred_coverage[0])
        self.assertEqual(second["scheduler"]["selected"], 2)
        decisions_path = Path(second["scheduler"]["decisions_path"])
        decisions = [json.loads(line) for line in decisions_path.read_text(encoding="utf-8").splitlines()]
        selected_second_wave = [
            row for row in decisions if row.get("event") == "agent_selected" and "resumed from deferred" in row.get("decision_reason", "")
        ]
        self.assertGreaterEqual(len(selected_second_wave), 2)

        fresh = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            scheduler="policy-aware",
            agent_wave_size=2,
            fresh=True,
        )
        self.assertEqual(fresh["classes_run"], ["canva-appmap-rce-1", "canva-appmap-rce-2"])

    def test_policy_aware_scheduler_ignores_deferred_state_from_changed_snapshot(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "static"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root, count=4)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            scheduler="policy-aware",
            agent_wave_size=2,
            snapshot_id="old-snapshot",
        )
        changed = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            scheduler="policy-aware",
            agent_wave_size=2,
            snapshot_id="new-snapshot",
        )

        decisions = [
            json.loads(line)
            for line in Path(changed["scheduler"]["decisions_path"]).read_text(encoding="utf-8").splitlines()
        ]
        latest_selected = [row for row in decisions if row.get("scheduler_wave_id") == decisions[-1].get("scheduler_wave_id") and row.get("event") == "agent_selected"]
        self.assertEqual({row.get("hypothesis_id") for row in latest_selected}, {"H001", "H002"})
        self.assertTrue(all("resumed from deferred" not in row.get("decision_reason", "") for row in latest_selected))

    def test_policy_aware_scheduler_cluster_events_expand_all_members_with_snapshot_identity(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "static"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root, count=2, shared_source_sink=True)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            brainstorm_cluster_size=2,
            scheduler="policy-aware",
            agent_wave_size="all",
        )

        self.assertEqual(len(result["classes_run"]), 1)
        decisions = [
            json.loads(line)
            for line in Path(result["scheduler"]["decisions_path"]).read_text(encoding="utf-8").splitlines()
        ]
        selected = [row for row in decisions if row.get("event") == "agent_selected"]
        self.assertEqual({row.get("hypothesis_id") for row in selected}, {"H001", "H002"})
        self.assertEqual({row.get("scheduler_master_agent_key") for row in selected}, set(result["classes_run"]))
        self.assertTrue(all(row.get("snapshot_id") == "snap-1" for row in selected))
        self.assertTrue(all(row.get("snapshot_version") == "1.2.3" for row in selected))

    def test_policy_aware_category_master_mode_builds_generic_master_profile(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "static"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root, count=4)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            scheduler="policy-aware",
            agent_wave_size="all",
            category_master_mode=True,
            max_hypotheses_per_master_agent=6,
        )

        self.assertEqual(len(spawned_profiles), 1)
        master = spawned_profiles[0]
        self.assertTrue(master.key.endswith("-master"))
        self.assertEqual(result["classes_run"], [master.key])
        metadata = master.brainstorm_metadata
        self.assertTrue(metadata["scheduler_category_master"])
        self.assertEqual(len(metadata["brainstorm_cluster_assignments"]), 4)
        self.assertEqual(
            {item["hypothesis_id"] for item in metadata["brainstorm_cluster_assignments"]},
            {"H001", "H002", "H003", "H004"},
        )
        self.assertIn("Category-master assignment metadata", master.prompt_addendum)
        self.assertIn("H004", master.prompt_addendum)

        decisions = [
            json.loads(line)
            for line in Path(result["scheduler"]["decisions_path"]).read_text(encoding="utf-8").splitlines()
        ]
        selected = [row for row in decisions if row.get("event") == "agent_selected"]
        self.assertEqual({row.get("hypothesis_id") for row in selected}, {"H001", "H002", "H003", "H004"})
        self.assertEqual({row.get("scheduler_master_agent_key") for row in selected}, {master.key})
        self.assertTrue(result["scheduler"]["category_master_mode"])

    def test_category_master_mode_is_explicit_and_legacy_default_is_unchanged(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "static"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root, count=4)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        result = self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            scheduler="legacy",
            category_master_mode=True,
        )

        self.assertEqual(len(spawned_profiles), 4)
        self.assertEqual(result["classes_run"], [f"canva-appmap-rce-{index}" for index in range(1, 5)])
        self.assertNotIn("category_master_mode", result["scheduler"])

    def test_category_master_mode_respects_max_hypotheses_per_master_agent(self) -> None:
        lane_root = self.tmp / "Shared" / "appmap" / "canva" / "static"
        target = lane_root / "input" / "app_asar"
        target.mkdir(parents=True)
        spec_path = self._write_appmap_spec(lane_root, count=5)
        storage = self._appmap_storage(lane_root)
        spawned_profiles: list = []

        self._run_appmap_brainstorm(
            lane_root=lane_root,
            target=target,
            spec_path=spec_path,
            storage=storage,
            spawned_profiles=spawned_profiles,
            scheduler="policy-aware",
            agent_wave_size="all",
            category_master_mode=True,
            max_hypotheses_per_master_agent=2,
        )

        self.assertEqual(len(spawned_profiles), 3)
        self.assertEqual(
            [len(profile.brainstorm_metadata.get("brainstorm_cluster_assignments", [])) for profile in spawned_profiles],
            [2, 2, 0],
        )
        self.assertTrue(all(profile.key.endswith("-master") for profile in spawned_profiles[:2]))
        self.assertEqual(spawned_profiles[2].key, "canva-appmap-rce-5")

    def test_scheduler_cli_args_parse(self) -> None:
        args = zero_day_team._parse_cli_args(
            [
                "canva",
                "/tmp/target",
                "--scheduler",
                "policy-aware",
                "--agent-wave-size",
                "10",
                "--max-per-surface-family",
                "2",
                "--max-amplifier-family-first-wave",
                "1",
                "--category-master-mode",
                "--max-hypotheses-per-master-agent",
                "4",
                "--no-prefer-deferred",
            ]
        )

        self.assertEqual(args.scheduler, "policy-aware")
        self.assertEqual(args.agent_wave_size, "10")
        self.assertEqual(args.max_per_surface_family, 2)
        self.assertEqual(args.max_amplifier_family_first_wave, 1)
        self.assertTrue(args.category_master_mode)
        self.assertEqual(args.max_hypotheses_per_master_agent, 4)
        self.assertTrue(args.no_prefer_deferred)

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
                "--brainstorm-spec",
                str(self.tmp / "brainstorm" / "rce-spec.md"),
                "--brainstorm-spec-dir",
                str(self.tmp / "brainstorm" / "generated_specs"),
                "--brainstorm-only",
                "--brainstorm-hypothesis",
                "H001",
            ]
        )

        self.assertEqual(
            args.brainstorm_spec,
            [
                str(self.tmp / "brainstorm" / "spec.md"),
                str(self.tmp / "brainstorm" / "rce-spec.md"),
            ],
        )
        self.assertEqual(args.brainstorm_spec_dir, str(self.tmp / "brainstorm" / "generated_specs"))
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
