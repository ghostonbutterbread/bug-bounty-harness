from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from agents.base_team import AgentSpec, BaseTeam
from agents.dynamic_agent_builder import AgentSpec as DynamicBuilderAgentSpec
from agents.hunt_pipeline.models import HypothesisAgentPacket
from agents.hunt_pipeline.runtime_adapter import (
    grouped_decisions_to_base_team_agent_specs,
    packet_to_base_team_agent_spec,
    packet_to_dynamic_agent_builder_agent_spec,
)


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


def _packet(**overrides) -> HypothesisAgentPacket:
    payload = dict(
        id="HP-123",
        key="ipc-bridge-hp-123",
        title="Investigate IPC bridge trust boundary",
        role="entry",
        surface_family="ipc-bridge",
        priority="high",
        target_kind="electron",
        ruleset_id="electron-overlay",
        source_evidence=(
            {
                "id": "S0001",
                "kind": "ipc",
                "file": "src/main/ipc.ts",
                "trace": {"appmap_run": "run-1", "candidate_id": "C0001"},
            },
        ),
        secondary_families=("rendering-content-parser",),
        evidence_requirements=("Identify exposed IPC channel", "Trace renderer-controlled args"),
        chain_requirements=("Prove preload reachability",),
        focus_files=("src/main/ipc.ts", "src/preload.ts"),
        tags=("desktop", "electron"),
        reasons=("Surface was selected by policy-shaped AppMap evidence",),
        scheduler_metadata={
            "hypothesis_id": "HP-123",
            "brainstorm_agent_key": "ipc-bridge-hp-123",
            "trace": {"appmap_run": "run-1", "candidate_id": "C0001"},
        },
    )
    payload.update(overrides)
    return HypothesisAgentPacket(**payload)


def _group_packet(
    *,
    hypothesis_id: str,
    source_id: str,
    file_path: str,
    surface_family: str = "ipc-bridge",
    kind: str = "ipc",
    priority: str = "high",
    role: str = "entry",
    title: str | None = None,
) -> HypothesisAgentPacket:
    return HypothesisAgentPacket(
        id=hypothesis_id,
        key=f"{surface_family}-{hypothesis_id.lower()}",
        title=title or f"{surface_family} {hypothesis_id}",
        role=role,
        surface_family=surface_family,
        priority=priority,
        target_kind="electron",
        ruleset_id="electron-overlay",
        source_evidence=(
            {
                "id": source_id,
                "kind": kind,
                "file": file_path,
            },
        ),
        evidence_requirements=("trace renderer-controlled entry",),
        chain_requirements=("check adjacent branch when code evidence supports it",),
        focus_files=(file_path, "src/preload.ts"),
        tags=("desktop", surface_family),
        reasons=(f"selected from {source_id}",),
        scheduler_metadata={"hypothesis_id": hypothesis_id},
    )


def test_packet_to_base_team_agent_spec_maps_fields() -> None:
    packet = _packet()

    spec = packet_to_base_team_agent_spec(
        packet,
        program="demo",
        snapshot_id="snapshot-1",
        created_at="2026-05-13T12:00:00Z",
    )

    assert spec.key == "ipc-bridge-hp-123"
    assert spec.program == "demo"
    assert spec.snapshot_id == "snapshot-1"
    assert spec.created_at == "2026-05-13T12:00:00Z"
    assert spec.surface == "ipc-bridge"
    assert spec.vuln_class == "ipc-bridge"
    assert spec.focus_globs == ["src/main/ipc.ts", "src/preload.ts"]
    assert spec.code_patterns == [
        "Identify exposed IPC channel",
        "Trace renderer-controlled args",
        "Prove preload reachability",
        "desktop",
        "electron",
        "rendering-content-parser",
    ]
    assert spec.metadata["hypothesis_id"] == "HP-123"
    assert spec.metadata["runtime_handoff"]["spawn_enabled"] is False
    assert spec.metadata["runtime_handoff"]["ledger_writes_enabled"] is False


def test_packet_trace_metadata_is_preserved_by_value() -> None:
    packet = _packet()
    spec = packet_to_base_team_agent_spec(packet, program="demo", snapshot_id="snapshot-1")

    packet.scheduler_metadata["trace"]["appmap_run"] = "mutated"
    packet.source_evidence[0]["trace"]["candidate_id"] = "mutated"

    assert spec.metadata["scheduler_metadata"]["trace"] == {
        "appmap_run": "run-1",
        "candidate_id": "C0001",
    }
    assert spec.metadata["source_evidence"][0]["trace"] == {
        "appmap_run": "run-1",
        "candidate_id": "C0001",
    }
    assert spec.metadata["packet"]["scheduler_metadata"]["trace"]["appmap_run"] == "run-1"


def test_base_team_prompt_template_renders_with_base_placeholders(tmp_path: Path) -> None:
    packet = _packet()
    spec = packet_to_base_team_agent_spec(packet, program="demo", snapshot_id="snapshot-1")
    target = tmp_path / "target"
    target.mkdir()

    with patch.object(Path, "home", return_value=tmp_path):
        team = DummyTeam(
            "demo",
            "0day_team",
            target,
            output_root=tmp_path / "out",
            target_kind="api",
            max_agents=1,
        )

    rendered = team._render_prompt(spec)

    assert "You are a hunt-pipeline handoff agent for demo." in rendered
    assert f"Target path: {target}" in rendered
    assert "Agent key: ipc-bridge-hp-123" in rendered
    assert "Hypothesis title: Investigate IPC bridge trust boundary" in rendered
    assert "- src/main/ipc.ts" in rendered
    assert "- Identify exposed IPC channel" in rendered
    assert "{program}" not in rendered
    assert "{target_path}" not in rendered


def test_base_team_prompt_template_escapes_packet_braces(tmp_path: Path) -> None:
    packet = _packet(
        title="Investigate {renderer} bridge",
        evidence_requirements=("Trace args like {payload}",),
        reasons=("Generated from {policy} note",),
        source_evidence=({"id": "S{1}", "kind": "ipc", "file": "src/{main}.ts"},),
    )
    spec = packet_to_base_team_agent_spec(packet, program="demo", snapshot_id="snapshot-1")
    target = tmp_path / "target"
    target.mkdir()

    with patch.object(Path, "home", return_value=tmp_path):
        team = DummyTeam(
            "demo",
            "0day_team",
            target,
            output_root=tmp_path / "out",
            target_kind="api",
            max_agents=1,
        )

    rendered = team._render_prompt(spec)

    assert "Hypothesis title: Investigate {renderer} bridge" in rendered
    assert "- Trace args like {payload}" in rendered
    assert "- Generated from {policy} note" in rendered
    assert "- S{1} | ipc | src/{main}.ts" in rendered


def test_packet_to_dynamic_agent_builder_agent_spec_maps_legacy_shape() -> None:
    packet = _packet()

    spec = packet_to_dynamic_agent_builder_agent_spec(
        packet,
        version="pipeline-v1",
        created_at="2026-05-13T12:00:00Z",
    )

    assert isinstance(spec, DynamicBuilderAgentSpec)
    assert spec.key == "ipc-bridge-hp-123"
    assert spec.name == "Investigate IPC bridge trust boundary"
    assert spec.surface_type == "ipc-bridge"
    assert spec.vuln_class == "ipc-bridge"
    assert spec.focus_files_glob == ["src/main/ipc.ts", "src/preload.ts"]
    assert spec.created_by == "hunt_pipeline"
    assert spec.parent_keys == ["hunt-pipeline", "electron-overlay", "HP-123"]
    assert spec.version == "pipeline-v1"
    assert spec.created_at == "2026-05-13T12:00:00Z"


def test_grouped_decisions_collapse_duplicates_rank_under_cap_and_report_coverage(tmp_path: Path) -> None:
    packets = [
        _group_packet(hypothesis_id="HP-1", source_id="S0001", file_path="src/ipc/a.ts"),
        _group_packet(
            hypothesis_id="HP-2",
            source_id="S0001",
            file_path="src/ipc/a.ts",
            title="duplicate source same family should collapse",
        ),
        _group_packet(
            hypothesis_id="HP-3",
            source_id="S0002",
            file_path="src/preload/b.ts",
            surface_family="preload-native-bridge",
            kind="preload",
            role="amplifier",
        ),
        _group_packet(
            hypothesis_id="HP-4",
            source_id="S0003",
            file_path="src/render/c.ts",
            surface_family="rendering-content-parser",
            kind="rendering",
            priority="medium",
        ),
    ]
    scheduler_plan = {
        "selected": [{"hypothesis_id": "HP-1", "agent_key": "agent-1"}],
        "deferred": [{"hypothesis_id": "HP-3", "agent_key": "agent-3"}],
        "skipped": [],
    }

    specs, summary = grouped_decisions_to_base_team_agent_specs(
        scheduler_plan,
        packets,
        program="demo",
        snapshot_id="snapshot-1",
        max_agents=2,
        created_at="2026-05-13T12:00:00Z",
    )

    assert summary["input_hypotheses"] == 4
    assert summary["collapsed_groups"] == 3
    assert summary["selected_groups"] == 2
    assert summary["deferred_groups"] == 1
    assert summary["skipped_groups"] == 0
    assert summary["agent_specs_created"] == 2
    assert summary["top_source_coverage"][0]["source"] == "S0001|src/ipc/a.ts"
    assert summary["top_source_coverage"][0]["hypotheses"] == 2
    assert summary["hypothesis_counts"] == {"selected": 1, "deferred": 1, "skipped": 0, "candidate": 2}
    assert len(specs) == 2
    assert any("HP-1" in spec.prompt_template and "HP-2" in spec.prompt_template for spec in specs)
    assert all(spec.metadata["adapter"] == "agents.hunt_pipeline.runtime_adapter" for spec in specs)
    assert all(spec.metadata["runtime_handoff"]["spawn_enabled"] is False for spec in specs)

    target = tmp_path / "target"
    target.mkdir()
    with patch.object(Path, "home", return_value=tmp_path):
        team = DummyTeam("demo", "0day_team", target, output_root=tmp_path / "out", max_agents=2)
    rendered = [team._render_prompt(spec) for spec in specs]
    assert any("starting point, not a hard gate" in prompt for prompt in rendered)


def test_grouped_decisions_include_adjacent_same_source_hypotheses_in_prompt(tmp_path: Path) -> None:
    packets = [
        _group_packet(hypothesis_id="HP-1", source_id="S0001", file_path="src/ipc/a.ts"),
        _group_packet(
            hypothesis_id="HP-2",
            source_id="S0001",
            file_path="src/preload/b.ts",
            surface_family="preload-native-bridge",
            kind="preload",
            title="same source adjacent preload branch",
        ),
    ]
    scheduler_plan = {
        "selected": [{"hypothesis_id": "HP-1", "agent_key": "agent-1"}],
        "deferred": [{"hypothesis_id": "HP-2", "agent_key": "agent-2"}],
        "skipped": [],
    }

    specs, _summary = grouped_decisions_to_base_team_agent_specs(
        scheduler_plan,
        packets,
        program="demo",
        snapshot_id="snapshot-1",
        max_agents=1,
    )

    target = tmp_path / "target"
    target.mkdir()
    with patch.object(Path, "home", return_value=tmp_path):
        team = DummyTeam("demo", "0day_team", target, output_root=tmp_path / "out", max_agents=1)
    [prompt] = [team._render_prompt(spec) for spec in specs]

    assert len(specs) == 1
    assert "HP-1" in prompt
    assert "Adjacent source-backed hypotheses not assigned to this exact group:" in prompt
    assert "HP-2" in prompt
    assert "same source adjacent preload branch" in prompt
