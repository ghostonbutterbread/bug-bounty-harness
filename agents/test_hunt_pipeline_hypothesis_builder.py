from __future__ import annotations

from agents.hunt_pipeline.hypothesis_builder import build_hypothesis_packets
from agents.hunt_pipeline.models import NormalizedMapResult
from agents.hunt_pipeline.rulesets import resolve_ruleset


def test_hypothesis_builder_marks_electron_ipc_and_preload_as_amplifiers() -> None:
    normalized = NormalizedMapResult(
        appmap_root="/tmp/appmap",
        surfaces=(
            {"id": "S0001", "kind": "ipc", "file": "src/main.js"},
            {"id": "S0002", "kind": "preload", "file": "src/preload.js"},
            {"id": "S0003", "kind": "rendering", "file": "src/view.js"},
        ),
    )
    ruleset = resolve_ruleset("auto", target_kind="electron")

    packets = build_hypothesis_packets(normalized, ruleset, target_kind="electron")

    by_surface = {packet.source_evidence[0]["id"]: packet for packet in packets}
    assert by_surface["S0001"].role == "amplifier"
    assert by_surface["S0001"].surface_family == "ipc-bridge"
    assert by_surface["S0002"].role == "amplifier"
    assert by_surface["S0002"].surface_family == "preload-native-bridge"
    assert by_surface["S0003"].role == "entry"
    assert by_surface["S0003"].surface_family == "rendering-content-parser"


def test_hypothesis_builder_promotes_amplifier_to_entry_when_app_entry_evidence_exists() -> None:
    normalized = NormalizedMapResult(
        appmap_root="/tmp/appmap",
        surfaces=(
            {
                "id": "S0001",
                "kind": "ipc",
                "file": "src/main.js",
                "app_entry_evidence": True,
            },
        ),
    )
    ruleset = resolve_ruleset("electron-overlay")

    packet = build_hypothesis_packets(normalized, ruleset, target_kind="electron")[0]

    assert packet.role == "entry"
    assert packet.surface_family == "ipc-bridge"
    assert "prove navigation, rendering, protocol, auth, file, or import/export entry into the privileged Electron lane" not in packet.chain_requirements


def test_hypothesis_builder_does_not_promote_sink_only_process_exec_to_entry() -> None:
    normalized = NormalizedMapResult(
        appmap_root="/tmp/appmap",
        surfaces=(
            {
                "id": "S0001",
                "role": "sink",
                "kind": "process-exec",
                "file": "src/runner.js",
            },
        ),
    )
    ruleset = resolve_ruleset("desktop-baseline")

    packet = build_hypothesis_packets(normalized, ruleset, target_kind="desktop")[0]

    assert packet.role == "notes_only"
    assert packet.priority == "low"
    assert packet.surface_family == "file-ingestion-import"
    assert "prove an application-level entry reaches this lane before report framing" in packet.chain_requirements


def test_hypothesis_builder_promotes_process_exec_sink_when_app_entry_evidence_exists() -> None:
    normalized = NormalizedMapResult(
        appmap_root="/tmp/appmap",
        surfaces=(
            {
                "id": "S0001",
                "role": "sink",
                "kind": "process-exec",
                "file": "src/runner.js",
                "proven_app_entry": True,
            },
        ),
    )
    ruleset = resolve_ruleset("desktop-baseline")

    packet = build_hypothesis_packets(normalized, ruleset, target_kind="desktop")[0]

    assert packet.role == "entry"
    assert packet.priority == "high"
    assert packet.chain_requirements == ()


def test_hypothesis_builder_does_not_treat_flow_linked_sink_as_standalone() -> None:
    normalized = NormalizedMapResult(
        appmap_root="/tmp/appmap",
        surfaces=(
            {"id": "S0001", "role": "source", "kind": "cli", "file": "src/runner.js"},
            {"id": "K0001", "role": "sink", "kind": "process-exec", "file": "src/runner.js"},
        ),
        flows=({"id": "F0001", "source_id": "S0001", "sink_id": "K0001"},),
    )
    ruleset = resolve_ruleset("desktop-baseline")

    packets = build_hypothesis_packets(normalized, ruleset, target_kind="desktop")
    by_id = {packet.source_evidence[0]["id"]: packet for packet in packets}

    assert by_id["K0001"].role == "entry"
    assert by_id["K0001"].priority == "high"
    assert by_id["K0001"].chain_requirements == ()
