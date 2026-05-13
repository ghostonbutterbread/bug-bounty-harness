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
