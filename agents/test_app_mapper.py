from __future__ import annotations

import json
import re
import shlex
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from agents.app_mapper import (
    PatternSpec,
    TARGET_PACKS,
    VULNERABILITY_PACKS,
    HybridResearchProvider,
    TargetDetection,
    TargetPack,
    VulnerabilityPack,
    WebFetchResearchProvider,
    build_rce_flows,
    build_parser,
    canonical_output_root,
    _assignment_identities_for_status,
    campaign_status,
    generate_research_artifacts,
    list_promoted_handoffs,
    main as app_mapper_main,
    map_application,
    plan_promoted_handoff_command,
    promote_appmap_handoff,
    register_target_pack,
    register_vulnerability_pack,
    render_rce_spec,
    resolve_output_root,
    validate_promoted_handoff,
    validate_run_id,
    write_artifacts,
    write_agent_contexts,
)
from agents.appmap_research import normalize_research_query
from agents.brainstorm_adapters import (
    brainstorm_intent_to_dynamic_agent_spec,
    brainstorm_intent_to_zero_day_profile,
)
from agents.brainstorm_spec import hypothesis_to_agent_intents, parse_brainstorm_spec
import agents.hunting_policy as hunting_policy_module
from agents import zero_day_team
from agents.hunting_policy import resolve_hunting_policy
from agents.zero_day_team import _discover_brainstorm_spec_dir


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _suggested_summary_command(summary_text: str) -> str:
    marker = "```bash\n"
    start = summary_text.index(marker) + len(marker)
    end = summary_text.index("\n```", start)
    return summary_text[start:end]


def test_static_app_mapper_classifies_electron_and_builds_rce_candidate(tmp_path: Path) -> None:
    target = tmp_path / "electron-app"
    _write(
        target / "package.json",
        """
{
  "main": "src/main.js",
  "dependencies": {
    "electron": "^30.0.0"
  },
  "scripts": {
    "start": "electron ."
  }
}
""".strip(),
    )
    _write(
        target / "src" / "main.js",
        """
const { app, ipcMain } = require("electron");
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");

ipcMain.handle("run-project-command", async () => {
  const configPath = path.join(process.cwd(), "project.json");
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  return child_process.exec(config.command);
});
""".strip(),
    )

    result = map_application("example electron", target, target_kind="auto")

    assert result.profile.target_kind == "electron"
    assert "electron" in result.profile.frameworks
    assert result.candidates
    candidate = result.candidates[0]
    assert candidate["source"]["kind"] in {"config", "ipc"}
    assert candidate["boundary"]["kind"] in {"electron-boundary", "project-boundary"}
    assert candidate["sink"]["kind"] == "process-exec"


def test_app_mapper_rejects_unpaired_sources_and_sinks(tmp_path: Path) -> None:
    target = tmp_path / "mixed"
    _write(
        target / "sink_only.js",
        """
const child_process = require("child_process");
function trusted() {
  child_process.exec("open -a Calculator");
}
""".strip(),
    )
    _write(
        target / "source_only.py",
        """
import argparse
parser = argparse.ArgumentParser()
args = parser.parse_args()
""".strip(),
    )

    result = map_application("mixed", target)

    assert result.candidates == []
    reasons = {item["reason"] for item in result.rejected_candidates}
    assert "sink evidence lacks same-file attacker-controlled source and trust boundary" in reasons
    assert "source or boundary evidence lacks same-file RCE sink" in reasons


def test_app_mapper_rejects_same_file_static_and_distant_cooccurrence_false_positive(tmp_path: Path) -> None:
    target = tmp_path / "cooccur"
    filler = "\n".join(f"const filler{i} = {i};" for i in range(70))
    _write(
        target / "index.js",
        f"""
const fs = require("fs");
const child_process = require("child_process");
const path = require("path");

const configPath = path.join(process.cwd(), "project.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
{filler}
function maintenance() {{
  child_process.exec("open -a Calculator");
}}
""".strip(),
    )
    _write(
        target / "reverse.py",
        """
import argparse
import os
import subprocess

subprocess.run(cmd, shell=True)
parser = argparse.ArgumentParser()
cwd = os.getcwd()
""".strip(),
    )

    result = map_application("cooccur", target)

    assert result.candidates == []
    reasons = {item["reason"] for item in result.rejected_candidates}
    assert "sink evidence is an obvious static literal command" in reasons
    assert "same-file evidence lacks ordered proximate or linked source-to-sink chain" in reasons


def test_call_pattern_regexes_match_literal_paren_calls(tmp_path: Path) -> None:
    target = tmp_path / "calls"
    _write(
        target / "cli.js",
        """
const rc = require("rc");
const minimist = require("minimist");
const child_process = require("child_process");

const cfg = rc("demo");
const args = minimist(process.argv.slice(2));
const root = process.cwd();
child_process.exec(args.command);
""".strip(),
    )
    _write(
        target / "runner.py",
        """
import argparse
import os
import subprocess

parser = argparse.ArgumentParser()
args = parser.parse_args()
root = os.getcwd()
subprocess.run(args.command, shell=True)
""".strip(),
    )

    result = map_application("calls", target)
    matched = {(surface["role"], surface["kind"], surface["file"]) for surface in result.surfaces}

    assert ("source", "config", "cli.js") in matched
    assert ("source", "cli", "cli.js") in matched
    assert ("boundary", "project-boundary", "cli.js") in matched
    assert ("boundary", "project-boundary", "runner.py") in matched


def test_app_mapper_filters_generated_js_and_caps_config_file_surfaces(tmp_path: Path) -> None:
    target = tmp_path / "generated-noise"
    _write(
        target / "package.json",
        """
{
  "main": "runner.js",
  "scripts": {
    "start": "node runner.js"
  }
}
""".strip(),
    )
    _write(
        target / "src" / "en.strings.js",
        """
!function(){var data = JSON.parse("{\\"ok\\":true}"); var match = /x/.exec(data.value); deserialize(data);}
""".strip(),
    )
    _write(
        target / "dist" / "stats.json",
        "{\n" + ",\n".join(f'  "asset{i}": "bundle{i}.js"' for i in range(30)) + "\n}",
    )

    result = map_application("generated noise", target, target_kind="node")

    noisy_surfaces = [surface for surface in result.surfaces if surface["file"] == "src/en.strings.js"]
    assert noisy_surfaces == []
    stats_surfaces = [surface for surface in result.surfaces if surface["file"] == "dist/stats.json"]
    assert len(stats_surfaces) <= 1
    assert all(surface["kind"] == "config-file" for surface in stats_surfaces)
    package_config_surfaces = [
        surface
        for surface in result.surfaces
        if surface["file"] == "package.json" and surface["kind"] == "config-file"
    ]
    assert len(package_config_surfaces) == 1
    assert package_config_surfaces[0]["line"] == 1


def test_app_mapper_avoids_lowercase_function_and_member_exec_false_positives(tmp_path: Path) -> None:
    target = tmp_path / "js-false-positives"
    _write(
        target / "runner.js",
        """
!function wrapper() {
  const match = /run/.exec(input);
  service.exec(input);
}
""".strip(),
    )

    result = map_application("js false positives", target, target_kind="node")
    runner_surfaces = [surface for surface in result.surfaces if surface["file"] == "runner.js"]

    assert not any(surface["kind"] == "dynamic-code" for surface in runner_surfaces)
    assert not any(surface["kind"] == "process-exec" for surface in runner_surfaces)


def test_app_mapper_maps_child_process_exec_variable_candidate(tmp_path: Path) -> None:
    target = tmp_path / "child-process-candidate"
    _write(
        target / "runner.js",
        """
const fs = require("fs");
const path = require("path");
const child_process = require("child_process");

const configPath = path.join(process.cwd(), "project.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
child_process.exec(config.command);
""".strip(),
    )

    result = map_application("child process candidate", target, target_kind="node")

    assert result.candidates
    assert result.candidates[0]["sink"]["kind"] == "process-exec"


def test_app_mapper_maps_direct_child_process_require_exec(tmp_path: Path) -> None:
    target = tmp_path / "direct-require-candidate"
    _write(
        target / "runner.js",
        """
const fs = require("fs");
const path = require("path");

const configPath = path.join(process.cwd(), "project.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
require("child_process").exec(config.command);
""".strip(),
    )

    result = map_application("direct require candidate", target, target_kind="node")

    assert result.candidates
    assert result.candidates[0]["sink"]["kind"] == "process-exec"


def test_write_specs_generates_parser_valid_rce_spec_and_artifacts(tmp_path: Path) -> None:
    target = tmp_path / "python-app"
    _write(
        target / "runner.py",
        """
import argparse
import os
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--config")
args = parser.parse_args()

config_path = os.getcwd() + "/" + args.config
subprocess.run(config_path, shell=True)
""".strip(),
    )

    result = map_application("python target", target)
    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="test-run",
        write_specs=True,
    )

    assert paths["rce_spec"].is_file()
    spec = parse_brainstorm_spec(paths["rce_spec"])
    assert spec.metadata["Program"] == "python-target"
    assert spec.metadata["AppMap run id"] == "test-run"
    assert spec.hypotheses[0].tags[:3] == ["rce", "appmap", "static"]
    candidate = result.candidates[0]
    expected_focus_files = sorted(
        {
            str(candidate["source"]["file"]),
            str(candidate["boundary"]["file"]),
            str(candidate["sink"]["file"]),
            *(
                [str(candidate["transform"]["file"])]
                if candidate.get("transform")
                else []
            ),
        }
    )
    assert spec.hypotheses[0].focus_files_glob == expected_focus_files
    assert not any(path.startswith("**/") for path in spec.hypotheses[0].focus_files_glob)

    surfaces = [
        json.loads(line)
        for line in paths["surfaces"].read_text(encoding="utf-8").splitlines()
        if line
    ]
    candidates = [
        json.loads(line)
        for line in paths["candidates"].read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert surfaces
    assert candidates


def test_app_mapper_default_generated_specs_use_category_master(tmp_path: Path) -> None:
    result = _two_candidate_result(tmp_path)

    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="default-granularity-run",
        write_specs=True,
    )

    spec = parse_brainstorm_spec(paths["rce_spec"])
    agent_keys = [hypothesis.suggested_agents[0] for hypothesis in spec.hypotheses]
    assert spec.metadata["Agent granularity"] == "category-master"
    assert agent_keys == ["exec-sink-reachability", "exec-sink-reachability"]


def test_app_mapper_narrow_specs_use_per_hypothesis_keys(tmp_path: Path) -> None:
    result = _two_candidate_result(tmp_path)

    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="narrow-granularity-run",
        write_specs=True,
        agent_granularity="narrow",
    )

    spec = parse_brainstorm_spec(paths["rce_spec"])
    agent_keys = [hypothesis.suggested_agents[0] for hypothesis in spec.hypotheses]
    assert spec.metadata["Agent granularity"] == "per-hypothesis"
    assert len(agent_keys) == 2
    assert len(set(agent_keys)) == 2
    assert all(key.startswith("two-candidate-appmap-rce-") for key in agent_keys)
    context_paths = sorted(paths["agent_contexts"].glob("*.json"))
    for hypothesis, candidate, agent_key in zip(spec.hypotheses, result.candidates, agent_keys):
        assert f"appmap-context:{hypothesis.id}:{candidate['id']}:{agent_key}" in hypothesis.evidence
        context_path = next(
            path
            for path in context_paths
            if path.name == f"{hypothesis.id}-{candidate['id']}-{agent_key}.json"
        )
        packet = json.loads(context_path.read_text(encoding="utf-8"))
        assert packet["hypothesis_linkage"]["hypothesis_id"] == hypothesis.id
        assert packet["hypothesis_linkage"]["agent_key"] == agent_key


def test_app_mapper_resolves_and_writes_canonical_lane_appmap_root(tmp_path: Path) -> None:
    shared_root = tmp_path / "Shared"
    lane_root = canonical_output_root(
        family="Binaries",
        program="Canva App",
        lane="EXE",
        shared_root=shared_root,
    )

    assert lane_root == shared_root / "binaries" / "Canva_App" / "exe"
    assert resolve_output_root(
        "Canva App",
        output_mode="canonical",
        family="Binaries",
        lane="EXE",
        shared_root=shared_root,
    ) == lane_root
    with pytest.raises(ValueError, match="requires --family and --lane"):
        resolve_output_root("Canva App", output_mode="canonical", family="Binaries")

    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="canonical-run",
        write_specs=True,
        output_mode="canonical",
    )

    assert paths["run_root"] == lane_root.resolve(strict=False) / "appmap" / "canonical-run"
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    assert manifest["output_mode"] == "canonical"
    assert manifest["run_root"] == str(paths["run_root"])
    assert manifest["artifacts"]["surfaces"] == "surfaces.jsonl"
    index_rows = [
        json.loads(line)
        for line in paths["index"].read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert index_rows[-1]["run_id"] == "canonical-run"
    assert index_rows[-1]["run_root"] == str(paths["run_root"])


def test_app_mapper_preserves_standalone_output_root_compatibility(tmp_path: Path) -> None:
    output_root = tmp_path / "legacy-out"
    result = _one_candidate_result(tmp_path)

    paths = write_artifacts(
        result,
        output_root=output_root,
        run_id="standalone-run",
        write_specs=True,
    )

    assert resolve_output_root("one candidate", output_root=output_root) == output_root
    assert paths["run_root"] == output_root.resolve(strict=False) / "appmap" / "standalone-run"
    assert paths["rce_spec"].parent == paths["run_root"] / "generated_specs"
    assert json.loads(paths["manifest"].read_text(encoding="utf-8"))["output_mode"] == "standalone"


def test_appmap_promotion_copies_only_handoff_files_and_preserves_run_trace(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    brainstorm_root = lane_root / "brainstorm"
    brainstorm_root.mkdir(parents=True)
    (brainstorm_root / "spec.md").write_text("# Existing human brainstorm\n", encoding="utf-8")
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="promo-run",
        write_specs=True,
        output_mode="canonical",
    )

    collision_root = brainstorm_root / "appmap-promo-run-rce"
    collision_root.mkdir(parents=True)
    (collision_root / "spec.md").write_text("# Existing promoted spec\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        promote_appmap_handoff(
            paths,
            brainstorm_root=brainstorm_root,
            run_id="promo-run",
            spec_name="spec.md",
        )

    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=brainstorm_root,
        run_id="promo-run",
    )

    promoted_spec = promotion.spec_paths[0]
    assert promoted_spec == brainstorm_root.resolve(strict=False) / "appmap-promo-run-rce" / "rce-spec.md"
    assert promotion.promotion_root == brainstorm_root.resolve(strict=False) / "appmap-promo-run-rce"
    assert (brainstorm_root / "spec.md").read_text(encoding="utf-8") == "# Existing human brainstorm\n"
    promoted_text = promoted_spec.read_text(encoding="utf-8")
    assert f"- AppMap run root: {paths['run_root']}" in promoted_text
    assert promotion.context_paths
    assert promotion.context_paths[0].parent == promotion.promotion_root / "agent_contexts"
    packet = json.loads(promotion.context_paths[0].read_text(encoding="utf-8"))
    assert packet["appmap_run_root"] == str(paths["run_root"])
    assert packet["hypothesis_linkage"]["spec_file"] == "generated_specs/rce-spec.md"
    manifest = json.loads(promotion.manifest_path.read_text(encoding="utf-8").splitlines()[-1])
    assert manifest["appmap_run_root"] == str(paths["run_root"])
    assert manifest["promotion_root"] == "appmap-promo-run-rce"
    assert manifest["promoted_contexts"] == [f"agent_contexts/{promotion.context_paths[0].name}"]
    assert not (lane_root / "ledgers").exists()
    assert not (lane_root / "reports").exists()
    assert not (brainstorm_root / "surfaces.jsonl").exists()
    assert not (brainstorm_root / "flows.jsonl").exists()
    assert not (brainstorm_root / "candidates.jsonl").exists()


def test_appmap_category_promotion_uses_focus_folder_and_manifest_record(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    brainstorm_root = lane_root / "brainstorm"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="category-run",
        write_specs=True,
        output_mode="canonical",
    )

    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=brainstorm_root,
        run_id="category-run",
        promotion_layout="category",
    )

    assert promotion.promotion_root == brainstorm_root.resolve(strict=False) / "appmap-category-run" / "rce"
    assert promotion.spec_paths == [promotion.promotion_root / "rce-spec.md"]
    assert promotion.context_paths
    assert promotion.context_paths[0].parent == promotion.promotion_root / "agent_contexts"
    manifest = json.loads(promotion.manifest_path.read_text(encoding="utf-8").splitlines()[-1])
    assert manifest["promotion_layout"] == "category"
    assert manifest["promotion_root"] == "appmap-category-run/rce"
    assert manifest["focus"] == "rce"
    assert manifest["promoted_specs"] == ["rce-spec.md"]
    assert manifest["promoted_contexts"] == [f"agent_contexts/{promotion.context_paths[0].name}"]
    assert not (brainstorm_root / "appmap-category-run" / "surfaces.jsonl").exists()
    assert not (brainstorm_root / "appmap-category-run" / "rce" / "candidates.jsonl").exists()


def test_appmap_category_promotion_supports_spec_name_override(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="category-spec-name-run",
        write_specs=True,
        output_mode="canonical",
    )

    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="category-spec-name-run",
        spec_name="spec.md",
        promotion_layout="category",
    )

    assert promotion.spec_paths == [
        lane_root.resolve(strict=False) / "brainstorm" / "appmap-category-spec-name-run" / "rce" / "spec.md"
    ]
    assert validate_promoted_handoff(promotion.spec_paths[0]).ok


def test_dynamic_agent_conversion_consumes_promoted_appmap_packet_context(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="promoted-adapter-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="promoted-adapter-run",
    )
    spec = parse_brainstorm_spec(promotion.spec_paths[0])
    intent = hypothesis_to_agent_intents(spec, spec.hypotheses[0])[0]

    dynamic_spec = brainstorm_intent_to_dynamic_agent_spec(
        intent,
        program=spec.metadata["Program"],
        version=spec.metadata["AppMap run id"],
    )

    assert "Use this AppMap context packet as the complete assignment context" in dynamic_spec.agent_prompt_template
    assert str(lane_root / "brainstorm" / "appmap-promoted-adapter-run-rce" / "agent_contexts") in dynamic_spec.brainstorm_metadata["appmap_context_packet"]
    assert dynamic_spec.brainstorm_metadata["appmap_candidate_id"] == result.candidates[0]["id"]
    assert dynamic_spec.brainstorm_metadata["appmap_flow_id"] == result.candidates[0]["flow_id"]
    assert "surfaces.jsonl" not in dynamic_spec.brainstorm_metadata
    assert "flows.jsonl" not in dynamic_spec.brainstorm_metadata
    assert "candidates.jsonl" not in dynamic_spec.brainstorm_metadata


def test_appmap_lists_promoted_handoffs_from_manifest_and_per_run_dirs(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="listed-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="listed-run",
    )
    manual_root = lane_root / "brainstorm" / "appmap-manual-run-rce"
    manual_root.mkdir(parents=True)
    manual_spec = manual_root / "spec.md"
    manual_spec.write_text(promotion.spec_paths[0].read_text(encoding="utf-8"), encoding="utf-8")
    manual_context_root = manual_root / "agent_contexts"
    manual_context_root.mkdir()
    for context_path in promotion.context_paths:
        (manual_context_root / context_path.name).write_text(context_path.read_text(encoding="utf-8"), encoding="utf-8")

    handoffs = list_promoted_handoffs(lane_root / "brainstorm")

    by_spec = {handoff.spec_path: handoff for handoff in handoffs}
    assert promotion.spec_paths[0] in by_spec
    assert by_spec[promotion.spec_paths[0]].source == "manifest,directory"
    assert by_spec[promotion.spec_paths[0]].run_id == "listed-run"
    assert manual_spec.resolve(strict=False) in by_spec
    assert by_spec[manual_spec.resolve(strict=False)].source == "directory"
    assert by_spec[manual_spec.resolve(strict=False)].context_count == len(promotion.context_paths)


def test_appmap_list_validate_and_plan_category_layout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="category-handoff-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="category-handoff-run",
        promotion_layout="category",
    )

    handoffs = list_promoted_handoffs(lane_root / "brainstorm")
    by_spec = {handoff.spec_path: handoff for handoff in handoffs}
    handoff = by_spec[promotion.spec_paths[0]]
    assert handoff.run_id == "category-handoff-run"
    assert handoff.focus == "rce"
    assert handoff.context_count == len(promotion.context_paths)
    assert handoff.source == "manifest,directory"
    assert validate_promoted_handoff(promotion.spec_paths[0]).ok
    command = plan_promoted_handoff_command(promotion.spec_paths[0], selected_hypothesis="H001")
    assert f"--brainstorm-spec {promotion.spec_paths[0]}" in command
    assert "--brainstorm-hypothesis H001" in command
    assert "--appmap" not in command

    coverage_path = lane_root / "brainstorm" / "coverage.jsonl"
    identity = _assignment_identities_for_status(promotion.spec_paths[0])[0]
    coverage_event = {
        "event": "agent_completed_no_finding",
        "hypothesis_id": identity["hypothesis_id"],
        "agent_key": identity["agent_key"],
        "source_spec_path": str(promotion.spec_paths[0]),
        "brainstorm_spec": str(promotion.spec_paths[0]),
        "appmap_candidate_id": identity["candidate_id"],
        "appmap_run_id": "category-handoff-run",
    }
    coverage_path.write_text(json.dumps(coverage_event, sort_keys=True) + "\n", encoding="utf-8")
    status = campaign_status(lane_root / "brainstorm")
    assert status["status_counts"] == {"complete": 1}
    assert status["specs"][0]["coverage_events"]["agent_completed_no_finding"] == 1
    assert status["specs"][0]["assignments"] == {"covered": 1, "review": 0, "attention": 0, "running": 0, "pending": 0}

    assert app_mapper_main(["--list-handoffs", "--brainstorm-root", str(lane_root / "brainstorm")]) == 0
    list_out = capsys.readouterr().out
    assert "run_id=category-handoff-run" in list_out
    assert "focus=rce" in list_out
    assert "contexts=1" in list_out

    assert app_mapper_main(["--campaign-status", "--brainstorm-root", str(lane_root / "brainstorm")]) == 0
    status_out = capsys.readouterr().out
    assert "campaign status" in status_out
    assert "statuses: complete=1" in status_out
    assert "status=complete" in status_out
    assert "covered=1" in status_out


def test_appmap_campaign_status_uses_latest_terminal_per_assignment(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="status-latest-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="status-latest-run",
        promotion_layout="category",
    )
    coverage_path = lane_root / "brainstorm" / "coverage.jsonl"
    identity = _assignment_identities_for_status(promotion.spec_paths[0])[0]
    base = {
        "hypothesis_id": identity["hypothesis_id"],
        "agent_key": identity["agent_key"],
        "source_spec_path": str(promotion.spec_paths[0]),
        "brainstorm_spec": str(promotion.spec_paths[0]),
        "appmap_candidate_id": identity["candidate_id"],
        "appmap_run_id": "status-latest-run",
    }
    coverage_path.write_text(
        "\n".join(
            json.dumps({"event": event, **base}, sort_keys=True)
            for event in ("agent_completed_with_raw_findings", "review_promoted")
        )
        + "\n",
        encoding="utf-8",
    )

    status = campaign_status(lane_root / "brainstorm")

    assert status["status_counts"] == {"complete": 1}
    assert status["specs"][0]["assignments"] == {"covered": 1, "review": 0, "attention": 0, "running": 0, "pending": 0}


def test_appmap_campaign_status_does_not_complete_from_duplicate_events_for_one_assignment(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _two_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="status-pending-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="status-pending-run",
        promotion_layout="category",
    )
    coverage_path = lane_root / "brainstorm" / "coverage.jsonl"
    identity = _assignment_identities_for_status(promotion.spec_paths[0])[0]
    base = {
        "hypothesis_id": identity["hypothesis_id"],
        "agent_key": identity["agent_key"],
        "source_spec_path": str(promotion.spec_paths[0]),
        "brainstorm_spec": str(promotion.spec_paths[0]),
        "appmap_candidate_id": identity["candidate_id"],
        "appmap_run_id": "status-pending-run",
    }
    coverage_path.write_text(
        "\n".join(json.dumps({"event": "agent_completed_no_finding", **base}, sort_keys=True) for _ in range(2))
        + "\n",
        encoding="utf-8",
    )

    status = campaign_status(lane_root / "brainstorm")

    assert status["status_counts"] == {"ready": 1}
    assert status["specs"][0]["assignments"] == {"covered": 1, "review": 0, "attention": 0, "running": 0, "pending": 1}


def test_appmap_campaign_status_running_is_latest_per_assignment(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _two_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="status-running-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="status-running-run",
        promotion_layout="category",
    )
    identities = _assignment_identities_for_status(promotion.spec_paths[0])
    coverage_path = lane_root / "brainstorm" / "coverage.jsonl"
    covered_base = {
        "hypothesis_id": identities[0]["hypothesis_id"],
        "agent_key": identities[0]["agent_key"],
        "source_spec_path": str(promotion.spec_paths[0]),
        "brainstorm_spec": str(promotion.spec_paths[0]),
        "appmap_candidate_id": identities[0]["candidate_id"],
        "appmap_run_id": "status-running-run",
    }
    running_base = {
        "hypothesis_id": identities[1]["hypothesis_id"],
        "agent_key": identities[1]["agent_key"],
        "source_spec_path": str(promotion.spec_paths[0]),
        "brainstorm_spec": str(promotion.spec_paths[0]),
        "appmap_candidate_id": identities[1]["candidate_id"],
        "appmap_run_id": "status-running-run",
    }
    coverage_path.write_text(
        "\n".join(
            [
                json.dumps({"event": "agent_queued", **covered_base}, sort_keys=True),
                json.dumps({"event": "agent_spawned", **covered_base}, sort_keys=True),
                json.dumps({"event": "agent_completed_no_finding", **covered_base}, sort_keys=True),
                json.dumps({"event": "agent_queued", **running_base}, sort_keys=True),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    status = campaign_status(lane_root / "brainstorm")

    assert status["status_counts"] == {"running": 1}
    assert status["specs"][0]["assignments"] == {
        "covered": 1,
        "review": 0,
        "attention": 0,
        "running": 1,
        "pending": 0,
    }


def test_zero_day_team_spec_dir_discovers_category_focus_folder(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="category-spec-dir-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="category-spec-dir-run",
        promotion_layout="category",
    )

    assert _discover_brainstorm_spec_dir(promotion.promotion_root) == promotion.spec_paths
    assert _discover_brainstorm_spec_dir(promotion.promotion_root.parent) == promotion.spec_paths


def test_appmap_list_skips_tampered_manifest_escapes(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="tamper-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="tamper-run",
    )
    outside_root = tmp_path / "outside"
    outside_root.mkdir()
    outside_spec = outside_root / "spec.md"
    outside_spec.write_text(promotion.spec_paths[0].read_text(encoding="utf-8"), encoding="utf-8")
    with promotion.manifest_path.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "appmap_run_id": "escape-dotdot",
                    "promotion_root": "../outside",
                    "promoted_specs": ["spec.md"],
                }
            )
            + "\n"
        )
        handle.write(
            json.dumps(
                {
                    "appmap_run_id": "escape-absolute",
                    "promotion_root": str(outside_root.resolve(strict=False)),
                    "promoted_specs": ["spec.md"],
                }
            )
            + "\n"
        )
        handle.write(
            json.dumps(
                {
                    "appmap_run_id": "escape-spec",
                    "promotion_root": promotion.promotion_root.name,
                    "promoted_specs": [f"../{outside_root.name}/spec.md"],
                }
            )
            + "\n"
        )

    handoffs = list_promoted_handoffs(lane_root / "brainstorm")

    by_spec = {handoff.spec_path: handoff for handoff in handoffs}
    assert promotion.spec_paths[0] in by_spec
    assert outside_spec.resolve(strict=False) not in by_spec
    assert {handoff.run_id for handoff in handoffs} == {"tamper-run"}


def test_appmap_list_skips_symlinked_appmap_dirs_and_specs(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="symlink-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="symlink-run",
    )
    brainstorm_root = lane_root / "brainstorm"
    outside_root = tmp_path / "outside-link-target"
    outside_root.mkdir()
    outside_spec = outside_root / "spec.md"
    outside_spec.write_text(promotion.spec_paths[0].read_text(encoding="utf-8"), encoding="utf-8")
    (brainstorm_root / "appmap-linked-dir-rce").symlink_to(outside_root, target_is_directory=True)
    spec_link_root = brainstorm_root / "appmap-linked-spec-rce"
    spec_link_root.mkdir()
    (spec_link_root / "spec.md").symlink_to(outside_spec)

    handoffs = list_promoted_handoffs(brainstorm_root)

    listed_paths = {handoff.spec_path for handoff in handoffs}
    assert promotion.spec_paths[0] in listed_paths
    assert outside_spec.resolve(strict=False) not in listed_paths
    assert (spec_link_root / "spec.md").resolve(strict=False) not in listed_paths


def test_appmap_flat_handoff_listing_stays_non_recursive(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="flat-nonrecursive-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="flat-nonrecursive-run",
    )
    nested = promotion.promotion_root / "nested"
    nested.mkdir()
    (nested / "spec.md").write_text(promotion.spec_paths[0].read_text(encoding="utf-8"), encoding="utf-8")

    listed_paths = {handoff.spec_path for handoff in list_promoted_handoffs(lane_root / "brainstorm")}

    assert promotion.spec_paths[0] in listed_paths
    assert (nested / "spec.md").resolve(strict=False) not in listed_paths


def test_appmap_category_discovery_skips_symlinked_focus_dirs_and_specs(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="category-symlink-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="category-symlink-run",
        promotion_layout="category",
    )
    brainstorm_root = lane_root / "brainstorm"
    outside_root = tmp_path / "outside-category"
    outside_root.mkdir()
    outside_spec = outside_root / "spec.md"
    outside_spec.write_text(promotion.spec_paths[0].read_text(encoding="utf-8"), encoding="utf-8")
    linked_run_root = brainstorm_root / "appmap-linked-category"
    linked_run_root.mkdir()
    (linked_run_root / "rce").symlink_to(outside_root, target_is_directory=True)
    linked_spec_root = brainstorm_root / "appmap-linked-category-spec" / "rce"
    linked_spec_root.mkdir(parents=True)
    (linked_spec_root / "spec.md").symlink_to(outside_spec)

    handoffs = list_promoted_handoffs(brainstorm_root)

    listed_paths = {handoff.spec_path for handoff in handoffs}
    assert promotion.spec_paths[0] in listed_paths
    assert outside_spec.resolve(strict=False) not in listed_paths
    assert (linked_spec_root / "spec.md").resolve(strict=False) not in listed_paths


def test_appmap_listing_ignores_non_spec_markdown(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="notes-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="notes-run",
    )
    notes_root = lane_root / "brainstorm" / "appmap-notes-manual-rce"
    notes_root.mkdir()
    notes_path = notes_root / "notes.md"
    notes_path.write_text("# Operational notes\n\nNot a brainstorm spec.\n", encoding="utf-8")

    handoffs = list_promoted_handoffs(lane_root / "brainstorm")

    listed_paths = {handoff.spec_path for handoff in handoffs}
    assert promotion.spec_paths[0] in listed_paths
    assert notes_path.resolve(strict=False) not in listed_paths


def test_appmap_validate_promoted_handoff_success_and_failures(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="validate-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="validate-run",
    )

    success = validate_promoted_handoff(promotion.spec_paths[0])

    assert success.ok
    assert success.counts == {
        "hypotheses": 1,
        "appmap_hypotheses": 1,
        "appmap_intents": 1,
        "packets": 1,
    }

    missing_packet = promotion.context_paths[0]
    packet_text = missing_packet.read_text(encoding="utf-8")
    missing_packet.unlink()
    missing = validate_promoted_handoff(promotion.spec_paths[0])
    assert not missing.ok
    assert any("expected exactly one sibling AppMap context packet" in error for error in missing.errors)

    missing_packet.write_text(packet_text, encoding="utf-8")
    packet = json.loads(packet_text)
    packet["run_id"] = "other-run"
    missing_packet.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    mismatch = validate_promoted_handoff(promotion.spec_paths[0])
    assert not mismatch.ok
    assert any("does not match spec AppMap run id" in error for error in mismatch.errors)


def test_appmap_validate_promoted_handoff_rejects_symlinked_context_packet(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="symlink-packet-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="symlink-packet-run",
    )
    packet_path = promotion.context_paths[0]
    outside_packet = tmp_path / "outside-context.json"
    outside_packet.write_text(packet_path.read_text(encoding="utf-8"), encoding="utf-8")
    packet_path.unlink()
    packet_path.symlink_to(outside_packet)

    result = validate_promoted_handoff(promotion.spec_paths[0])

    assert not result.ok
    assert any("context packet must not be a symlink" in error for error in result.errors)
    assert result.counts["packets"] == 0



def test_appmap_direct_validate_and_plan_reject_symlinked_spec(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="symlink-spec-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="symlink-spec-run",
    )
    symlink_spec = lane_root / "brainstorm" / "appmap-symlink-spec-run-rce" / "linked-spec.md"
    symlink_spec.symlink_to(promotion.spec_paths[0])

    validation = validate_promoted_handoff(symlink_spec)

    assert not validation.ok
    assert any("spec path must not be a symlink" in error for error in validation.errors)
    with pytest.raises(ValueError, match="spec path must not be a symlink"):
        plan_promoted_handoff_command(symlink_spec)

def test_appmap_validate_handoff_fails_on_strict_path_violation(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="strict-validate-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="strict-validate-run",
    )
    text = promotion.spec_paths[0].read_text(encoding="utf-8")
    promotion.spec_paths[0].write_text(text.replace("  - runner.js", "  - ../escape.js", 1), encoding="utf-8")

    result = validate_promoted_handoff(promotion.spec_paths[0])

    assert not result.ok
    assert any("strict brainstorm spec parse failed" in error for error in result.errors)
    assert any("resolves outside lane root" in error for error in result.errors)
    with pytest.raises(ValueError, match="strict brainstorm spec parse failed"):
        plan_promoted_handoff_command(promotion.spec_paths[0])


def test_appmap_validate_handoff_fails_without_appmap_content(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    brainstorm_root = lane_root / "brainstorm"
    spec_root = brainstorm_root / "appmap-empty-run-rce"
    spec_root.mkdir(parents=True)
    spec_path = spec_root / "spec.md"
    spec_path.write_text(
        "\n".join(
            [
                "# Brainstorm Spec: Empty AppMap",
                "",
                "## Metadata",
                "- Program: empty-appmap",
                "- Family: appmap",
                "- Lane: static",
                "- Target kind: node",
                "- Target path: .",
                "- Created: 2026-05-04",
                "- Status: active",
                "- AppMap run id: empty-run",
                f"- AppMap run root: {lane_root / 'appmap' / 'empty-run'}",
                "",
                "## Target mental model",
                "No AppMap-linked hypotheses are present.",
                "",
                "## Impact primitives",
                "### P001 - Manual primitive",
                "- Source: local note",
                "- Impact: local note",
                "- Evidence: local-note",
                "- Status: active",
                "",
                "## Hypotheses",
                "### H001 - Manual hypothesis",
                "- Status: untested",
                "- Priority: high",
                "- Surface: manual surface",
                "- Entry point: manual entry",
                "- Expected chain: manual source -> manual sink",
                "- Suggested agents:",
                "  - manual-agent",
                "- Focus files:",
                "  - .",
                "- Tags: rce, static",
                "- Evidence:",
                "  - local-note",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = validate_promoted_handoff(spec_path)

    assert not result.ok
    assert result.counts["appmap_hypotheses"] == 0
    assert result.counts["appmap_intents"] == 0
    assert result.counts["packets"] == 0
    assert any("zero AppMap hypotheses" in error for error in result.errors)
    assert any("zero AppMap agent intents" in error for error in result.errors)
    assert any("zero AppMap context packets" in error for error in result.errors)


def test_appmap_plan_handoff_prints_existing_runtime_command_without_writes(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="plan-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="plan-run",
    )

    command = plan_promoted_handoff_command(promotion.spec_paths[0], selected_hypothesis="H001")

    assert command == (
        "python3 agents/zero_day_team.py one-candidate "
        f"{result.profile.target_path} --brainstorm-spec {promotion.spec_paths[0]} "
        "--brainstorm-only --brainstorm-hypothesis H001"
    )
    assert "--appmap" not in command
    assert not (lane_root / "ledgers").exists()
    assert not (lane_root / "reports").exists()


def test_appmap_plan_handoff_rejects_missing_or_retired_selected_hypothesis(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="selected-plan-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="selected-plan-run",
    )

    with pytest.raises(ValueError, match="not found or is retired"):
        plan_promoted_handoff_command(promotion.spec_paths[0], selected_hypothesis="H999")

    text = promotion.spec_paths[0].read_text(encoding="utf-8")
    promotion.spec_paths[0].write_text(text.replace("- Status: untested", "- Status: retired", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="not found or is retired"):
        plan_promoted_handoff_command(promotion.spec_paths[0], selected_hypothesis="H001")


def test_appmap_plan_handoff_rejects_non_appmap_selected_hypothesis_from_mixed_spec(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="mixed-selected-plan-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="mixed-selected-plan-run",
    )
    text = promotion.spec_paths[0].read_text(encoding="utf-8")
    manual_hypothesis = "\n".join(
        [
            "### H002 - Manual hypothesis",
            "- Status: untested",
            "- Priority: high",
            "- Surface: manual surface",
            "- Entry point: manual entry",
            "- Expected chain: manual source -> manual sink",
            "- Suggested agents:",
            "  - manual-agent",
            "- Focus files:",
            "  - .",
            "- Tags: rce, static",
            "- Evidence:",
            "  - manual-note",
            "",
        ]
    )
    promotion.spec_paths[0].write_text(
        text.replace("\n## Coverage log\n", f"\n{manual_hypothesis}\n## Coverage log\n"),
        encoding="utf-8",
    )

    command = plan_promoted_handoff_command(promotion.spec_paths[0], selected_hypothesis="H001")
    assert "--brainstorm-hypothesis H001" in command
    with pytest.raises(ValueError, match="not an AppMap-linked hypothesis"):
        plan_promoted_handoff_command(promotion.spec_paths[0], selected_hypothesis="H002")
    with pytest.raises(ValueError, match="not an AppMap-linked hypothesis"):
        plan_promoted_handoff_command(promotion.spec_paths[0])


def test_appmap_handoff_cli_parse_and_modes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="cli-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="cli-run",
    )
    parser = build_parser()

    args = parser.parse_args(["demo", "/tmp/target"])
    assert args.program == "demo"
    assert args.target_path == "/tmp/target"
    assert args.promotion_layout == "flat"
    category_args = parser.parse_args(["demo", "/tmp/target", "--promotion-layout", "category"])
    assert category_args.promotion_layout == "category"
    granularity_args = parser.parse_args(["demo", "/tmp/target", "--agent-granularity", "narrow"])
    assert granularity_args.agent_granularity == "narrow"
    shortcut_args = parser.parse_args(["demo", "/tmp/target", "--category-master-agents"])
    assert shortcut_args.category_master_agents
    policy_args = parser.parse_args(
        [
            "demo",
            "/tmp/target",
            "--triage-policy",
            "electron-entry-first",
            "--policy-config",
            "/tmp/policy.json",
        ]
    )
    assert policy_args.triage_policy == "electron-entry-first"
    assert policy_args.policy_config == "/tmp/policy.json"
    list_args = parser.parse_args(["--list-handoffs", "--brainstorm-root", str(lane_root / "brainstorm")])
    assert list_args.program is None
    assert list_args.list_handoffs

    assert app_mapper_main(["--validate-handoff", str(promotion.spec_paths[0])]) == 0
    validate_out = capsys.readouterr().out
    assert "handoff validation: ok" in validate_out
    assert "packets=1" in validate_out

    assert app_mapper_main(["--plan-handoff", str(promotion.spec_paths[0])]) == 0
    plan_out = capsys.readouterr().out
    assert "agents/zero_day_team.py one-candidate" in plan_out
    assert "--brainstorm-spec" in plan_out
    assert "--appmap" not in plan_out

    with pytest.raises(SystemExit, match="program and target_path are required"):
        app_mapper_main(["demo"])


def test_repeated_appmap_promotions_namespace_packets_by_run(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    first_paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="repeat-run-one",
        write_specs=True,
        output_mode="canonical",
    )
    second_paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="repeat-run-two",
        write_specs=True,
        output_mode="canonical",
    )

    first = promote_appmap_handoff(
        first_paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="repeat-run-one",
        spec_name="spec.md",
    )
    second = promote_appmap_handoff(
        second_paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="repeat-run-two",
        spec_name="spec.md",
        overwrite=True,
    )

    first_spec = parse_brainstorm_spec(first.spec_paths[0])
    second_spec = parse_brainstorm_spec(second.spec_paths[0])
    first_intent = hypothesis_to_agent_intents(first_spec, first_spec.hypotheses[0])[0]
    second_intent = hypothesis_to_agent_intents(second_spec, second_spec.hypotheses[0])[0]
    first_dynamic = brainstorm_intent_to_dynamic_agent_spec(
        first_intent,
        program=first_spec.metadata["Program"],
        version=first_spec.metadata["AppMap run id"],
    )
    second_dynamic = brainstorm_intent_to_dynamic_agent_spec(
        second_intent,
        program=second_spec.metadata["Program"],
        version=second_spec.metadata["AppMap run id"],
    )

    assert first.spec_paths[0] == lane_root / "brainstorm" / "appmap-repeat-run-one-rce" / "spec.md"
    assert second.spec_paths[0] == lane_root / "brainstorm" / "appmap-repeat-run-two-rce" / "spec.md"
    assert "appmap-repeat-run-one-rce/agent_contexts" in first_dynamic.brainstorm_metadata["appmap_context_packet"]
    assert "appmap-repeat-run-two-rce/agent_contexts" in second_dynamic.brainstorm_metadata["appmap_context_packet"]
    first_packet = json.loads(Path(first_dynamic.brainstorm_metadata["appmap_context_packet"]).read_text(encoding="utf-8"))
    second_packet = json.loads(Path(second_dynamic.brainstorm_metadata["appmap_context_packet"]).read_text(encoding="utf-8"))
    assert first_packet["run_id"] == "repeat-run-one"
    assert second_packet["run_id"] == "repeat-run-two"


def test_repeated_category_focus_collision_preflight_leaves_no_partial_artifacts(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    first_paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="category-repeat-run",
        write_specs=True,
        output_mode="canonical",
    )
    second_paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="category-repeat-run",
        write_specs=True,
        output_mode="canonical",
    )
    first = promote_appmap_handoff(
        first_paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="category-repeat-run",
        spec_name="spec.md",
        promotion_layout="category",
    )
    original_spec_text = first.spec_paths[0].read_text(encoding="utf-8")
    original_context_text = first.context_paths[0].read_text(encoding="utf-8")
    manifest_text = first.manifest_path.read_text(encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing to overwrite existing promoted AppMap file"):
        promote_appmap_handoff(
            second_paths,
            brainstorm_root=lane_root / "brainstorm",
            run_id="category-repeat-run",
            spec_name="spec.md",
            promotion_layout="category",
        )

    assert first.spec_paths[0].read_text(encoding="utf-8") == original_spec_text
    assert first.context_paths[0].read_text(encoding="utf-8") == original_context_text
    assert first.manifest_path.read_text(encoding="utf-8") == manifest_text


def test_appmap_adapter_rejects_packet_run_id_mismatch(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="packet-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=lane_root / "brainstorm",
        run_id="packet-run",
    )
    packet_path = promotion.context_paths[0]
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["run_id"] = "different-run"
    packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    spec = parse_brainstorm_spec(promotion.spec_paths[0])
    intent = hypothesis_to_agent_intents(spec, spec.hypotheses[0])[0]

    with pytest.raises(ValueError, match="run_id does not match spec AppMap run id"):
        brainstorm_intent_to_dynamic_agent_spec(
            intent,
            program=spec.metadata["Program"],
            version=spec.metadata["AppMap run id"],
        )


def test_appmap_promotion_refuses_destination_symlink(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="dest-link-run",
        write_specs=True,
        output_mode="canonical",
    )
    promotion_root = lane_root / "brainstorm" / "appmap-dest-link-run-rce"
    promotion_root.mkdir(parents=True)
    outside = tmp_path / "outside-spec.md"
    outside.write_text("# outside\n", encoding="utf-8")
    (promotion_root / "rce-spec.md").symlink_to(outside)

    with pytest.raises(ValueError, match="refusing symlink destination"):
        promote_appmap_handoff(
            paths,
            brainstorm_root=lane_root / "brainstorm",
            run_id="dest-link-run",
        )


def test_appmap_promotion_refuses_source_symlink(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="source-link-run",
        write_specs=True,
        output_mode="canonical",
    )
    real_context = next((paths["agent_contexts"]).glob("*.json"))
    context_text = real_context.read_text(encoding="utf-8")
    real_context.unlink()
    source_target = tmp_path / "source-target.json"
    source_target.write_text(context_text, encoding="utf-8")
    real_context.symlink_to(source_target)

    with pytest.raises(ValueError, match="refusing symlink source"):
        promote_appmap_handoff(
            paths,
            brainstorm_root=lane_root / "brainstorm",
            run_id="source-link-run",
        )
    assert not (lane_root / "brainstorm").exists()


def test_appmap_promotion_context_collision_preflight_leaves_no_partial_spec(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="context-collision-run",
        write_specs=True,
        output_mode="canonical",
    )
    source_context = next((paths["agent_contexts"]).glob("*.json"))
    promotion_root = lane_root / "brainstorm" / "appmap-context-collision-run-rce"
    collision = promotion_root / "agent_contexts" / source_context.name
    collision.parent.mkdir(parents=True)
    collision.write_text('{"existing": true}\n', encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing to overwrite existing promoted AppMap file"):
        promote_appmap_handoff(
            paths,
            brainstorm_root=lane_root / "brainstorm",
            run_id="context-collision-run",
        )

    assert not (promotion_root / "rce-spec.md").exists()
    assert collision.read_text(encoding="utf-8") == '{"existing": true}\n'



def test_appmap_promotion_manifest_non_file_preflight_leaves_no_partial_artifacts(tmp_path: Path) -> None:
    lane_root = tmp_path / "Shared" / "binaries" / "canva" / "exe"
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=lane_root,
        run_id="manifest-dir-run",
        write_specs=True,
        output_mode="canonical",
    )
    brainstorm_root = lane_root / "brainstorm"
    (brainstorm_root / "appmap_promotions.jsonl").mkdir(parents=True)

    with pytest.raises(FileExistsError, match="refusing non-file promoted AppMap manifest destination"):
        promote_appmap_handoff(
            paths,
            brainstorm_root=brainstorm_root,
            run_id="manifest-dir-run",
        )

    promotion_root = brainstorm_root / "appmap-manifest-dir-run-rce"
    assert not (promotion_root / "rce-spec.md").exists()
    assert not (promotion_root / "agent_contexts").exists()

def test_app_mapper_writes_candidate_isolated_agent_context(tmp_path: Path) -> None:
    target = tmp_path / "node-app"
    _write(
        target / "package.json",
        """
{
  "main": "runner.js",
  "scripts": {
    "start": "node runner.js"
  }
}
""".strip(),
    )
    _write(
        target / "runner.js",
        """
const fs = require("fs");
const path = require("path");
const child_process = require("child_process");

const configPath = path.join(process.cwd(), "project.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
child_process.exec(config.command);
""".strip(),
    )

    result = map_application("node target", target, target_kind="node")
    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="context-run",
        write_specs=True,
    )

    spec = parse_brainstorm_spec(paths["rce_spec"])
    candidate = result.candidates[0]
    context_path = paths[f"agent_context_{candidate['id'].lower()}"]
    context = json.loads(context_path.read_text(encoding="utf-8"))
    context_text = json.dumps(context, sort_keys=True)

    assert context_path.is_file()
    assert context["candidate"]["id"] == candidate["id"]
    assert context["candidate"]["map_ids"] == {
        "candidate_id": candidate["id"],
        "flow_id": candidate["flow_id"],
        "source_id": candidate["source"]["id"],
        "boundary_id": candidate["boundary"]["id"],
        "transform_id": candidate["transform"]["id"] if candidate.get("transform") else None,
        "sink_id": candidate["sink"]["id"],
        "surface_id": candidate["surface_id"],
    }
    assert context["evidence"]["source"]["file"] == candidate["source"]["file"]
    assert context["evidence"]["source"]["snippet"] == candidate["source"]["snippet"]
    assert context["evidence"]["boundary"]["file"] == candidate["boundary"]["file"]
    assert context["evidence"]["boundary"]["snippet"] == candidate["boundary"]["snippet"]
    assert context["evidence"]["sink"]["file"] == candidate["sink"]["file"]
    assert context["evidence"]["sink"]["snippet"] == candidate["sink"]["snippet"]
    if candidate.get("transform"):
        assert context["evidence"]["transform"]["file"] == candidate["transform"]["file"]
        assert context["evidence"]["transform"]["snippet"] == candidate["transform"]["snippet"]
    else:
        assert context["evidence"]["transform"] is None
    assert context["hypothesis_linkage"]["hypothesis_id"] == spec.hypotheses[0].id
    assert context["hypothesis_linkage"]["agent_key"] == spec.hypotheses[0].suggested_agents[0]
    assert f"appmap-{candidate['id']}" in context["hypothesis_linkage"]["evidence_refs"]
    assert context["hypothesis_linkage"]["spec_file"] == "generated_specs/rce-spec.md"
    assert context["active_target_packs"] == ["node", "config"]
    assert context["active_vulnerability_pack"] == "rce"
    assert "electron" not in context_text.lower()


def test_app_mapper_mixed_electron_node_candidate_context_does_not_leak_electron_pack(tmp_path: Path) -> None:
    target = tmp_path / "mixed-electron-node"
    _write(
        target / "package.json",
        """
{
  "main": "src/electron-main.js",
  "dependencies": {
    "electron": "^30.0.0"
  }
}
""".strip(),
    )
    _write(
        target / "src" / "electron-main.js",
        """
const { app } = require("electron");
app.whenReady();
""".strip(),
    )
    _write(
        target / "tools" / "runner.js",
        """
const fs = require("fs");
const path = require("path");
const child_process = require("child_process");

const configPath = path.join(process.cwd(), "project.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
child_process.exec(config.command);
""".strip(),
    )

    result = map_application("mixed target", target, target_kind="electron-exe")
    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="mixed-run",
        write_specs=True,
    )
    candidate = next(item for item in result.candidates if item["source"]["file"] == "tools/runner.js")
    context_path = paths[f"agent_context_{candidate['id'].lower()}"]
    context = json.loads(context_path.read_text(encoding="utf-8"))
    context_without_run_path = {
        key: value
        for key, value in context.items()
        if key != "appmap_run_root"
    }
    context_text = json.dumps(context_without_run_path, sort_keys=True).lower()

    assert context["active_target_packs"] == ["node", "config"]
    assert context["target_profile"]["target_kind"] == "node"
    assert "frameworks" not in context["target_profile"]
    assert "detected_kinds" not in context["target_profile"]
    assert "electron" not in context_text


def test_app_mapper_writes_cited_research_artifacts_and_candidate_scoped_packets(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)
    seed_path = tmp_path / "research-seed.json"
    seed_path.write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "id": "S0001",
                        "title": "Node child_process guidance",
                        "url": "https://example.test/node-child-process",
                        "summary": "Command execution risk depends on attacker-controlled command material.",
                    },
                    {
                        "id": "S0002",
                        "title": "Electron IPC guidance",
                        "url": "https://example.test/electron-ipc",
                        "summary": "Renderer to main IPC can be security sensitive.",
                    },
                ],
                "technique_packs": [
                    {
                        "id": "node-rce-config",
                        "title": "Node config to process execution",
                        "summary": "Review config parsing and command construction before child_process sinks.",
                        "vulnerability_pack": "rce",
                        "target_pack_keys": ["node"],
                        "applicable_surface_kinds": ["config", "process-exec"],
                        "source_ids": ["S0001"],
                    },
                    {
                        "id": "electron-ipc-rce",
                        "title": "Electron IPC to privileged sink",
                        "summary": "Review renderer IPC messages that reach privileged Electron APIs.",
                        "vulnerability_pack": "rce",
                        "target_pack_keys": ["electron"],
                        "applicable_surface_kinds": ["ipc"],
                        "source_ids": ["S0002"],
                    },
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    result.research = generate_research_artifacts(result, seed_paths=[seed_path])

    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="research-run",
        write_specs=True,
    )

    manifest = json.loads(paths["research_manifest"].read_text(encoding="utf-8"))
    sources = [json.loads(line) for line in paths["research_sources"].read_text(encoding="utf-8").splitlines()]
    techniques = [
        json.loads(line)
        for line in paths["research_technique_packs"].read_text(encoding="utf-8").splitlines()
    ]
    context = json.loads(paths["agent_context_c0001"].read_text(encoding="utf-8"))
    spec_text = paths["rce_spec"].read_text(encoding="utf-8")
    context_text = json.dumps(context, sort_keys=True).lower()

    assert manifest["provider"] == "local-seed"
    assert manifest["network_access"] is False
    assert manifest["counts"] == {"errors": 0, "sources": 2, "technique_packs": 2}
    assert {source["id"] for source in sources} == {"s0001", "s0002"}
    assert {technique["id"] for technique in techniques} == {"node-rce-config", "electron-ipc-rce"}
    assert context["research"]["technique_summaries"][0]["id"] == "node-rce-config"
    assert context["research"]["sources"][0]["citation"] == "[s0001]"
    assert "research-technique:node-rce-config" in spec_text
    assert "research-technique:node-rce-config citations:" not in spec_text
    assert "electron-ipc-rce" not in context_text
    assert "electron ipc" not in spec_text.lower()


def test_app_mapper_research_requires_explicit_applicability_without_applies_to_all(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)
    seed_path = tmp_path / "research-seed.json"
    seed_path.write_text(
        json.dumps(
            {
                "technique_packs": [
                    {
                        "id": "generic-rce-without-applicability",
                        "title": "Generic RCE technique",
                        "summary": "This should not be treated as matching every target or surface.",
                        "vulnerability_pack": "rce",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result.research = generate_research_artifacts(result, seed_paths=[seed_path])

    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="strict-research-run",
        write_specs=True,
    )

    context = json.loads(paths["agent_context_c0001"].read_text(encoding="utf-8"))
    spec_text = paths["rce_spec"].read_text(encoding="utf-8")

    assert context["research"]["technique_summaries"] == []
    assert "generic-rce-without-applicability" not in spec_text


def test_app_mapper_research_metadata_survives_dynamic_agent_conversion_without_citation_evidence_split(
    tmp_path: Path,
) -> None:
    result = _one_candidate_result(tmp_path)
    seed_path = tmp_path / "research-seed.json"
    seed_path.write_text(
        json.dumps(
            {
                "sources": [
                    {"id": "S0001", "title": "First source", "url": "https://example.test/one"},
                    {"id": "S0002", "title": "Second source", "url": "https://example.test/two"},
                ],
                "technique_packs": [
                    {
                        "id": "node-multisource-rce",
                        "title": "Node multisource RCE",
                        "summary": "Review attacker controlled config into child_process.",
                        "vulnerability_pack": "rce",
                        "target_pack_keys": ["node"],
                        "applicable_surface_kinds": ["config", "process-exec"],
                        "source_ids": ["S0001", "S0002"],
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    result.research = generate_research_artifacts(result, seed_paths=[seed_path])
    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="research-metadata-run",
        write_specs=True,
    )
    spec = parse_brainstorm_spec(paths["rce_spec"])
    hypothesis = spec.hypotheses[0]
    intent = hypothesis_to_agent_intents(spec, hypothesis)[0]

    dynamic_spec = brainstorm_intent_to_dynamic_agent_spec(
        intent,
        program=spec.metadata["Program"],
        version=spec.metadata["AppMap run id"],
    )

    assert "research-technique:node-multisource-rce" in hypothesis.evidence
    assert "[s0001]" not in hypothesis.evidence
    assert "[s0002]" not in hypothesis.evidence
    assert dynamic_spec.brainstorm_metadata["appmap_research_technique_ids"] == ["node-multisource-rce"]
    assert dynamic_spec.brainstorm_metadata["appmap_research_source_ids"] == ["s0001", "s0002"]
    assert dynamic_spec.brainstorm_metadata["appmap_research_citations"] == ["[s0001]", "[s0002]"]
    assert '"appmap_research_technique_ids": [' in dynamic_spec.agent_prompt_template
    assert '"appmap_research_citations": [' in dynamic_spec.agent_prompt_template


def test_app_mapper_research_seed_jsonl_preserves_valid_rows_and_records_normalization_errors(
    tmp_path: Path,
) -> None:
    result = _one_candidate_result(tmp_path)
    jsonl_seed = tmp_path / "research-seed.jsonl"
    jsonl_seed.write_text(
        "\n".join(
            [
                json.dumps({"type": "source", "id": "S0001", "title": "Valid source"}),
                "{bad json",
                json.dumps(
                    {
                        "type": "technique",
                        "id": "duplicate-technique",
                        "title": "First duplicate",
                        "summary": "Valid JSONL technique should survive a bad neighboring row.",
                        "vulnerability_pack": "rce",
                        "target_pack_keys": ["node"],
                        "applicable_surface_kinds": ["config"],
                        "source_ids": ["S0001"],
                    }
                ),
                json.dumps(
                    {
                        "type": "technique",
                        "id": "duplicate-technique",
                        "title": "Second duplicate",
                        "summary": "Duplicate IDs should be made unique.",
                        "vulnerability_pack": "rce",
                        "target_pack_keys": ["node"],
                        "applicable_surface_kinds": ["config"],
                        "source_ids": ["missing-source"],
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )
    single_technique_seed = tmp_path / "single-technique.json"
    single_technique_seed.write_text(
        json.dumps(
            {
                "type": "technique",
                "id": "single-dict-technique",
                "title": "Single dict technique",
                "summary": "A single dict root with type technique is a technique pack.",
                "vulnerability_pack": "rce",
                "target_pack_keys": ["node"],
                "applicable_surface_kinds": ["config"],
            }
        ),
        encoding="utf-8",
    )

    research = generate_research_artifacts(result, seed_paths=[jsonl_seed, single_technique_seed])

    assert research is not None
    manifest = research["manifest"]
    sources = research["sources"]
    techniques = research["technique_packs"]
    technique_ids = [technique["id"] for technique in techniques]
    duplicate_ids = [technique_id for technique_id in technique_ids if technique_id.startswith("duplicate-technique")]
    unresolved = next(technique for technique in techniques if technique["title"] == "Second duplicate")

    assert manifest["counts"]["sources"] == 1
    assert sources[0]["source_type"] == "seed"
    assert manifest["counts"]["technique_packs"] == 3
    assert manifest["counts"]["errors"] == 2
    assert any("line 2: invalid JSON" in error for error in manifest["errors"])
    assert any("references unknown source id 'missing-source'" in error for error in manifest["errors"])
    assert len(technique_ids) == len(set(technique_ids))
    assert len(duplicate_ids) == 2
    assert "single-dict-technique" in technique_ids
    assert unresolved["source_ids"] == []
    assert unresolved["citations"] == []


def test_app_mapper_research_query_normalizes_simple_words() -> None:
    query = normalize_research_query(["electron", "xss"], focus="rce", target_kind="electron-exe")

    assert query.raw_terms == ("electron", "xss")
    assert query.normalized_terms == ("electron", "xss")
    assert query.platform_candidates == ("electron",)
    assert query.vulnerability_candidates == ("xss", "rce")
    assert query.query_key == "electron-xss"
    assert "platform:electron" in query.categories
    assert "vulnerability:xss" in query.categories


def test_app_mapper_local_research_mode_writes_query_and_db_ready_fields(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)
    seed_path = tmp_path / "research-seed.json"
    seed_path.write_text(
        json.dumps(
            {
                "sources": [{"id": "S0001", "title": "Electron XSS source"}],
                "technique_packs": [
                    {
                        "id": "electron-xss-rce",
                        "title": "Electron XSS to privileged sink",
                        "summary": "Review renderer-controlled data reaching privileged execution.",
                        "vulnerability_pack": "rce",
                        "target_pack_keys": ["node"],
                        "applicable_surface_kinds": ["config"],
                        "source_ids": ["S0001"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result.research = generate_research_artifacts(
        result,
        seed_paths=[seed_path],
        research_mode="local",
        research_query_terms=["electron", "xss"],
    )
    paths = write_artifacts(result, output_root=tmp_path / "out", run_id="query-fields-run", write_specs=True)
    manifest = json.loads(paths["research_manifest"].read_text(encoding="utf-8"))
    source = json.loads(paths["research_sources"].read_text(encoding="utf-8").splitlines()[0])
    technique = json.loads(paths["research_technique_packs"].read_text(encoding="utf-8").splitlines()[0])
    run_manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    context = json.loads(paths["agent_context_c0001"].read_text(encoding="utf-8"))

    assert manifest["research_mode"] == "local"
    assert manifest["research_query"]["query_key"] == "electron-xss"
    assert manifest["validation_status"] == "unreviewed"
    assert source["research_mode"] == "local"
    assert source["research_query"] == "electron-xss"
    assert source["validation_status"] == "unreviewed"
    assert source["source_type"] == "seed"
    assert 0.0 <= source["trust_score"] <= 1.0
    assert technique["source_type"] == "technique-pack"
    assert technique["validation_status"] == "unreviewed"
    assert run_manifest["research_mode"] == "local"
    assert context["research"]["research_query"]["query_key"] == "electron-xss"
    assert context["research"]["technique_summaries"][0]["validation_status"] == "unreviewed"


def test_app_mapper_cli_auto_policy_writes_appmap_policy_metadata(tmp_path: Path) -> None:
    target = tmp_path / "electron-cli-app"
    _write(
        target / "package.json",
        '{"main":"src/main.js","dependencies":{"electron":"^30.0.0"}}',
    )
    _write(
        target / "src" / "main.js",
        """
const { BrowserWindow } = require("electron");
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");
const configPath = path.join(process.cwd(), "project.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const win = new BrowserWindow({});
child_process.exec(config.command);
""".strip(),
    )
    output_root = tmp_path / "out"

    assert (
        app_mapper_main(
            [
                "electron target",
                str(target),
                "--run-id",
                "policy-cli-run",
                "--output-root",
                str(output_root),
                "--hunting-policy",
                "auto",
                "--write-specs",
            ]
        )
        == 0
    )

    run_root = output_root / "appmap" / "policy-cli-run"
    manifest = json.loads((run_root / "manifest.json").read_text(encoding="utf-8"))
    spec_text = (run_root / "generated_specs" / "rce-spec.md").read_text(encoding="utf-8")
    context = json.loads(next((run_root / "agent_contexts").glob("*.json")).read_text(encoding="utf-8"))

    assert manifest["hunting_policy_id"] == "electron-application-first-loose"
    assert context["hunting_policy_id"] == "electron-application-first-loose"
    assert "- Hunting policy: electron-application-first-loose" in spec_text


def test_app_mapper_default_research_writes_no_artifacts_without_flags(tmp_path: Path) -> None:
    target = tmp_path / "python-app"
    _write(
        target / "runner.py",
        """
import argparse
import subprocess

parser = argparse.ArgumentParser()
args = parser.parse_args()
subprocess.run(args.command, shell=True)
""".strip(),
    )
    output_root = tmp_path / "out"

    assert (
        app_mapper_main(
            [
                "python target",
                str(target),
                "--run-id",
                "no-research-run",
                "--output-root",
                str(output_root),
                "--write-specs",
            ]
        )
        == 0
    )

    assert not (output_root / "appmap" / "no-research-run" / "research").exists()


def test_app_mapper_seed_research_uses_local_provider_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _one_candidate_result(tmp_path)
    seed_path = tmp_path / "research-seed.json"
    seed_path.write_text(
        json.dumps({"sources": [{"id": "seed-source", "title": "Seed", "summary": "Local only."}]}),
        encoding="utf-8",
    )

    def fail_network(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("seed provider must not use network")

    monkeypatch.setattr("agents.appmap_research.urllib.request.urlopen", fail_network)

    research = generate_research_artifacts(result, seed_paths=[seed_path])

    assert research is not None
    assert research["manifest"]["provider"] == "local-seed"
    assert research["manifest"]["network_access"] is False
    assert research["manifest"]["counts"]["sources"] == 1


def test_app_mapper_research_online_default_local_provider_writes_empty_artifacts_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "python-app"
    _write(
        target / "runner.py",
        """
import argparse
import os
import subprocess

parser = argparse.ArgumentParser()
args = parser.parse_args()
root = os.getcwd()
subprocess.run(args.command, shell=True)
""".strip(),
    )
    output_root = tmp_path / "out"

    def fail_network(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("default local provider must not use network")

    monkeypatch.setattr("agents.appmap_research.urllib.request.urlopen", fail_network)

    assert (
        app_mapper_main(
            [
                "python target",
                str(target),
                "--run-id",
                "research-online-run",
                "--output-root",
                str(output_root),
                "--write-specs",
                "--research-online",
            ]
        )
        == 0
    )

    research_root = output_root / "appmap" / "research-online-run" / "research"
    manifest = json.loads((research_root / "research_manifest.json").read_text(encoding="utf-8"))
    assert manifest["provider"] == "local-seed"
    assert manifest["online_requested"] is True
    assert manifest["network_access"] is False
    assert manifest["counts"]["sources"] == 0
    assert (research_root / "sources.jsonl").read_text(encoding="utf-8") == ""


def test_app_mapper_web_fetch_provider_implies_online_for_web_mode(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)
    fetched: list[str] = []

    def fake_open(request: object, timeout: float = 0.0) -> "_FakeWebResponse":
        fetched.append(getattr(request, "full_url"))
        return _FakeWebResponse(getattr(request, "full_url"), b"<title>Implicit online</title>")

    research = generate_research_artifacts(
        result,
        research_mode="web",
        source_urls=["https://research.example/appmap.html"],
        provider=WebFetchResearchProvider(opener=fake_open),
    )

    assert fetched == ["https://research.example/appmap.html"]
    assert research["manifest"]["research_mode"] == "web"
    assert research["manifest"]["online_requested"] is True
    assert research["manifest"]["network_access"] is True


def test_app_mapper_cli_web_research_mode_implies_online_without_extra_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "python-app"
    _write(
        target / "runner.py",
        """
import argparse
import subprocess

parser = argparse.ArgumentParser()
args = parser.parse_args()
subprocess.run(args.command, shell=True)
""".strip(),
    )
    output_root = tmp_path / "out"
    fetched: list[str] = []

    def fake_open(request: object, timeout: float = 0.0) -> "_FakeWebResponse":
        fetched.append(getattr(request, "full_url"))
        return _FakeWebResponse(getattr(request, "full_url"), b"<title>CLI Web Research</title>")

    monkeypatch.setattr(
        "agents.app_mapper._build_research_provider",
        lambda _provider_key: WebFetchResearchProvider(opener=fake_open),
    )

    assert (
        app_mapper_main(
            [
                "python target",
                str(target),
                "--run-id",
                "cli-web-research-run",
                "--output-root",
                str(output_root),
                "--write-specs",
                "--research-mode",
                "web",
                "--research-source-url",
                "https://research.example/cli-web",
            ]
        )
        == 0
    )

    research_root = output_root / "appmap" / "cli-web-research-run" / "research"
    manifest = json.loads((research_root / "research_manifest.json").read_text(encoding="utf-8"))
    assert fetched == ["https://research.example/cli-web"]
    assert manifest["provider"] == "web-fetch"
    assert manifest["research_mode"] == "web"
    assert manifest["online_requested"] is True
    assert manifest["network_access"] is True
    assert manifest["source_urls"] == ["https://research.example/cli-web"]


class _FakeWebResponse:
    def __init__(
        self,
        url: str,
        body: bytes,
        content_type: str = "text/html",
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.url = url
        self.status = status
        self.headers = {"Content-Type": content_type, **(headers or {})}
        self._body = body

    def __enter__(self) -> "_FakeWebResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def read(self, limit: int = -1) -> bytes:
        if limit is None or limit < 0:
            return self._body
        return self._body[:limit]


def test_app_mapper_web_fetch_provider_records_sources_and_explicit_json_techniques(
    tmp_path: Path,
) -> None:
    result = _one_candidate_result(tmp_path)
    fetched: list[str] = []

    metadata_body = json.dumps(
        {
            "sources": [
                {
                    "id": "SRC1",
                    "title": "Explicit JSON source",
                    "url": "https://research.example/source",
                    "summary": "Explicit source metadata can be cited.",
                }
            ],
            "technique_packs": [
                {
                    "id": "json-technique",
                    "title": "JSON supplied technique",
                    "summary": "Review config data reaching child_process.",
                    "vulnerability_pack": "rce",
                    "target_pack_keys": ["node"],
                    "applicable_surface_kinds": ["config", "process-exec"],
                    "source_ids": ["SRC1"],
                }
            ],
        },
        sort_keys=True,
    ).encode("utf-8")
    html_body = b"<html><head><title>HTML source</title></head><body>Plain prose must not become a technique.</body></html>"

    def fake_open(request: object, timeout: float = 0.0) -> _FakeWebResponse:
        assert timeout == 5.0
        url = getattr(request, "full_url")
        fetched.append(url)
        if url.endswith("/metadata.json"):
            return _FakeWebResponse(url, metadata_body, "application/json; charset=utf-8")
        return _FakeWebResponse(url, html_body, "text/html; charset=utf-8")

    provider = WebFetchResearchProvider(
        opener=fake_open,
        now=lambda: datetime(2026, 5, 6, tzinfo=timezone.utc),
    )
    result.research = generate_research_artifacts(
        result,
        research_online=True,
        research_mode="web",
        source_urls=["https://research.example/metadata.json", "https://research.example/page"],
        provider=provider,
    )

    assert fetched == ["https://research.example/metadata.json", "https://research.example/page"]
    paths = write_artifacts(result, output_root=tmp_path / "out", run_id="web-research-run", write_specs=True)
    manifest = json.loads(paths["research_manifest"].read_text(encoding="utf-8"))
    sources = [json.loads(line) for line in paths["research_sources"].read_text(encoding="utf-8").splitlines()]
    techniques = [
        json.loads(line)
        for line in paths["research_technique_packs"].read_text(encoding="utf-8").splitlines()
    ]

    assert manifest["provider"] == "web-fetch"
    assert manifest["research_mode"] == "web"
    assert manifest["network_access"] is True
    assert manifest["source_urls"] == ["https://research.example/metadata.json", "https://research.example/page"]
    assert [item["status"] for item in manifest["fetched"]] == ["ok", "ok"]
    assert manifest["counts"] == {"errors": 0, "sources": 3, "technique_packs": 1}
    assert any(source["title"] == "HTML source" and source["content_sha256"] for source in sources)
    assert techniques[0]["id"] == "json-technique"
    assert techniques[0]["source_ids"] == ["src1"]


def test_app_mapper_hybrid_research_uses_local_seed_then_explicit_web_fetch(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)
    seed_path = tmp_path / "research-seed.json"
    seed_path.write_text(
        json.dumps(
            {
                "sources": [{"id": "SRC1", "title": "Local source"}],
                "technique_packs": [
                    {
                        "id": "local-technique",
                        "title": "Local technique",
                        "summary": "Local seed applies first.",
                        "vulnerability_pack": "rce",
                        "target_pack_keys": ["node"],
                        "applicable_surface_kinds": ["config"],
                        "source_ids": ["SRC1"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    metadata_body = json.dumps(
        {
            "sources": [{"id": "SRC1", "title": "Web metadata source"}],
            "technique_packs": [
                {
                    "id": "web-technique",
                    "title": "Web technique",
                    "summary": "Explicit web metadata applies after local seed.",
                    "vulnerability_pack": "rce",
                    "target_pack_keys": ["node"],
                    "applicable_surface_kinds": ["config"],
                    "source_ids": ["SRC1"],
                }
            ],
        }
    ).encode("utf-8")
    fetched: list[str] = []

    def fake_open(request: object, timeout: float = 0.0) -> _FakeWebResponse:
        fetched.append(getattr(request, "full_url"))
        return _FakeWebResponse(getattr(request, "full_url"), metadata_body, "application/json; charset=utf-8")

    result.research = generate_research_artifacts(
        result,
        research_mode="hybrid",
        research_online=True,
        seed_paths=[seed_path],
        source_urls=["https://research.example/hybrid.json"],
        research_query_terms=["electron", "xss"],
        provider=HybridResearchProvider(opener=fake_open),
    )
    manifest = result.research["manifest"]
    source_ids = [source["id"] for source in result.research["sources"]]
    technique_ids = [technique["id"] for technique in result.research["technique_packs"]]

    assert fetched == ["https://research.example/hybrid.json"]
    assert manifest["research_mode"] == "hybrid"
    assert manifest["network_access"] is True
    assert manifest["counts"]["sources"] == 3
    assert len(source_ids) == len(set(source_ids))
    assert technique_ids == ["local-technique", "web-technique"]
    assert all(technique["research_query"] == "electron-xss" for technique in result.research["technique_packs"])


def test_app_mapper_hybrid_research_skips_web_without_online(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)

    def fail_network(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("hybrid must not fetch without --research-online")

    research = generate_research_artifacts(
        result,
        research_mode="hybrid",
        source_urls=["https://research.example/skipped"],
        provider=HybridResearchProvider(opener=fail_network),
    )

    assert research["manifest"]["provider"] == "hybrid"
    assert research["manifest"]["research_mode"] == "hybrid"
    assert research["manifest"]["network_access"] is False
    assert research["manifest"]["counts"] == {"errors": 1, "sources": 0, "technique_packs": 0}
    assert "skipped because --research-online was not set" in research["manifest"]["errors"][0]


def test_app_mapper_direct_hybrid_provider_stamps_hybrid_records(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)

    def fake_open(request: object, timeout: float = 0.0) -> _FakeWebResponse:
        return _FakeWebResponse(getattr(request, "full_url"), b"<title>Hybrid</title><p>Electron XSS notes.</p>")

    research = generate_research_artifacts(
        result,
        research_online=True,
        research_provider="hybrid",
        source_urls=["https://research.example/hybrid"],
        provider=HybridResearchProvider(opener=fake_open),
    )

    assert research["manifest"]["provider"] == "hybrid"
    assert research["manifest"]["research_mode"] == "hybrid"
    assert research["sources"][0]["research_mode"] == "hybrid"


def test_app_mapper_web_fetch_provider_records_failures_non_fatal(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)

    def failing_open(_request: object, timeout: float = 0.0) -> object:
        raise urllib.error.URLError("fixture failure")

    research = generate_research_artifacts(
        result,
        research_online=True,
        research_provider="web-fetch",
        source_urls=["https://research.example/failure", "http://127.0.0.1/local"],
        provider=WebFetchResearchProvider(opener=failing_open),
    )

    assert research is not None
    manifest = research["manifest"]
    assert manifest["network_access"] is True
    assert [item["status"] for item in manifest["fetched"]] == ["error", "rejected"]
    assert manifest["counts"] == {"errors": 2, "sources": 0, "technique_packs": 0}
    assert any("fixture failure" in error for error in manifest["errors"])
    assert any("absolute https URL" in error for error in manifest["errors"])


@pytest.mark.parametrize(
    ("location", "label"),
    [
        ("http://research.example/insecure", "https_to_http"),
        ("https://other.example/resource", "https_to_different_https"),
    ],
)
def test_app_mapper_web_fetch_provider_rejects_redirects_without_following(
    tmp_path: Path,
    location: str,
    label: str,
) -> None:
    result = _one_candidate_result(tmp_path)
    start_url = f"https://research.example/{label}"
    fetched: list[str] = []

    def fake_open(request: object, timeout: float = 0.0) -> _FakeWebResponse:
        url = getattr(request, "full_url")
        fetched.append(url)
        if url != start_url:
            raise AssertionError(f"redirect target must not be fetched: {url}")
        return _FakeWebResponse(url, b"", status=302, headers={"Location": location})

    research = generate_research_artifacts(
        result,
        research_online=True,
        research_provider="web-fetch",
        source_urls=[start_url],
        provider=WebFetchResearchProvider(opener=fake_open),
    )

    manifest = research["manifest"]
    assert fetched == [start_url]
    assert research["sources"] == []
    assert manifest["fetched"][0]["status"] == "redirect_rejected"
    assert manifest["fetched"][0]["location"] == location
    assert manifest["counts"] == {"errors": 1, "sources": 0, "technique_packs": 0}
    assert any(f"Location: {location}" in error for error in manifest["errors"])


def test_app_mapper_web_fetch_provider_rejects_too_many_source_urls_before_fetching(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)
    fetched: list[str] = []

    def fake_open(request: object, timeout: float = 0.0) -> _FakeWebResponse:
        fetched.append(getattr(request, "full_url"))
        return _FakeWebResponse(getattr(request, "full_url"), b"unused")

    with pytest.raises(ValueError, match="at most 10 URLs"):
        generate_research_artifacts(
            result,
            research_online=True,
            research_provider="web-fetch",
            source_urls=[f"https://research.example/{index}" for index in range(11)],
            provider=WebFetchResearchProvider(opener=fake_open),
        )

    assert fetched == []


def test_app_mapper_web_fetch_cache_key_excludes_fetch_timestamps(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)
    body = b"<html><head><title>Stable</title></head><body>Same content.</body></html>"

    def fake_open(request: object, timeout: float = 0.0) -> _FakeWebResponse:
        url = getattr(request, "full_url")
        return _FakeWebResponse(url, body, "text/html; charset=utf-8")

    first = generate_research_artifacts(
        result,
        research_online=True,
        research_provider="web-fetch",
        source_urls=["https://research.example/stable"],
        provider=WebFetchResearchProvider(
            opener=fake_open,
            now=lambda: datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc),
        ),
    )
    second = generate_research_artifacts(
        result,
        research_online=True,
        research_provider="web-fetch",
        source_urls=["https://research.example/stable"],
        provider=WebFetchResearchProvider(
            opener=fake_open,
            now=lambda: datetime(2026, 5, 7, 12, 0, tzinfo=timezone.utc),
        ),
    )

    assert first["manifest"]["cache_key"] == second["manifest"]["cache_key"]
    assert first["manifest"]["fetched"][0]["requested_at"] != second["manifest"]["fetched"][0]["requested_at"]
    assert first["sources"][0]["retrieved_at"] != second["sources"][0]["retrieved_at"]


def test_app_mapper_web_fetch_provider_records_byte_truncation(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)

    def fake_open(request: object, timeout: float = 0.0) -> _FakeWebResponse:
        url = getattr(request, "full_url")
        return _FakeWebResponse(url, b"0123456789ABCDEF", "text/plain; charset=utf-8")

    provider = WebFetchResearchProvider(opener=fake_open)
    provider.max_bytes = 8
    research = generate_research_artifacts(
        result,
        research_online=True,
        research_provider="web-fetch",
        source_urls=["https://research.example/large.txt"],
        provider=provider,
    )

    fetched = research["manifest"]["fetched"][0]
    assert fetched["status"] == "ok_truncated"
    assert fetched["bytes_read"] == 8
    assert fetched["truncated"] is True
    assert "truncated after 8 bytes" in fetched["error"]
    assert research["sources"][0]["content_bytes"] == 8


def test_app_mapper_cli_research_option_errors_before_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_mapping(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("invalid research options must fail before target mapping")

    monkeypatch.setattr("agents.app_mapper.map_application", fail_mapping)

    with pytest.raises(SystemExit, match="--research-source-url requires --research-mode web\\|hybrid or --research-provider web-fetch"):
        app_mapper_main(
            [
                "demo",
                str(tmp_path / "missing-target"),
                "--research-source-url",
                "https://research.example/source",
            ]
        )

    with pytest.raises(SystemExit, match="--research-mode web requires at least one --research-source-url"):
        app_mapper_main(
            [
                "demo",
                str(tmp_path / "missing-target"),
                "--research-mode",
                "web",
            ]
        )

    for mode_arg in (["--research-mode", "local"], ["--research-mode=local"]):
        with pytest.raises(SystemExit, match="--research-provider is deprecated"):
            app_mapper_main(
                [
                    "demo",
                    str(tmp_path / "missing-target"),
                    *mode_arg,
                    "--research-provider",
                    "web-fetch",
                    "--research-online",
                    "--research-source-url",
                    "https://research.example/source",
                ]
            )


def test_appmap_context_linkage_rejects_duplicate_and_multi_candidate_evidence(tmp_path: Path) -> None:
    result = _two_candidate_result(tmp_path)
    spec_path = tmp_path / "generated_specs" / "rce-spec.md"
    spec_path.parent.mkdir(parents=True)
    spec_text = render_rce_spec(result, run_id="strict-run")

    duplicate_text = spec_text.replace("  - appmap-C0001", "  - appmap-C0001\n  - appmap-C0001", 1)
    spec_path.write_text(duplicate_text, encoding="utf-8")
    duplicate_spec = parse_brainstorm_spec(spec_path)
    with pytest.raises(ValueError, match="duplicate candidate evidence"):
        write_agent_contexts(
            result,
            run_root=tmp_path,
            run_id="strict-run",
            spec_path=spec_path,
            parsed_spec=duplicate_spec,
        )

    multi_text = spec_text.replace("  - appmap-C0001", "  - appmap-C0001\n  - appmap-C0002", 1)
    spec_path.write_text(multi_text, encoding="utf-8")
    multi_spec = parse_brainstorm_spec(spec_path)
    with pytest.raises(ValueError, match="aggregates multiple candidate IDs"):
        write_agent_contexts(
            result,
            run_root=tmp_path,
            run_id="strict-run",
            spec_path=spec_path,
            parsed_spec=multi_spec,
        )


def test_appmap_context_linkage_rejects_missing_candidate_evidence(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)
    spec_path = tmp_path / "generated_specs" / "rce-spec.md"
    spec_path.parent.mkdir(parents=True)
    spec_text = render_rce_spec(result, run_id="missing-run")
    spec_path.write_text(spec_text.replace("  - appmap-C0001\n", "", 1), encoding="utf-8")
    spec = parse_brainstorm_spec(spec_path)

    with pytest.raises(ValueError, match="missing appmap-C#### candidate evidence"):
        write_agent_contexts(
            result,
            run_root=tmp_path,
            run_id="missing-run",
            spec_path=spec_path,
            parsed_spec=spec,
        )


def test_appmap_context_writes_one_packet_per_suggested_agent(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)
    spec_path = tmp_path / "generated_specs" / "rce-spec.md"
    spec_path.parent.mkdir(parents=True)
    spec_text = render_rce_spec(result, run_id="multi-agent-run")
    first_agent = parse_brainstorm_spec(_write_temp_spec(spec_path, spec_text)).hypotheses[0].suggested_agents[0]
    second_agent = "appmap-second-agent"
    spec_text = spec_text.replace(f"  - {first_agent}", f"  - {first_agent}\n  - {second_agent}", 1)
    spec_path.write_text(spec_text, encoding="utf-8")
    spec = parse_brainstorm_spec(spec_path)

    context_paths = write_agent_contexts(
        result,
        run_root=tmp_path,
        run_id="multi-agent-run",
        spec_path=spec_path,
        parsed_spec=spec,
    )

    assert len(context_paths) == 2
    names = {path.name for path in context_paths}
    assert names == {f"H001-C0001-{first_agent}.json", f"H001-C0001-{second_agent}.json"}
    packets = [json.loads(path.read_text(encoding="utf-8")) for path in context_paths]
    assert {packet["hypothesis_linkage"]["agent_key"] for packet in packets} == {
        first_agent,
        second_agent,
    }


def test_brainstorm_runtime_adapter_uses_appmap_packet_instead_of_full_spec_context(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)
    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="adapter-run",
        write_specs=True,
    )
    spec = parse_brainstorm_spec(paths["rce_spec"])
    intent = hypothesis_to_agent_intents(spec, spec.hypotheses[0])[0]

    dynamic_spec = brainstorm_intent_to_dynamic_agent_spec(
        intent,
        program=spec.metadata["Program"],
        version=spec.metadata["AppMap run id"],
    )

    assert "Use this AppMap context packet as the complete assignment context" in dynamic_spec.agent_prompt_template
    assert "Target mental model:" not in dynamic_spec.agent_prompt_template
    assert "Impact primitives:" not in dynamic_spec.agent_prompt_template
    assert "appmap_context_packet" in dynamic_spec.agent_prompt_template
    assert dynamic_spec.brainstorm_metadata["appmap_candidate_id"] == "C0001"
    assert dynamic_spec.brainstorm_metadata["appmap_context_packet"].endswith(".json")



def test_app_mapper_policy_metadata_inherits_into_manifest_context_and_brainstorm_prompt(tmp_path: Path) -> None:
    result = _one_candidate_electron_app_entry_result(tmp_path)
    policy = resolve_hunting_policy(
        "auto",
        target_kind=result.profile.target_kind,
        target_path=result.profile.target_path,
    )

    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="policy-run",
        write_specs=True,
        hunting_policy=policy,
    )
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    context = json.loads(paths["agent_context_c0001"].read_text(encoding="utf-8"))
    spec_text = paths["rce_spec"].read_text(encoding="utf-8")
    spec = parse_brainstorm_spec(paths["rce_spec"])
    intent = hypothesis_to_agent_intents(spec, spec.hypotheses[0])[0]
    dynamic_spec = brainstorm_intent_to_dynamic_agent_spec(
        intent,
        program=spec.metadata["Program"],
        version=spec.metadata["AppMap run id"],
    )

    assert manifest["hunting_policy_id"] == "electron-application-first-loose"
    assert manifest["hunting_policy"]["hunt_posture"] == "application-first-loose"
    assert "ipc" in manifest["hunting_policy"]["deprioritize"]
    assert context["hunting_policy_id"] == "electron-application-first-loose"
    assert context["hunting_policy"]["id"] == "electron-application-first-loose"
    assert context["candidate"]["policy"]["policy_id"] == "electron-application-first-loose"
    assert context["candidate"]["policy"]["reportability"] == "submit"
    assert context["candidate"]["policy"]["finding_role"] == "entry"
    assert context["candidate"]["policy"]["entry_status"] == "proven"
    summary_text = paths["summary"].read_text(encoding="utf-8")
    assert "--hunting-policy electron-application-first-loose" in summary_text
    assert "- Hunting policy: electron-application-first-loose" in spec_text
    assert "- Hunting posture: application-first-loose" in spec_text
    assert dynamic_spec.brainstorm_metadata["hunting_policy_id"] == "electron-application-first-loose"
    assert dynamic_spec.brainstorm_metadata["hunting_policy"]["id"] == "electron-application-first-loose"
    assert '"hunting_policy_id": "electron-application-first-loose"' in dynamic_spec.agent_prompt_template


def test_app_mapper_policy_on_holds_raw_ipc_candidate_and_preserves_raw_surfaces_and_flows(tmp_path: Path) -> None:
    result = _one_candidate_electron_result(tmp_path)
    raw_surface_count = len(result.surfaces)
    raw_flow_count = len(result.flows)
    policy = resolve_hunting_policy(
        "auto",
        target_kind=result.profile.target_kind,
        target_path=result.profile.target_path,
    )

    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="policy-held-run",
        write_specs=True,
        hunting_policy=policy,
    )
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    rejected = [
        json.loads(line)
        for line in paths["rejected_candidates"].read_text(encoding="utf-8").splitlines()
        if line
    ]
    surfaces = [line for line in paths["surfaces"].read_text(encoding="utf-8").splitlines() if line]
    flows = [line for line in paths["flows"].read_text(encoding="utf-8").splitlines() if line]

    assert manifest["counts"]["surfaces"] == raw_surface_count
    assert manifest["counts"]["flows"] == raw_flow_count
    assert manifest["counts"]["candidates"] == 0
    assert manifest["counts"]["rejected_candidates"] >= 1
    assert len(surfaces) == raw_surface_count
    assert len(flows) == raw_flow_count
    assert "rce_spec" not in paths
    assert "agent_contexts" not in paths
    held = next(item for item in rejected if item.get("candidate_id") == "C0001")
    assert held["policy_id"] == "electron-application-first-loose"
    assert held["reportability"] == "hold_for_chain"
    assert held["hold_for_chain"] is True
    assert held["finding_role"] == "chain"
    assert held["entry_status"] == "missing"
    assert held["policy"]["reason_code"] == "deprioritized-source-without-app-entry"


def test_app_mapper_summary_preserves_custom_policy_config_in_handoff_command(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)
    policy_config = tmp_path / "policy configs" / "custom policy.json"
    policy_config.parent.mkdir()
    policy_config.write_text('{"id":"custom-policy","enabled":true}', encoding="utf-8")
    policy = resolve_hunting_policy("custom-policy", target_path=result.profile.target_path, policy_config=policy_config)

    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="custom-policy-summary-run",
        write_specs=True,
        hunting_policy=policy,
        policy_config=policy_config,
    )
    summary_text = paths["summary"].read_text(encoding="utf-8")
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=tmp_path / "brainstorm",
        run_id="custom-policy-summary-run",
    )
    planned_command = plan_promoted_handoff_command(promotion.spec_paths[0], selected_hypothesis="H001")

    summary_args = shlex.split(_suggested_summary_command(summary_text))
    planned_args = shlex.split(planned_command)

    assert manifest["hunting_policy_config"] == str(policy_config)
    assert summary_args[summary_args.index("--hunting-policy") + 1] == "custom-policy"
    assert summary_args[summary_args.index("--policy-config") + 1] == str(policy_config)
    assert planned_args[planned_args.index("--hunting-policy") + 1] == "custom-policy"
    assert planned_args[planned_args.index("--policy-config") + 1] == str(policy_config)


def test_app_mapper_summary_preserves_named_config_policy_path_in_handoff_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _one_candidate_result(tmp_path)
    config_dir = tmp_path / "policies"
    config_dir.mkdir()
    policy_config = config_dir / "strict-program-scope.json"
    policy_config.write_text('{"id":"strict-program-scope","enabled":true}', encoding="utf-8")
    monkeypatch.setattr(hunting_policy_module, "DEFAULT_POLICY_CONFIG_DIR", config_dir)
    policy = resolve_hunting_policy("strict-program-scope", target_path=result.profile.target_path)

    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="named-policy-summary-run",
        write_specs=True,
        hunting_policy=policy,
    )
    summary_text = paths["summary"].read_text(encoding="utf-8")
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    promotion = promote_appmap_handoff(
        paths,
        brainstorm_root=tmp_path / "brainstorm",
        run_id="named-policy-summary-run",
    )
    planned_command = plan_promoted_handoff_command(promotion.spec_paths[0], selected_hypothesis="H001")

    summary_args = shlex.split(_suggested_summary_command(summary_text))
    planned_args = shlex.split(planned_command)

    assert manifest["hunting_policy_config"] == str(policy_config)
    assert summary_args[summary_args.index("--hunting-policy") + 1] == "strict-program-scope"
    assert summary_args[summary_args.index("--policy-config") + 1] == str(policy_config)
    assert planned_args[planned_args.index("--hunting-policy") + 1] == "strict-program-scope"
    assert planned_args[planned_args.index("--policy-config") + 1] == str(policy_config)


def test_app_mapper_policy_off_preserves_legacy_artifact_metadata(tmp_path: Path) -> None:
    result = _one_candidate_electron_result(tmp_path)
    policy_config = tmp_path / "disabled-policy-config.json"
    policy_config.write_text('{"id":"custom-policy","enabled":true}', encoding="utf-8")
    policy = resolve_hunting_policy(
        "off",
        target_kind=result.profile.target_kind,
        target_path=result.profile.target_path,
        policy_config=policy_config,
    )

    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="policy-off-run",
        write_specs=True,
        hunting_policy=policy,
        policy_config=policy_config,
    )
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    context = json.loads(paths["agent_context_c0001"].read_text(encoding="utf-8"))
    spec_text = paths["rce_spec"].read_text(encoding="utf-8")
    summary_text = paths["summary"].read_text(encoding="utf-8")

    assert manifest["counts"]["candidates"] == 1
    assert "hunting_policy" not in manifest
    assert "hunting_policy_id" not in manifest
    assert "policy" not in context["candidate"]
    assert "hunting_policy" not in context
    assert "hunting_policy_id" not in context
    assert "- Hunting policy:" not in spec_text
    assert "--hunting-policy" not in summary_text
    assert "--policy-config" not in summary_text

    stale_manifest = dict(manifest)
    stale_manifest["hunting_policy_config"] = str(policy_config)
    paths["manifest"].write_text(json.dumps(stale_manifest, sort_keys=True), encoding="utf-8")
    promotion = promote_appmap_handoff(paths, brainstorm_root=tmp_path / "brainstorm", run_id="policy-off-run")
    planned_command = plan_promoted_handoff_command(promotion.spec_paths[0], selected_hypothesis="H001")
    assert "--hunting-policy" not in planned_command
    assert "--policy-config" not in planned_command


def test_brainstorm_runtime_adapter_handles_mixed_case_appmap_agent_key(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)
    spec_path = tmp_path / "generated_specs" / "rce-spec.md"
    spec_path.parent.mkdir(parents=True)
    spec_text = render_rce_spec(result, run_id="mixed-case-run")
    original_agent = parse_brainstorm_spec(_write_temp_spec(spec_path, spec_text)).hypotheses[0].suggested_agents[0]
    mixed_agent = "AppMapAgent"
    spec_text = spec_text.replace(f"  - {original_agent}", f"  - {mixed_agent}", 1)
    spec_text = spec_text.replace(
        f"appmap-context:H001:C0001:{original_agent}",
        f"appmap-context:H001:C0001:{mixed_agent}",
        1,
    )
    spec_path.write_text(spec_text, encoding="utf-8")
    spec = parse_brainstorm_spec(spec_path)
    context_paths = write_agent_contexts(
        result,
        run_root=tmp_path,
        run_id="mixed-case-run",
        spec_path=spec_path,
        parsed_spec=spec,
    )
    assert [path.name for path in context_paths] == ["H001-C0001-appmapagent.json"]

    intent = hypothesis_to_agent_intents(spec, spec.hypotheses[0])[0]
    dynamic_spec = brainstorm_intent_to_dynamic_agent_spec(
        intent,
        program=spec.metadata["Program"],
        version=spec.metadata["AppMap run id"],
    )

    assert "Use this AppMap context packet as the complete assignment context" in dynamic_spec.agent_prompt_template
    assert dynamic_spec.brainstorm_metadata["brainstorm_agent_key"] == mixed_agent
    assert dynamic_spec.brainstorm_metadata["appmap_candidate_id"] == "C0001"


def test_non_appmap_spec_can_reference_appmap_like_evidence_without_packet(tmp_path: Path) -> None:
    spec_path = tmp_path / "brainstorm" / "spec.md"
    spec_path.parent.mkdir(parents=True)
    spec_path.write_text(
        """# Brainstorm Spec: Generic AppMap Reference

## Metadata
- Program: demo
- Family: web
- Lane: source
- Target kind: node
- Target path: .
- Created: 2026-05-04
- Status: active

## Target mental model
This is a normal hand-authored spec that mentions a legacy AppMap-looking artifact.

## Impact primitives
### P001 - Historical artifact
- Source: old report
- Impact: may inform a manual review
- Evidence: appmap-C0001
- Status: active

## Hypotheses
### H001 - Manual review should keep normal context
- Status: untested
- Priority: medium
- Surface: manual-review
- Entry point: operator supplied report
- Expected chain: report -> reviewer -> finding
- Suggested agents:
  - ManualAgent
- Focus files:
  - .
- Tags: manual, appmap-reference
- Evidence:
  - appmap-C0001

## Coverage log
| Hypothesis | Agent | Status | Result | Linked FIDs | Run ID | Notes |
|---|---|---|---|---|---|---|
""",
        encoding="utf-8",
    )
    spec = parse_brainstorm_spec(spec_path, validate_paths=False)
    intent = hypothesis_to_agent_intents(spec, spec.hypotheses[0])[0]

    dynamic_spec = brainstorm_intent_to_dynamic_agent_spec(intent, program="demo", version="manual")

    assert "Use this AppMap context packet as the complete assignment context" not in dynamic_spec.agent_prompt_template
    assert "Target mental model:" in dynamic_spec.agent_prompt_template
    assert "appmap_context_packet" not in dynamic_spec.brainstorm_metadata

def test_run_id_traversal_is_rejected(tmp_path: Path) -> None:
    result = _one_candidate_result(tmp_path)

    with pytest.raises(ValueError, match="run_id must"):
        write_artifacts(
            result,
            output_root=tmp_path / "out",
            run_id="../escape",
            write_specs=True,
        )
    assert validate_run_id("safe.Run_123-abc") == "safe.Run_123-abc"


def test_synthetic_canva_electron_smoke_spec_remains_parser_valid(tmp_path: Path) -> None:
    target = tmp_path / "canva-synthetic"
    _write(
        target / "package.json",
        """
{
  "main": "src/main.js",
  "dependencies": {
    "electron": "^30.0.0"
  }
}
""".strip(),
    )
    _write(
        target / "src" / "main.js",
        """
const { ipcMain } = require("electron");
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");

ipcMain.handle("export:run", async (_event, project) => {
  const configPath = path.join(process.cwd(), project.config);
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  return child_process.exec(config.command);
});
""".strip(),
    )

    result = map_application("Canva synthetic", target, target_kind="electron-exe")
    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="canva-smoke",
        write_specs=True,
    )

    spec = parse_brainstorm_spec(paths["rce_spec"])

    assert spec.metadata["Program"] == "canva-synthetic"
    assert spec.hypotheses
    assert list((paths["agent_contexts"]).glob("*.json"))


def test_generated_agent_key_is_stable_and_bounded_for_long_program_names(tmp_path: Path) -> None:
    target = tmp_path / "python-app"
    _write(
        target / "runner.py",
        """
import argparse
import os
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--command")
args = parser.parse_args()

root = os.getcwd()
subprocess.run(args.command, shell=True)
""".strip(),
    )
    program = "Very Long Program Name " * 12

    first = map_application(program, target)
    second = map_application(program, target)
    first_spec = parse_brainstorm_spec(
        _write_spec(tmp_path / "first.md", first, run_id="stable-run"),
        validate_paths=False,
    )
    second_spec = parse_brainstorm_spec(
        _write_spec(tmp_path / "second.md", second, run_id="stable-run"),
        validate_paths=False,
    )
    first_key = first_spec.hypotheses[0].suggested_agents[0]
    second_key = second_spec.hypotheses[0].suggested_agents[0]

    assert first_key == second_key
    assert len(first_key) <= 64


def test_generated_spec_converts_to_brainstorm_intents_and_profiles_without_running_agents(tmp_path: Path) -> None:
    target = tmp_path / "python-app"
    _write(
        target / "runner.py",
        """
import argparse
import os
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--config")
args = parser.parse_args()

config_path = os.getcwd() + "/" + args.config
subprocess.run(config_path, shell=True)
""".strip(),
    )

    result = map_application("python target", target)
    paths = write_artifacts(
        result,
        output_root=tmp_path / "out",
        run_id="profile-smoke",
        write_specs=True,
    )
    spec = parse_brainstorm_spec(paths["rce_spec"])
    hypothesis = spec.hypotheses[0]
    intent = hypothesis_to_agent_intents(spec, hypothesis)[0]
    dynamic_spec = brainstorm_intent_to_dynamic_agent_spec(
        intent,
        program=spec.metadata["Program"],
        version=spec.metadata["AppMap run id"],
    )
    profile = brainstorm_intent_to_zero_day_profile(
        intent,
        program=spec.metadata["Program"],
        version=spec.metadata["AppMap run id"],
    )

    assert dynamic_spec.key == hypothesis.suggested_agents[0] == intent.agent_key == profile.key
    assert dynamic_spec.focus_files_glob == hypothesis.focus_files_glob == list(profile.focus_globs)
    assert intent.expected_chain == hypothesis.expected_chain
    assert dynamic_spec.patterns[0] == hypothesis.expected_chain
    assert dynamic_spec.brainstorm_metadata["brainstorm_agent_key"] == intent.agent_key
    assert profile.brainstorm_metadata["expected_chain"] == hypothesis.expected_chain
    assert profile.brainstorm_metadata["hypothesis_id"] == hypothesis.id


def test_app_mapper_packs_are_extensible_without_core_language_branches(tmp_path: Path) -> None:
    target = tmp_path / "demo-app"
    _write(target / "demo.manifest", "demo framework\n")
    _write(
        target / "src" / "flow.demo",
        """
input = externalConfig()
boundary = projectWorkspace()
run(input)
""".strip(),
    )

    original_target_packs = dict(TARGET_PACKS)
    original_vuln_packs = dict(VULNERABILITY_PACKS)

    def render_demo_spec(result, run_id: str) -> str:
        candidate = result.candidates[0]
        focus_files = sorted(
            {
                str(candidate["source"]["file"]),
                str(candidate["boundary"]["file"]),
                str(candidate["sink"]["file"]),
            }
        )
        return "\n".join(
            [
                "# Brainstorm Spec: demo target AppMap Demo",
                "",
                "## Metadata",
                "- Program: demo-target",
                "- Family: appmap",
                "- Lane: static",
                f"- Target kind: {result.profile.target_kind}",
                "- Target path: .",
                "- Created: 2026-05-04",
                "- Status: active",
                f"- AppMap run id: {run_id}",
                "",
                "## Target mental model",
                f"Custom Pack Renderer handled {result.focus}.",
                "",
                "## Impact primitives",
                "### P001 - Demo sink",
                "- Source: demo external config source",
                "- Impact: custom renderer controls this output",
                f"- Evidence: appmap-{candidate['id']}",
                "- Status: active",
                "",
                "## Hypotheses",
                "### H001 - Demo custom renderer",
                "Can demo framework input reach the demo sink?",
                "- Status: untested",
                "- Priority: high",
                f"- Surface: appmap-{candidate['surface_id']}-config",
                "- Entry point: demo external config source (project-controlled)",
                "- Expected chain: config source -> project-boundary boundary -> process-exec sink",
                "- Suggested agents:",
                "  - demo-appmap-agent",
                "- Focus files:",
                *[f"  - {path}" for path in focus_files],
                "- Tags: demo-rce, appmap, static",
                "- Evidence:",
                f"  - appmap-{candidate['id']}",
                f"- Notes: Custom Pack Renderer run {run_id}",
                "",
                "## Coverage log",
                "| Hypothesis | Agent | Status | Result | Linked FIDs | Run ID | Notes |",
                "|---|---|---|---|---|---|---|",
                "",
            ]
        )

    try:
        register_target_pack(
            TargetPack(
                key="demo-framework",
                aliases=("demo-framework",),
                file_extensions=(".demo",),
                manifest_names=("demo.manifest",),
                detect=lambda target_path, _languages: TargetDetection(
                    detected_kind="demo-framework",
                    frameworks=("demo-framework",),
                    manifests=("demo.manifest",),
                    confidence_bonus=0.2,
                )
                if (target_path / "demo.manifest").is_file()
                else None,
                source_patterns_for_file=lambda path: (
                    PatternSpec(
                        "demo-external-config",
                        re.compile(r"externalConfig", re.IGNORECASE),
                        "source",
                        "config",
                        "demo external config source",
                        "project-controlled",
                        "medium",
                        0.8,
                    ),
                )
                if path.suffix == ".demo"
                else (),
                boundary_patterns_for_file=lambda path: (
                    PatternSpec(
                        "demo-project-boundary",
                        re.compile(r"projectWorkspace", re.IGNORECASE),
                        "boundary",
                        "project-boundary",
                        "demo project boundary",
                        "project-controlled",
                        "medium",
                        0.8,
                    ),
                )
                if path.suffix == ".demo"
                else (),
            )
        )
        register_vulnerability_pack(
            VulnerabilityPack(
                key="demo-rce",
                sink_patterns_for_file=lambda path: (
                    PatternSpec(
                        "demo-run",
                        re.compile(r"\brun\(", re.IGNORECASE),
                        "sink",
                        "process-exec",
                        "demo process execution sink",
                        "privileged-local",
                        "unknown",
                        0.9,
                    ),
                )
                if path.suffix == ".demo"
                else (),
                transform_patterns_for_file=lambda _path: (),
                build_flows=build_rce_flows,
                render_spec=render_demo_spec,
            )
        )

        result = map_application("demo target", target, focus="demo-rce")
        paths = write_artifacts(
            result,
            output_root=tmp_path / "out",
            run_id="demo-run",
            write_specs=True,
        )

        assert result.profile.target_kind == "demo-framework"
        assert "demo-framework" in result.profile.frameworks
        assert result.candidates
        assert result.candidates[0]["sink"]["kind"] == "process-exec"
        assert paths["spec"].name == "demo-rce-spec.md"
        assert paths["demo_rce_spec"] == paths["spec"]
        assert "rce_spec" not in paths
        spec_text = paths["spec"].read_text(encoding="utf-8")
        assert "Custom Pack Renderer handled demo-rce." in spec_text
        assert "Custom Pack Renderer run demo-run" in spec_text
        context_path = paths[f"agent_context_{result.candidates[0]['id'].lower()}"]
        context_text = context_path.read_text(encoding="utf-8")
        context = json.loads(context_text)
        assert context["active_target_packs"] == ["demo-framework", "config"]
        assert context["active_vulnerability_pack"] == "demo-rce"
        assert context["hypothesis_linkage"]["agent_key"] == "demo-appmap-agent"
        assert "electron" not in context_text.lower()
    finally:
        TARGET_PACKS.clear()
        TARGET_PACKS.update(original_target_packs)
        VULNERABILITY_PACKS.clear()
        VULNERABILITY_PACKS.update(original_vuln_packs)


def _write_spec(path: Path, result, *, run_id: str) -> Path:
    from agents.app_mapper import render_rce_spec

    path.write_text(render_rce_spec(result, run_id=run_id), encoding="utf-8")
    return path


def _write_temp_spec(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _one_candidate_result(tmp_path: Path):
    target = tmp_path / "one-candidate"
    _write(
        target / "runner.js",
        """
const fs = require("fs");
const path = require("path");
const child_process = require("child_process");

const configPath = path.join(process.cwd(), "project.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
child_process.exec(config.command);
""".strip(),
    )
    return map_application("one candidate", target, target_kind="node")


def _one_candidate_electron_result(tmp_path: Path):
    target = tmp_path / "one-candidate-electron"
    _write(
        target / "package.json",
        """
{
  "main": "src/main.js",
  "dependencies": {
    "electron": "^30.0.0"
  }
}
""".strip(),
    )
    _write(
        target / "src" / "main.js",
        """
const { ipcMain } = require("electron");
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");

ipcMain.handle("run-project-command", async () => {
  const configPath = path.join(process.cwd(), "project.json");
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  return child_process.exec(config.command);
});
""".strip(),
    )
    return map_application("one candidate electron", target, target_kind="auto")


def _one_candidate_electron_app_entry_result(tmp_path: Path):
    target = tmp_path / "one-candidate-electron-app-entry"
    _write(
        target / "package.json",
        """
{
  "main": "src/main.js",
  "dependencies": {
    "electron": "^30.0.0"
  }
}
""".strip(),
    )
    _write(
        target / "src" / "main.js",
        """
const { BrowserWindow } = require("electron");
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");

const configPath = path.join(process.cwd(), "project.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const win = new BrowserWindow({});
child_process.exec(config.command);
""".strip(),
    )
    return map_application("one candidate electron app entry", target, target_kind="auto")


def _two_candidate_result(tmp_path: Path):
    target = tmp_path / "two-candidate"
    for name in ("first.js", "second.js"):
        _write(
            target / name,
            f"""
const fs = require("fs");
const path = require("path");
const child_process = require("child_process");

const configPath = path.join(process.cwd(), "{name}.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
child_process.exec(config.command);
""".strip(),
        )
    return map_application("two candidate", target, target_kind="node")


def test_appmap_promoted_handoff_to_zero_day_report_pipeline_is_non_live_e2e(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_shared = Path.home() / "Shared"
    fake_home = tmp_path / "fake-home"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))

    program = "appmap-e2e"
    run_id = "e2e-run"
    shared_root = tmp_path / "Shared"
    lane_root = shared_root / "binaries" / program / "exe"
    target = lane_root / "input" / "demo"
    _write(
        target / "package.json",
        """
{
  "main": "src/main.js",
  "dependencies": {
    "electron": "^30.0.0"
  }
}
""".strip(),
    )
    _write(
        target / "src" / "main.js",
        """
const { ipcMain } = require("electron");
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");

ipcMain.handle("run-project-command", async () => {
  const configPath = path.join(process.cwd(), "project.json");
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  return child_process.exec(config.command);
});
""".strip(),
    )
    _write(
        target / "src" / "worker.js",
        """
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");

function runHook() {
  const hookPath = path.join(process.cwd(), "hooks.json");
  const hooks = JSON.parse(fs.readFileSync(hookPath, "utf8"));
  return child_process.exec(hooks.postInstall);
}
module.exports = { runHook };
""".strip(),
    )
    assert not target.resolve(strict=False).is_relative_to(Path.cwd().resolve())

    assert (
        app_mapper_main(
            [
                program,
                str(target),
                "--target-kind",
                "auto",
                "--focus",
                "rce",
                "--write-specs",
                "--output-mode",
                "canonical",
                "--family",
                "binaries",
                "--lane",
                "exe",
                "--shared-root",
                str(shared_root),
                "--run-id",
                run_id,
                "--promote-to-brainstorm",
                "--promotion-layout",
                "category",
                "--no-triage-policy",
            ]
        )
        == 0
    )

    run_root = lane_root / "appmap" / run_id
    promoted_spec = lane_root / "brainstorm" / f"appmap-{run_id}" / "rce" / "rce-spec.md"
    promoted_context_root = promoted_spec.parent / "agent_contexts"
    manifest = json.loads((run_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["target_path"] == str(target.resolve(strict=False))
    assert manifest["agent_granularity"] == "category-master"
    assert manifest["counts"]["candidates"] == 2
    assert promoted_spec.is_file()
    assert len(list(promoted_context_root.glob("*.json"))) == 2

    context_packets = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(promoted_context_root.glob("*.json"))]
    assert {packet["candidate"]["id"] for packet in context_packets} == {"C0001", "C0002"}
    assert {packet["hypothesis_linkage"]["hypothesis_id"] for packet in context_packets} == {"H001", "H002"}
    assert all(packet["run_id"] == run_id for packet in context_packets)
    assert all(packet["appmap_run_root"] == str(run_root) for packet in context_packets)

    handoffs = list_promoted_handoffs(lane_root / "brainstorm")
    assert [handoff.spec_path for handoff in handoffs] == [promoted_spec.resolve(strict=False)]
    validation = validate_promoted_handoff(promoted_spec)
    assert validation.ok, validation.errors
    assert validation.counts["appmap_hypotheses"] == 2
    assert validation.counts["packets"] == 2
    planned = plan_promoted_handoff_command(promoted_spec, selected_hypothesis="H001")
    assert "agents/zero_day_team.py" in planned
    assert "--brainstorm-spec" in planned
    assert "--brainstorm-only" in planned
    assert "--appmap" not in planned
    assert str(target.resolve(strict=False)) in planned

    spawned_profiles: list = []
    update_log = lane_root / "ledgers" / "ledger_updates.jsonl"

    class FakeProcess:
        pid = 31337

        def wait(self, timeout=None) -> int:
            return 0

    class FakeLedger:
        path = lane_root / "ledgers" / "ledger.json"
        run_id = "zero-day-e2e-run"
        root_override = shared_root

        def get_class_context(self, _class_name: str) -> str:
            return ""

        def check(self, finding: dict) -> tuple[bool, str, dict]:
            return False, "ZDT-E2E-001", {**finding, "fid": "ZDT-E2E-001"}

    def fake_spawn(*, profile, agents_root, coverage_path=None, **_kwargs):
        spawned_profiles.append(profile)
        agents_root.mkdir(parents=True, exist_ok=True)
        log_path = agents_root / f"agent_{profile.key}_e2e.log"
        assignments = profile.brainstorm_metadata.get("brainstorm_cluster_assignments") or [
            profile.brainstorm_metadata
        ]
        first_assignment = {**profile.brainstorm_metadata, **dict(assignments[0])}
        raw_finding = {
            **first_assignment,
            "agent": first_assignment["brainstorm_agent_key"],
            "category": "class",
            "class_name": "exec-sink-reachability",
            "type": "Project config command reaches child_process.exec",
            "file": "src/main.js",
            "line": 9,
            "description": "The mocked AppMap handoff follows project config into child_process.exec.",
            "severity": "HIGH",
            "context": "child_process.exec(config.command)",
            "source": "project.json command",
            "trust_boundary": "project config crosses into Electron main process",
            "flow_path": "project.json -> JSON.parse -> child_process.exec",
            "sink": "child_process.exec(config.command)",
            "exploitability": "Synthetic non-live finding emitted by the test harness.",
        }
        log_path.write_text(json.dumps(raw_finding, sort_keys=True) + "\n", encoding="utf-8")
        return zero_day_team.AgentSession(
            profile=profile,
            workspace=agents_root / profile.key,
            log_path=log_path,
            process=FakeProcess(),
            coverage_path=coverage_path,
        )

    def fake_review(findings, *_args, **_kwargs):
        return ([{**finding, "review_tier": "CONFIRMED", "tier": "CONFIRMED"} for finding in findings], [], [])

    def fake_update_team_finding(program_slug, finding, **kwargs):
        root_override = Path(kwargs["root_override"]).resolve(strict=False)
        assert root_override == shared_root.resolve(strict=False)
        update_log.parent.mkdir(parents=True, exist_ok=True)
        updated = {
            **finding,
            "program": program_slug,
            "family": kwargs["family"],
            "lane": kwargs["lane"],
            "snapshot_id": kwargs["snapshot_id"],
            "version_label": kwargs["version_label"],
        }
        with update_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(updated, sort_keys=True) + "\n")
        return updated

    monkeypatch.setattr(zero_day_team, "SubagentLogger", None)
    monkeypatch.setattr(
        zero_day_team,
        "DynamicAgentBuilder",
        lambda *args, **kwargs: SimpleNamespace(
            registry=SimpleNamespace(reg_dir=tmp_path / "dynamic-agent-registry"),
            run=lambda *a, **k: [],
        ),
    )
    monkeypatch.setattr(
        zero_day_team,
        "get_snapshot_identity",
        lambda *_args, **_kwargs: {
            "snapshot_id": "snap-e2e",
            "version_label": "1.0.0-test",
            "channel": "stable",
        },
    )
    monkeypatch.setattr(zero_day_team, "create_team_ledger_from_storage", lambda *args, **kwargs: FakeLedger())
    monkeypatch.setattr(zero_day_team, "_spawn_agent", fake_spawn)
    monkeypatch.setattr(zero_day_team, "stage2_ghost_review", fake_review)
    monkeypatch.setattr(zero_day_team, "update_team_finding", fake_update_team_finding)
    monkeypatch.setattr(zero_day_team, "_pretty_print_findings", lambda *_args, **_kwargs: None)

    summary = zero_day_team.orchestrate_zero_day_team(
        program,
        str(target),
        no_preflight=True,
        no_shared_brain=True,
        brainstorm_spec=str(promoted_spec),
        brainstorm_only=True,
        output_root=str(shared_root),
        hunting_policy="off",
        scheduler="policy-aware",
        agent_wave_size="all",
    )

    assert summary["classes_run"] == ["exec-sink-reachability"]
    assert summary["by_tier"]["confirmed"] == 1
    assert summary["brainstorm"]["hypotheses"] == ["H001", "H002"]
    assert len(spawned_profiles) == 1
    spawned = spawned_profiles[0]
    assert spawned.brainstorm_metadata["category_master"] is True
    assert {item["hypothesis_id"] for item in spawned.brainstorm_metadata["brainstorm_cluster_assignments"]} == {
        "H001",
        "H002",
    }
    assert "Use this AppMap context packet" in spawned.prompt_addendum

    coverage_path = lane_root / "brainstorm" / "coverage.jsonl"
    coverage_rows = _jsonl(coverage_path)
    coverage_events = [row["event"] for row in coverage_rows]
    assert coverage_events.count("hypothesis_loaded") == 2
    assert coverage_events.count("agent_queued") == 2
    assert coverage_events.count("agent_spawned") == 2
    assert "agent_completed_with_raw_findings" in coverage_events
    assert "agent_completed_no_finding" in coverage_events
    assert "review_promoted" in coverage_events
    assert all(
        row.get("appmap_context_packet", "").startswith(str(promoted_context_root))
        for row in coverage_rows
        if row.get("appmap_context_packet")
    )

    scheduler_path = lane_root / "brainstorm" / "scheduler_decisions.jsonl"
    scheduler_rows = _jsonl(scheduler_path)
    assert scheduler_rows
    assert {row["event"] for row in scheduler_rows} == {"agent_selected"}
    assert {row["hypothesis_id"] for row in scheduler_rows} == {"H001", "H002"}
    assert {row["scheduler_master_agent_key"] for row in scheduler_rows} == {"exec-sink-reachability"}

    findings_path = lane_root / "ledgers" / zero_day_team.FINDINGS_FILENAME
    findings = _jsonl(findings_path)
    assert len(findings) == 1
    assert findings[0]["fid"] == "ZDT-E2E-001"
    assert findings[0]["appmap_candidate_id"] == "C0001"
    assert findings[0]["appmap_context_packet"].startswith(str(promoted_context_root))
    ledger_updates = _jsonl(update_log)
    assert len(ledger_updates) == 1
    assert ledger_updates[0]["fid"] == "ZDT-E2E-001"

    reports = summary["reports"]
    assert Path(reports["daily_confirmed"]).is_file()
    assert Path(reports["daily_index"]).is_file()
    finding_reports = list(Path(reports["findings_root"]).rglob("*.md"))
    assert finding_reports
    assert all(path.resolve(strict=False).is_relative_to(tmp_path.resolve()) for path in finding_reports)

    status = campaign_status(lane_root / "brainstorm")
    assert status["handoff_count"] == 1
    assert status["status_counts"]["complete"] == 1
    assert status["specs"][0]["assignments"]["covered"] == 2
    assert status["specs"][0]["coverage_events"]["review_promoted"] == 1

    generated_roots = [
        run_root,
        lane_root / "brainstorm",
        lane_root / "agents",
        lane_root / "ledgers",
        lane_root / "reports",
    ]
    for root in generated_roots:
        assert root.resolve(strict=False).is_relative_to(tmp_path.resolve())
        assert not root.resolve(strict=False).is_relative_to(real_shared.resolve(strict=False))
    assert not (fake_home / "Shared").exists()
