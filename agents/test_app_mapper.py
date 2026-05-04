from __future__ import annotations

import json
import re
from pathlib import Path

from agents.app_mapper import (
    PatternSpec,
    TARGET_PACKS,
    VULNERABILITY_PACKS,
    TargetDetection,
    TargetPack,
    VulnerabilityPack,
    build_rce_flows,
    map_application,
    register_target_pack,
    register_vulnerability_pack,
    write_artifacts,
)
from agents.brainstorm_adapters import (
    brainstorm_intent_to_dynamic_agent_spec,
    brainstorm_intent_to_zero_day_profile,
)
from agents.brainstorm_spec import hypothesis_to_agent_intents, parse_brainstorm_spec


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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
    finally:
        TARGET_PACKS.clear()
        TARGET_PACKS.update(original_target_packs)
        VULNERABILITY_PACKS.clear()
        VULNERABILITY_PACKS.update(original_vuln_packs)


def _write_spec(path: Path, result, *, run_id: str) -> Path:
    from agents.app_mapper import render_rce_spec

    path.write_text(render_rce_spec(result, run_id=run_id), encoding="utf-8")
    return path
