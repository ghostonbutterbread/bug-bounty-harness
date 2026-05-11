import json
from pathlib import Path

import pytest

from agents.brainstorm_spec import parse_brainstorm_spec
from agents.appmap_research_librarian import main, plan_appmap_command, validate_seed
from agents.hunting_policy import policy_artifact_metadata, resolve_hunting_policy


def test_librarian_init_writes_campaign_artifacts(tmp_path: Path) -> None:
    output_root = tmp_path / "campaigns"

    assert (
        main(
            [
                "init",
                "canva",
                "--category",
                "electron-ipc",
                "--research-query",
                "electron",
                "rce",
                "--target-kind",
                "electron-exe",
                "--output-root",
                str(output_root),
                "--run-id",
                "unit-run",
            ]
        )
        == 0
    )

    campaign = output_root / "canva" / "unit-run"
    manifest = json.loads((campaign / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 1
    assert manifest["program"] == "canva"
    assert manifest["focus"] == "rce"
    assert manifest["target_kind"] == "electron-exe"
    assert manifest["run_id"] == "unit-run"
    assert manifest["status"] == "initialized"
    assert manifest["research_query"]["query_key"] == "electron-ipc-electron-rce"
    assert (campaign / "scout_brief.md").is_file()
    assert (campaign / "validator_brief.md").is_file()
    assert (campaign / "sources.todo.jsonl").read_text(encoding="utf-8") == ""
    assert json.loads((campaign / "validated_research_seed.json").read_text(encoding="utf-8")) == {
        "sources": [],
        "technique_packs": [],
    }
    assert "wrapper performs no network calls" in manifest["network_policy"]
    assert "--research-mode local" in (campaign / "README.md").read_text(encoding="utf-8")

    (campaign / "validated_research_seed.json").write_text(
        json.dumps({"sources": [{"id": "S0001", "title": "Do not delete", "url": "https://example.test"}]}),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="campaign already exists"):
        main(
            [
                "init",
                "canva",
                "--category",
                "electron-ipc",
                "--output-root",
                str(output_root),
                "--run-id",
                "unit-run",
            ]
        )
    assert "Do not delete" in (campaign / "validated_research_seed.json").read_text(encoding="utf-8")


def test_librarian_validate_seed_reports_counts_and_strict_errors(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    manifest = {
        "program": "canva",
        "focus": "rce",
        "target_kind": "electron-exe",
        "category": ["electron-ipc"],
        "research_query_terms": ["rce"],
    }
    (campaign / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seed = campaign / "validated_research_seed.json"
    seed.write_text(
        json.dumps(
            {
                "sources": [{"id": "S0001", "title": "Electron IPC", "url": "https://example.test/ipc"}],
                "technique_packs": [
                    {
                        "id": "electron-ipc-rce",
                        "title": "Electron IPC RCE",
                        "summary": "Renderer IPC input reaches privileged main-process execution.",
                        "vulnerability_pack": "rce",
                        "target_pack_keys": ["electron"],
                        "applicable_surface_kinds": ["ipc"],
                        "source_ids": ["S0001"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    assert main(["validate", str(campaign)]) == 0
    report = json.loads((campaign / "validation_report.json").read_text(encoding="utf-8"))

    assert report["status"] == "ok"
    assert report["network_access"] is False
    assert report["counts"] == {"sources": 1, "technique_packs": 1, "errors": 0}
    assert "platform:electron" in report["categories"]
    assert report["manifest"]["provider"] == "local-seed"

    bad_seed = campaign / "bad.json"
    bad_seed.write_text(
        json.dumps(
            {
                "sources": [{"id": "S0001"}],
                "technique_packs": [
                    {
                        "id": "missing-applicability",
                        "title": "Missing applicability",
                        "summary": "Incomplete technique.",
                        "vulnerability_pack": "rce",
                        "source_ids": ["S0001"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    bad_report = validate_seed(bad_seed, manifest=manifest, campaign_root=campaign)

    assert bad_report["status"] == "failed"
    assert any("missing title" in error for error in bad_report["errors"])
    assert any("missing target_pack_keys" in error for error in bad_report["errors"])
    assert any("missing applicable_surface_kinds" in error for error in bad_report["errors"])

    duplicate_seed = campaign / "duplicate.json"
    duplicate_seed.write_text(
        json.dumps(
            {
                "sources": [
                    {"id": "S0001", "title": "One", "url": "https://example.test/one"},
                    {"id": "S0001", "title": "Duplicate", "url": "https://example.test/two"},
                ],
                "technique_packs": [
                    {
                        "id": "dupe",
                        "title": "Duplicate",
                        "summary": "One",
                        "vulnerability_pack": "rce",
                        "target_pack_keys": ["electron"],
                        "applicable_surface_kinds": ["ipc"],
                        "source_ids": ["S0001"],
                    },
                    {
                        "id": "dupe",
                        "title": "Duplicate again",
                        "summary": "Two",
                        "vulnerability_pack": "rce",
                        "target_pack_keys": ["electron"],
                        "applicable_surface_kinds": ["ipc"],
                        "source_ids": ["S0001"],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    duplicate_report = validate_seed(duplicate_seed, manifest=manifest, campaign_root=campaign)
    assert any("duplicate source id" in error for error in duplicate_report["errors"])
    assert any("duplicate technique id" in error for error in duplicate_report["errors"])


def test_librarian_plan_appmap_command_local_and_web_sources(tmp_path: Path, capsys) -> None:
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    manifest = {
        "program": "canva",
        "focus": "rce",
        "target_kind": "electron-exe",
        "category": ["electron-ipc"],
        "research_query_terms": ["rce"],
    }
    (campaign / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seed = campaign / "validated_research_seed.json"
    seed.write_text(
        json.dumps(
            {
                "sources": [
                    {"id": "S0001", "title": "One", "url": "https://research.example/one"},
                    {"id": "S0002", "title": "Two", "url": "https://research.example/two"},
                ],
                "technique_packs": [
                    {
                        "id": "electron-ipc-rce",
                        "title": "Electron IPC RCE",
                        "summary": "Renderer IPC input reaches privileged main-process execution.",
                        "vulnerability_pack": "rce",
                        "target_pack_keys": ["electron"],
                        "applicable_surface_kinds": ["ipc"],
                        "source_ids": ["S0001", "S0002"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    local_command = plan_appmap_command(
        manifest,
        seed_path=seed,
        target_path=tmp_path / "target app",
        run_id="appmap-run",
        write_specs=True,
        output_mode="canonical",
        family="binaries",
        lane="exe",
        promote_to_brainstorm=True,
    )

    assert "agents/app_mapper.py canva" in local_command
    assert "--research-mode local" in local_command
    assert f"--research-seed {seed}" in local_command
    assert "--research-query electron-ipc rce" in local_command
    assert "--output-mode canonical --family binaries --lane exe" in local_command
    assert "--promote-to-brainstorm" in local_command

    assert main(["plan-appmap", str(campaign), str(tmp_path / "target"), "--use-web-sources"]) == 0
    captured = capsys.readouterr()
    assert "--research-mode web" in captured.out
    assert "--research-source-url https://research.example/one" in captured.out
    assert "--research-source-url https://research.example/two" in captured.out
    assert (campaign / "plan_appmap_command.txt").is_file()

    seed.write_text(
        json.dumps(
            {
                "sources": [{"id": "S0001", "title": "One", "url": "https://research.example/one"}],
                "technique_packs": [
                    {
                        "id": "missing-applicability",
                        "title": "Missing applicability",
                        "summary": "Incomplete technique.",
                        "vulnerability_pack": "rce",
                        "source_ids": ["S0001"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="validated seed failed local validation"):
        main(["plan-appmap", str(campaign), str(tmp_path / "target")])
    failed_report = json.loads((campaign / "validation_report.json").read_text(encoding="utf-8"))
    assert failed_report["status"] == "failed"

    seed.write_text(json.dumps({"sources": [], "technique_packs": []}), encoding="utf-8")
    with pytest.raises(SystemExit, match="at least one source and one technique_pack"):
        main(["plan-appmap", str(campaign), str(tmp_path / "target")])


def test_librarian_hypothesize_generates_generic_rce_config_to_exec(tmp_path: Path) -> None:
    campaign = _write_hypothesis_campaign(tmp_path)
    appmap_run = _write_hypothesis_appmap_run(tmp_path)
    output = tmp_path / "hypotheses.jsonl"
    markdown = tmp_path / "hypotheses.md"

    assert (
        main(
            [
                "hypothesize",
                str(campaign),
                "--appmap-run",
                str(appmap_run),
                "--category",
                "rce",
                "--output",
                str(output),
                "--markdown-output",
                str(markdown),
            ]
        )
        == 0
    )

    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    hypothesis = rows[0]
    searchable = json.dumps(hypothesis).lower()
    assert hypothesis["id"] == "HYP001"
    assert hypothesis["category"] == "rce-config-to-exec"
    assert hypothesis["appmap_candidate_refs"] == ["C0001"]
    assert "S0001" in hypothesis["research_refs"]
    assert hypothesis["technique_pack_refs"] == ["node-rce-config"]
    assert "config" in searchable
    assert "sanitization" in searchable
    assert "load" in searchable
    assert "executor" in searchable
    assert "dll" in searchable or "hijack" in searchable
    assert "config parsing" in markdown.read_text(encoding="utf-8").lower()


def test_librarian_hypothesize_dry_run_does_not_write_outputs(tmp_path: Path, capsys) -> None:
    campaign = _write_hypothesis_campaign(tmp_path)
    appmap_run = _write_hypothesis_appmap_run(tmp_path)
    output = tmp_path / "dry" / "hypotheses.jsonl"
    markdown = tmp_path / "dry" / "hypotheses.md"
    brainstorm = tmp_path / "dry" / "spec.md"

    assert (
        main(
            [
                "hypothesize",
                str(campaign),
                "--appmap-run",
                str(appmap_run),
                "--output",
                str(output),
                "--markdown-output",
                str(markdown),
                "--brainstorm-spec-out",
                str(brainstorm),
                "--dry-run",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()

    assert "dry-run hypotheses=1" in captured.out
    assert not output.exists()
    assert not markdown.exists()
    assert not brainstorm.exists()
    assert not (campaign / "validation_report.json").exists()


def test_librarian_hypothesize_missing_appmap_run_fails_without_outputs(tmp_path: Path) -> None:
    campaign = _write_hypothesis_campaign(tmp_path)
    output = tmp_path / "hypotheses.jsonl"

    with pytest.raises(SystemExit, match="--appmap-run must be an existing directory"):
        main(["hypothesize", str(campaign), "--appmap-run", str(tmp_path / "missing-run"), "--output", str(output)])

    assert not output.exists()


def test_librarian_hypothesize_rejects_manifest_artifact_path_traversal(tmp_path: Path) -> None:
    campaign = _write_hypothesis_campaign(tmp_path)
    appmap_run = _write_hypothesis_appmap_run(tmp_path)
    output = tmp_path / "hypotheses.jsonl"
    escaped = tmp_path / "escaped-candidates.jsonl"
    escaped.write_text((appmap_run / "candidates.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
    manifest = json.loads((appmap_run / "manifest.json").read_text(encoding="utf-8"))
    manifest["artifacts"]["candidates"] = "../escaped-candidates.jsonl"
    (appmap_run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(SystemExit, match="must not contain '..'"):
        main(["hypothesize", str(campaign), "--appmap-run", str(appmap_run), "--output", str(output)])

    assert not output.exists()


def test_librarian_hypothesize_defaults_to_first_manifest_category_before_focus(tmp_path: Path) -> None:
    campaign = _write_hypothesis_campaign(tmp_path)
    appmap_run = _write_hypothesis_appmap_run(tmp_path)
    output = tmp_path / "hypotheses.jsonl"
    manifest = json.loads((campaign / "manifest.json").read_text(encoding="utf-8"))
    manifest["focus"] = "rce"
    manifest["category"] = ["node-config-rce", "fallback-category"]
    (campaign / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seed = json.loads((campaign / "validated_research_seed.json").read_text(encoding="utf-8"))
    seed["technique_packs"][0]["vulnerability_pack"] = "node-config-rce"
    (campaign / "validated_research_seed.json").write_text(json.dumps(seed), encoding="utf-8")

    assert main(["hypothesize", str(campaign), "--appmap-run", str(appmap_run), "--output", str(output)]) == 0

    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert rows[0]["category"] == "node-config-rce-config-to-exec"


def test_librarian_hypothesize_accepts_seed_override(tmp_path: Path) -> None:
    campaign = _write_hypothesis_campaign(tmp_path)
    appmap_run = _write_hypothesis_appmap_run(tmp_path)
    output = tmp_path / "hypotheses.jsonl"
    alternate_seed = tmp_path / "alternate-seed.json"
    alternate_seed.write_text((campaign / "validated_research_seed.json").read_text(encoding="utf-8"), encoding="utf-8")
    (campaign / "validated_research_seed.json").write_text(json.dumps({"sources": [], "technique_packs": []}), encoding="utf-8")

    assert (
        main(
            [
                "hypothesize",
                str(campaign),
                "--appmap-run",
                str(appmap_run),
                "--seed",
                str(alternate_seed),
                "--output",
                str(output),
            ]
        )
        == 0
    )

    assert len(output.read_text(encoding="utf-8").splitlines()) == 1


def test_librarian_hypothesize_require_appmap_ref_filters_unreferenced_candidates(tmp_path: Path) -> None:
    campaign = _write_hypothesis_campaign(tmp_path)
    appmap_run = _write_hypothesis_appmap_run(tmp_path, include_ids=False)
    loose_output = tmp_path / "loose.jsonl"
    strict_output = tmp_path / "strict.jsonl"

    assert main(["hypothesize", str(campaign), "--appmap-run", str(appmap_run), "--output", str(loose_output)]) == 0
    loose_rows = [json.loads(line) for line in loose_output.read_text(encoding="utf-8").splitlines()]
    assert len(loose_rows) == 1
    assert loose_rows[0]["appmap_candidate_refs"] == []
    assert loose_rows[0]["appmap_surface_refs"] == []

    assert (
        main(
            [
                "hypothesize",
                str(campaign),
                "--appmap-run",
                str(appmap_run),
                "--output",
                str(strict_output),
                "--require-appmap-ref",
            ]
        )
        == 0
    )
    assert strict_output.read_text(encoding="utf-8") == ""


def test_librarian_hypothesize_writes_brainstorm_spec(tmp_path: Path) -> None:
    campaign = _write_hypothesis_campaign(tmp_path)
    appmap_run = _write_hypothesis_appmap_run(tmp_path)
    spec = tmp_path / "brainstorm" / "spec.md"

    assert (
        main(
            [
                "hypothesize",
                str(campaign),
                "--appmap-run",
                str(appmap_run),
                "--brainstorm-spec-out",
                str(spec),
            ]
        )
        == 0
    )

    text = spec.read_text(encoding="utf-8")
    assert "### H001 - Config-controlled value may reach process execution or unsafe loader" in text
    assert "appmap-C0001" in text
    assert "research:S0001" in text
    assert "research-technique:node-rce-config" in text
    assert "mapping_signature=" in text
    parsed = parse_brainstorm_spec(spec, validate_paths=False)
    assert len(parsed.hypotheses) == 1
    assert parsed.hypotheses[0].id == "H001"


def test_librarian_hypothesize_inherits_appmap_hunting_policy_metadata(tmp_path: Path) -> None:
    campaign = _write_hypothesis_campaign(tmp_path)
    appmap_run = _write_hypothesis_appmap_run(tmp_path)
    spec = tmp_path / "brainstorm" / "policy-spec.md"
    manifest_path = appmap_run / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    policy = resolve_hunting_policy("electron-application-first", target_path=tmp_path)
    manifest.update(policy_artifact_metadata(policy))
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert (
        main(
            [
                "hypothesize",
                str(campaign),
                "--appmap-run",
                str(appmap_run),
                "--brainstorm-spec-out",
                str(spec),
            ]
        )
        == 0
    )

    text = spec.read_text(encoding="utf-8")
    assert "- Hunting policy: electron-application-first-loose" in text
    assert "- Hunting posture: application-first-loose" in text


def test_librarian_hypothesize_rejects_empty_brainstorm_spec_output(tmp_path: Path) -> None:
    campaign = _write_hypothesis_campaign(tmp_path)
    appmap_run = _write_hypothesis_appmap_run(tmp_path)
    output = tmp_path / "hypotheses.jsonl"
    markdown = tmp_path / "hypotheses.md"
    spec = tmp_path / "empty-spec.md"

    with pytest.raises(SystemExit, match="requires at least one generated hypothesis"):
        main(
            [
                "hypothesize",
                str(campaign),
                "--appmap-run",
                str(appmap_run),
                "--output",
                str(output),
                "--markdown-output",
                str(markdown),
                "--brainstorm-spec-out",
                str(spec),
                "--surface-kind",
                "unmatched-kind",
            ]
        )

    assert not output.exists()
    assert not markdown.exists()
    assert not spec.exists()


def _write_hypothesis_campaign(tmp_path: Path) -> Path:
    campaign = tmp_path / "campaign"
    campaign.mkdir(exist_ok=True)
    manifest = {
        "program": "example",
        "focus": "rce",
        "target_kind": "node",
        "category": ["rce"],
        "research_query_terms": ["config", "process-exec"],
    }
    (campaign / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (campaign / "validated_research_seed.json").write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "id": "S0001",
                        "title": "Node child process guidance",
                        "url": "https://example.test/node-child-process",
                        "summary": "Command execution depends on attacker control of command material.",
                    }
                ],
                "technique_packs": [
                    {
                        "id": "node-rce-config",
                        "title": "Node config to process execution",
                        "summary": "Review config sanitization, load paths, executor construction, and DLL hijack style loader behavior before child_process sinks.",
                        "vulnerability_pack": "rce",
                        "target_pack_keys": ["node"],
                        "applicable_surface_kinds": ["config", "process-exec"],
                        "source_ids": ["S0001"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return campaign


def _write_hypothesis_appmap_run(tmp_path: Path, *, include_ids: bool = True) -> Path:
    run_root = tmp_path / ("appmap-run-ids" if include_ids else "appmap-run-no-ids")
    run_root.mkdir(exist_ok=True)
    manifest = {
        "run_id": run_root.name,
        "artifacts": {
            "target_profile": "target_profile.json",
            "architecture": "architecture.md",
            "surfaces": "surfaces.jsonl",
            "candidates": "candidates.jsonl",
        },
    }
    (run_root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run_root / "target_profile.json").write_text(
        json.dumps({"program": "example", "target_kind": "node", "frameworks": ["node"], "languages": {"javascript": 1}}),
        encoding="utf-8",
    )
    (run_root / "architecture.md").write_text("# Architecture\n\nConfig loader reaches executor.\n", encoding="utf-8")
    source = {
        "role": "source",
        "kind": "config",
        "file": "src/config.js",
        "line": 4,
        "description": "project config load",
        "confidence": 0.84,
    }
    boundary = {
        "role": "boundary",
        "kind": "project-boundary",
        "file": "src/config.js",
        "line": 6,
        "description": "project trust boundary",
        "confidence": 0.78,
    }
    sink = {
        "role": "sink",
        "kind": "process-exec",
        "file": "src/config.js",
        "line": 12,
        "description": "child_process.exec call",
        "confidence": 0.91,
    }
    candidate = {
        "flow_id": "F0001",
        "source": source,
        "boundary": boundary,
        "transform": None,
        "sink": sink,
        "score": 0.86,
        "priority": "high",
    }
    if include_ids:
        source["id"] = "S0001"
        boundary["id"] = "B0001"
        sink["id"] = "K0001"
        candidate["id"] = "C0001"
        candidate["surface_id"] = "S0001"
    surfaces = [source, boundary, sink]
    (run_root / "surfaces.jsonl").write_text("".join(json.dumps(item) + "\n" for item in surfaces), encoding="utf-8")
    (run_root / "candidates.jsonl").write_text(json.dumps(candidate) + "\n", encoding="utf-8")
    return run_root
