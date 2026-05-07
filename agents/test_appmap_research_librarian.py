import json
from pathlib import Path

import pytest

from agents.appmap_research_librarian import main, plan_appmap_command, validate_seed


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
