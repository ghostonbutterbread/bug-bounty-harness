from __future__ import annotations

from pathlib import Path
import json
import sys
from typing import Any
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import program_init

@pytest.fixture(autouse=True)
def local_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(program_init.Path, "home", lambda: tmp_path)


def test_initializer_uses_artifact_env_at_invocation(monkeypatch, tmp_path: Path, capsys) -> None:
    artifact = tmp_path / "custom-artifacts"
    monkeypatch.setenv("BOUNTY_ARTIFACT_ROOT", str(artifact))
    assert program_init.main(["demo", "--skip-scope", "--shared-root", str(tmp_path / "Shared"), "--dry-run", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["artifact_root"] == str(artifact / "demo")


def test_initializer_explicit_artifact_root_overrides_empty_env(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("BOUNTY_ARTIFACT_ROOT", "")
    artifact = tmp_path / "selected"
    assert program_init.main([
        "demo", "--skip-scope", "--artifact-root", str(artifact), "--dry-run", "--json",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["artifact_root"] == str(artifact / "demo")


def test_initializer_rejects_unmounted_bounty_before_scope_or_layout(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("os.path.ismount", lambda path: False)
    with patch.object(program_init, "pull_scope", side_effect=AssertionError("scope pull before mount preflight")) as pull, patch.object(program_init, "ensure_layout") as layout:
        with pytest.raises(SystemExit, match="/mnt/bounty.*mount"):
            program_init.initialize_program(
                "demo", lanes=["web"], shared_root=tmp_path / "Shared",
                artifact_root=Path("/mnt/bounty"), platform="hackerone", skip_scope=False,
                dry_run=False,
            )
        pull.assert_not_called()
        layout.assert_not_called()
    assert not (tmp_path / "Shared").exists()


def test_initializer_rejects_nested_symlink_into_unmounted_bounty_before_scope(monkeypatch, tmp_path: Path) -> None:
    import agents.artifact_root as root_guard

    unmounted = tmp_path / "unmounted-bounty"
    unmounted.mkdir()
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    (artifact_root / "demo").symlink_to(unmounted, target_is_directory=True)
    monkeypatch.setattr(root_guard, "LEGACY_ARTIFACT_ROOT", unmounted)
    monkeypatch.setattr("os.path.ismount", lambda path: False)
    with patch.object(program_init, "pull_scope", side_effect=AssertionError("scope pull before mount preflight")) as pull:
        with pytest.raises(SystemExit, match="not mounted"):
            program_init.initialize_program(
                "demo", lanes=["web"], shared_root=tmp_path / "Shared",
                artifact_root=artifact_root, platform="hackerone", skip_scope=False, dry_run=False,
            )
        pull.assert_not_called()
    assert not list(unmounted.iterdir())
    assert not (tmp_path / "Shared").exists()


def test_reinitialization_rejects_changed_root_before_scope_or_layout(monkeypatch, tmp_path: Path) -> None:
    shared = tmp_path / "Shared"
    first, second = tmp_path / "first", tmp_path / "second"
    monkeypatch.setattr("socket.gethostname", lambda: "node-a")
    with patch.object(program_init, "_read_scope", return_value=(set(), set())):
        program_init.initialize_program("demo", lanes=["web"], shared_root=shared,
            artifact_root=first, platform=None, skip_scope=True, dry_run=False)
    meta = shared / "web_bounty" / "demo" / "web" / "recon" / "_meta" / "program-init.json"
    artifact_map = meta.parent.parent / "artifact-map.md"
    original_manifest, original_map = meta.read_bytes(), artifact_map.read_bytes()
    assert json.loads(original_manifest)["artifact_host"] == "node-a"
    assert "node-a" in original_map.decode()
    with patch.object(program_init, "pull_scope") as pull:
        with pytest.raises(ValueError, match="artifact root.*existing"):
            program_init.initialize_program("demo", lanes=["web"], shared_root=shared,
                artifact_root=second, platform="hackerone", skip_scope=False, dry_run=False)
        pull.assert_not_called()
    assert not second.exists()
    assert meta.read_bytes() == original_manifest
    assert artifact_map.read_bytes() == original_map


def test_reinitialization_records_host_without_overwriting_original(monkeypatch, tmp_path: Path) -> None:
    shared, artifact_root = tmp_path / "Shared", tmp_path / "bulk"
    monkeypatch.setattr("socket.gethostname", lambda: "node-a")
    kwargs: dict[str, Any] = dict(lanes=["web"], shared_root=shared, artifact_root=artifact_root,
                                 platform=None, skip_scope=True, dry_run=False)
    with patch.object(program_init, "_read_scope", return_value=(set(), set())):
        first = program_init.initialize_program("demo", **kwargs)
        manifest = shared / "web_bounty" / "demo" / "web" / "recon" / "_meta" / "program-init.json"
        before = manifest.read_bytes()
        monkeypatch.setattr("socket.gethostname", lambda: "node-b")
        second = program_init.initialize_program("demo", **kwargs)
    assert manifest.read_bytes() == before
    for result, host in ((first, "node-a"), (second, "node-b")):
        receipts = result["artifact_host_receipts"]
        assert isinstance(receipts, dict)
        receipt = Path(receipts["web"])
        record = json.loads(receipt.read_text())
        assert record["artifact_host"] == host
        assert record["artifact_root"] == str(artifact_root / "demo" / "web")
        assert record["js_library_root"] == str(artifact_root / "demo" / "web" / "recon" / "js" / "_library")
    first_receipts, second_receipts = first["artifact_host_receipts"], second["artifact_host_receipts"]
    assert isinstance(first_receipts, dict) and isinstance(second_receipts, dict)
    assert first_receipts["web"] != second_receipts["web"]
    second_warnings = second["warnings"]
    assert isinstance(second_warnings, list)
    assert any("existing artifact map preserved" in warning for warning in second_warnings)


def test_initializer_rejects_unreadable_existing_pointer_before_scope(tmp_path: Path) -> None:
    shared = tmp_path / "Shared"
    manifest = shared / "web_bounty" / "demo" / "web" / "recon" / "_meta" / "program-init.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("{not-valid-json", encoding="utf-8")
    with patch.object(program_init, "pull_scope") as pull:
        with pytest.raises(ValueError, match="cannot verify existing artifact root"):
            program_init.initialize_program("demo", lanes=["web"], shared_root=shared,
                artifact_root=tmp_path / "bulk", platform="hackerone", skip_scope=False, dry_run=False)
        pull.assert_not_called()
    assert manifest.read_text(encoding="utf-8") == "{not-valid-json"
    assert not (tmp_path / "bulk").exists()


def test_cli_reports_host_receipt_and_existing_map_warning(tmp_path: Path, capsys) -> None:
    args = ["demo", "--skip-scope", "--shared-root", str(tmp_path / "Shared"),
            "--artifact-root", str(tmp_path / "bulk")]
    assert program_init.main(args) == 0
    first = capsys.readouterr().out
    assert "web host receipt:" in first
    assert program_init.main(args) == 0
    second = capsys.readouterr().out
    assert "existing artifact map preserved" in second


@pytest.mark.parametrize("first_lane,second_lane", [("web", "api"), ("api", "web")])
def test_initializer_rejects_cross_lane_shared_js_root_mismatch(tmp_path: Path, first_lane: str, second_lane: str) -> None:
    shared = tmp_path / "Shared"
    first, second = tmp_path / "first", tmp_path / "second"
    with patch.object(program_init, "_read_scope", return_value=(set(), set())):
        program_init.initialize_program("demo", lanes=[first_lane], shared_root=shared,
            artifact_root=first, platform=None, skip_scope=True, dry_run=False)
    with patch.object(program_init, "pull_scope") as pull:
        with pytest.raises(ValueError, match="artifact root.*existing"):
            program_init.initialize_program("demo", lanes=[second_lane], shared_root=shared,
                artifact_root=second, platform="hackerone", skip_scope=False, dry_run=False)
        pull.assert_not_called()
    assert not second.exists()


def test_handoff_records_artifact_host_for_each_invocation(monkeypatch, tmp_path: Path) -> None:
    shared, artifact_root = tmp_path / "Shared", tmp_path / "bulk"
    kwargs: dict[str, Any] = dict(lanes=["web"], shared_root=shared, artifact_root=artifact_root,
        platform="hackerone", skip_scope=False, dry_run=False, mode="js")
    with patch.object(program_init, "_read_scope", return_value=({"demo.test"}, set())), patch.object(
        program_init, "pull_scope", return_value=object()
    ):
        monkeypatch.setattr("socket.gethostname", lambda: "node-a")
        first = program_init.initialize_program("demo", **kwargs)
        monkeypatch.setattr("socket.gethostname", lambda: "node-b")
        second = program_init.initialize_program("demo", **kwargs)
    assert isinstance(first["handoff"], dict) and isinstance(second["handoff"], dict)
    assert first["handoff"]["storage"]["artifact_host"] == "node-a"
    assert second["handoff"]["storage"]["artifact_host"] == "node-b"
    assert json.loads(Path(str(second["handoff_path"])).read_text())["storage"]["artifact_host"] == "node-b"


def test_initialize_program_creates_shared_and_mounted_lanes(tmp_path: Path) -> None:
    shared_root = tmp_path / "Shared"
    artifact_root = tmp_path / "bounty"
    with patch.object(program_init, "_read_scope", return_value=({"*.demo.test"}, {"https://api.demo.test"})):
        result = program_init.initialize_program(
            "demo program",
            lanes=["web", "apk"],
            shared_root=shared_root,
            artifact_root=artifact_root,
            platform=None,
            skip_scope=True,
            dry_run=False,
        )

    assert result["program"] == "demo_program"
    web_root = shared_root / "web_bounty" / "demo_program" / "web"
    apk_root = shared_root / "binaries" / "demo_program" / "apk"
    assert (web_root / "context" / "target_profile.json").exists()
    assert (web_root / "recon" / "urls.txt").read_text(encoding="utf-8") == "https://api.demo.test\n"
    assert (web_root / "recon" / "wild.txt").read_text(encoding="utf-8") == "demo.test\n"
    assert (web_root / "recon" / "_meta" / "program-init.json").exists()
    assert not (web_root / "recon" / "_runs").exists()
    assert not (web_root / "recon" / "_batches").exists()
    assert not (web_root / "recon" / "_scratch").exists()
    assert (apk_root / "input" / "original").is_dir()
    assert (artifact_root / "demo_program" / "web" / "proxy" / "har").is_dir()
    assert (artifact_root / "demo_program" / "web" / "recon" / "js" / "_library" / "downloads").is_dir()
    assert not (artifact_root / "demo_program" / "web" / "recon" / "javascript").exists()
    assert not (artifact_root / "demo_program" / "web" / "browser-profiles").exists()
    assert (artifact_root / "demo_program" / "apk" / "static" / "jadx" / "runs").is_dir()


def test_initialize_program_requires_scope_decision(tmp_path: Path) -> None:
    try:
        program_init.initialize_program(
            "demo",
            lanes=["web"],
            shared_root=tmp_path / "Shared",
            artifact_root=tmp_path / "bounty",
            platform=None,
            skip_scope=False,
            dry_run=False,
        )
    except ValueError as exc:
        assert "scope is required" in str(exc)
    else:
        raise AssertionError("scope decision should be required")

    try:
        program_init.initialize_program(
            "demo",
            lanes=["web"],
            shared_root=tmp_path / "Shared",
            artifact_root=tmp_path / "bounty",
            platform="bugcrowd",
            skip_scope=True,
            dry_run=True,
        )
    except ValueError as exc:
        assert "cannot be used together" in str(exc)
    else:
        raise AssertionError("scope modes should be mutually exclusive")


def test_failed_scope_pull_fails_before_creating_program_layout(tmp_path: Path) -> None:
    with patch.object(program_init, "pull_scope", return_value=None):
        try:
            program_init.initialize_program(
                "demo",
                lanes=["web"],
                shared_root=tmp_path / "Shared",
                artifact_root=tmp_path / "bounty",
                platform="bugcrowd",
                skip_scope=False,
                dry_run=False,
            )
        except RuntimeError as exc:
            assert "scope pull failed" in str(exc)
        else:
            raise AssertionError("failed scope pulls must fail closed")

    assert not (tmp_path / "Shared").exists()
    assert not (tmp_path / "bounty").exists()


def test_api_only_init_uses_existing_web_js_library_and_preserves_legacy(tmp_path: Path) -> None:
    root = tmp_path / "bulk"
    legacy = root / "demo" / "web" / "recon" / "javascript" / "retained.js"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("legacy body", encoding="utf-8")
    with patch.object(program_init, "_read_scope", return_value=(set(), set())):
        program_init.initialize_program(
            "demo", lanes=["api"], shared_root=tmp_path / "Shared", artifact_root=root,
            platform=None, skip_scope=True, dry_run=False)
    assert (root / "demo" / "web" / "recon" / "js" / "_library" / "downloads").is_dir()
    assert legacy.read_text(encoding="utf-8") == "legacy body"


def test_api_only_artifact_map_includes_shared_js_library(tmp_path: Path) -> None:
    shared_root = tmp_path / "Shared"
    artifact_root = tmp_path / "bulk"
    with patch.object(program_init, "_read_scope", return_value=(set(), set())):
        program_init.initialize_program(
            "demo", lanes=["api"], shared_root=shared_root, artifact_root=artifact_root,
            platform=None, skip_scope=True, dry_run=False,
        )

    library = artifact_root / "demo" / "web" / "recon" / "js" / "_library"
    artifact_map = shared_root / "web_bounty" / "demo" / "api" / "recon" / "artifact-map.md"
    contents = artifact_map.read_text(encoding="utf-8")
    assert library.is_dir()
    assert f"`{artifact_root / 'demo' / 'api'}`" in contents
    assert f"`{library}`" in contents


def test_api_reinitialization_preserves_existing_artifact_map(tmp_path: Path) -> None:
    shared_root = tmp_path / "Shared"
    artifact_map = shared_root / "web_bounty" / "demo" / "api" / "recon" / "artifact-map.md"
    artifact_map.parent.mkdir(parents=True)
    artifact_map.write_text("curated map\n", encoding="utf-8")
    with patch.object(program_init, "_read_scope", return_value=(set(), set())):
        program_init.initialize_program(
            "demo", lanes=["api"], shared_root=shared_root, artifact_root=tmp_path / "bulk",
            platform=None, skip_scope=True, dry_run=False,
        )
    assert artifact_map.read_text(encoding="utf-8") == "curated map\n"


def test_reinitialization_preserves_existing_context_and_recon_seeds(tmp_path: Path) -> None:
    shared_root = tmp_path / "Shared"
    artifact_root = tmp_path / "bounty"
    with patch.object(program_init, "_read_scope", return_value=({"*.demo.test"}, {"https://api.demo.test"})):
        program_init.initialize_program(
            "demo",
            lanes=["web"],
            shared_root=shared_root,
            artifact_root=artifact_root,
            platform=None,
            skip_scope=True,
            dry_run=False,
        )

    web_root = shared_root / "web_bounty" / "demo" / "web"
    protected = {
        web_root / "context" / "target_profile.json": b"curated profile\n",
        web_root / "context" / "me_context.md": b"curated context\n",
        web_root / "recon" / "urls.txt": b"curated url\n",
        web_root / "recon" / "wild.txt": b"curated wildcard\n",
    }
    for path, content in protected.items():
        path.write_bytes(content)

    with patch.object(program_init, "_read_scope", return_value=(set(), set())):
        program_init.initialize_program(
            "demo",
            lanes=["web"],
            shared_root=shared_root,
            artifact_root=artifact_root,
            platform=None,
            skip_scope=True,
            dry_run=False,
        )

    assert {path: path.read_bytes() for path in protected} == protected


def test_dry_run_does_not_create_paths(tmp_path: Path) -> None:
    result = program_init.initialize_program(
        "demo",
        lanes=["web"],
        shared_root=tmp_path / "Shared",
        artifact_root=tmp_path / "bounty",
        platform=None,
        skip_scope=True,
        dry_run=True,
    )

    assert result["dry_run"] is True
    assert result["created"]
    assert not (tmp_path / "Shared").exists()
    assert not (tmp_path / "bounty").exists()


def test_recon_init_execution_passes_resolved_storage_to_workers() -> None:
    skill = (Path(__file__).resolve().parents[1] / "skills/recon/SKILL.md").read_text()
    assert "storage.js_library_root" in skill
    assert "storage.artifact_host" in skill
    assert "worker's mutable storage selection" in skill
    assert "--library-root" in skill
    assert "--output-root" in skill


def test_initializer_handoff_drives_js_inventory_to_custom_artifact_root(tmp_path: Path) -> None:
    from agents import js_analyzer
    import hashlib

    artifact_root = tmp_path / "bulk"
    conflicting_root = tmp_path / "wrong-default"
    with patch.object(program_init, "_read_scope", return_value=({"demo.test"}, set())):
        result = program_init.initialize_program(
            "demo", lanes=["web"], shared_root=tmp_path / "Shared", artifact_root=artifact_root,
            platform="bugcrowd", skip_scope=False, dry_run=True, mode="js")
    handoff = result["handoff"]
    assert isinstance(handoff, dict)
    storage = handoff["storage"]
    assert isinstance(storage, dict)
    library = Path(storage["js_library_root"])
    run_root = Path(storage["js_run_parent"]) / "fixture-run"
    inputs = tmp_path / "urls.txt"
    inputs.write_text("https://demo.test/app.js\n")
    body = b"const fixture = true;"
    with patch.object(js_analyzer, "load_config", return_value={"defaults": {"program_root": str(conflicting_root)}}), patch.object(
        js_analyzer, "http_get", return_value=(body, 200, "application/javascript")
    ):
        assert js_analyzer.main([
            "inventory", "demo", "--input", str(inputs), "--target-host", "demo.test",
            "--source-maps", "off", "--source-map-wayback", "off", "--run-id", "fixture-run",
            "--library-root", str(library), "--output-root", str(run_root),
            "--integration-index-root", storage["js_integration_index_root"],
        ]) == 0
    digest = hashlib.sha256(body).hexdigest()
    assert (library / "downloads" / f"{digest}.js").read_bytes() == body
    assert json.loads((run_root / "manifest.json").read_text())["outputs"]["library"] == str(library)
    assert (library / "ledger.json").is_file()
    assert not conflicting_root.exists()
    observations = tmp_path / "observations.jsonl"
    observations.write_text(json.dumps({"sha256": digest, "lens": "fixture", "run_id": "fixture-run"}) + "\n")
    assert js_analyzer.main(["observe", "demo", "--input", str(observations), "--library-root", str(library)]) == 0
    assert (library / "observations.jsonl").is_file()
    assert (library / "js_info.sqlite").is_file()


def test_full_handoff_is_deterministic_and_pending(tmp_path: Path) -> None:
    shared = tmp_path / "Shared"
    artifacts = tmp_path / "artifacts"
    kwargs: dict[str, Any] = dict(lanes=["web"], shared_root=shared, artifact_root=artifacts,
                                  platform="bugcrowd", skip_scope=False, dry_run=False, mode="full")
    with patch.object(program_init, "pull_scope", return_value=object()), patch.object(
        program_init, "_read_scope", return_value=({"*.demo.test"}, {"https://api.demo.test/v1"})
    ):
        first = program_init.initialize_program("demo", **kwargs)
        assert isinstance(first["handoff_path"], str)
        path = Path(first["handoff_path"])
        original = path.read_bytes()
        second = program_init.initialize_program("demo", **kwargs)
        preview_kwargs: dict[str, Any] = dict(kwargs)
        preview_kwargs["dry_run"] = True
        preview = program_init.initialize_program("demo", **preview_kwargs)
    assert path.read_bytes() == original
    assert preview["scope_state"] == "saved"
    assert preview["refreshed"] == []
    assert second["handoff"] == first["handoff"]
    assert str(path) in first["created"]
    assert str(path) not in second["created"]
    assert second["refreshed"] == []
    data = json.loads(original)
    stages = {stage["id"]: stage for stage in data["stages"]}
    assert list(stages) == ["full-recon", "js-url-acquisition", "katana-endpoints", "public-docs",
                            "api-mapping", "api-reconciliation", "parameter-mining", "recon-bus-promotion", "url-ingest-review"]
    assert stages["js-url-acquisition"]["depends_on"] == []
    assert data["storage"]["js_library_root"] == str(artifacts / "demo" / "web" / "recon" / "js" / "_library")
    assert data["storage"]["js_run_parent"] == str(artifacts / "demo" / "web" / "recon" / "js")
    assert data["storage"]["js_integration_index_root"] == str(artifacts / "demo" / "web" / "intel" / "integrations")
    assert "--integration-index-root" in stages["js-url-acquisition"]["task"]
    assert "--library-root" in stages["js-url-acquisition"]["task"]
    assert "--output-root" in stages["js-url-acquisition"]["task"]
    assert stages["katana-endpoints"]["depends_on"] == ["js-url-acquisition"]
    assert "-jc" in stages["katana-endpoints"]["task"]
    assert "baseline freshness" in stages["full-recon"]["task"]
    assert stages["parameter-mining"]["depends_on"] == ["full-recon", "js-url-acquisition", "api-reconciliation", "public-docs"]
    assert stages["api-mapping"]["depends_on"] == ["js-url-acquisition", "katana-endpoints", "public-docs"]
    assert stages["api-reconciliation"]["depends_on"] == ["full-recon", "api-mapping"]
    assert "Recon Bus append or promote-run" in stages["recon-bus-promotion"]["task"]
    assert "--no-probe" in stages["recon-bus-promotion"]["task"]
    assert stages["recon-bus-promotion"]["status"] == "pending-prerequisites"
    assert all(stage["status"].startswith("pending-") for stage in stages.values())
    assert "does not spawn Hermes subagents" in data["execution_boundary"]
    assert data["scope"]["urls"] == ["https://api.demo.test/v1"]
    assert data["schema_version"] == 2


@pytest.mark.parametrize("mode,expected,docs", [
    ("js", ["full-recon", "js-url-acquisition", "recon-bus-promotion", "url-ingest-review"], False),
    ("api", ["full-recon", "js-url-acquisition", "katana-endpoints", "public-docs", "api-mapping",
             "recon-bus-promotion", "url-ingest-review"], True),
    ("params", ["full-recon", "js-url-acquisition", "katana-endpoints", "public-docs", "api-mapping",
                "parameter-mining", "recon-bus-promotion", "url-ingest-review"], True),
])
def test_focused_mode_dependency_handoff(tmp_path: Path, mode: str, expected: list[str], docs: bool) -> None:
    with patch.object(program_init, "_read_scope", return_value=({"*.demo.test"}, {"https://api.demo.test"})):
        result = program_init.initialize_program(
            "demo", lanes=["web"], shared_root=tmp_path / "Shared", artifact_root=tmp_path / "artifacts",
            platform="bugcrowd", skip_scope=False, dry_run=True, mode=mode)
    handoff = result["handoff"]
    assert isinstance(handoff, dict)
    stages = {stage["id"]: stage for stage in handoff["stages"]}
    assert str(result["handoff_path"]).endswith(f"init-{mode}-handoff.json")
    assert handoff["mode"] == mode
    assert list(stages) == expected
    assert ("public-docs" in stages) is docs
    assert stages["js-url-acquisition"]["depends_on"] == ["full-recon"]
    if "api-mapping" in stages:
        assert stages["api-mapping"]["depends_on"] == ["full-recon", "js-url-acquisition", "katana-endpoints", "public-docs"]
    assert stages["recon-bus-promotion"]["depends_on"] == expected[:-2]
    assert not (tmp_path / "Shared").exists()


def test_js_mode_can_opt_into_docs(tmp_path: Path) -> None:
    with patch.object(program_init, "_read_scope", return_value=({"demo.test"}, set())):
        result = program_init.initialize_program(
            "demo", lanes=["web"], shared_root=tmp_path / "Shared", artifact_root=tmp_path / "artifacts",
            platform="hackerone", skip_scope=False, dry_run=True, mode="js", include_docs=True)
    handoff = result["handoff"]
    assert isinstance(handoff, dict)
    assert "public-docs" in {stage["id"] for stage in handoff["stages"]}


def test_focused_handoff_writes_once_and_refreshes_without_target_traffic(tmp_path: Path) -> None:
    kwargs: dict[str, Any] = dict(lanes=["web"], shared_root=tmp_path / "Shared", artifact_root=tmp_path / "artifacts",
                                  platform="bugcrowd", skip_scope=False, dry_run=False, mode="params")
    with patch.object(program_init, "pull_scope", return_value=object()) as pull, patch.object(
        program_init, "_read_scope", return_value=({"demo.test"}, set())
    ) as read_scope:
        first = program_init.initialize_program("demo", **kwargs)
        path = Path(first["handoff_path"])
        assert path.exists()
        assert first["handoff"] == json.loads(path.read_text())
        second = program_init.initialize_program("demo", **kwargs)
        read_scope.return_value = ({"api.demo.test"}, set())
        third = program_init.initialize_program("demo", **kwargs)
    assert pull.call_count == 3
    assert str(path) in first["created"]
    assert second["refreshed"] == []
    assert third["refreshed"] == [str(path)]
    assert json.loads(path.read_text())["scope"]["domains"] == ["api.demo.test"]
    assert not (tmp_path / "Shared" / "web_bounty" / "demo" / "web" / "recon" / "aggregated").exists()


@pytest.mark.parametrize("mode", ["js", "api", "params"])
def test_focused_modes_reject_missing_scope_before_layout(tmp_path: Path, mode: str) -> None:
    with patch.object(program_init, "pull_scope", return_value=object()), patch.object(
        program_init, "_read_scope", return_value=(set(), set())
    ):
        with pytest.raises(ValueError, match="non-empty saved scope"):
            program_init.initialize_program(
                "demo", lanes=["web"], shared_root=tmp_path / "Shared",
                artifact_root=tmp_path / "artifacts", platform="bugcrowd", skip_scope=False,
                dry_run=False, mode=mode)
    assert not (tmp_path / "Shared").exists()


def test_full_docs_explicit_and_basic_unchanged(tmp_path: Path) -> None:
    with patch.object(program_init, "_read_scope", return_value=({"demo.test"}, set())):
        result = program_init.initialize_program(
            "demo", lanes=["api"], shared_root=tmp_path / "Shared",
            artifact_root=tmp_path / "artifacts", platform="hackerone", skip_scope=False,
            dry_run=True, mode="full", include_docs=True)
    handoff = result["handoff"]
    assert isinstance(handoff, dict)
    stages = {stage["id"]: stage for stage in handoff["stages"]}
    assert "public-docs" in stages
    assert result["scope_state"] == "saved"
    assert handoff["scope"]["source"] == "saved platform scope"
    assert "public-docs" in stages["recon-bus-promotion"]["depends_on"]
    assert not (tmp_path / "Shared").exists()
    assert program_init.build_parser().parse_args(["demo", "--skip-scope"]).mode == "basic"


def test_full_rejects_missing_scope_and_skip_before_layout(tmp_path: Path) -> None:
    kwargs: dict[str, Any] = dict(lanes=["web"], shared_root=tmp_path / "Shared",
                                  artifact_root=tmp_path / "artifacts", platform="bugcrowd",
                                  skip_scope=False, dry_run=False, mode="full")
    with patch.object(program_init, "pull_scope", return_value=object()), patch.object(
        program_init, "_read_scope", return_value=(set(), set())
    ):
        try:
            program_init.initialize_program("demo", **kwargs)
        except ValueError as exc:
            assert "non-empty saved scope" in str(exc)
        else:
            raise AssertionError("missing scope must block full")
    assert not (tmp_path / "Shared").exists()
    assert not (tmp_path / "artifacts").exists()
    for changes in ({"platform": None, "skip_scope": True}, {"include_docs": True, "mode": "basic"}):
        try:
            program_init.initialize_program("demo", **(kwargs | changes))
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected invalid full options: {changes}")

def test_full_handoff_refresh_not_created_and_dry_run_preview(tmp_path: Path) -> None:
    kwargs = dict(lanes=["web"], shared_root=tmp_path / "Shared", artifact_root=tmp_path / "artifacts",
                  platform="bugcrowd", skip_scope=False, mode="full")
    with patch.object(program_init, "pull_scope", return_value=object()), patch.object(
        program_init, "_read_scope", return_value=({"demo.test"}, set())
    ) as read_scope:
        first = program_init.initialize_program("demo", **kwargs, dry_run=False)
        handoff = Path(first["handoff_path"])
        read_scope.return_value = ({"other.demo.test"}, set())
        preview = program_init.initialize_program("demo", **kwargs, dry_run=True)
        assert preview["refreshed"] == [str(handoff)]
        assert handoff.read_bytes() == json.dumps(first["handoff"], indent=2, sort_keys=True).encode() + b"\n"
        second = program_init.initialize_program("demo", **kwargs, dry_run=False)
    assert second["refreshed"] == [str(handoff)]
    assert str(handoff) not in second["created"]
    assert json.loads(handoff.read_text())["scope"]["domains"] == ["other.demo.test"]

@pytest.mark.parametrize("dry_run", [True, False])
def test_full_rejects_custom_root_before_pull_or_layout(tmp_path: Path, dry_run: bool) -> None:
    mode = "full"
    with patch.object(program_init, "pull_scope") as pull, patch.object(program_init, "_read_scope") as read:
        with pytest.raises(ValueError, match="--shared-root is not supported"):
            program_init.initialize_program("demo", lanes=["web"], shared_root=tmp_path / "custom",
                                            artifact_root=tmp_path / "artifacts", platform="bugcrowd",
                                            skip_scope=False, dry_run=dry_run, mode=mode)
    pull.assert_not_called()
    read.assert_not_called()
    assert not (tmp_path / "custom").exists()
    assert not (tmp_path / "artifacts").exists()


def test_basic_platform_retains_custom_root(tmp_path: Path) -> None:
    with patch.object(program_init, "pull_scope", return_value=object()), patch.object(
        program_init, "_read_scope", return_value=({"demo.test"}, set())
    ):
        result = program_init.initialize_program(
            "demo", lanes=["web"], shared_root=tmp_path / "custom",
            artifact_root=tmp_path / "artifacts", platform="bugcrowd",
            skip_scope=False, dry_run=False,
        )
    assert isinstance(result["lanes"], dict)
    assert str(result["lanes"]["web"]).startswith(str(tmp_path / "custom"))
