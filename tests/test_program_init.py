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
    assert (apk_root / "input" / "original").is_dir()
    assert (artifact_root / "demo_program" / "web" / "proxy" / "har").is_dir()
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
    assert list(stages) == ["full-recon", "js-url-acquisition", "katana-endpoints", "api-mapping",
                            "public-docs", "recon-bus-promotion", "url-ingest-review"]
    assert stages["katana-endpoints"]["depends_on"] == ["js-url-acquisition"]
    assert "-jc" in stages["katana-endpoints"]["task"]
    assert "completed comparable" in stages["full-recon"]["task"]
    assert stages["recon-bus-promotion"]["status"] == "pending-prerequisites"
    assert all(stage["status"].startswith("pending-") for stage in stages.values())
    assert "does not spawn Hermes subagents" in data["execution_boundary"]
    assert data["scope"]["urls"] == ["https://api.demo.test/v1"]


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
