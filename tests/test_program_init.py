from __future__ import annotations

from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import program_init


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
