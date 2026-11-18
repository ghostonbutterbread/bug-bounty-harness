from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "agents" / "public_artifacts.py"


def run_cli(tmp_path: Path, *args: str) -> dict:
    env = os.environ.copy()
    core_source = env.get("BOUNTY_CORE_TEST_SOURCE")
    if core_source:
        env["PYTHONPATH"] = core_source
    else:
        env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, str(CLI), "--root", str(tmp_path), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return json.loads(result.stdout)


def record_args(*, event: str, artifact_id: str | None = None, visibility: str = "public", cleanup_verified: bool = False) -> list[str]:
    args = [
        "record", "--program", "community-signal", "--event", event,
        "--account-ref", "owned+community@example.test", "--artifact-kind", "community-post",
        "--url", "https://community.example.test/posts/42", "--visibility", visibility,
    ]
    if artifact_id:
        args.extend(("--artifact-id", artifact_id))
    if cleanup_verified:
        args.append("--cleanup-verified")
    return args


def test_cli_records_reuses_and_cleans_an_owned_public_artifact(tmp_path):
    created = run_cli(tmp_path, *record_args(event="created"))
    current = run_cli(tmp_path, "current", "--program", "community-signal")
    assert current["artifacts"] == [created]

    private = run_cli(tmp_path, *record_args(event="visibility_changed", artifact_id=created["artifact_id"], visibility="private"))
    assert run_cli(tmp_path, "current", "--program", "community-signal")["artifacts"] == [private]
    run_cli(tmp_path, *record_args(event="cleanup_pending", artifact_id=created["artifact_id"], visibility="private"))
    assert run_cli(tmp_path, "current", "--program", "community-signal")["artifacts"] == []
    run_cli(tmp_path, *record_args(event="deleted", artifact_id=created["artifact_id"], visibility="private"))
    verified = run_cli(tmp_path, *record_args(event="cleanup_verified", artifact_id=created["artifact_id"], visibility="private", cleanup_verified=True))

    history = run_cli(tmp_path, "current", "--program", "community-signal", "--include-cleaned")
    assert history["artifacts"] == [verified]


def test_cli_rejects_lifecycle_events_without_the_prior_artifact(tmp_path):
    env = os.environ.copy()
    core_source = env.get("BOUNTY_CORE_TEST_SOURCE")
    if core_source:
        env["PYTHONPATH"] = core_source
    else:
        env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, str(CLI), "--root", str(tmp_path), *record_args(event="deleted")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode != 0
    assert "artifact_id is required" in result.stderr


def test_cli_rejects_sensitive_urls_and_cleanup_that_skips_private_pending_state(tmp_path):
    env = os.environ.copy()
    core_source = env.get("BOUNTY_CORE_TEST_SOURCE")
    if core_source:
        env["PYTHONPATH"] = core_source
    else:
        env.pop("PYTHONPATH", None)
    created = run_cli(tmp_path, *record_args(event="created"))
    for args, message in (
        (record_args(event="created")[:-2] + ["--url", "https://community.example.test/posts/43?share=SHARE_SECRET"], "canonical URL"),
        (record_args(event="cleanup_pending", artifact_id=created["artifact_id"], visibility="private"), "prior recorded visibility"),
        (record_args(event="deleted", artifact_id=created["artifact_id"], visibility="public"), "visibility private"),
        (record_args(event="deleted", artifact_id=created["artifact_id"], visibility="private"), "prior cleanup_pending"),
    ):
        result = subprocess.run(
            [sys.executable, str(CLI), "--root", str(tmp_path), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode != 0
        assert message in result.stderr


def test_cli_accepts_benign_security_language_in_purpose(tmp_path):
    purpose = "Testing token handling and session lifecycle"
    created = run_cli(tmp_path, *record_args(event="created"), "--purpose", purpose)
    assert created["purpose"] == purpose
    assert run_cli(tmp_path, "current", "--program", "community-signal")["artifacts"] == [created]


@pytest.mark.parametrize("purpose", [
    "session=synthetic-secret-value",
    "Reference https://example.test/path?token=synthetic-secret-value",
])
def test_cli_rejects_credential_bearing_purpose_without_recording(tmp_path, purpose):
    env = os.environ.copy()
    env.pop("BOUNTY_CORE_TEST_SOURCE", None)
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, str(CLI), "--root", str(tmp_path),
         *record_args(event="created"), "--purpose", purpose],
        cwd=ROOT, capture_output=True, text=True, env=env,
    )
    assert result.returncode != 0
    assert "non-secret short label" in result.stderr
    assert "synthetic-secret-value" not in result.stdout + result.stderr
    assert run_cli(tmp_path, "current", "--program", "community-signal")["artifacts"] == []
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert b"synthetic-secret-value" not in path.read_bytes()
