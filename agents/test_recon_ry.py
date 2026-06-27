from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from pathlib import Path

from agents import recon_ry


def test_ingest_copies_recon_outputs_and_writes_manifest(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(recon_ry, "import_url_artifacts", lambda **_: [])
    monkeypatch.setattr(recon_ry, "summarize_url_index", lambda _program: {})
    source = tmp_path / "source"
    source.mkdir()
    (source / "alive.txt").write_text("https://a.example\nhttps://b.example\n", encoding="utf-8")
    (source / "params.txt").write_text("https://a.example/?q=1\n", encoding="utf-8")
    (source / "jsfiles.txt").write_text("https://a.example/app.js\n", encoding="utf-8")
    (source / "dirs_status").mkdir()
    (source / "dirs_status" / "200.txt").write_text("https://a.example/admin\n", encoding="utf-8")

    args = recon_ry.build_parser().parse_args(
        [
            "ingest",
            "demo",
            "--source",
            str(source),
            "--target",
            "app.example",
            "--root",
            str(tmp_path / "shared"),
        ]
    )

    manifest_path = recon_ry.ingest(args)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["tool"] == "recon-ry"
    assert manifest["program"] == "demo"
    assert manifest["family"] == "web_bounty"
    assert manifest["lane"] == "web"
    assert manifest["counts"]["alive_urls"] == 2
    assert manifest["counts"]["params"] == 1
    assert manifest["counts"]["js_files"] == 1
    assert manifest["counts"]["promoted_findings"] == 0
    assert (manifest_path.parent / "parsed" / "alive.txt").read_text(encoding="utf-8").startswith("https://a.example")
    assert (manifest_path.parent / "raw" / "dirs_status" / "200.txt").exists()


def test_start_dry_run_uses_hoster_wrapper(capsys) -> None:
    parser = recon_ry.build_parser()
    args = parser.parse_args(
        [
            "start",
            "demo",
            "--url",
            "example.com",
            "--profile",
            "subs",
            "--dry-run",
            "--allow-unscoped",
        ]
    )

    recon_ry.start_remote(args)

    output = capsys.readouterr().out
    assert "$HOME/bin/recon-ry" in output
    assert "--subs" in output
    assert "--url 'example.com'" in output
    assert "rate_limit.conf" in output
    assert "default=2" in output
    assert "urls.txt" in output
    assert "wild.txt" in output
    assert "export PATH='$HOME/go/bin:$HOME/.local/bin:$HOME/bin:/usr/local/bin:/usr/bin:/bin':\"$PATH\"" in output


def test_start_dry_run_stages_manual_auth_without_leaking_values(capsys) -> None:
    parser = recon_ry.build_parser()
    args = parser.parse_args(
        [
            "start",
            "demo",
            "--url",
            "https://example.com",
            "--profile",
            "urls",
            "--dry-run",
            "--allow-unscoped",
            "--auth-header",
            "Authorization: Bearer SECRET_TOKEN",
            "--cookie",
            "sid=SECRET_COOKIE",
        ]
    )

    recon_ry.start_remote(args)

    output = capsys.readouterr().out
    assert "--auth-seed '/home/ryushe/bounties/demo/.auth/recon-ry-auth.json'" in output
    assert "env RECON_RY_AUTH_SEED='/home/ryushe/bounties/demo/.auth/recon-ry-auth.json'" in output
    assert '"redacted": true' in output
    assert "SECRET_TOKEN" not in output
    assert "SECRET_COOKIE" not in output


def test_start_dry_run_auth_limits_seed_files_to_requested_target(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        recon_ry,
        "build_remote_seed_files",
        lambda *_args, **_kwargs: {
            "urls.txt": "https://example.com\nhttps://api.example.com\n",
            "wild.txt": "example.com\n",
        },
    )
    parser = recon_ry.build_parser()
    args = parser.parse_args(
        [
            "start",
            "demo",
            "--url",
            "https://example.com",
            "--profile",
            "urls",
            "--dry-run",
            "--allow-unscoped",
            "--auth-header",
            "Authorization: Bearer SECRET_TOKEN",
        ]
    )

    recon_ry.start_remote(args)

    output = capsys.readouterr().out
    assert "https://example.com" in output
    assert "https://api.example.com" not in output
    assert "cat > '/home/ryushe/bounties/demo/wild.txt'" in output
    assert "'RECONRY_WILD_TXT'\nRECONRY_WILD_TXT" in output


def test_start_dry_run_uses_explicit_auth_seed_metadata_only(tmp_path: Path, capsys) -> None:
    seed = tmp_path / "auth.json"
    seed.write_text(
        json.dumps(
            {
                "account_label": "blue",
                "session_source": "test",
                "cookies": [{"name": "sid", "value": "SECRET_COOKIE", "url": "https://example.com"}],
                "headers": {"Authorization": "Bearer SECRET_TOKEN"},
            }
        ),
        encoding="utf-8",
    )
    seed.chmod(0o600)
    parser = recon_ry.build_parser()
    args = parser.parse_args(
        [
            "start",
            "demo",
            "--url",
            "https://example.com",
            "--profile",
            "urls",
            "--dry-run",
            "--allow-unscoped",
            "--auth-seed-file",
            str(seed),
        ]
    )

    recon_ry.start_remote(args)

    output = capsys.readouterr().out
    assert '"cookie_count": 1' in output
    assert "Authorization" in output
    assert "SECRET_TOKEN" not in output
    assert "SECRET_COOKIE" not in output


def test_live_auth_staging_uses_stdin_not_ssh_argv(monkeypatch) -> None:
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(recon_ry.subprocess, "run", fake_run)
    args = SimpleNamespace(remote="ryushe@hoster", ssh_key="/tmp/key", dry_run=False)
    seed = {
        "headers": {"Authorization": "Bearer SECRET_TOKEN"},
        "cookies": [{"name": "sid", "value": "SECRET_COOKIE", "url": "https://example.com"}],
    }

    path = recon_ry.stage_remote_auth_seed(args, "/home/ryushe/bounties/demo", seed, {"status": "enabled"})

    assert path == "/home/ryushe/bounties/demo/.auth/recon-ry-auth.json"
    assert calls
    command, kwargs = calls[0]
    assert "SECRET_TOKEN" not in " ".join(command)
    assert "SECRET_COOKIE" not in " ".join(command)
    assert "SECRET_TOKEN" in kwargs["input"]
    assert "SECRET_COOKIE" in kwargs["input"]


def test_build_remote_seed_files_uses_saved_scope(monkeypatch) -> None:
    class DemoScope:
        def __init__(self, program: str, strict: bool = True):
            self.program = program
            self.strict = strict
            self._entries = [
                SimpleNamespace(raw="*.example.com", entry_type="wildcard"),
                SimpleNamespace(raw="api.example.com", entry_type="domain"),
                SimpleNamespace(raw="https://app.example.com/login", entry_type="url_pattern"),
            ]

        def is_empty(self) -> bool:
            return False

    monkeypatch.setattr(recon_ry, "ScopeValidator", DemoScope)

    files = recon_ry.build_remote_seed_files("demo", "example.com")

    assert files["urls.txt"] == "example.com\nhttps://app.example.com/login\napi.example.com\n"
    assert "url.txt" not in files
    assert files["wild.txt"] == "example.com\n"


def test_validate_start_scope_fails_closed_when_no_scope(monkeypatch) -> None:
    class EmptyScope:
        def __init__(self, program: str, strict: bool = True):
            self.program = program
            self.strict = strict

        def is_empty(self) -> bool:
            return True

    monkeypatch.setattr(recon_ry, "ScopeValidator", EmptyScope)

    try:
        recon_ry.validate_start_scope("demo", "https://example.com")
    except SystemExit as exc:
        assert "No saved scope" in str(exc)
    else:
        raise AssertionError("expected fail-closed SystemExit")


def test_validate_start_scope_rejects_out_of_scope(monkeypatch) -> None:
    class DemoScope:
        def __init__(self, program: str, strict: bool = True):
            self.program = program
            self.strict = strict

        def is_empty(self) -> bool:
            return False

        def validate_or_fail(self, url: str) -> None:
            raise recon_ry.OutOfScopeError("out of scope")

    monkeypatch.setattr(recon_ry, "ScopeValidator", DemoScope)

    try:
        recon_ry.validate_start_scope("demo", "https://evil.example")
    except SystemExit as exc:
        assert "out of scope" in str(exc)
    else:
        raise AssertionError("expected out-of-scope SystemExit")
