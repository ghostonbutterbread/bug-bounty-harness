from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from pathlib import Path

from agents import recon_ry


def test_ingest_copies_recon_outputs_and_writes_manifest(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(recon_ry, "promote_run", lambda _args: {"status": "ok", "appends": {}})
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
    assert (manifest_path.parent / "parsed" / "dirs_status" / "200.txt").exists()
    assert manifest["recon_bus_promotion"]["status"] == "ok"


def test_remote_ingest_uses_unique_fetch_dir_and_cleans_on_failure(tmp_path: Path, monkeypatch) -> None:
    fetched_dirs: list[Path] = []

    def fake_fetch(_source: str, destination: Path, _ssh_key: Path | None = None) -> None:
        fetched_dirs.append(destination)
        destination.mkdir(parents=True, exist_ok=True)
        (destination / ".auth").mkdir()
        (destination / ".auth" / "recon-ry-auth.json").write_text("secret", encoding="utf-8")
        (destination / "alive.txt").write_text("https://a.example\n", encoding="utf-8")

    def fail_promotion(_args):
        raise RuntimeError("promotion failed")

    monkeypatch.setattr(recon_ry, "fetch_remote_source", fake_fetch)
    monkeypatch.setattr(recon_ry, "promote_run", fail_promotion)
    monkeypatch.setattr(recon_ry, "summarize_url_index", lambda _program: {})
    args = recon_ry.build_parser().parse_args(
        [
            "ingest",
            "demo",
            "--source",
            "ryushe@hoster:/home/ryushe/bounties/demo",
            "--target",
            "app.example",
            "--root",
            str(tmp_path / "shared"),
            "--work-dir",
            str(tmp_path / "fetch-work"),
        ]
    )

    manifest_path = recon_ry.ingest(args)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "partial"
    assert manifest["recon_bus_promotion"]["status"] == "partial_promotion_failed"

    assert len(fetched_dirs) == 1
    assert fetched_dirs[0].name.startswith("recon_ry_fetch_demo_")
    assert not fetched_dirs[0].exists()


def test_remote_ingest_keep_fetched_uses_per_run_dirs(tmp_path: Path, monkeypatch) -> None:
    fetched_dirs: list[Path] = []

    def fake_fetch(_source: str, destination: Path, _ssh_key: Path | None = None) -> None:
        fetched_dirs.append(destination)
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "alive.txt").write_text("https://a.example\n", encoding="utf-8")

    monkeypatch.setattr(recon_ry, "fetch_remote_source", fake_fetch)
    monkeypatch.setattr(recon_ry, "promote_run", lambda _args: {"status": "ok", "appends": {}})
    monkeypatch.setattr(recon_ry, "summarize_url_index", lambda _program: {})

    for _ in range(2):
        args = recon_ry.build_parser().parse_args(
            [
                "ingest",
                "demo",
                "--source",
                "ryushe@hoster:/home/ryushe/bounties/demo",
                "--target",
                "app.example",
                "--root",
                str(tmp_path / "shared"),
                "--work-dir",
                str(tmp_path / "fetch-work"),
                "--keep-fetched",
            ]
        )
        recon_ry.ingest(args)

    assert len(fetched_dirs) == 2
    assert fetched_dirs[0] != fetched_dirs[1]
    assert all(path.exists() for path in fetched_dirs)


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
    assert "--url" in output
    assert "example.com" in output
    assert "rate_limit.conf" in output
    assert "timeout=0" in output
    assert "default=2" in output
    assert "aggregating run into Recon Bus" in output
    assert "bbh --root" in output
    assert "bbh --print-command scripts/recon_bus.py" in output
    assert output.index("bbh --root") < output.index("nohup")
    assert "bbh scripts/recon_bus.py" in output
    assert "/home/ryushe/projects/bug_bounty_harness" not in output
    assert "promote-run" in output
    assert "--no-probe" in output
    assert "urls.txt" in output
    assert "wild.txt" in output
    assert "export PATH='$HOME/go/bin:$HOME/.local/bin:$HOME/bin:/usr/local/bin:/usr/bin:/bin':\"$PATH\"" in output


def test_start_dry_run_uses_exact_urls_flag(capsys) -> None:
    parser = recon_ry.build_parser()
    args = parser.parse_args(
        [
            "start",
            "demo",
            "--url",
            "https://app.example.com",
            "--profile",
            "exact-urls",
            "--dry-run",
            "--allow-unscoped",
        ]
    )

    recon_ry.start_remote(args)

    output = capsys.readouterr().out
    assert '"$HOME/bin/recon-ry" recon --exact-urls' in output
    assert "--full" not in output
    assert "--subs" not in output


def test_start_dry_run_uses_header_safe_exact_profile_for_manual_headers(capsys) -> None:
    parser = recon_ry.build_parser()
    args = parser.parse_args(
        [
            "start",
            "demo",
            "--url",
            "https://app.example.com",
            "--profile",
            "exact-urls",
            "--auth-header",
            "X-Bugcrowd-Username: ryushe",
            "--dry-run",
            "--allow-unscoped",
        ]
    )

    recon_ry.start_remote(args)

    output = capsys.readouterr().out
    assert '"$HOME/bin/recon-ry" recon --profile exact-urls-header' in output
    assert '"$HOME/bin/recon-ry" recon --exact-urls' not in output
    assert '"header_names": [' in output
    assert "X-Bugcrowd-Username" in output


def test_queue_dry_run_uses_one_exact_url_at_a_time(tmp_path: Path, capsys) -> None:
    urls = tmp_path / "targets.txt"
    urls.write_text("https://one.example.com\nhttps://two.example.com/\n", encoding="utf-8")
    args = recon_ry.build_parser().parse_args(
        [
            "queue", "demo", "--url-file", str(urls), "--profile", "exact-urls", "--allow-unscoped", "--dry-run"
        ]
    )

    recon_ry.queue_remote(args)

    output = capsys.readouterr().out
    assert "queue_urls.txt" in output
    assert "timeout=0" in output
    assert "--exact-urls" in output
    assert "promote-run" not in output
    assert "one.example.com" in output
    assert "two.example.com" in output
    assert "while IFS= read -r target_url" in output


def test_start_and_queue_timeout_default_to_unlimited() -> None:
    parser = recon_ry.build_parser()
    start = parser.parse_args(["start", "demo", "--url", "https://example.com"])
    queue = parser.parse_args(["queue", "demo", "--url-file", "/tmp/targets.txt"])

    assert start.timeout == 0
    assert queue.timeout == 0


def test_start_full_fails_closed_when_scope_has_no_wildcards(monkeypatch) -> None:
    class ExactOnlyScope:
        def __init__(self, program: str, strict: bool = True):
            self._entries = [SimpleNamespace(raw="https://api.example.com", entry_type="url_pattern")]

        def is_empty(self) -> bool:
            return False

        def validate_or_fail(self, _url: str) -> None:
            return None

    monkeypatch.setattr(recon_ry, "ScopeValidator", ExactOnlyScope)
    args = recon_ry.build_parser().parse_args(
        ["start", "demo", "--url", "https://api.example.com", "--profile", "full", "--dry-run"]
    )

    try:
        recon_ry.start_remote(args)
    except SystemExit as exc:
        assert "no wildcard targets" in str(exc)
    else:
        raise AssertionError("expected full profile to reject exact-only scope")


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
    assert "--auth-seed" in output
    assert "/home/ryushe/bounties/demo/.auth/recon-ry-auth.json" in output
    assert "nohup env RECON_RY_AUTH_SEED" in output
    assert "RECON_RY_AUTH_HOST" in output
    assert "bash -c" in output
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
