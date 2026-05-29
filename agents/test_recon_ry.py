from __future__ import annotations

import json
from pathlib import Path

from agents import recon_ry


def test_ingest_copies_recon_outputs_and_writes_manifest(tmp_path: Path) -> None:
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
