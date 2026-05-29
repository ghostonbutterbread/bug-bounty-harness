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
    args = parser.parse_args(["start", "demo", "--url", "example.com", "--profile", "subs", "--dry-run"])

    recon_ry.start_remote(args)

    output = capsys.readouterr().out
    assert "$HOME/bin/recon-ry" in output
    assert "--subs" in output
    assert "--url 'example.com'" in output
