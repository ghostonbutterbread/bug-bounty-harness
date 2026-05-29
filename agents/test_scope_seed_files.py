from __future__ import annotations

from pathlib import Path

from agents import scope_seed_files


def test_recon_seed_lines_split_exact_urls_and_wildcards() -> None:
    urls, wild = scope_seed_files.recon_seed_lines(
        {"*.example.com", "api.example.com", "https://*.wild.example/path", "example.org"},
        {"https://app.example.com/login"},
    )

    assert urls == ["https://app.example.com/login", "api.example.com", "example.org"]
    assert wild == ["example.com", "wild.example"]


def test_write_recon_seed_files_writes_urls_and_wild(tmp_path: Path) -> None:
    counts = scope_seed_files.write_recon_seed_files(
        tmp_path,
        {"*.example.com", "api.example.com"},
        {"https://app.example.com"},
    )

    assert counts == {"urls": 2, "wildcards": 1}
    assert (tmp_path / "urls.txt").read_text(encoding="utf-8") == "https://app.example.com\napi.example.com\n"
    assert not (tmp_path / "url.txt").exists()
    assert (tmp_path / "wild.txt").read_text(encoding="utf-8") == "example.com\n"
