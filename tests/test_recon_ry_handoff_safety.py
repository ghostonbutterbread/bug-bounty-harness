"""Offline synthetic regression for a path-denied seed on a host-wide grant."""

import socket

import pytest

from agents import recon_ry


def test_exact_start_refuses_host_with_path_exclusion(tmp_path, monkeypatch, capsys):
    def no_network(*args, **kwargs):
        raise AssertionError("network disabled for synthetic scope tests")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(recon_ry.subprocess, "run", no_network)
    monkeypatch.setattr(recon_ry.ScopeValidator, "SCOPES_BASE", tmp_path)
    monkeypatch.setattr(recon_ry.ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = tmp_path / "synthetic"
    scope.mkdir()
    (scope / "in-scope.txt").write_text("*.example.test\n")
    (scope / "out-of-scope.txt").write_text("https://app.example.test/private\n")
    args = recon_ry.build_parser().parse_args([
        "start", "synthetic", "--url", "https://app.example.test/public",
        "--profile", "exact-urls", "--dry-run",
    ])
    with pytest.raises(SystemExit, match="(?i)(exclu|den|restrict)"):
        recon_ry.start_remote(args)
    assert '"$HOME/bin/recon-ry" recon' not in capsys.readouterr().out
