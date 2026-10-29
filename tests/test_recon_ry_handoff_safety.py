"""Synthetic offline tests for the Recon-Ry launch containment gate."""

import socket

import pytest

from agents import recon_ry


@pytest.fixture
def isolated_scope(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("network disabled for synthetic scope tests")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(recon_ry.subprocess, "run", no_network)
    monkeypatch.setattr(recon_ry.subprocess, "Popen", no_network)
    monkeypatch.setattr(recon_ry.ScopeValidator, "SCOPES_BASE", tmp_path)
    monkeypatch.setattr(recon_ry.ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = tmp_path / "synthetic"
    scope.mkdir()
    return scope


def arguments(mode, tmp_path, *, dry_run=False):
    if mode == "queue":
        url_file = tmp_path / "queue.txt"
        url_file.write_text("https://app.example.test/\n")
        args = ["queue", "synthetic", "--url-file", str(url_file)]
    else:
        args = ["start", "synthetic", "--url", "https://app.example.test/public"]
        if mode == "exact":
            args += ["--profile", "exact-urls"]
            if not dry_run:
                args += ["--auth", "synthetic"]
    if dry_run:
        args.append("--dry-run")
    return recon_ry.build_parser().parse_args(args)


def test_exact_start_refuses_host_with_path_exclusion(isolated_scope, tmp_path, capsys):
    (isolated_scope / "in-scope.txt").write_text("*.example.test\n")
    (isolated_scope / "out-of-scope.txt").write_text("https://app.example.test/private\n")
    args = arguments("exact", tmp_path, dry_run=True)
    with pytest.raises(SystemExit, match="(?i)(exclu|den|restrict)"):
        recon_ry.start_remote(args)
    assert '"$HOME/bin/recon-ry" recon' not in capsys.readouterr().out


@pytest.mark.parametrize("mode", ["exact", "queue", "default"])
@pytest.mark.parametrize("filename,restriction", [
    ("out-of-scope.txt", "https://app.example.test/private"),
    ("out-of-scope.txt", "app.example.test/private"),
    ("out-of-scope.txt", "https://app.example.test"),
    ("out-of-scope.txt", "app.example.test:8443"),
    ("out-of-scope.txt", "*.other.example.test/private"),
    ("in-scope.txt", "other.example.test/allowed"),
    ("in-scope.txt", "https://other.example.test/allowed"),
    ("in-scope.txt", "https://other.example.test"),
    ("in-scope.txt", "other.example.test:8443"),
])
def test_unrepresentable_saved_scope_refuses_before_any_child(isolated_scope, tmp_path, capsys, mode, filename, restriction):
    (isolated_scope / "in-scope.txt").write_text("*.example.test\n")
    path = isolated_scope / filename
    with path.open("a") as handle:
        handle.write(restriction + "\n")
    args = arguments(mode, tmp_path)
    with pytest.raises(SystemExit) as failure:
        args.func(args)
    message = str(failure.value).lower()
    assert "restrict" in message and "request" in message and "defer" in message
    assert '"$HOME/bin/recon-ry" recon' not in capsys.readouterr().out


@pytest.mark.parametrize("mode", ["exact", "queue", "default"])
def test_host_only_scope_still_allows_dry_run(isolated_scope, tmp_path, capsys, mode):
    (isolated_scope / "in-scope.txt").write_text("*.example.test\n")
    (isolated_scope / "out-of-scope.txt").write_text("blocked.example.test\n")
    args = arguments(mode, tmp_path, dry_run=True)
    args.func(args)
    assert '"$HOME/bin/recon-ry" recon' in capsys.readouterr().out


@pytest.mark.parametrize("mode", ["exact", "queue", "default"])
def test_host_only_active_run_reaches_ssh_without_network(isolated_scope, tmp_path, monkeypatch, mode):
    (isolated_scope / "in-scope.txt").write_text("*.example.test\n192.0.2.0/24\n2001:db8::/32\n")
    (isolated_scope / "out-of-scope.txt").write_text("blocked.example.test\n")
    calls = []
    monkeypatch.setattr(recon_ry.subprocess, "run", lambda command, **kwargs: calls.append(command))
    args = arguments(mode, tmp_path)
    args.auth = None
    args.func(args)
    assert len(calls) == 1 and calls[0][0] == "ssh"
    assert '"$HOME/bin/recon-ry" recon' in calls[0][-1]


@pytest.mark.parametrize("mode", ["exact", "queue", "default"])
def test_allow_unscoped_does_not_override_restricted_exclusion(isolated_scope, tmp_path, mode):
    (isolated_scope / "out-of-scope.txt").write_text("app.example.test/private\n")
    args = arguments(mode, tmp_path)
    args.allow_unscoped = True
    with pytest.raises(SystemExit, match="request-level containment"):
        args.func(args)


@pytest.mark.parametrize("profile", ["snap", "full", "exact-urls"])
@pytest.mark.parametrize("seed,denial", [
    ("https://app.example.test/", "app.example.test"),
    ("https://app.example.test/", "*.example.test"),
    ("http://192.0.2.8/", "192.0.2.0/24"),
])
def test_unscoped_start_refuses_explicit_denial_before_process(isolated_scope, seed, denial, profile):
    (isolated_scope / "in-scope.txt").write_text("")
    (isolated_scope / "out-of-scope.txt").write_text(denial + "\n")
    args = recon_ry.build_parser().parse_args([
        "start", "synthetic", "--url", seed, "--profile", profile, "--allow-unscoped",
    ])
    with pytest.raises(SystemExit, match="(?i)(den|exclu)"):
        args.func(args)


@pytest.mark.parametrize("seed,denial", [
    ("https://app.example.test/", "app.example.test"),
    ("http://192.0.2.8/", "192.0.2.0/24"),
])
def test_unscoped_queue_refuses_explicit_denial_before_process(isolated_scope, tmp_path, seed, denial):
    (isolated_scope / "in-scope.txt").write_text("")
    (isolated_scope / "out-of-scope.txt").write_text(denial + "\n")
    urls = tmp_path / "queue.txt"
    urls.write_text("https://other.example.test/\n" + seed + "\n")
    args = recon_ry.build_parser().parse_args([
        "queue", "synthetic", "--url-file", str(urls), "--allow-unscoped",
    ])
    with pytest.raises(SystemExit, match="(?i)(den|exclu)"):
        args.func(args)


@pytest.mark.parametrize("mode", ["exact", "queue", "default"])
def test_unscoped_with_other_exclusion_refuses_unfiltered_run(isolated_scope, tmp_path, mode):
    (isolated_scope / "out-of-scope.txt").write_text("blocked.example.test\n")
    args = arguments(mode, tmp_path)
    args.auth = None
    args.allow_unscoped = True
    with pytest.raises(SystemExit, match="(?i)(den|exclu)"):
        args.func(args)


@pytest.mark.parametrize("mode", ["exact", "queue", "default"])
def test_truly_unscoped_approved_run_reaches_only_mock_ssh(isolated_scope, tmp_path, monkeypatch, mode):
    calls = []
    monkeypatch.setattr(recon_ry.subprocess, "run", lambda command, **kwargs: calls.append(command))
    args = arguments(mode, tmp_path)
    args.auth = None
    args.allow_unscoped = True
    args.func(args)
    assert len(calls) == 1 and calls[0][0] == "ssh"
