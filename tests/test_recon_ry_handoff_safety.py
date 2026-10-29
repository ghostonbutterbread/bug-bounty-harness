"""Synthetic offline tests for the Recon-Ry launch containment gate."""

import builtins
import socket

import pytest

from agents import recon_ry
from scope_validator import ScopeExclusionReadError


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


def fail_exclusion_open(monkeypatch, path, *, fail_on_read=1):
    real_open = builtins.open
    reads = 0

    def guarded_open(file, *args, **kwargs):
        nonlocal reads
        if str(file) == str(path):
            reads += 1
            if reads >= fail_on_read:
                raise PermissionError("synthetic exclusion read failure")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)


@pytest.mark.parametrize("filename", ["out-of-scope.txt", "excluded.txt"])
@pytest.mark.parametrize("builder", ["scope", "seed", "seed_unscoped"])
def test_builders_propagate_exclusion_read_failure(isolated_scope, monkeypatch, filename, builder):
    (isolated_scope / "in-scope.txt").write_text("*.example.test\n")
    exclusion = isolated_scope / filename
    exclusion.write_text("blocked.example.test\n")
    fail_exclusion_open(monkeypatch, exclusion)
    with pytest.raises(ScopeExclusionReadError, match=filename) as failure:
        if builder == "scope":
            recon_ry.build_remote_scope_files("synthetic")
        else:
            recon_ry.build_remote_seed_files("synthetic", "https://app.example.test/", allow_unscoped=builder == "seed_unscoped")
    assert isinstance(failure.value.__cause__, PermissionError)
    assert "synthetic exclusion read failure" in str(failure.value)


def test_exact_late_exclusion_failure_precedes_auth_process(isolated_scope, tmp_path, monkeypatch):
    (isolated_scope / "in-scope.txt").write_text("*.example.test\n")
    exclusion = isolated_scope / "excluded.txt"
    exclusion.write_text("blocked.example.test\n")
    # Initial guard and seed load succeed; scope-file load fails.
    fail_exclusion_open(monkeypatch, exclusion, fail_on_read=3)
    args = arguments("exact", tmp_path)
    with pytest.raises(ScopeExclusionReadError, match="excluded.txt"):
        args.func(args)


@pytest.mark.parametrize("mode", ["exact", "default", "queue"])
@pytest.mark.parametrize("filename", ["out-of-scope.txt", "excluded.txt"])
@pytest.mark.parametrize("grants", ["", "*.example.test\n"])
@pytest.mark.parametrize("allow_unscoped", [False, True])
def test_launch_initial_exclusion_read_failure(isolated_scope, tmp_path, monkeypatch, mode, filename, grants, allow_unscoped):
    (isolated_scope / "in-scope.txt").write_text(grants)
    exclusion = isolated_scope / filename
    exclusion.write_text("blocked.example.test\n")
    fail_exclusion_open(monkeypatch, exclusion)
    args = arguments(mode, tmp_path)
    args.allow_unscoped = allow_unscoped
    with pytest.raises(ScopeExclusionReadError, match=filename) as failure:
        args.func(args)
    assert str(exclusion) in str(failure.value)
    assert isinstance(failure.value.__cause__, PermissionError)


@pytest.mark.parametrize("filename", ["out-of-scope.txt", "excluded.txt"])
@pytest.mark.parametrize("mode,fail_on_read", [
    ("exact", 2), ("exact", 3),
    ("default", 2), ("default", 3), ("default", 4),
    ("queue", 2),
])
def test_later_exclusion_read_failure_never_launches(isolated_scope, tmp_path, monkeypatch, filename, mode, fail_on_read):
    (isolated_scope / "in-scope.txt").write_text("*.example.test\n")
    exclusion = isolated_scope / filename
    exclusion.write_text("blocked.example.test\n")
    fail_exclusion_open(monkeypatch, exclusion, fail_on_read=fail_on_read)
    args = arguments(mode, tmp_path)
    if mode == "queue":
        (tmp_path / "queue.txt").write_text("https://app.example.test/\nhttps://other.example.test/\n")
    with pytest.raises(ScopeExclusionReadError, match=filename) as failure:
        args.func(args)
    assert isinstance(failure.value.__cause__, PermissionError)


@pytest.mark.parametrize("filename", ["out-of-scope.txt", "excluded.txt"])
@pytest.mark.parametrize("mode,fail_on_read", [
    ("exact", 2), ("exact", 3),
    ("default", 2), ("default", 3), ("default", 4), ("default", 5), ("default", 6),
    ("queue", 2),
])
def test_unscoped_later_exclusion_read_failure_never_launches(isolated_scope, tmp_path, monkeypatch, filename, mode, fail_on_read):
    (isolated_scope / "in-scope.txt").write_text("")
    exclusion = isolated_scope / filename
    exclusion.write_text("")
    fail_exclusion_open(monkeypatch, exclusion, fail_on_read=fail_on_read)
    args = arguments(mode, tmp_path)
    args.allow_unscoped = True
    if mode == "queue":
        (tmp_path / "queue.txt").write_text("https://app.example.test/\nhttps://other.example.test/\n")
    with pytest.raises(ScopeExclusionReadError, match=filename) as failure:
        args.func(args)
    assert isinstance(failure.value.__cause__, PermissionError)


@pytest.mark.parametrize("mode", ["exact", "default", "queue"])
def test_two_exclusion_files_include_denied_seed(isolated_scope, tmp_path, mode):
    (isolated_scope / "in-scope.txt").write_text("*.example.test\n")
    (isolated_scope / "out-of-scope.txt").write_text("blocked.example.test\n")
    (isolated_scope / "excluded.txt").write_text("app.example.test\n")
    args = arguments(mode, tmp_path)
    with pytest.raises(SystemExit, match="NOT in scope"):
        args.func(args)
    files, _ = recon_ry.build_remote_scope_files("synthetic")
    assert "blocked.example.test" in files["_scope/out-of-scope-hosts.txt"]
    assert "app.example.test" in files["_scope/out-of-scope-hosts.txt"]


@pytest.mark.parametrize("mode", ["exact", "default", "queue"])
@pytest.mark.parametrize("allow_unscoped", [False, True])
def test_two_exclusion_files_include_later_restriction(isolated_scope, tmp_path, mode, allow_unscoped):
    (isolated_scope / "in-scope.txt").write_text("*.example.test\n")
    (isolated_scope / "out-of-scope.txt").write_text("blocked.example.test\n")
    (isolated_scope / "excluded.txt").write_text("app.example.test/private\n")
    args = arguments(mode, tmp_path)
    args.allow_unscoped = allow_unscoped
    with pytest.raises(SystemExit, match="request-level containment"):
        args.func(args)


@pytest.mark.parametrize("mode", ["exact", "default", "queue"])
def test_host_only_without_exclusions_reaches_mock_ssh(isolated_scope, tmp_path, monkeypatch, mode):
    (isolated_scope / "in-scope.txt").write_text("*.example.test\n")
    calls = []
    monkeypatch.setattr(recon_ry.subprocess, "run", lambda command, **kwargs: calls.append(command))
    args = arguments(mode, tmp_path)
    args.auth = None
    args.func(args)
    assert len(calls) == 1 and calls[0][0] == "ssh"


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
