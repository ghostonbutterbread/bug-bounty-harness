"""Synthetic launch target checks; no SSH, auth or network is performed."""
import builtins
import sys

import pytest

from agents import recon_ry

PROFILES = ("snap", "full", "subs", "fast", "urls", "params", "dork", "dir", "exact-urls", "custom")


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("target", ["https://app.example.test:8443/path", "https://app.example.test:0/path"])
@pytest.mark.parametrize("unscoped", [False, True])
def test_start_rejects_unsafe_ports_before_auth_or_ssh(tmp_path, monkeypatch, profile, target, unscoped):
    monkeypatch.setattr(recon_ry.ScopeValidator, "SCOPES_BASE", tmp_path)
    monkeypatch.setattr(recon_ry.ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = tmp_path / "synthetic"
    scope.mkdir()
    if not unscoped:
        (scope / "in-scope.txt").write_text("*.example.test\n")
    def forbidden(*args, **kwargs):
        pytest.fail("auth or subprocess reached")
    monkeypatch.setattr(recon_ry, "resolve_auth_seed", forbidden)
    monkeypatch.setattr(recon_ry.subprocess, "run", forbidden)
    args = recon_ry.build_parser().parse_args(["start", "synthetic", "--url", target, "--profile", profile])
    args.allow_unscoped = unscoped
    with pytest.raises(SystemExit, match="port"):
        args.func(args)


@pytest.mark.parametrize("mode", list(PROFILES) + ["queue"])
@pytest.mark.parametrize("unscoped", [False, True])
@pytest.mark.parametrize("target", [
    "https://app.example.test:", "https://app.example.test:abc/",
    "https://app.example.test:65536/", "http://app.example.test:443/",
    "https://[2001:db8::1]:0/", "https://[2001:db8::1]:8443/",
    "https://[2001:db8::1]suffix:443/", "https://user@app.example.test/",
    "https://app%2eexample.test/", "https://app.example.test\\@evil.test/",
    "https://127.1/", "https://app.example.test\t:443/",
])
def test_all_launch_modes_reject_invalid_targets(tmp_path, monkeypatch, mode, unscoped, target):
    monkeypatch.setattr(recon_ry.ScopeValidator, "SCOPES_BASE", tmp_path)
    monkeypatch.setattr(recon_ry.ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = tmp_path / "synthetic"
    scope.mkdir()
    if not unscoped:
        (scope / "in-scope.txt").write_text("*.example.test\n2001:db8::/32\n")
    monkeypatch.setattr(recon_ry, "resolve_auth_seed", lambda *_: pytest.fail("auth reached"))
    monkeypatch.setattr(recon_ry.subprocess, "run", lambda *a, **k: pytest.fail("SSH reached"))
    if mode == "queue":
        path = tmp_path / "queue.txt"
        path.write_text(target + "\n")
        argv = ["queue", "synthetic", "--url-file", str(path)]
    else:
        argv = ["start", "synthetic", "--url", target, "--profile", mode]
    if unscoped:
        argv.append("--allow-unscoped")
    args = recon_ry.build_parser().parse_args(argv)
    with pytest.raises(SystemExit, match="Invalid|non-default"):
        args.func(args)


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("target", ["app.example.test/public", "https://app.example.test:443/public", "http://app.example.test:80/public", "https://[2001:db8::1]:443/public"])
def test_valid_host_wide_paths_reach_only_mock_ssh(tmp_path, monkeypatch, profile, target):
    monkeypatch.setattr(recon_ry.ScopeValidator, "SCOPES_BASE", tmp_path)
    monkeypatch.setattr(recon_ry.ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = tmp_path / "synthetic"
    scope.mkdir()
    (scope / "in-scope.txt").write_text("*.example.test\n2001:db8::/32\n")
    calls = []
    monkeypatch.setattr(recon_ry, "resolve_auth_seed", lambda *_: (None, {"status": "disabled"}))
    monkeypatch.setattr(recon_ry.subprocess, "run", lambda command, **kw: calls.append(command))
    args = recon_ry.build_parser().parse_args(["start", "synthetic", "--url", target, "--profile", profile])
    args.func(args)
    assert len(calls) == 1 and calls[0][0] == "ssh"


@pytest.mark.parametrize("filename", ["in-scope.txt", "out-of-scope.txt", "excluded.txt"])
@pytest.mark.parametrize("profile,unscoped,read_number", [
    (profile, unscoped, read_number)
    for profile in PROFILES for unscoped in (False, True)
    for read_number in range(1, (7 if unscoped else 5) if profile in {"snap", "full", "subs", "fast", "urls"} else 4)
])
def test_every_start_read_propagates_actual_wrapper_scope_error(tmp_path, monkeypatch, filename, profile, unscoped, read_number):
    monkeypatch.setattr(recon_ry.ScopeValidator, "SCOPES_BASE", tmp_path)
    monkeypatch.setattr(recon_ry.ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = tmp_path / "synthetic"
    scope.mkdir()
    (scope / "in-scope.txt").write_text("" if unscoped else "*.example.test\n")
    path = scope / filename
    if filename != "in-scope.txt":
        path.write_text("")
    original_open = builtins.open
    reads = 0
    def failing_open(file, *args, **kwargs):
        nonlocal reads
        if str(file) == str(path):
            reads += 1
            if reads == read_number:
                raise PermissionError("synthetic read failure")
        return original_open(file, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", failing_open)
    monkeypatch.setattr(recon_ry, "resolve_auth_seed", lambda *_: pytest.fail("auth reached"))
    monkeypatch.setattr(recon_ry.subprocess, "run", lambda *a, **k: pytest.fail("SSH reached"))
    args = recon_ry.build_parser().parse_args(["start", "synthetic", "--url", "https://app.example.test/", "--profile", profile])
    args.allow_unscoped = unscoped
    validator_module = sys.modules[recon_ry.ScopeValidator.__module__]
    with pytest.raises(validator_module.ScopeFileReadError) as failure:
        args.func(args)
    assert isinstance(failure.value.__cause__, PermissionError)
    assert reads == read_number


@pytest.mark.parametrize("filename", ["in-scope.txt", "out-of-scope.txt", "excluded.txt"])
@pytest.mark.parametrize("unscoped", [False, True])
@pytest.mark.parametrize("read_number", [1, 2])
def test_queue_read_failures_abort(tmp_path, monkeypatch, filename, unscoped, read_number):
    monkeypatch.setattr(recon_ry.ScopeValidator, "SCOPES_BASE", tmp_path)
    monkeypatch.setattr(recon_ry.ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = tmp_path / "synthetic"
    scope.mkdir()
    (scope / "in-scope.txt").write_text("" if unscoped else "*.example.test\n")
    path = scope / filename
    if filename != "in-scope.txt":
        path.write_text("")
    urls = tmp_path / "queue.txt"
    urls.write_text("https://app.example.test/\nhttps://other.example.test/\n")
    original_open = builtins.open
    reads = 0
    def failing_open(file, *args, **kwargs):
        nonlocal reads
        if str(file) == str(path):
            reads += 1
            if reads == read_number:
                raise PermissionError("synthetic read failure")
        return original_open(file, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", failing_open)
    monkeypatch.setattr(recon_ry.subprocess, "run", lambda *a, **k: pytest.fail("SSH reached"))
    args = recon_ry.build_parser().parse_args(["queue", "synthetic", "--url-file", str(urls)])
    args.allow_unscoped = unscoped
    validator_module = sys.modules[recon_ry.ScopeValidator.__module__]
    with pytest.raises(validator_module.ScopeFileReadError) as failure:
        args.func(args)
    assert isinstance(failure.value.__cause__, PermissionError)
    assert reads == read_number


@pytest.mark.parametrize("filename", ["in-scope.txt", "out-of-scope.txt", "excluded.txt"])
@pytest.mark.parametrize("unscoped", [False, True])
@pytest.mark.parametrize("builder", ["seed", "scope"])
def test_builders_never_swallow_scope_file_error(tmp_path, monkeypatch, filename, unscoped, builder):
    monkeypatch.setattr(recon_ry.ScopeValidator, "SCOPES_BASE", tmp_path)
    monkeypatch.setattr(recon_ry.ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = tmp_path / "synthetic"
    scope.mkdir()
    (scope / "in-scope.txt").write_text("" if unscoped else "*.example.test\n")
    path = scope / filename
    if filename != "in-scope.txt":
        path.write_text("")
    original_open = builtins.open
    def failing_open(file, *args, **kwargs):
        if str(file) == str(path):
            raise PermissionError("synthetic read failure")
        return original_open(file, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", failing_open)
    validator_module = sys.modules[recon_ry.ScopeValidator.__module__]
    with pytest.raises(validator_module.ScopeFileReadError) as failure:
        if builder == "seed":
            recon_ry.build_remote_seed_files("synthetic", "https://app.example.test/", allow_unscoped=unscoped)
        else:
            recon_ry.build_remote_scope_files("synthetic", url="https://app.example.test/", allow_unscoped=unscoped)
    assert isinstance(failure.value.__cause__, PermissionError)
