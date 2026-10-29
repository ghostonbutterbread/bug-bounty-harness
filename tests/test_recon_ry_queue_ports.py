"""Offline queue destination safety tests; no real subprocesses or network."""

import socket

import pytest

from agents import recon_ry


@pytest.fixture
def queue_env(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected network, auth or subprocess")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(recon_ry.subprocess, "run", forbidden)
    monkeypatch.setattr(recon_ry.subprocess, "Popen", forbidden)
    monkeypatch.setattr(recon_ry, "resolve_auth_seed", forbidden)
    monkeypatch.setattr(recon_ry.ScopeValidator, "SCOPES_BASE", tmp_path)
    monkeypatch.setattr(recon_ry.ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = tmp_path / "synthetic"
    scope.mkdir()
    return scope


@pytest.mark.parametrize("unscoped", [False, True])
def test_queue_rejects_distinct_nondefault_ports_before_launch(queue_env, tmp_path, unscoped):
    if not unscoped:
        (queue_env / "in-scope.txt").write_text("*.example.test\n")
    urls = tmp_path / "targets.txt"
    urls.write_text("https://app.example.test:8443/\nhttps://app.example.test:9443/\n")
    argv = ["queue", "synthetic", "--url-file", str(urls)]
    if unscoped:
        argv.append("--allow-unscoped")
    args = recon_ry.build_parser().parse_args(argv)
    with pytest.raises(SystemExit, match="non-default port"):
        args.func(args)


@pytest.mark.parametrize("target", ["https://[2001:db8::1]:8443/", "http://app.example.test:8080/"])
def test_queue_rejects_nondefault_port_even_after_valid_target(queue_env, tmp_path, target):
    urls = tmp_path / "targets.txt"
    urls.write_text("https://app.example.test/\n" + target + "\n")
    args = recon_ry.build_parser().parse_args([
        "queue", "synthetic", "--url-file", str(urls), "--allow-unscoped",
    ])
    with pytest.raises(SystemExit, match="non-default port"):
        args.func(args)


def test_queue_keeps_http_and_https_in_separate_projects(queue_env, tmp_path, monkeypatch):
    urls = tmp_path / "targets.txt"
    urls.write_text("https://app.example.test/\nhttp://app.example.test:80/\n")
    calls = []
    monkeypatch.setattr(recon_ry.subprocess, "run", lambda command, **kwargs: calls.append(command))
    args = recon_ry.build_parser().parse_args([
        "queue", "synthetic", "--url-file", str(urls), "--allow-unscoped",
    ])
    args.func(args)
    command = calls[0][-1]
    body = command.split("<<'RECONRY_QUEUE_URLS'\n", 1)[1].split("RECONRY_QUEUE_URLS\n", 1)[0]
    assert body.splitlines() == ["https://app.example.test/", "http://app.example.test:80/"]
    assert 'project="$queue_root/$target_scheme-$target_host"' in command


def test_equivalent_default_ports_are_validated_before_dedup(queue_env, tmp_path, monkeypatch):
    urls = tmp_path / "targets.txt"
    submitted = ["https://app.example.test:443/", "https://app.example.test/"]
    urls.write_text("\n".join(submitted) + "\n")
    seen = []
    real_load = recon_ry._load_recon_scope
    calls = []

    def load(program, url, **kwargs):
        seen.append(url)
        return real_load(program, url, **kwargs)

    monkeypatch.setattr(recon_ry, "_load_recon_scope", load)
    monkeypatch.setattr(recon_ry.subprocess, "run", lambda command, **kwargs: calls.append(command))
    args = recon_ry.build_parser().parse_args([
        "queue", "synthetic", "--url-file", str(urls), "--allow-unscoped",
    ])
    args.func(args)
    assert seen == submitted
    body = calls[0][-1].split("<<'RECONRY_QUEUE_URLS'\n", 1)[1].split("RECONRY_QUEUE_URLS\n", 1)[0]
    assert body.splitlines() == submitted[:1]


@pytest.mark.parametrize("target", [
    "https://app.example.test:443/",
    "http://app.example.test:80/",
    "https://[2001:db8::1]:443/",
])
def test_queue_preserves_default_port_and_ipv6_in_validation_and_launch(queue_env, tmp_path, monkeypatch, target):
    urls = tmp_path / "targets.txt"
    urls.write_text(target + "\n" + target + "\n")
    calls = []
    checked = []
    real_load = recon_ry._load_recon_scope

    def load(program, url, **kwargs):
        checked.append(url)
        return real_load(program, url, **kwargs)

    monkeypatch.setattr(recon_ry, "_load_recon_scope", load)
    monkeypatch.setattr(recon_ry.subprocess, "run", lambda command, **kwargs: calls.append(command))
    args = recon_ry.build_parser().parse_args([
        "queue", "synthetic", "--url-file", str(urls), "--allow-unscoped",
    ])
    args.func(args)
    assert checked and all(value == target for value in checked)
    assert len(calls) == 1
    command = calls[0][-1]
    body = command.split("<<'RECONRY_QUEUE_URLS'\n", 1)[1].split("RECONRY_QUEUE_URLS\n", 1)[0]
    assert body.splitlines() == [target]
    assert '--url "$target_url"' in command


@pytest.mark.parametrize("target", [
    "https://app.example.test:0/", "https://app.example.test:/",
    "https://app.example.test:65536/", "https://app.example.test:abc/",
    "https://[2001:db8::1]:0/", "https://[2001:db8::1]:bad/",
    "https://[2001:db8::1]suffix:443/",
])
@pytest.mark.parametrize("unscoped", [False, True])
def test_queue_rejects_invalid_ports_before_launch(queue_env, tmp_path, target, unscoped):
    if not unscoped:
        (queue_env / "in-scope.txt").write_text("*.example.test\n2001:db8::/32\n")
    urls = tmp_path / "targets.txt"
    urls.write_text(target + "\n")
    argv = ["queue", "synthetic", "--url-file", str(urls)]
    if unscoped:
        argv.append("--allow-unscoped")
    args = recon_ry.build_parser().parse_args(argv)
    with pytest.raises(SystemExit, match="Invalid port"):
        args.func(args)


@pytest.mark.parametrize("target", [
    "https://app.example.test\t:443/",
    "https://app.example.test:443\t/",
    "https://app.example.test\\\\evil.test/",
    "https://user@app.example.test/",
])
def test_unscoped_queue_rejects_ambiguous_authority(queue_env, tmp_path, target):
    urls = tmp_path / "targets.txt"
    urls.write_text(target + "\n")
    args = recon_ry.build_parser().parse_args([
        "queue", "synthetic", "--url-file", str(urls), "--allow-unscoped",
    ])
    with pytest.raises(SystemExit, match="Invalid URL"):
        args.func(args)
