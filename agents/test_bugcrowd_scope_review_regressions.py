from pathlib import Path

import pytest

from agents import scope_puller as p
from agents.scope_validator import ScopeValidator


def payload(domains=(), urls=(), exclusions=()):
    return {"platform": "bugcrowd", "domains": set(domains), "urls": set(urls),
            "out_of_scope": list(exclusions)}


@pytest.mark.parametrize("bad", ["\n", "\r", "\t", "\x00", "\x7f", "\x85", "\u2028"])
def test_control_in_saved_scope_rejected_before_writes(tmp_path: Path, monkeypatch, bad):
    monkeypatch.setattr(p.Path, "home", lambda: tmp_path)
    path = tmp_path / "Shared/scopes/demo/in-scope.txt"
    path.parent.mkdir(parents=True)
    path.write_text("previous.example.test\n")
    with pytest.raises((ValueError, RuntimeError)):
        p.save_scope("demo", payload(urls=[f"https://*.example.test/private{bad}*.unrelated.test"]))
    assert path.read_text() == "previous.example.test\n"
    assert not (path.parent / "out-of-scope.txt").exists()


def test_control_in_bugcrowd_uri_rejected_before_normalization():
    domains, urls = set(), set()
    with pytest.raises(ValueError, match="control"):
        p.add_bugcrowd_target_to_scope(domains, urls, name="", uri="https://*.example.test/private\n*.unrelated.test")
    assert not domains and not urls


def test_control_in_non_bugcrowd_exclusion_refuses_save(tmp_path, monkeypatch):
    monkeypatch.setattr(p.Path, "home", lambda: tmp_path)
    path = tmp_path / "Shared/scopes/demo/in-scope.txt"
    path.parent.mkdir(parents=True)
    path.write_text("previous.example.test\n")
    data = payload(["*.example.test"], exclusions=[{"uri": "private.example.test\n"}])
    data["platform"] = "hackerone"
    with pytest.raises((ValueError, RuntimeError)):
        p.save_scope("demo", data)
    assert path.read_text() == "previous.example.test\n"


def test_bugcrowd_parser_rejects_control_before_stripping(monkeypatch):
    monkeypatch.setattr(p, "fetch_json", lambda _: {"data": {"scope": [{
        "inScope": True, "targets": [{"uri": "https://example.test/\n"}],
    }]}})
    html = '<div data-api-endpoints="{&quot;engagementBriefApi&quot;:{&quot;getBriefVersionDocument&quot;:&quot;/brief&quot;}}"></div>'
    with pytest.raises(ValueError, match="control"):
        p.parse_bugcrowd_public_engagement("demo", html)


@pytest.mark.parametrize("uri", [r"https://private.example.test\@other.example.test/",
                                   "https://private.example.test@other.example.test/",
                                   "https://private.example.test:bad/",
                                   "https://private.example.test:99999/",
                                   "https://[v1.example.test]/"])
def test_malformed_exclusion_blocks_save(tmp_path: Path, monkeypatch, uri):
    monkeypatch.setattr(p.Path, "home", lambda: tmp_path)
    path = tmp_path / "Shared/scopes/demo/in-scope.txt"
    path.parent.mkdir(parents=True)
    path.write_text("previous.example.test\n")
    with pytest.raises((ValueError, RuntimeError)):
        p.save_scope("demo", payload(["*.example.test"], exclusions=[{"uri": uri}]))
    assert path.read_text() == "previous.example.test\n"


@pytest.mark.parametrize("uri", ["https://example.test:8443/", "https://*.example.test:8443/"])
def test_port_specific_wildcard_does_not_grant_other_ports(tmp_path: Path, monkeypatch, uri):
    monkeypatch.setattr(p.Path, "home", lambda: tmp_path)
    domains, urls = set(), set()
    p.add_bugcrowd_target_to_scope(domains, urls, name="*.example.test", uri=uri)
    p.save_scope("demo", payload(domains, urls))
    validator = ScopeValidator("demo", scopes_base=tmp_path / "Shared/scopes")
    assert validator.is_in_scope("https://sub.example.test:8443/")
    assert not validator.is_in_scope("https://sub.example.test:443/")
    assert not validator.is_in_scope("http://sub.example.test:8443/")


@pytest.mark.parametrize("name,uri", [
    ("*.example.test", "https://example.test/"),
    ("", "https://*.example.test/"),
    ("", "http://*.example.test/"),
])
def test_wildcard_url_retains_scheme_and_default_port(tmp_path: Path, monkeypatch, name, uri):
    monkeypatch.setattr(p.Path, "home", lambda: tmp_path)
    domains, urls = set(), set()
    p.add_bugcrowd_target_to_scope(domains, urls, name=name, uri=uri)
    p.save_scope("demo", payload(domains, urls))
    validator = ScopeValidator("demo", scopes_base=tmp_path / "Shared/scopes")
    scheme = uri.split(":", 1)[0]
    other = "http" if scheme == "https" else "https"
    default_port = 443 if scheme == "https" else 80
    assert validator.is_in_scope(f"{scheme}://sub.example.test/")
    assert validator.is_in_scope(f"{scheme}://sub.example.test:{default_port}/")
    assert not validator.is_in_scope(f"{other}://sub.example.test/")
    assert not validator.is_in_scope(f"{scheme}://sub.example.test:8443/")
    assert not validator.is_in_scope("sub.example.test")


@pytest.mark.parametrize("uri", [
    "https://***@example.test:8443/",
    "https://user@example.test/",
    "https://example.test:99999/",
    "https://example.test:/",
])
def test_invalid_original_uri_cannot_infer_wildcard(uri):
    domains, urls = set(), set()
    try:
        p.add_bugcrowd_target_to_scope(domains, urls, name="*.example.test", uri=uri)
    except ValueError:
        pass
    assert not domains and not urls


def test_overlimit_seed_refuses_before_any_replacement(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(p.Path, "home", lambda: tmp_path)
    paths = [tmp_path / "Shared/scopes/demo/in-scope.txt",
             tmp_path / "Shared/scopes/demo/out-of-scope.txt",
             tmp_path / "Shared/bounty_recon/demo/scope/in-scope.txt",
             tmp_path / "Shared/bounty_recon/demo/urls.txt"]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("previous\n")
    data = payload(["*.example.test", "*.example" + "(-a)?" * 9 + ".test"])
    with pytest.raises(ValueError):
        p.save_scope("demo", data)
    assert all(path.read_text() == "previous\n" for path in paths)
