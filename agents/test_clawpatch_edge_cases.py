from __future__ import annotations

from agents.ssrf_escalation import build_ssrf_url
from agents.subdomain_agent import is_safe_url, is_target_host


def test_subdomain_agent_safe_url_rejects_internal_ip_literals():
    blocked = [
        "http://127.0.0.1/app.js",
        "http://0.0.0.0/app.js",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/app.js",
        "http://[fe80::1]/app.js",
        "http://10.0.0.5/app.js",
        "http://192.168.0.10/app.js",
        "http://172.16.0.1/app.js",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]
    for url in blocked:
        assert not is_safe_url(url), url


def test_subdomain_agent_safe_url_allows_public_http_hosts():
    assert is_safe_url("https://cdn.example.com/app.js")


def test_subdomain_agent_target_host_requires_domain_boundary():
    assert is_target_host("example.com", "example.com")
    assert is_target_host("cdn.example.com", "example.com")
    assert not is_target_host("badexample.com", "example.com")
    assert not is_target_host("cdn.thirdparty.test", "example.com")


def test_build_ssrf_url_replaces_exact_parameter_only():
    result = build_ssrf_url(
        "https://target.test/fetch?callback_url=https://a.test",
        "url",
        "http://169.254.169.254/",
    )
    assert "callback_url=https%3A%2F%2Fa.test" in result
    assert "url=http%3A%2F%2F169.254.169.254%2F" in result


def test_build_ssrf_url_replaces_empty_and_existing_exact_parameter():
    result = build_ssrf_url("https://target.test/fetch?url=&x=1", "url", "http://127.0.0.1/")
    assert result == "https://target.test/fetch?url=http%3A%2F%2F127.0.0.1%2F&x=1"


def test_build_ssrf_url_preserves_placeholder_mode_unencoded():
    result = build_ssrf_url("https://target.test/fetch/{url}", "url", "http://127.0.0.1/")
    assert result == "https://target.test/fetch/http://127.0.0.1/"
