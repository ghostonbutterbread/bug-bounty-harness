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


def test_recon_scope_file_lines_expand_optional_group_and_defer_labels() -> None:
    lines, deferred = scope_seed_files.recon_scope_file_lines(
        [
            "*.site(-eu1)?.example.com",
            "app.example.com",
            "customer connected domain",
            "*.mail.example.net",
        ]
    )

    assert sorted(lines) == sorted(
        ["*.site-eu1.example.com", "*.site.example.com", "app.example.com", "*.mail.example.net"]
    )
    assert deferred == ["customer connected domain"]


def test_recon_seed_lines_skip_labels_and_expand_groups() -> None:
    urls, wild = scope_seed_files.recon_seed_lines(
        {
            "*.site(-eu1)?.example.com",
            "app.example.com",
            "customer portal",
            "example.net",
        },
        {"https://app.example.com"},
    )

    assert "https://app.example.com" in urls
    assert "app.example.com" in urls
    assert "example.net" in urls
    assert "customer portal" not in urls
    assert sorted(wild) == ["site-eu1.example.com", "site.example.com"]


def test_is_dns_scope_value() -> None:
    assert scope_seed_files.is_dns_scope_value("*.mail.example.net")
    assert scope_seed_files.is_dns_scope_value("app.example.com")
    assert scope_seed_files.is_dns_scope_value("192.0.2.1")
    assert scope_seed_files.is_dns_scope_value("192.0.2.0/24")
    assert not scope_seed_files.is_dns_scope_value("999.999.999.999")
    assert not scope_seed_files.is_dns_scope_value("192.0.2.0/33")
    assert scope_seed_files.is_dns_scope_value("2001:db8::1")
    assert scope_seed_files.is_dns_scope_value("2001:db8::1/32")
    assert not scope_seed_files.is_dns_scope_value("*.192.0.2.1")
    assert not scope_seed_files.is_dns_scope_value("a" * 64 + ".example.com")
    assert not scope_seed_files.is_dns_scope_value("customer portal")
    assert not scope_seed_files.is_dns_scope_value("*.site(-eu1)?.example.com")


def test_recon_seed_lines_infix_wildcard_never_widens_to_parent() -> None:
    urls, wild = scope_seed_files.recon_seed_lines(
        {"app*.example.com", "api*.example.net"}, set()
    )

    assert urls == []
    assert wild == []

    allowed, deferred = scope_seed_files.recon_scope_file_lines(["app*.example.com"])
    assert allowed == []
    assert deferred == ["app*.example.com"]


def test_optional_exact_host_expands_without_widening() -> None:
    urls, wild = scope_seed_files.recon_seed_lines({"api(-eu1)?.example.com"}, set())
    assert urls == ["api.example.com", "api-eu1.example.com"]
    assert wild == []


def test_host_bit_cidr_is_canonical_in_allow_and_deny_scope() -> None:
    allowed, deferred = scope_seed_files.recon_scope_file_lines(["192.0.2.1/24"])
    denied, _ = scope_seed_files.recon_scope_file_lines(["192.0.2.99/24"])
    assert allowed == denied == ["192.0.2.0/24"]
    assert deferred == []
    ipv6, _ = scope_seed_files.recon_scope_file_lines(["2001:db8::1/32", "2001:db8::1"])
    assert ipv6 == ["2001:db8::/32", "2001:db8::1"]
