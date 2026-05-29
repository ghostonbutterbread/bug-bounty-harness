"""Build recon seed files from normalized program scope."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse


def clean_scope_value(value: str) -> str:
    """Return a normalized single-line scope value without inline comments."""
    value = str(value or "").strip()
    if not value or value.startswith("#"):
        return ""
    if "#" in value:
        value = value.split("#", 1)[0].strip()
    return value.strip().rstrip("/")


def host_from_scope_value(value: str) -> str:
    value = clean_scope_value(value)
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return (urlparse(value).hostname or "").lower()
    return value.split("/", 1)[0].split(":", 1)[0].lower()


def wildcard_base(value: str) -> str:
    host = host_from_scope_value(value)
    if host.startswith("*."):
        return host[2:]
    return ""


def recon_seed_lines(domains: set[str] | list[str], urls: set[str] | list[str]) -> tuple[list[str], list[str]]:
    """Return ``(urls_txt, wild_txt)`` lines for recon-ry-compatible seeds.

    ``urls.txt`` receives exact URLs and exact host/domain entries.
    ``wild.txt`` receives wildcard base domains with the leading ``*.`` removed.
    """
    url_lines: list[str] = []
    wild_lines: list[str] = []

    for value in sorted(clean_scope_value(v) for v in urls):
        if value:
            url_lines.append(value)

    for value in sorted(clean_scope_value(v) for v in domains):
        if not value:
            continue
        base = wildcard_base(value)
        if base:
            wild_lines.append(base)
            continue
        if value.startswith(("http://", "https://")):
            url_lines.append(value)
        else:
            url_lines.append(host_from_scope_value(value) or value)

    return _dedupe(url_lines), _dedupe(wild_lines)


def write_recon_seed_files(base: Path, domains: set[str] | list[str], urls: set[str] | list[str]) -> dict[str, int]:
    """Write root-level recon seed files under a program bounty_recon directory."""
    url_lines, wild_lines = recon_seed_lines(domains, urls)
    base.mkdir(parents=True, exist_ok=True)
    urls_body = "\n".join(url_lines) + ("\n" if url_lines else "")
    wild_body = "\n".join(wild_lines) + ("\n" if wild_lines else "")
    (base / "urls.txt").write_text(urls_body, encoding="utf-8")
    (base / "url.txt").write_text(urls_body, encoding="utf-8")
    (base / "wild.txt").write_text(wild_body, encoding="utf-8")
    return {"urls": len(url_lines), "wildcards": len(wild_lines)}


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))
