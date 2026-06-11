#!/usr/bin/env python3
"""Convert a raw HTTP proxy request into an ordered curl command."""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path
from urllib.parse import urlsplit


FRAMING_HEADERS = {"content-length", "connection"}


def split_head_body(raw: str) -> tuple[str, str]:
    raw = raw.replace("\r\n", "\n")
    if "\n\n" in raw:
        return raw.split("\n\n", 1)
    return raw, ""


def unfold_headers(lines: list[str]) -> list[str]:
    unfolded: list[str] = []
    for line in lines:
        if not line:
            continue
        if line[0] in " \t" and unfolded:
            unfolded[-1] += " " + line.strip()
        else:
            unfolded.append(line.rstrip("\n"))
    return unfolded


def parse_raw_request(raw: str) -> tuple[str, str, list[tuple[str, str]], str]:
    head, body = split_head_body(raw)
    lines = head.splitlines()
    if not lines:
        raise ValueError("empty request")

    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"invalid request line: {lines[0]!r}")

    method = parts[0].upper()
    target = parts[1]
    headers: list[tuple[str, str]] = []
    for line in unfold_headers(lines[1:]):
        if ":" not in line:
            raise ValueError(f"invalid header line: {line!r}")
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.lstrip()))
    return method, target, headers, body


def build_url(target: str, headers: list[tuple[str, str]], scheme: str) -> str:
    parsed = urlsplit(target)
    if parsed.scheme and parsed.netloc:
        return target

    host = next((value for name, value in headers if name.lower() == "host"), None)
    if not host:
        raise ValueError("origin-form request target needs a Host header")
    if not target.startswith("/"):
        target = "/" + target
    return f"{scheme}://{host}{target}"


def shell_join(parts: list[str]) -> str:
    return " \\\n  ".join(shlex.quote(part) for part in parts)


def curl_command(
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: str,
    body_file: str | None,
    drop_framing_headers: bool,
    omit_host: bool,
    http1_1: bool,
    max_time: str | None,
) -> str:
    parts = ["curl", "--path-as-is", "--compressed"]
    if http1_1:
        parts.append("--http1.1")
    if max_time:
        parts.extend(["--max-time", max_time])
    parts.extend(["-X", method, url])

    for name, value in headers:
        lower = name.lower()
        if drop_framing_headers and lower in FRAMING_HEADERS:
            continue
        if lower == "host" and omit_host:
            continue
        parts.extend(["-H", f"{name}: {value}"])

    if body:
        if body_file:
            Path(body_file).write_text(body, encoding="utf-8")
            parts.extend(["--data-binary", f"@{body_file}"])
        else:
            parts.extend(["--data-binary", body])

    return shell_join(parts)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Convert a raw HTTP proxy request to an ordered curl command."
    )
    parser.add_argument("request", nargs="?", help="Raw request file. Reads stdin if omitted.")
    parser.add_argument("--scheme", choices=["https", "http"], default="https")
    parser.add_argument("--body-file", help="Write captured body to this file and reference it.")
    parser.add_argument(
        "--drop-framing-headers",
        action="store_true",
        help="Omit Content-Length and Connection so curl recomputes transport framing.",
    )
    parser.add_argument("--omit-host", action="store_true")
    parser.add_argument("--http1.1", dest="http1_1", action="store_true")
    parser.add_argument("--max-time", default="20")
    args = parser.parse_args(argv)

    raw = Path(args.request).read_text(encoding="utf-8") if args.request else sys.stdin.read()
    method, target, headers, body = parse_raw_request(raw)
    url = build_url(target, headers, args.scheme)
    print(
        curl_command(
            method=method,
            url=url,
            headers=headers,
            body=body,
            body_file=args.body_file,
            drop_framing_headers=args.drop_framing_headers,
            omit_host=args.omit_host,
            http1_1=args.http1_1,
            max_time=args.max_time,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
