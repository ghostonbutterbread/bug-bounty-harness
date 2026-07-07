#!/usr/bin/env python3
"""Cloudflare / WAF block detector for ffuf output.

Heuristic detection: if >80% of responses are 403/503 with uniform
content lengths, the target is likely behind a WAF or Cloudflare.

Usage:
    python3 agents/cloudflare_detector.py check ffuf.json --host api.example.com
    python3 agents/cloudflare_detector.py check ffuf.json --host api.example.com --record

Output:
    JSON with classification and block status on stdout.
    When --record is given, also appends to cf_blocked.jsonl in the
    program's recon root.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# -- Configuration -------------------------------------------------------------

CF_HTTP_BLOCK_THRESHOLD = 0.8   # ratio of 403/503 that signals an HTTP-level block
CF_TIMEOUT_THRESHOLD = 0.9      # ratio of missing responses that signals a TCP-level block
CF_MIN_SAMPLES = 10             # minimum results before HTTP heuristics fire
CF_MIN_EXPECTED = 50            # minimum expected requests before timeout heuristics fire
BLOCK_STATUSES = {403, 503}
DEFAULT_ARTIFACT_ROOT = Path.home() / "Shared" / "web_bounty"

TIMEOUT_PATTERNS = [
    "Timeout",
    "timed out",
    "connection refused",
    "connection reset",
    "no route to host",
    "network is unreachable",
    "TLS handshake timeout",
    "i/o timeout",
    "EOF",
]

WAF_PATTERNS = [
    "cloudflare",
    "cf-ray",
    "attention required",
    "checking your browser",
    "just a moment",
    "ddos protection",
]


# -- Detection -----------------------------------------------------------------


def classify(
    results: list[dict[str, Any]],
    *,
    expected_requests: int = 0,
    stderr_text: str = "",
) -> dict[str, Any] | None:
    """Return a classification when a WAF/Cloudflare block is detected.

    Two detection paths:
    1. **HTTP-level block** — >80% of responses are 403/503 with uniform
       content lengths (Cloudflare challenge page).
    2. **TCP-level block** — very few responses vs expected requests AND
       stderr shows connection timeouts (Cloudflare dropping connections).
    """
    # -- Path 1: HTTP-level block (403/503 heuristics) ------------------------
    http_block = _detect_http_block(results)

    # -- Path 2: TCP-level / timeout block ------------------------------------
    timeout_block = _detect_timeout_block(results, expected_requests, stderr_text)

    # Prefer timeout detection (Cloudflare TCP drops are more definitive)
    if timeout_block:
        return timeout_block
    if http_block:
        return http_block
    return None


def _detect_http_block(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not results or len(results) < CF_MIN_SAMPLES:
        return None

    total = len(results)
    blocked = [r for r in results if r.get("status") in BLOCK_STATUSES]
    if not blocked:
        return None

    blocked_ratio = len(blocked) / total
    if blocked_ratio < CF_HTTP_BLOCK_THRESHOLD:
        return None

    lengths = [r.get("length") for r in blocked if r.get("length") is not None]
    if not lengths:
        return None
    unique_lengths = set(lengths)
    top_length = max(set(lengths), key=lengths.count)
    top_ratio = lengths.count(top_length) / len(lengths)

    confidence = "low"
    reason_parts: list[str] = []

    if top_ratio >= 0.9 and len(unique_lengths) <= 3:
        confidence = "high"
        reason_parts.append(f"{top_ratio:.0%} same response length ({top_length} bytes)")
    elif top_ratio >= 0.7:
        confidence = "medium"
        reason_parts.append(f"{top_ratio:.0%} same response length ({top_length} bytes)")
    else:
        reason_parts.append(f"varied response lengths ({len(unique_lengths)} unique)")

    status_summary = ", ".join(
        f"{s}={sum(1 for r in blocked if r.get('status') == s)}"
        for s in sorted(BLOCK_STATUSES)
        if any(r.get("status") == s for r in blocked)
    )
    reason_parts.insert(0, f"{blocked_ratio:.0%} HTTP blocked ({status_summary})")

    return {
        "blocked": True,
        "block_type": "http",
        "confidence": confidence,
        "blocked_ratio": round(blocked_ratio, 3),
        "total_results": total,
        "blocked_count": len(blocked),
        "unique_response_lengths": len(unique_lengths),
        "top_length_ratio": round(top_ratio, 3),
        "reason": "; ".join(reason_parts),
        "evidence": {
            "sample_statuses": [r.get("status") for r in blocked[:5]],
            "sample_urls": [r.get("url") for r in blocked[:3] if r.get("url")],
        },
    }


def _detect_timeout_block(
    results: list[dict[str, Any]],
    expected_requests: int,
    stderr_text: str,
) -> dict[str, Any] | None:
    """Detect TCP-level blocking: very few responses, stderr full of timeouts."""
    if expected_requests < CF_MIN_EXPECTED:
        return None

    total = len(results)
    response_ratio = total / expected_requests

    # ffuf JSON usually contains filtered matches, not every attempted request,
    # so generic transport errors alone are normal fuzzing noise. Only promote
    # this path when the stderr/body evidence also names a WAF/CDN challenge.
    if response_ratio >= 0.10:
        return None  # >10% response rate — probably not blocked at TCP level

    stderr_lower = stderr_text.lower()
    waf_hits = [p for p in WAF_PATTERNS if p in stderr_lower]
    if not waf_hits:
        return None
    timeout_hits = [p for p in TIMEOUT_PATTERNS if p.lower() in stderr_lower]
    if not timeout_hits:
        return None

    confidence = "high" if response_ratio <= 0.02 else "medium"

    return {
        "blocked": True,
        "block_type": "timeout",
        "confidence": confidence,
        "response_ratio": round(response_ratio, 4),
        "total_results": total,
        "expected_requests": expected_requests,
        "missing_responses": expected_requests - total,
        "waf_signals": waf_hits[:5],
        "timeout_errors": timeout_hits[:5],
        "reason": (
            f"{response_ratio:.1%} response rate ({total}/{expected_requests}); "
            f"waf: {', '.join(waf_hits[:3])}; stderr: {', '.join(timeout_hits[:3])}"
        ),
    }


# -- Persistence ---------------------------------------------------------------


def record(
    program: str,
    host: str,
    classification: dict[str, Any],
    target_url: str = "",
) -> Path:
    """Append a Cloudflare block record and return the blocklist path."""
    root = DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "fuzz"
    root.mkdir(parents=True, exist_ok=True)

    record_json = {
        "program": program,
        "host": host,
        "target": target_url,
        "confidence": classification["confidence"],
        "blocked_ratio": classification.get("blocked_ratio", classification.get("response_ratio", 0)),
        "blocked_count": classification.get("blocked_count", classification.get("missing_responses", 0)),
        "total_results": classification.get("total_results", 0),
        "reason": classification["reason"],
        "detected_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }

    # JSONL blocklist
    blocklist = root / "cf_blocked.jsonl"
    blocklist.parent.mkdir(parents=True, exist_ok=True)
    with blocklist.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record_json, sort_keys=True) + "\n")

    # Plain-text host list
    host_list = root / "cf_blocked_hosts.txt"
    existing = set()
    if host_list.is_file():
        existing.update(
            line.strip()
            for line in host_list.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    if host not in existing:
        with host_list.open("a", encoding="utf-8") as f:
            f.write(host + "\n")

    return blocklist


# -- ffuf JSON loading ---------------------------------------------------------


def load_ffuf_results(path: Path) -> list[dict[str, Any]]:
    """Load ffuf JSON results from a file (handles both wrapper and raw arrays)."""
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = payload.get("results") if isinstance(payload, dict) else payload
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    except json.JSONDecodeError:
        pass
    return []


# -- CLI -----------------------------------------------------------------------


def cmd_check(args: argparse.Namespace) -> int:
    results = load_ffuf_results(Path(args.ffuf_json).expanduser())

    stderr_text = ""
    if args.stderr:
        stderr_path = Path(args.stderr).expanduser()
        if stderr_path.is_file():
            stderr_text = stderr_path.read_text(encoding="utf-8", errors="ignore")

    classification = classify(
        results,
        expected_requests=args.wordlist_size or 0,
        stderr_text=stderr_text,
    )

    if classification is None:
        print(json.dumps({"blocked": False, "total_results": len(results)}))
    else:
        print(json.dumps(classification, indent=2))

    if classification and args.record:
        path = record(
            args.program or "unknown",
            args.host or "unknown",
            classification,
            target_url=args.target or "",
        )
        print(f"\nRecorded to: {path}", file=sys.stderr)

    return 0 if classification is None else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cloudflare / WAF block detector for ffuf output"
    )
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="Classify ffuf results")
    check.add_argument("ffuf_json", help="Path to ffuf JSON output")
    check.add_argument("--host", help="Target hostname")
    check.add_argument("--target", default="", help="Target base URL")
    check.add_argument("--program", default="unknown", help="Program name for recording")
    check.add_argument(
        "--record", action="store_true", help="Append to cf_blocked.jsonl on detection"
    )
    check.add_argument(
        "--wordlist-size", type=int, default=0,
        help="Expected request count (wordlist lines) for timeout detection",
    )
    check.add_argument(
        "--stderr", default="",
        help="Path to stderr log for timeout pattern matching",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "check":
        return cmd_check(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
