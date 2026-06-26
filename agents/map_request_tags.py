#!/usr/bin/env python3
"""Normalize MapStore request-contract gate and retest metadata.

This helper keeps replayable request entries from drifting into many different
tag names for the same auth or permission state. It intentionally allows
target-specific retest keys, but normalizes their spelling and warns on vague
names.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any


CONTROLLED_GATES = {
    "auth",
    "csrf",
    "feature",
    "plan",
    "role",
    "company",
    "tenant",
    "ownership",
    "object_acl",
    "parser",
    "unknown",
}

CONTROLLED_REASONS = {
    "auth_required",
    "missing_token",
    "missing_sdk_token",
    "csrf_required",
    "csrf_mismatch",
    "invalid_permissions",
    "not_in_company",
    "no_access_to_feature",
    "plan_required",
    "role_required",
    "owner_required",
    "tenant_required",
    "acl_permission",
    "parser_before_auth",
    "not_found_or_hidden",
    "unknown",
}

VAGUE_RETEST_KEYS = {
    "admin",
    "company",
    "feature",
    "linked",
    "normal",
    "paid",
    "permission",
    "role",
    "user",
    "user1",
    "user2",
    "worked",
}


@dataclass
class NormalizedRequestState:
    gate: dict[str, Any]
    retest_matrix: dict[str, bool | None]
    last_retested_for: list[str]
    next_retest_when: list[str]
    tags: list[str]
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "retest_matrix": self.retest_matrix,
            "last_retested_for": self.last_retested_for,
            "next_retest_when": self.next_retest_when,
            "tags": self.tags,
            "warnings": self.warnings,
        }


def normalize_key(value: str) -> str:
    """Normalize a free-form key into lowercase snake_case."""
    cleaned = value.strip().lower()
    cleaned = re.sub(r"[^a-z0-9]+", "_", cleaned)
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    if not cleaned:
        raise ValueError("empty key after normalization")
    return cleaned


def parse_tristate(value: str) -> bool | None:
    """Parse true/false/null for retest matrix values."""
    lowered = value.strip().lower()
    if lowered in {"true", "yes", "1", "pass", "passed", "worked"}:
        return True
    if lowered in {"false", "no", "0", "fail", "failed", "blocked"}:
        return False
    if lowered in {"null", "none", "unknown", "untested", "not_tested", "pending"}:
        return None
    raise ValueError(f"invalid tri-state value: {value!r}")


def parse_assignment(value: str) -> tuple[str, bool | None]:
    if "=" not in value:
        raise ValueError(f"expected KEY=VALUE assignment: {value!r}")
    key, raw_state = value.split("=", 1)
    return normalize_key(key), parse_tristate(raw_state)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def build_state(
    *,
    gate_type: str,
    status: int,
    reason: str,
    tested: dict[str, bool | None] | None = None,
    next_retest: list[str] | None = None,
    body_fingerprint: str | None = None,
) -> NormalizedRequestState:
    """Build normalized gate/retest metadata plus canonical tags."""
    warnings: list[str] = []
    gate = normalize_key(gate_type)
    normalized_reason = normalize_key(reason)

    if gate not in CONTROLLED_GATES:
        warnings.append(f"unknown gate.type {gate!r}; add it to the controlled list if intentional")
    if normalized_reason not in CONTROLLED_REASONS:
        warnings.append(
            f"unknown gate.reason {normalized_reason!r}; add it to the controlled list if intentional"
        )

    matrix: dict[str, bool | None] = {}
    for key, state in (tested or {}).items():
        normalized_key = normalize_key(key)
        matrix[normalized_key] = state
        if normalized_key in VAGUE_RETEST_KEYS:
            warnings.append(f"retest key {normalized_key!r} is vague; prefer a role/state-specific key")

    normalized_next: list[str] = []
    for key in next_retest or []:
        normalized_key = normalize_key(key)
        normalized_next.append(normalized_key)
        matrix.setdefault(normalized_key, None)
        if normalized_key in VAGUE_RETEST_KEYS:
            warnings.append(f"retest key {normalized_key!r} is vague; prefer a role/state-specific key")

    normalized_next = _dedupe(normalized_next)
    last_retested_for = [key for key, state in matrix.items() if state is not None]

    gate_obj: dict[str, Any] = {
        "type": gate,
        "status": status,
        "reason": normalized_reason,
    }
    if body_fingerprint:
        gate_obj["body_fingerprint"] = body_fingerprint

    tags = [
        "request-contract",
        f"gate:{gate}",
        f"status:{status}",
        f"reason:{normalized_reason}",
    ]
    tags.extend(f"tested:{key}" for key in last_retested_for)
    tags.extend(f"retest:{key}" for key in normalized_next)

    return NormalizedRequestState(
        gate=gate_obj,
        retest_matrix=matrix,
        last_retested_for=last_retested_for,
        next_retest_when=normalized_next,
        tags=_dedupe(tags),
        warnings=_dedupe(warnings),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Normalize MapStore request-contract gate, retest matrix, and tags."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    explain = subparsers.add_parser("explain", help="emit normalized request-contract metadata")
    explain.add_argument("--gate", required=True, help="gate type, e.g. feature, company, role")
    explain.add_argument("--status", required=True, type=int, help="observed HTTP status")
    explain.add_argument("--reason", required=True, help="normalized or free-form failure reason")
    explain.add_argument(
        "--tested",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="retest matrix entry, e.g. basic_user=false or company_admin=true",
    )
    explain.add_argument(
        "--next",
        action="append",
        default=[],
        metavar="KEY",
        help="auth/role/token state worth retesting later",
    )
    explain.add_argument(
        "--body-fingerprint",
        default=None,
        help="sanitized body/error fingerprint, not raw sensitive response data",
    )
    explain.add_argument("--compact", action="store_true", help="emit compact JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "explain":
        tested = dict(parse_assignment(value) for value in args.tested)
        state = build_state(
            gate_type=args.gate,
            status=args.status,
            reason=args.reason,
            tested=tested,
            next_retest=args.next,
            body_fingerprint=args.body_fingerprint,
        )
        indent = None if args.compact else 2
        print(json.dumps(state.as_dict(), indent=indent, sort_keys=True))
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
