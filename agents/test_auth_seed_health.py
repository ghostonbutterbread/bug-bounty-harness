"""Planning-time auth-seed usability from non-secret metadata (synthetic fixtures only)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from agents.auth_seed_health import (
    auth_check_url_warning,
    classify_seed,
    effective_seed_status,
    liveness_from_check,
    seed_auth_material,
    seed_status_snapshot,
)

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
SEED_REF = "auth-seed:/synthetic/seeds/blue.json"


def iso(delta: timedelta) -> str:
    return (NOW - delta).isoformat()


def account(**status):
    record: dict[str, Any] = {"alias": "blue", "auth_seed_ref": SEED_REF}
    if status:
        record["auth_seed_status"] = status
    return record


def test_old_format_record_without_status_reads_unverified_never_usable():
    verdict = classify_seed({"alias": "blue", "auth_seed_ref": SEED_REF}, now=NOW)

    assert verdict["state"] == "unverified"
    assert verdict["reasons"] == ["no-recorded-seed-status"]


def test_old_seed_without_captured_at_reads_unverified():
    snapshot = seed_status_snapshot({"cookies": [{"name": "sid", "value": "synthetic"}]})

    assert snapshot["captured_at"] is None
    assert classify_seed(account(**snapshot), now=NOW)["reasons"] == ["never-verified"]


def test_seed_without_replayable_auth_material_is_unusable_even_if_verified_live():
    verdict = classify_seed(
        account(auth_material="absent", last_verified_result="live", last_verified_at=iso(timedelta(minutes=5))),
        now=NOW,
    )

    assert verdict["state"] == "unusable"
    assert verdict["reasons"] == ["no-replayable-auth-material"]


def test_failed_last_verification_is_stale():
    verdict = classify_seed(
        account(
            auth_material="present",
            captured_at=iso(timedelta(hours=1)),
            last_verified_at=iso(timedelta(minutes=1)),
            last_verified_result="expired",
            last_verified_reason="http-401",
        ),
        now=NOW,
    )

    assert verdict["state"] == "stale"
    assert verdict["reasons"] == ["last-check-expired:http-401"]


def test_seed_older_than_declared_ttl_is_stale_without_live_traffic():
    record = account(auth_material="present", captured_at=iso(timedelta(days=33)))
    record["auth_session_ttl_hours"] = 24 * 7

    verdict = classify_seed(record, now=NOW)

    assert verdict["state"] == "stale"
    assert verdict["reasons"] == ["older-than-declared-ttl:168h"]


@pytest.mark.parametrize(
    "verified_ago,ttl,state,reason",
    [
        (timedelta(hours=2), None, "usable", "verified-live"),
        (timedelta(hours=30), None, "unverified", "verification-older-than:24h"),
        (timedelta(hours=30), 72, "usable", "verified-live"),
    ],
)
def test_live_verification_is_current_only_within_window(verified_ago, ttl, state, reason):
    record = account(
        auth_material="present",
        captured_at=iso(timedelta(hours=40)),
        last_verified_at=iso(verified_ago),
        last_verified_result="live",
    )
    if ttl:
        record["auth_session_ttl_hours"] = ttl

    verdict = classify_seed(record, now=NOW)

    assert (verdict["state"], verdict["reasons"]) == (state, [reason])


def test_inconclusive_check_stays_unverified_with_reason():
    verdict = classify_seed(
        account(auth_material="present", last_verified_at=iso(timedelta(minutes=1)),
                last_verified_result="unknown", last_verified_reason="cached-response"),
        now=NOW,
    )

    assert verdict == {
        "state": "unverified",
        "reasons": ["last-check-inconclusive:cached-response"],
        "last_verified_at": iso(timedelta(minutes=1)),
        "last_verified_result": "unknown",
    }


@pytest.mark.parametrize("record", [{"alias": "pink"}, {"alias": "cyan", "credential_ref": "bitwarden:item"}])
def test_account_without_seed_reference_is_none(record):
    assert classify_seed(record, now=NOW)["state"] == "none"


@pytest.mark.parametrize(
    "seed,required,material,names",
    [
        ({"cookies": [], "headers": {"User-Agent": "x", "Accept": "*/*"}}, (), "absent", []),
        ({"cookies": [{"name": "sid", "value": ""}]}, (), "absent", []),
        ({"headers": {"X-CSRF-Token": "synthetic"}}, (), "absent", []),
        ({"headers": {"Authorization": "synthetic"}}, (), "present", ["Authorization"]),
        ({"headers": {"X-Tenant-Grant": "synthetic"}}, ("x-tenant-grant",), "present", ["X-Tenant-Grant"]),
        ({"cookies": [{"name": "sid", "value": "synthetic"}]}, (), "present", []),
        ({}, (), "absent", []),
    ],
)
def test_seed_auth_material_counts_only_replayable_auth(seed, required, material, names):
    result = seed_auth_material(seed, required)

    assert result["auth_material"] == material
    assert result["auth_header_names"] == names
    assert "synthetic" not in repr(result)


def test_verification_does_not_carry_over_to_a_replaced_seed():
    stored = {
        "captured_at": iso(timedelta(days=2)),
        "auth_material": "present",
        "last_verified_at": iso(timedelta(days=1)),
        "last_verified_result": "live",
    }
    same = effective_seed_status(stored, {"captured_at": stored["captured_at"], "auth_material": "present"})
    replaced = effective_seed_status(stored, {"captured_at": iso(timedelta(minutes=1)), "auth_material": "present"})

    assert same["last_verified_result"] == "live"
    assert "last_verified_result" not in replaced


def test_liveness_records_discriminator_without_query_and_skips_unrun_checks():
    verification = liveness_from_check(
        {"status": "failed", "url": "https://api.example.test/v1/me?sig=synthetic#x", "method": "get", "status_code": 401},
        now=NOW,
    )

    assert verification == {
        "last_verified_at": NOW.isoformat(),
        "last_verified_result": "expired",
        "last_verified_reason": "http-401",
        "last_verified_check": {"method": "GET", "url": "https://api.example.test/v1/me"},
    }
    assert liveness_from_check({"status": "skipped", "reason": "no-target-url"}) is None
    inconclusive = liveness_from_check({"status": "inconclusive", "reason": "html-document"})
    assert inconclusive is not None and inconclusive["last_verified_result"] == "unknown"


@pytest.mark.parametrize(
    "url,warns",
    [
        ("https://app.example.test/", True),
        ("https://app.example.test", True),
        ("https://app.example.test/index.html", True),
        ("https://app.example.test/static/app.js", True),
        ("https://api.example.test/v1/me", False),
        ("https://app.example.test/api/session", False),
        (None, False),
    ],
)
def test_static_auth_check_url_warning(url, warns):
    assert (auth_check_url_warning(url) is not None) is warns
