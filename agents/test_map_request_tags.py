"""Tests for map_request_tags.py."""

from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from agents.map_request_tags import (
    build_state,
    normalize_key,
    parse_assignment,
    parse_tristate,
)


def test_normalize_key_snake_cases_custom_retest_names():
    assert normalize_key("Company Admin") == "company_admin"
    assert normalize_key("sdk-token") == "sdk_token"
    assert normalize_key("Canva linked user") == "canva_linked_user"


def test_parse_tristate_accepts_supported_values():
    assert parse_tristate("true") is True
    assert parse_tristate("blocked") is False
    assert parse_tristate("untested") is None


def test_parse_assignment_normalizes_key_and_value():
    assert parse_assignment("Company Admin=false") == ("company_admin", False)


def test_parse_assignment_rejects_missing_equals():
    with pytest.raises(ValueError):
        parse_assignment("company_admin")


def test_build_state_generates_structured_fields_and_tags():
    state = build_state(
        gate_type="feature",
        status=403,
        reason="no access to feature",
        tested={"basic_user": False, "linked_user": False},
        next_retest=["sdk_token", "company_admin"],
        body_fingerprint="error.message contains no access",
    )

    assert state.gate == {
        "type": "feature",
        "status": 403,
        "reason": "no_access_to_feature",
        "body_fingerprint": "error.message contains no access",
    }
    assert state.retest_matrix == {
        "basic_user": False,
        "linked_user": False,
        "sdk_token": None,
        "company_admin": None,
    }
    assert state.last_retested_for == ["basic_user", "linked_user"]
    assert state.next_retest_when == ["sdk_token", "company_admin"]
    assert state.tags == [
        "request-contract",
        "gate:feature",
        "status:403",
        "reason:no_access_to_feature",
        "tested:basic_user",
        "tested:linked_user",
        "retest:sdk_token",
        "retest:company_admin",
    ]
    assert state.warnings == []


def test_build_state_allows_custom_specific_retest_keys():
    state = build_state(
        gate_type="role",
        status=403,
        reason="role_required",
        tested={"workspace_owner": True},
        next_retest=["billing_admin"],
    )

    assert state.retest_matrix["workspace_owner"] is True
    assert state.retest_matrix["billing_admin"] is None
    assert "tested:workspace_owner" in state.tags
    assert "retest:billing_admin" in state.tags
    assert state.warnings == []


def test_build_state_warns_on_vague_retest_keys_and_unknown_reason():
    state = build_state(
        gate_type="company",
        status=403,
        reason="company stuff",
        tested={"company": False},
    )

    assert state.gate["reason"] == "company_stuff"
    assert any("unknown gate.reason" in warning for warning in state.warnings)
    assert any("retest key 'company' is vague" in warning for warning in state.warnings)
