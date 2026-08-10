from __future__ import annotations

import json
from pathlib import Path


def test_append_attempt_writes_required_fields_and_redacts_secrets(tmp_path: Path) -> None:
    from agents.attempts import append_attempt

    path = tmp_path / "attempts.jsonl"
    append_attempt(
        path,
        {
            "timestamp": "2026-08-06T00:00:00Z",
            "tool": "xss_framework",
            "target": "https://example.test/search?q=needle&nonce=secret-nonce",
            "outcome": "cold",
            "stop_reason": "marker_absent_raw_response",
            "request_headers": {"Cookie": "session=secret-cookie"},
        },
    )

    row = json.loads(path.read_text(encoding="utf-8"))
    assert row["outcome"] == "cold"
    assert "secret-nonce" not in json.dumps(row)
    assert "secret-cookie" not in json.dumps(row)
    assert row["request_headers"]["Cookie"] == "REDACTED"


def test_append_attempt_redacts_sensitive_key_value_forms_in_nonsecret_fields(tmp_path: Path) -> None:
    from agents.attempts import append_attempt

    path = tmp_path / "attempts.jsonl"
    append_attempt(
        path,
        {
            "timestamp": "2026-08-06T00:00:00Z",
            "tool": "xss_framework",
            "target": "https://example.test/search?q=needle",
            "outcome": "cold",
            "stop_reason": "raw_response_only_inconclusive",
            "body_snippet": "password=hunter2; session: session-value; cookie=crumb; token: bearer-token",
        },
    )

    serialized = path.read_text(encoding="utf-8")
    assert "password=REDACTED" in serialized
    assert "session: REDACTED" in serialized
    assert "cookie=REDACTED" in serialized
    assert "token: REDACTED" in serialized
    for secret in ("hunter2", "session-value", "crumb", "bearer-token"):
        assert secret not in serialized


def test_append_attempt_rejects_missing_required_fields(tmp_path: Path) -> None:
    from agents.attempts import append_attempt

    try:
        append_attempt(tmp_path / "attempts.jsonl", {"tool": "xss_framework"})
    except ValueError as exc:
        assert "timestamp" in str(exc)
    else:
        raise AssertionError("missing required fields must be rejected")


def test_attempts_are_written_as_core_events_and_queryable_by_generic_fields(tmp_path: Path) -> None:
    from agents.attempts import append_attempt, read_attempts

    path = tmp_path / "attempts.jsonl"
    stored = append_attempt(
        path,
        {
            "timestamp": "2026-08-06T00:00:00Z",
            "tool": "xss_framework",
            "target": "https://example.test/search?q=needle",
            "outcome": "warm",
            "stop_reason": "context_character_differential",
            "vuln_class": "xss",
        },
    )

    assert stored["schema_version"] == 1
    assert stored["producer"] == "xss_framework"
    assert stored["subject"] == "https://example.test/search?q=needle"
    assert stored["reason"] == "context_character_differential"
    assert stored["attempt_id"].startswith("A-")
    assert read_attempts(path, where={"vuln_class": "xss"}) == [stored]


def test_resolve_attempts_path_uses_generic_run_stream_not_vulnerability_filenames(tmp_path: Path) -> None:
    from agents.attempts import resolve_attempts_path

    path = resolve_attempts_path(
        "Example Program",
        run_id="run-test-001",
        root_override=tmp_path,
    )

    assert path == tmp_path / "web_bounty" / "Example_Program" / "recon" / "attempts" / "_runs" / "run-test-001" / "attempts.jsonl"
    assert "xss" not in str(path).lower()



def test_read_attempt_bucket_queries_all_runs_and_filters_without_exact_run_path(tmp_path: Path) -> None:
    from agents.attempts import append_attempt, read_attempt_bucket, resolve_attempts_path

    first = resolve_attempts_path("example", run_id="run-001", root_override=tmp_path)
    second = resolve_attempts_path("example", run_id="run-002", root_override=tmp_path)
    for path, timestamp, vuln_class in (
        (first, "2026-08-06T00:00:00Z", "lfi"),
        (second, "2026-08-07T00:00:00Z", "xss"),
    ):
        append_attempt(path, {
            "timestamp": timestamp,
            "tool": "test_agent",
            "target": "https://example.test/check",
            "outcome": "inert",
            "stop_reason": "test_fixture",
            "vuln_class": vuln_class,
        })

    all_rows = read_attempt_bucket("example", root_override=tmp_path)
    assert [row["vuln_class"] for row in all_rows] == ["xss", "lfi"]
    assert read_attempt_bucket("example", root_override=tmp_path, where={"vuln_class": "lfi"})[0]["run_id"] == "run-001"


def test_resolve_attempts_path_rejects_path_like_run_id(tmp_path: Path) -> None:
    from agents.attempts import resolve_attempts_path

    for invalid_run_id in ("../escape", ".", ".."):
        try:
            resolve_attempts_path("example", run_id=invalid_run_id, root_override=tmp_path)
        except ValueError as exc:
            assert "path-safe" in str(exc)
        else:
            raise AssertionError(f"path-like run ID was accepted: {invalid_run_id!r}")
