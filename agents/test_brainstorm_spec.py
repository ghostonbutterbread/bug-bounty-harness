from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.brainstorm_spec import (
    BrainstormSpecError,
    append_coverage,
    parse_brainstorm_spec,
    spec_to_agent_intents,
    summarize_coverage,
)
from agents.brainstorm_adapters import (
    brainstorm_intent_to_apk_profile,
    brainstorm_intent_to_dynamic_agent_spec,
    brainstorm_intent_to_zero_day_profile,
)


def _valid_spec_text() -> str:
    return """# Brainstorm Spec: Canva Desktop EXE

## Metadata
- Program: canva
- Family: binaries
- Lane: exe
- Target kind: electron-exe
- Target path: input/app_asar
- Created: 2026-04-30
- Status: active

## Target mental model
Canva Desktop is an Electron application wrapping a rich design/editor web app.
It handles imports, uploads, shared links, notifications, and native integrations.

## Impact primitives
### P001 — ElectronBridge host RPC access
- Source: `window.ElectronBridge.requestMessagePort`
- Impact: renderer JS can potentially reach host RPC modules
- Evidence: reports/dormant/index.md
- Status: active

## Hypotheses
### H001 — SVG import can create renderer script execution
Review sanitizer behavior and preview rendering before choosing payloads.
- Status: untested
- Priority: high
- Surface: import-upload-render
- Entry point: user imports or pastes SVG/design asset
- Expected chain: imported SVG/pasted content -> renderer script execution -> ElectronBridge host RPC
- Suggested agents:
  - canva-svg-import-xss
  - canva-renderer-bridge-chain
- Focus files:
  - dist/**/*.js
  - **/*svg*
  - **/*import*
- Tags: xss, import, renderer, electron-bridge
- Evidence:
  - DORMANT-1
  - reports/dormant/index.md:12
  - https://example.test/reports/DORMANT-1:details
- Notes: prioritize sanitizer and preview render paths

### H002 — Open redirect can pivot into desktop deep link or allowlist bypass
- Status: untested
- Priority: medium
- Surface: shared-link-navigation
- Entry point: trusted Canva link redirects to attacker-controlled or custom-protocol target
- Expected chain: trusted Canva URL -> redirect -> desktop deep link / privileged navigation / main-process fetch allowlist bypass
- Suggested agents:
  - canva-open-redirect-deeplink-chain
  - canva-redirect-allowlist-bypass
- Tags: open-redirect, deeplink, navigation, ssrf

## Coverage log
| Hypothesis | Agent | Status | Result | Linked FIDs | Run ID | Notes |
|---|---|---|---|---|---|---|
"""


def _write_spec(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "brainstorm" / "spec.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_parse_valid_spec_extracts_metadata_lists_and_hypotheses(tmp_path: Path) -> None:
    path = _write_spec(tmp_path, _valid_spec_text())

    spec = parse_brainstorm_spec(path)

    assert spec.path == path.resolve(strict=False)
    assert spec.metadata["Program"] == "canva"
    assert spec.metadata["Target path"] == "input/app_asar"
    assert "Electron application" in spec.mental_model
    assert spec.impact_primitives == [
        {
            "id": "P001",
            "title": "ElectronBridge host RPC access",
            "source": "window.ElectronBridge.requestMessagePort",
            "impact": "renderer JS can potentially reach host RPC modules",
            "evidence": "reports/dormant/index.md",
            "status": "active",
        }
    ]
    assert [hypothesis.id for hypothesis in spec.hypotheses] == ["H001", "H002"]
    first = spec.hypotheses[0]
    assert first.status == "untested"
    assert first.priority == "high"
    assert first.suggested_agents == [
        "canva-svg-import-xss",
        "canva-renderer-bridge-chain",
    ]
    assert first.focus_files_glob == ["dist/**/*.js", "**/*svg*", "**/*import*"]
    assert first.tags == ["xss", "import", "renderer", "electron-bridge"]
    assert first.evidence == [
        "DORMANT-1",
        "reports/dormant/index.md:12",
        "https://example.test/reports/DORMANT-1:details",
    ]
    assert first.notes == "prioritize sanitizer and preview render paths"
    assert (
        first.freeform_text
        == "Review sanitizer behavior and preview rendering before choosing payloads."
    )


def test_parse_rejects_duplicate_hypothesis_ids(tmp_path: Path) -> None:
    text = _valid_spec_text().replace("### H002", "### H001")
    path = _write_spec(tmp_path, text)

    with pytest.raises(BrainstormSpecError, match="duplicate hypothesis id: H001"):
        parse_brainstorm_spec(path)


def test_parse_rejects_invalid_status_and_priority(tmp_path: Path) -> None:
    bad_status = _valid_spec_text().replace("- Status: untested", "- Status: maybe", 1)
    with pytest.raises(BrainstormSpecError, match="invalid status 'maybe'"):
        parse_brainstorm_spec(_write_spec(tmp_path / "status", bad_status))

    bad_priority = _valid_spec_text().replace("- Priority: high", "- Priority: urgent", 1)
    with pytest.raises(BrainstormSpecError, match="invalid priority 'urgent'"):
        parse_brainstorm_spec(_write_spec(tmp_path / "priority", bad_priority))


def test_parse_rejects_missing_required_fields(tmp_path: Path) -> None:
    text = _valid_spec_text().replace(
        "- Expected chain: imported SVG/pasted content -> renderer script execution -> ElectronBridge host RPC\n",
        "",
        1,
    )
    path = _write_spec(tmp_path, text)

    with pytest.raises(BrainstormSpecError, match="missing required field\\(s\\): expected_chain"):
        parse_brainstorm_spec(path)


def test_parse_rejects_duplicate_suggested_agent_keys_across_active_hypotheses(
    tmp_path: Path,
) -> None:
    text = _valid_spec_text().replace(
        "canva-open-redirect-deeplink-chain",
        "canva-svg-import-xss",
    )
    path = _write_spec(tmp_path, text)

    with pytest.raises(BrainstormSpecError, match="duplicate suggested agent key"):
        parse_brainstorm_spec(path)


def test_parse_rejects_case_insensitive_suggested_agent_key_collisions(
    tmp_path: Path,
) -> None:
    same_hypothesis = _valid_spec_text().replace(
        "  - canva-renderer-bridge-chain",
        "  - Canva-Svg-Import-Xss",
        1,
    )
    with pytest.raises(BrainstormSpecError, match="duplicate suggested agent key"):
        parse_brainstorm_spec(_write_spec(tmp_path / "same", same_hypothesis))

    across_active_hypotheses = _valid_spec_text().replace(
        "canva-open-redirect-deeplink-chain",
        "CANVA-SVG-IMPORT-XSS",
        1,
    )
    with pytest.raises(BrainstormSpecError, match="duplicate suggested agent key"):
        parse_brainstorm_spec(_write_spec(tmp_path / "across", across_active_hypotheses))


def test_parse_rejects_unsafe_suggested_agent_keys(tmp_path: Path) -> None:
    unsafe_keys = [
        ("../escape", "path separators"),
        ("nested/agent", "path separators"),
        ("nested\\agent", "path separators"),
        ("-leading-dash", "start and end"),
        ("trailing-dash-", "start and end"),
        ("agent.name", "ASCII letters"),
        ("a" * 65, "exceeds 64 characters"),
    ]

    for unsafe_key, message in unsafe_keys:
        text = _valid_spec_text().replace("canva-svg-import-xss", unsafe_key, 1)
        with pytest.raises(BrainstormSpecError, match=message):
            parse_brainstorm_spec(_write_spec(tmp_path / unsafe_key.replace("/", "_"), text))


def test_parse_validates_retired_hypothesis_suggested_agent_keys(
    tmp_path: Path,
) -> None:
    unsafe_retired = _valid_spec_text().replace(
        "- Status: untested\n- Priority: medium",
        "- Status: retired\n- Priority: medium",
        1,
    ).replace("canva-open-redirect-deeplink-chain", "../escape", 1)
    with pytest.raises(BrainstormSpecError, match="path separators"):
        parse_brainstorm_spec(_write_spec(tmp_path / "unsafe_retired", unsafe_retired))

    retired_active_collision = _valid_spec_text().replace(
        "- Status: untested\n- Priority: medium",
        "- Status: retired\n- Priority: medium",
        1,
    ).replace("canva-open-redirect-deeplink-chain", "canva-svg-import-xss", 1)

    spec = parse_brainstorm_spec(
        _write_spec(tmp_path / "retired_collision", retired_active_collision)
    )

    assert spec.hypotheses[1].status == "retired"


def test_parse_preserves_nested_evidence_urls_and_freeform_text(tmp_path: Path) -> None:
    text = _valid_spec_text().replace(
        "Review sanitizer behavior and preview rendering before choosing payloads.",
        "Review sanitizer behavior and preview rendering before choosing payloads.\n"
        "Free-form analyst context before fields.",
        1,
    ).replace(
        "  - DORMANT-1",
        "  - DORMANT-1\n  - https://example.com/report?id=1:2",
        1,
    )

    spec = parse_brainstorm_spec(_write_spec(tmp_path, text))

    first = spec.hypotheses[0]
    assert first.freeform_text == (
        "Review sanitizer behavior and preview rendering before choosing payloads.\n"
        "Free-form analyst context before fields."
    )
    assert "https://example.com/report?id=1:2" in first.evidence
    assert "https://example.test/reports/DORMANT-1:details" in first.evidence


def test_parse_rejects_absolute_paths_outside_lane_root(tmp_path: Path) -> None:
    target_path_text = _valid_spec_text().replace(
        "- Target path: input/app_asar",
        "- Target path: /etc/passwd",
        1,
    )
    with pytest.raises(BrainstormSpecError, match="resolves outside lane root"):
        parse_brainstorm_spec(_write_spec(tmp_path / "target", target_path_text))

    focus_file_text = _valid_spec_text().replace(
        "  - dist/**/*.js",
        "  - /tmp/outside/**/*.js",
        1,
    )
    with pytest.raises(BrainstormSpecError, match="resolves outside lane root"):
        parse_brainstorm_spec(_write_spec(tmp_path / "focus", focus_file_text))

    evidence_text = _valid_spec_text().replace(
        "  - DORMANT-1",
        "  - /etc/shadow",
        1,
    )
    with pytest.raises(BrainstormSpecError, match="resolves outside lane root"):
        parse_brainstorm_spec(_write_spec(tmp_path / "evidence", evidence_text))


def test_parse_rejects_paths_outside_lane_root_by_default(tmp_path: Path) -> None:
    bad_target = _valid_spec_text().replace(
        "- Target path: input/app_asar",
        "- Target path: /etc/passwd",
    )
    with pytest.raises(BrainstormSpecError, match="metadata 'Target path' path"):
        parse_brainstorm_spec(_write_spec(tmp_path / "target", bad_target))

    bad_focus = _valid_spec_text().replace("dist/**/*.js", "../outside/**/*.js")
    with pytest.raises(BrainstormSpecError, match="focus_files path"):
        parse_brainstorm_spec(_write_spec(tmp_path / "focus", bad_focus))

    bad_evidence = _valid_spec_text().replace(
        "reports/dormant/index.md:12",
        "/var/tmp/outside.md",
    )
    with pytest.raises(BrainstormSpecError, match="evidence path"):
        parse_brainstorm_spec(_write_spec(tmp_path / "evidence", bad_evidence))


def test_parse_path_validation_can_be_explicitly_disabled(tmp_path: Path) -> None:
    text = _valid_spec_text().replace(
        "- Target path: input/app_asar",
        "- Target path: /etc/passwd",
    )
    spec = parse_brainstorm_spec(_write_spec(tmp_path, text), validate_paths=False)

    assert spec.metadata["Target path"] == "/etc/passwd"


def test_coverage_append_and_summary_distinguish_statuses_and_outcomes(
    tmp_path: Path,
) -> None:
    spec = parse_brainstorm_spec(_write_spec(tmp_path, _valid_spec_text()))
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"

    append_coverage(
        coverage_path,
        {
            "event": "hypothesis_loaded",
            "hypothesis_id": "H001",
            "status": "untested",
            "run_id": "run-1",
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "agent_queued",
            "hypothesis_id": "H001",
            "agent_key": "canva-svg-import-xss",
            "run_id": "run-1",
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "agent_spawned",
            "hypothesis_id": "H001",
            "agent_key": "canva-svg-import-xss",
            "run_id": "run-1",
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "agent_completed_no_finding",
            "hypothesis_id": "H001",
            "agent_key": "canva-svg-import-xss",
            "run_id": "run-1",
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "agent_timeout",
            "hypothesis_id": "H003",
            "agent_key": "timeout-agent",
            "run_id": "run-1",
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "agent_crashed",
            "hypothesis_id": "H004",
            "agent_key": "crash-agent",
            "run_id": "run-1",
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "agent_invalid_output",
            "hypothesis_id": "H005",
            "agent_key": "invalid-agent",
            "run_id": "run-1",
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "agent_duplicate_only",
            "hypothesis_id": "H006",
            "agent_key": "duplicate-agent",
            "run_id": "run-1",
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "review_rejected",
            "hypothesis_id": "H007",
            "agent_key": "rejected-agent",
            "run_id": "run-1",
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "review_promoted",
            "hypothesis_id": "H008",
            "agent_key": "promoted-agent",
            "linked_fids": ["D12"],
            "run_id": "run-1",
        },
    )

    lines = coverage_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 10
    assert json.loads(lines[0])["event"] == "hypothesis_loaded"

    summary = summarize_coverage(coverage_path, spec=spec)

    assert summary["hypotheses"]["H001"]["status"] == "tested_no_finding"
    assert summary["hypotheses"]["H002"]["status"] == "untested"
    assert summary["hypotheses"]["H003"]["status"] == "blocked"
    assert summary["hypotheses"]["H008"]["status"] == "tested_finding"
    assert summary["hypotheses"]["H008"]["linked_fids"] == ["D12"]
    assert summary["counts_by_status"]["untested"] == 1
    assert summary["counts_by_status"]["tested_no_finding"] == 3
    assert summary["counts_by_status"]["blocked"] == 3
    assert summary["counts_by_status"]["tested_finding"] == 1
    assert summary["counts_by_outcome"]["no_finding"] == 1
    assert summary["counts_by_outcome"]["timeout"] == 1
    assert summary["counts_by_outcome"]["crash"] == 1
    assert summary["counts_by_outcome"]["invalid_output"] == 1
    assert summary["counts_by_outcome"]["duplicate_only"] == 1
    assert summary["counts_by_outcome"]["review_rejected"] == 1
    assert summary["counts_by_outcome"]["review_promoted"] == 1


def test_coverage_raw_findings_are_pending_until_review_result(tmp_path: Path) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"

    append_coverage(
        coverage_path,
        {
            "event": "agent_completed_with_raw_findings",
            "hypothesis_id": "H001",
            "agent_key": "raw-agent",
            "raw_finding_signatures": ["raw-1"],
        },
    )
    raw_only = summarize_coverage(coverage_path)
    assert raw_only["hypotheses"]["H001"]["status"] == "raw_finding_pending"
    assert raw_only["counts_by_status"] == {"raw_finding_pending": 1}
    assert raw_only["counts_by_outcome"] == {"raw_finding_pending": 1}
    assert raw_only["hypotheses"]["H001"]["raw_findings"] == ["raw-1"]

    append_coverage(
        coverage_path,
        {
            "event": "review_rejected",
            "hypothesis_id": "H001",
            "agent_key": "raw-agent",
        },
    )
    rejected = summarize_coverage(coverage_path)
    assert rejected["hypotheses"]["H001"]["status"] == "tested_no_finding"
    assert rejected["hypotheses"]["H001"]["outcomes"]["review_rejected"] == 1

    append_coverage(
        coverage_path,
        {
            "event": "agent_completed_with_raw_findings",
            "hypothesis_id": "H002",
            "agent_key": "promoted-agent",
            "raw_findings": ["raw-2"],
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "review_promoted",
            "hypothesis_id": "H002",
            "agent_key": "promoted-agent",
            "linked_fids": ["D99"],
        },
    )
    promoted = summarize_coverage(coverage_path)
    assert promoted["hypotheses"]["H002"]["status"] == "tested_finding"
    assert promoted["hypotheses"]["H002"]["linked_fids"] == ["D99"]


def test_coverage_explicit_hypothesis_status_is_not_overwritten(tmp_path: Path) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"
    append_coverage(
        coverage_path,
        {
            "event": "review_promoted",
            "hypothesis_id": "H001",
            "agent_key": "agent-a",
            "linked_fids": ["D1"],
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "coverage_status_changed",
            "hypothesis_id": "H001",
            "status": "retired",
        },
    )

    summary = summarize_coverage(coverage_path)

    assert summary["hypotheses"]["H001"]["status"] == "retired"


@pytest.mark.parametrize(
    "events",
    [
        [
            {
                "event": "agent_timeout",
                "hypothesis_id": "H001",
                "agent_key": "agent-blocked",
            },
            {
                "event": "agent_completed_no_finding",
                "hypothesis_id": "H001",
                "agent_key": "agent-clean",
            },
        ],
        [
            {
                "event": "agent_completed_no_finding",
                "hypothesis_id": "H001",
                "agent_key": "agent-clean",
            },
            {
                "event": "agent_timeout",
                "hypothesis_id": "H001",
                "agent_key": "agent-blocked",
            },
        ],
    ],
)
def test_coverage_mixed_blocked_and_no_finding_status_is_order_independent(
    tmp_path: Path,
    events: list[dict[str, str]],
) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"

    for event in events:
        append_coverage(coverage_path, event)

    summary = summarize_coverage(coverage_path)

    assert summary["hypotheses"]["H001"]["status"] == "blocked"
    assert summary["hypotheses"]["H001"]["agents"]["agent-blocked"]["status"] == "blocked"
    assert (
        summary["hypotheses"]["H001"]["agents"]["agent-clean"]["status"]
        == "tested_no_finding"
    )


def test_coverage_rejects_agent_scoped_status_changes(tmp_path: Path) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"

    with pytest.raises(BrainstormSpecError, match="must not include agent_key"):
        append_coverage(
            coverage_path,
            {
                "event": "coverage_status_changed",
                "hypothesis_id": "H001",
                "agent_key": "agent-a",
                "status": "retired",
            },
        )


@pytest.mark.parametrize(
    "events",
    [
        [
            {
                "event": "coverage_status_changed",
                "hypothesis_id": "H001",
                "agent_key": "agent-a",
                "status": "retired",
            },
            {
                "event": "agent_completed_no_finding",
                "hypothesis_id": "H001",
                "agent_key": "agent-a",
            },
        ],
        [
            {
                "event": "agent_completed_no_finding",
                "hypothesis_id": "H001",
                "agent_key": "agent-a",
            },
            {
                "event": "coverage_status_changed",
                "hypothesis_id": "H001",
                "agent_key": "agent-a",
                "status": "retired",
            },
        ],
    ],
)
def test_coverage_ignores_legacy_agent_scoped_status_changes_order_independently(
    tmp_path: Path,
    events: list[dict[str, str]],
) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"
    coverage_path.parent.mkdir(parents=True, exist_ok=True)
    coverage_path.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )

    summary = summarize_coverage(coverage_path)

    assert summary["hypotheses"]["H001"]["status"] == "tested_no_finding"
    assert summary["hypotheses"]["H001"]["agents"]["agent-a"]["status"] == (
        "tested_no_finding"
    )


def test_append_coverage_rejects_malformed_event_shapes(tmp_path: Path) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"

    with pytest.raises(BrainstormSpecError, match="hypothesis_id"):
        append_coverage(coverage_path, {"event": "hypothesis_loaded"})

    with pytest.raises(BrainstormSpecError, match="agent_key"):
        append_coverage(
            coverage_path,
            {"event": "agent_spawned", "hypothesis_id": "H001"},
        )

    with pytest.raises(BrainstormSpecError, match="linked_fids"):
        append_coverage(
            coverage_path,
            {
                "event": "review_promoted",
                "hypothesis_id": "H001",
                "agent_key": "agent-a",
            },
        )

    with pytest.raises(BrainstormSpecError, match="raw_finding_signatures or raw_findings"):
        append_coverage(
            coverage_path,
            {
                "event": "agent_completed_with_raw_findings",
                "hypothesis_id": "H001",
                "agent_key": "agent-a",
            },
        )

    with pytest.raises(BrainstormSpecError, match="hypothesis_loaded event has invalid status"):
        append_coverage(
            coverage_path,
            {
                "event": "hypothesis_loaded",
                "hypothesis_id": "H001",
                "status": "maybe",
            },
        )

    with pytest.raises(
        BrainstormSpecError,
        match="coverage_status_changed event has invalid status",
    ):
        append_coverage(
            coverage_path,
            {
                "event": "coverage_status_changed",
                "hypothesis_id": "H001",
                "status": "maybe",
            },
        )


def test_raw_findings_are_pending_until_review_decision(tmp_path: Path) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"

    append_coverage(
        coverage_path,
        {
            "event": "agent_completed_with_raw_findings",
            "hypothesis_id": "H001",
            "agent_key": "raw-agent",
            "raw_finding_signatures": ["sig-1"],
        },
    )
    raw_only = summarize_coverage(coverage_path)
    assert raw_only["hypotheses"]["H001"]["status"] == "raw_finding_pending"
    assert raw_only["counts_by_status"]["raw_finding_pending"] == 1
    assert raw_only["counts_by_outcome"]["raw_finding_pending"] == 1
    assert raw_only["counts_by_status"].get("tested_finding", 0) == 0

    append_coverage(
        coverage_path,
        {
            "event": "review_rejected",
            "hypothesis_id": "H001",
            "agent_key": "raw-agent",
        },
    )
    rejected = summarize_coverage(coverage_path)
    assert rejected["hypotheses"]["H001"]["status"] == "tested_no_finding"
    assert rejected["counts_by_status"].get("tested_finding", 0) == 0

    promoted_path = tmp_path / "brainstorm" / "promoted.jsonl"
    append_coverage(
        promoted_path,
        {
            "event": "agent_completed_with_raw_findings",
            "hypothesis_id": "H002",
            "agent_key": "raw-agent",
            "raw_findings": [{"signature": "sig-2"}],
        },
    )
    append_coverage(
        promoted_path,
        {
            "event": "review_promoted",
            "hypothesis_id": "H002",
            "agent_key": "raw-agent",
            "linked_fids": ["D99"],
        },
    )
    promoted = summarize_coverage(promoted_path)
    assert promoted["hypotheses"]["H002"]["status"] == "tested_finding"
    assert promoted["hypotheses"]["H002"]["linked_fids"] == ["D99"]


def test_explicit_hypothesis_status_change_survives_reconcile(tmp_path: Path) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"
    append_coverage(
        coverage_path,
        {
            "event": "agent_completed_no_finding",
            "hypothesis_id": "H001",
            "agent_key": "agent-a",
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "coverage_status_changed",
            "hypothesis_id": "H001",
            "status": "retired",
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "agent_completed_no_finding",
            "hypothesis_id": "H002",
            "agent_key": "agent-b",
        },
    )
    append_coverage(
        coverage_path,
        {
            "event": "coverage_status_changed",
            "hypothesis_id": "H002",
            "status": "blocked",
        },
    )

    summary = summarize_coverage(coverage_path)

    assert summary["hypotheses"]["H001"]["status"] == "retired"
    assert summary["hypotheses"]["H002"]["status"] == "blocked"


def test_append_coverage_validates_event_shape(tmp_path: Path) -> None:
    coverage_path = tmp_path / "brainstorm" / "coverage.jsonl"

    with pytest.raises(BrainstormSpecError, match="hypothesis_id"):
        append_coverage(coverage_path, {"event": "hypothesis_loaded"})

    with pytest.raises(BrainstormSpecError, match="agent_key"):
        append_coverage(
            coverage_path,
            {"event": "agent_queued", "hypothesis_id": "H001"},
        )

    with pytest.raises(BrainstormSpecError, match="linked_fids"):
        append_coverage(
            coverage_path,
            {
                "event": "review_promoted",
                "hypothesis_id": "H001",
                "agent_key": "agent-a",
            },
        )

    with pytest.raises(BrainstormSpecError, match="raw_finding_signatures"):
        append_coverage(
            coverage_path,
            {
                "event": "agent_completed_with_raw_findings",
                "hypothesis_id": "H001",
                "agent_key": "agent-a",
            },
        )


def test_conversion_to_agent_intent_preserves_brainstorm_metadata(tmp_path: Path) -> None:
    spec = parse_brainstorm_spec(_write_spec(tmp_path, _valid_spec_text()))

    intents = spec_to_agent_intents(spec)

    first = intents[0]
    assert first.hypothesis_id == "H001"
    assert first.source_spec_path == spec.path
    assert (
        first.expected_chain
        == "imported SVG/pasted content -> renderer script execution -> ElectronBridge host RPC"
    )
    assert first.agent_key == "canva-svg-import-xss"
    assert first.hypothesis_title == "SVG import can create renderer script execution"
    assert first.focus_files_glob == ["dist/**/*.js", "**/*svg*", "**/*import*"]
    assert first.finding_metadata() == {
        "brainstorm_spec": str(spec.path),
        "hypothesis_id": "H001",
        "hypothesis_title": "SVG import can create renderer script execution",
        "brainstorm_agent_key": "canva-svg-import-xss",
        "brainstorm_surface": "import-upload-render",
        "brainstorm_tags": ["xss", "import", "renderer", "electron-bridge"],
    }


def test_brainstorm_intent_adapters_preserve_zero_day_and_apk_boundaries(
    tmp_path: Path,
) -> None:
    spec = parse_brainstorm_spec(_write_spec(tmp_path, _valid_spec_text()))
    intent = spec_to_agent_intents(spec)[0]

    dynamic_spec = brainstorm_intent_to_dynamic_agent_spec(
        intent,
        program="canva",
        version="snap-1",
    )
    zero_day_profile = brainstorm_intent_to_zero_day_profile(
        intent,
        program="canva",
        version="snap-1",
    )
    apk_profile = brainstorm_intent_to_apk_profile(
        intent,
        program="canva",
        version="snap-1",
    )

    for profile in (dynamic_spec, zero_day_profile, apk_profile):
        metadata = profile.brainstorm_metadata
        assert metadata["hypothesis_id"] == "H001"
        assert metadata["brainstorm_agent_key"] == "canva-svg-import-xss"
        assert metadata["expected_chain"] == (
            "imported SVG/pasted content -> renderer script execution -> ElectronBridge host RPC"
        )
        assert metadata["source_spec_path"] == str(spec.path)
        assert metadata["brainstorm_spec"] == str(spec.path)
        assert metadata["hypothesis_title"] == "SVG import can create renderer script execution"
        assert metadata["brainstorm_surface"] == "import-upload-render"
        assert metadata["brainstorm_tags"] == ["xss", "import", "renderer", "electron-bridge"]
        prompt_addendum = getattr(
            profile,
            "prompt_addendum",
            getattr(profile, "agent_prompt_template", ""),
        )
        assert "hypothesis_id" in prompt_addendum
        assert "brainstorm_agent_key" in prompt_addendum
        assert "Expected chain:" in prompt_addendum
