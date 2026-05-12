from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agents.agent_scheduler import (
    SchedulerConfig,
    assignments_from_profiles,
    bundle_category_masters,
    decision_events,
    infer_surface_family,
    plan_agent_wave,
)
from agents.base_team.scheduler import BaseTeamSchedulerOptions, schedule_profiles


@dataclass(frozen=True)
class Profile:
    key: str
    description: str = ""
    entry_questions: tuple[str, ...] = ()
    cross_questions: tuple[str, ...] = ()
    sink_categories: tuple[str, ...] = ()
    reasoning: str = ""
    display_name: str | None = None
    prompt_addendum: str = ""
    focus_globs: tuple[str, ...] = ("src/main.js",)
    ignore_globs: tuple[str, ...] = ()
    brainstorm_metadata: dict[str, Any] = field(default_factory=dict)


def _profile(
    key: str,
    *,
    priority: str = "medium",
    metadata: dict[str, Any] | None = None,
    focus_globs: tuple[str, ...] = ("src/main.js",),
) -> Profile:
    merged = {
        "hypothesis_id": f"H-{key}",
        "brainstorm_agent_key": key,
        "source_spec_path": "/tmp/spec.md",
        "priority": priority,
    }
    merged.update(metadata or {})
    return Profile(
        key=key,
        description=key.replace("-", " "),
        sink_categories=(str(merged.get("expected_chain") or key),),
        focus_globs=focus_globs,
        brainstorm_metadata=merged,
    )


def test_family_inference_uses_explicit_metadata_before_keywords() -> None:
    profile = _profile(
        "canva-hostrpc-service-boundary-auditor",
        metadata={
            "brainstorm_surface_family": "download-export-filesystem",
            "brainstorm_tags": ["hostrpc", "ipc"],
        },
    )

    family, secondaries = infer_surface_family(profile, metadata=profile.brainstorm_metadata)

    assert family == "download-export-filesystem"
    assert secondaries == ()


def test_family_inference_uses_key_tags_chain_and_focus_files() -> None:
    cases = [
        (_profile("hostrpc-method-audit", metadata={"brainstorm_tags": ["HostRpc"]}), "hostrpc"),
        (
            _profile(
                "download-export-abuse",
                metadata={"expected_chain": "download URL to reveal in filesystem"},
            ),
            "download-export-filesystem",
        ),
        (_profile("oauth-popup-callback", metadata={"brainstorm_tags": ["oauth", "callback"]}), "auth-session-callback"),
        (
            _profile("share-dialog-open-action", metadata={"expected_chain": "double-click opens selected shared item"}),
            "ui-dialog-window",
        ),
        (_profile("deeplink-router", metadata={"focus_files": ["src/protocol-handler.ts"]}), "custom-protocol-deeplink"),
    ]

    assert [infer_surface_family(profile, metadata=profile.brainstorm_metadata)[0] for profile, _ in cases] == [
        expected for _, expected in cases
    ]


def test_secondary_families_preserve_multi_agent_assignment_possibility() -> None:
    profile = _profile(
        "oauth-popup-callback",
        metadata={
            "surface_family": "auth-session-callback",
            "secondary_families": ["navigation-popup", "ipc"],
        },
    )

    family, secondaries = infer_surface_family(profile, metadata=profile.brainstorm_metadata)

    assert family == "auth-session-callback"
    assert secondaries == ("navigation-popup", "ipc-bridge")


def test_category_master_bundles_related_hypotheses_and_preserves_metadata() -> None:
    profiles = [
        _profile("download-a", metadata={"surface_family": "download-export-filesystem"}),
        _profile("download-b", metadata={"surface_family": "download-export-filesystem"}),
        _profile("dialog-a", metadata={"surface_family": "ui-dialog-window"}),
    ]
    assignments = assignments_from_profiles(profiles)

    bundled = bundle_category_masters(assignments, max_hypotheses_per_master_agent=5)

    master = next(item for item in bundled if item.key == "download-export-filesystem-master")
    assert len(bundled) == 2
    assert master.scheduler_metadata["category_master"] is True
    assert [item["hypothesis_id"] for item in master.assigned_hypotheses] == ["H-download-a", "H-download-b"]


def test_category_master_respects_max_hypotheses_per_master_agent() -> None:
    profiles = [
        _profile(f"download-{index}", metadata={"surface_family": "download-export-filesystem"})
        for index in range(5)
    ]
    assignments = assignments_from_profiles(profiles)

    bundled = bundle_category_masters(assignments, max_hypotheses_per_master_agent=2)

    masters = [item for item in bundled if item.key == "download-export-filesystem-master"]
    assert len(masters) == 2
    assert [len(master.assigned_hypotheses) for master in masters] == [2, 2]
    assert any(item.key == "download-4" for item in bundled)


def test_diversity_caps_defer_overrepresented_family_when_alternatives_exist() -> None:
    hostrpc_profiles = [
        _profile(f"hostrpc-{index}", priority="high", metadata={"surface_family": "hostrpc"})
        for index in range(8)
    ]
    app_profiles = [
        _profile(f"app-{family}", priority="medium", metadata={"surface_family": family})
        for family in (
            "download-export-filesystem",
            "custom-protocol-deeplink",
            "navigation-popup",
            "auth-session-callback",
            "ui-dialog-window",
            "file-ingestion-import",
            "rendering-content-parser",
            "storage-cache-state",
        )
    ]

    plan = plan_agent_wave(
        assignments_from_profiles([*hostrpc_profiles, *app_profiles]),
        SchedulerConfig(mode="policy-aware", agent_wave_size=10, max_per_surface_family=2),
    )

    selected_families = [item.surface_family for item in plan.selected]
    assert selected_families.count("hostrpc") == 2
    assert any(item.decision == "defer" and item.surface_family == "hostrpc" for item in plan.deferred)


def test_all_ipc_fallback_selects_instead_of_returning_empty_wave() -> None:
    profiles = [_profile(f"ipc-{index}", metadata={"surface_family": "ipc-bridge"}) for index in range(5)]

    plan = plan_agent_wave(
        assignments_from_profiles(profiles),
        SchedulerConfig(
            mode="policy-aware",
            agent_wave_size=4,
            max_per_surface_family=1,
            max_amplifier_family_first_wave=1,
        ),
    )

    assert [item.key for item in plan.selected] == ["ipc-0", "ipc-1", "ipc-2", "ipc-3"]
    assert plan.deferred[0].key == "ipc-4"


def test_standalone_critical_amplifier_bypasses_early_amplifier_cap() -> None:
    profiles = [
        _profile("hostrpc-normal", priority="high", metadata={"surface_family": "hostrpc"}),
        _profile(
            "ipc-critical",
            priority="medium",
            metadata={"surface_family": "ipc-bridge", "standalone_critical": True},
        ),
        _profile("download-entry", priority="medium", metadata={"surface_family": "download-export-filesystem"}),
    ]

    plan = plan_agent_wave(
        assignments_from_profiles(profiles),
        SchedulerConfig(
            mode="policy-aware",
            agent_wave_size=3,
            max_amplifier_family_first_wave=1,
            max_per_surface_family=1,
        ),
    )

    selected_keys = [item.key for item in plan.selected]
    assert "hostrpc-normal" in selected_keys
    assert "ipc-critical" in selected_keys


def test_deferred_decision_event_preserves_hypothesis_metadata() -> None:
    profiles = [
        _profile(
            f"hostrpc-{index}",
            metadata={"surface_family": "hostrpc", "appmap_candidate_id": f"C{index:04d}"},
        )
        for index in range(3)
    ] + [_profile("download-entry", metadata={"surface_family": "download-export-filesystem"})]

    plan = plan_agent_wave(
        assignments_from_profiles(profiles),
        SchedulerConfig(
            mode="policy-aware",
            agent_wave_size=2,
            max_per_surface_family=1,
            max_amplifier_family_first_wave=1,
        ),
    )

    deferred = next(item for item in plan.deferred if item.surface_family == "hostrpc")
    event = next(item for item in decision_events(plan, scheduler_wave_id="wave-1") if item["agent_key"] == deferred.key)
    assert event["event"] == "agent_deferred"
    assert event["hypothesis_id"] == deferred.hypothesis_id
    assert event["source_spec_path"] == "/tmp/spec.md"
    assert event["appmap_candidate_id"] == deferred.scheduler_metadata["profile_metadata"]["appmap_candidate_id"]
    assert event["surface_family"] == "hostrpc"
    assert event["scheduler_wave_id"] == "wave-1"


def test_scheduler_off_preserves_legacy_order_and_does_not_defer() -> None:
    profiles = [
        _profile("hostrpc-a", metadata={"surface_family": "hostrpc"}),
        _profile("download-a", metadata={"surface_family": "download-export-filesystem"}),
        _profile("hostrpc-b", metadata={"surface_family": "hostrpc"}),
    ]

    plan = plan_agent_wave(assignments_from_profiles(profiles), SchedulerConfig(mode="off", agent_wave_size=1))

    assert [item.key for item in plan.selected] == ["hostrpc-a", "download-a", "hostrpc-b"]
    assert plan.deferred == ()
    assert all(item.decision_reason == "scheduler disabled; preserving legacy order" for item in plan.selected)


def test_mixed_app_entry_and_hostrpc_prefers_application_entry_primary() -> None:
    candidate = _profile(
        "mixed-renderer-to-hostrpc",
        metadata={
            "brainstorm_tags": ["rendering", "hostrpc"],
            "expected_chain": "renderer XSS reaches HostRpc download/open",
            "app_entry_evidence": True,
        },
    )

    family, secondaries = infer_surface_family(candidate, metadata=candidate.brainstorm_metadata)

    assert family in {"rendering-content-parser", "download-export-filesystem"}
    assert family != "hostrpc"
    assert "hostrpc" in secondaries


def test_disabled_policy_dict_does_not_affect_score() -> None:
    enabled = assignments_from_profiles(
        [_profile("download-policy", metadata={"surface_family": "download-export-filesystem"})],
        policy={"id": "test", "enabled": True, "prioritize": ["import-export"]},
    )[0]
    disabled = assignments_from_profiles(
        [_profile("download-policy", metadata={"surface_family": "download-export-filesystem"})],
        policy={"id": "test", "enabled": False, "prioritize": ["import-export"]},
    )[0]

    assert enabled.policy_rank == 20
    assert disabled.policy_rank == 0
    assert enabled.final_score > disabled.final_score


def test_appmap_context_packet_metadata_drives_family_inference() -> None:
    candidate = _profile(
        "appmap-generated-agent",
        metadata={
            "brainstorm_tags": ["hostrpc"],
            "appmap_context_packet": {
                "candidate": {"policy": {"finding_role": "entry", "app_entry_evidence": True}},
                "evidence": {
                    "source": {"kind": "download"},
                    "boundary": {"kind": "renderer-ipc"},
                    "sink": {"kind": "hostrpc"},
                },
            },
        },
    )

    family, _secondaries = infer_surface_family(candidate, metadata=candidate.brainstorm_metadata)

    assert family == "download-export-filesystem"


def test_category_master_decision_events_expand_member_coverage_identities() -> None:
    profiles = [
        _profile(
            "download-a",
            metadata={
                "surface_family": "download-export-filesystem",
                "hypothesis_id": "H001",
                "brainstorm_agent_key": "download-a",
                "source_spec_path": "/tmp/spec-a.md",
                "appmap_candidate_id": "C0001",
                "appmap_context_packet": "packet-a.json",
                "snapshot_id": "snap-a",
            },
        ),
        _profile(
            "download-b",
            metadata={
                "surface_family": "download-export-filesystem",
                "hypothesis_id": "H002",
                "brainstorm_agent_key": "download-b",
                "source_spec_path": "/tmp/spec-b.md",
                "appmap_candidate_id": "C0002",
                "appmap_context_packet": "packet-b.json",
                "snapshot_id": "snap-b",
            },
        ),
    ]
    assignments = bundle_category_masters(assignments_from_profiles(profiles), max_hypotheses_per_master_agent=5)
    plan = plan_agent_wave(assignments, SchedulerConfig(agent_wave_size="all"))

    events = decision_events(plan, scheduler_wave_id="wave-master")

    assert [event["hypothesis_id"] for event in events] == ["H001", "H002"]
    assert {event["scheduler_master_agent_key"] for event in events} == {"download-export-filesystem-master"}
    assert {event["source_spec_path"] for event in events} == {"/tmp/spec-a.md", "/tmp/spec-b.md"}
    assert {event["appmap_candidate_id"] for event in events} == {"C0001", "C0002"}
    assert all(event["event"] == "agent_selected" for event in events)



def test_no_prefer_deferred_disables_resume_bias_in_sort_and_score() -> None:
    deferred_low = _profile(
        "deferred-low",
        priority="low",
        metadata={"surface_family": "download-export-filesystem", "coverage_status": "deferred"},
    )
    fresh_high = _profile(
        "fresh-high",
        priority="high",
        metadata={"surface_family": "ui-dialog-window"},
    )

    plan = plan_agent_wave(
        assignments_from_profiles([deferred_low, fresh_high]),
        SchedulerConfig(mode="policy-aware", agent_wave_size=1, prefer_deferred=False),
    )

    assert [item.key for item in plan.selected] == ["fresh-high"]
    assert plan.selected[0].coverage_status == "untested"


def test_terminal_coverage_skip_gets_distinct_event_name() -> None:
    profile = _profile("covered-dialog", metadata={"surface_family": "ui-dialog-window", "coverage_status": "covered"})

    plan = plan_agent_wave(assignments_from_profiles([profile]), SchedulerConfig(agent_wave_size="all"))
    events = decision_events(plan)

    assert plan.selected == ()
    assert events[0]["event"] == "agent_skipped_covered"


def test_base_team_scheduler_adapter_returns_profiles_summary_and_events() -> None:
    profiles = [
        _profile(f"hostrpc-{index}", metadata={"surface_family": "hostrpc"})
        for index in range(3)
    ] + [_profile("download-entry", metadata={"surface_family": "download-export-filesystem"})]

    result = schedule_profiles(
        profiles,
        options=BaseTeamSchedulerOptions(
            mode="policy-aware",
            agent_wave_size=2,
            max_per_surface_family=1,
            max_amplifier_family_first_wave=1,
            scheduler_wave_id="wave-adapter",
            run_id="run-adapter",
        ),
    )

    assert len(result.selected_profiles) == 2
    assert result.summary["selected"] == 2
    assert result.summary["deferred"] == 2
    assert set(result.deferred_keys) <= {profile.key for profile in profiles}
    assert {event["scheduler_wave_id"] for event in result.decision_events} == {"wave-adapter"}
    assert {event["run_id"] for event in result.decision_events} == {"run-adapter"}
