# Lead closure and durable consumers integration dossier

- **Status:** feature
- **Owner:** Hermes, Kanban `t_15ecfb58`
- **Branch:** `docs/lead-closure-durable-consumers`
- **Base commit:** `66378f7d9081f39cf10fa95131e3e6db4574c0dd`
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-16
- **Owning feature branch/ref:** `docs/lead-closure-durable-consumers`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration:** Hoster Shared seed `2026-11-16-lead-closure-durable-consumers.md`, SHA-256 `e6f9dd5e1df397b91c5b6117cdaee15bc687a8b75200608823749fb927d27423`; facet-close seed reviewed as background, not superseded.

## Intent

Carry forward stop-versus-negative and consumer-specific evidence as compact cross-class handoff guidance. Avoid extending the seed's proposed browser requirement, status restrictions, rate changes, blanket stored-value records, acquisition grants, or unimplementable automated semantic validation. Preserve the existing AI Policies chain-evidence owner, Coverage's scoped-review semantics, Leads' evidence threshold and status vocabulary, and existing class/safety policies.

## Implemented contract

Coverage prompts actual axes, material unresolved siblings and claim-appropriate observation channels. Leads preserves open questions on a pause and scopes negative claims. The goal coordinator hands off material open-lead IDs and wake conditions. XSS lifecycle retains a relevant evidence-backed unresolved consumer as a watch, without requiring a permanent lead per stored value or a running worker. No storage schema, CLI, rate, scope, permissions, or new status changes.

## Evidence and review

- Three independent read-only pre-implementation analyses compared cross-class policy, mechanics and safety; no target actions. Their traces are in the active bugfix profile's `cache/delegation/live/deleg_1f050b7d/`.
- Projected checkout at base `66378f7d`; Python from that checkout's virtualenv has Bounty Core pinned to the feature's `requirements.txt` revision.
- `PYTHONDONTWRITEBYTECODE=1 <projected-beta-venv>/bin/python -m pytest -q tests/test_lead_closure_guidance.py tests/test_coverage_generic_route.py tests/test_xss_consumer_reach.py tests/test_bunny_skill.py`: 25 passed.
- `PYTHONDONTWRITEBYTECODE=1 <projected-beta-venv>/bin/python -m pytest -q agents/test_surface_coverage.py::SurfaceCoverageTests::test_bounded_review_requires_exact_boundary_axes_and_evidence agents/test_surface_coverage.py::SurfaceCoverageTests::test_classes_and_sibling_inputs_do_not_inherit_exhaustion agents/test_surface_coverage.py::SurfaceCoverageTests::test_legacy_opaque_reference_still_writes agents/test_leads_cli.py tests/test_goal_router.py::test_hunt_stop_routes_to_existing_surface_skills_without_preloading_them`: 6 passed, 3 subtests passed.
- Mixed broad tests timed out at 300s after 63 dots; Coverage/Leads suite timed out at 120s after 3 dots. The individual `agents/test_surface_coverage.py::SurfaceCoverageTests::test_brief_can_page_through_every_counted_row` exceeded 35s; cause not established. Neither timeout is a passing receipt. Re-run with a suitable environment/time budget before claiming full-suite coverage.
- Independent complete-diff review: pending.

## Blockers and deferred work

The seed's mechanical enforcement requires a separate explicit typed evidence/facet and cross-writer contract, backward compatibility, and validation through real stores. Its rate and acquisition changes require independent safety and infrastructure decisions. No such changes are implemented or claimed here.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/lead-closure-durable-consumers`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit candidate and dossier, independent review, reconcile findings, then integrate only if gates pass.
- **Working-tree state at handoff:** feature edits pending.

## Decision gates

- **Integration:** independent complete-diff review and focused checks; a full-suite timeout must be investigated and reported honestly.
- **Activation:** verify intended runtime projection and a fresh consumer; do not infer from Git alone.
- **Promotion:** beta only; no stable promotion.
