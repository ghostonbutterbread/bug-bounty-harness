# Lead closure and durable consumers integration dossier

- **Status:** reviewed; accepted for beta integration
- **Owner:** Hermes, Kanban `t_15ecfb58`
- **Branch:** `docs/lead-closure-durable-consumers`
- **Base commit:** `66378f7d9081f39cf10fa95131e3e6db4574c0dd`
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-16
- **Owning feature branch/ref:** `docs/lead-closure-durable-consumers`
- **Latest immutable recovery checkpoint:** `5897261068aa0b57a80e03eaca4ee43998d69496` (reviewed candidate, includes local beta `8a3c7b77` and owner routes)
- **Feature implementation commit(s):** `0dd20df2c182260e32b54319dccad024def23e84`, `0570373fa95dc8e9d3034dc57563681eba8a6d3e`, `e18ae25e137c9a17d8b4098d9f1c4167f0efbbfe`, `5897261068aa0b57a80e03eaca4ee43998d69496`
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
- Independent complete-diff review of `0dd20df2`: no demonstrated semantic conflict; blocked on fresh-consumer behavior, stale dossier and timeout diagnosis. After review, local beta `8a3c7b77` was merged into feature at `0a884150`; it changes only unrelated Chromium handoff guidance and is not to be published as part of this work.
- Timeout diagnosis: in isolated trials 80 `fsync` calls took 41.92 seconds on the candidate, and baseline likewise stalled. A seccomp network-fenced, scratch-only run with SQLite synchronous=OFF for parent-process fixture databases passed 80 tests and 16 subtests; parent reran and observed the same. This is not a durability test; subprocess connections were not patched.
- Fresh Hermes CLI consumer attempt timed out after 240 seconds without an answer. A separate fresh read-only agent consumed the exact candidate skill files and policy owners at `0570373f`; its composite stored XSS, SSRF, and open-lead pause scenario returned the intended distinct dispositions and read trace (`cache/delegation/live/deleg_6536751b/task-0.log`). That is candidate-source behavior, not runtime projection verification.
- Independent correction review of `e18ae25e` found no semantic conflicts but required deterministic checks against an actual selected policy projection, not only synthetic owner files. `tests/verify_lead_closure_projection.py <policy-skills-root>` checks both real owner links and reference, then checks route and missing-file mutations on a temporary copy. Independent re-review accepted `58972610` for local beta; 30 focused tests and projection verification passed. See `cache/delegation/live/deleg_35f53784/task-0.log`.
- Earlier, the fenced relaxed-durability suite exposed an exact-phrase assertion broken by line wrapping; restoring the phrase on one line fixed it. Re-run: 83 passed and 16 subtests; no durability claim.

## Blockers and deferred work

The seed's mechanical enforcement requires a separate explicit typed evidence/facet and cross-writer contract, backward compatibility, and validation through real stores. Its rate and acquisition changes require independent safety and infrastructure decisions. No such changes are implemented or claimed here.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/lead-closure-durable-consumers`
- **Latest immutable recovery checkpoint:** `5897261068aa0b57a80e03eaca4ee43998d69496` (reviewed candidate, includes local beta `8a3c7b77` and owner routes)
- **Feature implementation commit(s):** `0dd20df2c182260e32b54319dccad024def23e84`, `0570373fa95dc8e9d3034dc57563681eba8a6d3e`, `e18ae25e137c9a17d8b4098d9f1c4167f0efbbfe`, `5897261068aa0b57a80e03eaca4ee43998d69496`
- **Exact resume point:** verify candidate consumers and review corrections; integrate locally only when gates pass, without pushing unrelated beta commits.
- **Working-tree state at handoff:** changes committed at the next checkpoint.

## Decision gates

- **Integration:** independent complete-diff review and focused checks; a full-suite timeout must be investigated and reported honestly.
- **Activation:** verify intended runtime projection and a fresh consumer; do not infer from Git alone.
- **Promotion:** beta only; no stable promotion.
