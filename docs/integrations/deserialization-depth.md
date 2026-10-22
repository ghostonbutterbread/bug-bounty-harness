# Deserialization teaching and discovery integration dossier

- **Status:** review-ready (independent review pending)
- **Owner:** Hermes, Kanban `t_581dd63e`
- **Branch / owning ref:** `feat/deserialization-depth`
- **Worktree:** Kanban-managed isolated project worktree for this task.
- **Base commit:** `2f5a204d5342911b5c2f5e2d59150afecc0c031b`
- **Intended integration target:** `beta`; no stable promotion.
- **Last updated:** 2026-10-22
- **Latest immutable recovery checkpoint:** `3909a59d547746218c9c83b6982af39ccab7a263`.
- **Feature implementation commits:** `3909a59d547746218c9c83b6982af39ccab7a263`.
  The branch tip includes a later dossier-only handoff commit.
- **Inspiration:** Ryu, Discord thread 1562883062767947837, message
  1562889915627348019; existing deserialization session-object packet.

## Intent and implemented contract

Extend the existing specialist, not create a second owner. Teach serialization,
unsafe reconstruction and gadgets, why trusted-state assumptions fail, and how
to distinguish accepted control from runtime behavior. Package ten technology
cards with primary-source preconditions and eight conditional investigation
branches with controls and falsifiers. Preserve the existing case and proof
selection route. Add the JavaScript evidence lens and a conditional JS-hunt
handoff; add deserialization to RCE metadata while retaining its body route.

This is a teaching/discovery-guidance change, not an analyzer implementation or
new mode. No target requests, untrusted deserializer invocation, exploit chain,
or payload execution. Existing JS collection, live scope/ownership, attempt
records, validation and lifecycle remain canonical. Source receipts preserve
URLs, capture pointers and hashes; they are not target vulnerability evidence.

## Evidence and review

- New packaging/route tests first returned two failures and two missing-reference
  errors; after implementation all five pass. Existing five deserialization
  tests also pass, preserving the historical case and safety distinctions.
- Focused deserialization, promotion-route and JS-hunt checks: 23 passed;
  the additional command-lane check reproduced an unrelated baseline failure.
- Broader `tests/` run after checkout-local environment setup: 311 passed,
  1 skipped, 3 explicitly deselected, 182 subtests passed. Deselections are
  script-index completeness, direct-checkout command guidance, and upload
  baseline-wording assertions; all three reproduced on unchanged base.
- Initial isolated-worktree safety CLI failures were missing `.venv`, not
  product failures. Compared identical requirements and linked the existing
  integration environment into the disposable feature worktree; those tests
  then passed. The link is not tracked or a deployment change.
- Frontmatter parses, local references resolve, and whitespace checks pass.
- Alignment checked: general-security-testing-policy, policy-authoring, rce,
  rce-surface-mapping, rce-exploration, rce-validation, rce-lifecycle, js-hunt,
  and the repository RAG template. This specialist owns reconstruction reasoning;
  no duplicate allow/ask/stop matrix, evidence store, or validation ladder.
- Independent review: pending exact committed candidate and semantic scenarios.

## Blockers and deferred work

Unrelated baseline failures are recorded in `BUGFIXES.md`; they prevent a claim
of an unfiltered green suite, not evidence for a feature defect. No JS analyzer
signature pass is implemented or advertised. Remote-host rollout is outside this
local security-profile activation slice.

## Interruption / resume handoff

Commit the implementation, record its immutable SHA here in a handoff-only
commit, and obtain a read-only independent review. Fix/re-review blockers; then
publish the feature, transfer its ref to the canonical integration clone if
necessary, merge into clean/current beta, remove this dossier from beta, rerun
checks, push beta, read back the remote and apply focused security projection.

## Decision gates

- Integration: focused checks, baseline-failure reconciliation, semantic
  scenario review, and independent acceptance of the exact candidate.
- Activation: reviewed published beta, focused no-surprise sync plan, expected
  local symlink targets, and a fresh runtime specialist/reference load.
- Stable promotion: requires separate explicit user direction.
