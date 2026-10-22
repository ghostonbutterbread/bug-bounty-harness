# Deserialization teaching and discovery integration dossier

- **Status:** accepted for beta integration; local activation pending.
- **Owner:** Hermes, Kanban `t_581dd63e`
- **Branch / owning ref:** `feat/deserialization-depth`
- **Worktree:** Kanban-managed isolated project worktree for this task.
- **Base commit:** `2f5a204d5342911b5c2f5e2d59150afecc0c031b`
- **Intended integration target:** `beta`; no stable promotion.
- **Last updated:** 2026-10-22
- **Latest immutable recovery checkpoint:** `f1b0cc37ba1198a6fda96c01022b7580e1ae901a`.
- **Feature implementation commits:** `3909a59d547746218c9c83b6982af39ccab7a263`,
  `f1b0cc37ba1198a6fda96c01022b7580e1ae901a`.
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
- Four focused deserialization, promotion-route and JS-hunt files: 22 passed,
  10 subtests passed. The earlier five-file batch had 23 passes (including one
  passing command-lane test) and one reproduced baseline command-lane failure.
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
- Independent review: ACCEPT for `a9ac1903651efa33f4b28909672117402439f6f3`,
  external report `deserialization-depth-review.md` in the Hermes review store;
  all six read-only semantic scenarios passed and eleven source capture hashes
  independently verified. Follow-up tightens the pre-existing signature/control
  sentence and reconciles the focused-test count. Narrow independent re-review
  ACCEPT for `f1b0cc37ba1198a6fda96c01022b7580e1ae901a` with 22 passes and
  10 subtests; report `deserialization-depth-rereview.md` in the same store.
  Corrected candidate broad rerun again returned 311 passed, 1 skipped,
  3 baseline deselections and 182 subtests passed.

## Blockers and deferred work

Unrelated baseline failures are recorded in `BUGFIXES.md`; they prevent a claim
of an unfiltered green suite, not evidence for a feature defect. No JS analyzer
signature pass is implemented or advertised. Remote-host rollout is outside this
local security-profile activation slice.

## Interruption / resume handoff

Implementation and follow-up are committed and independently accepted. This
final dossier-only commit records the verdict without changing reviewed skill
content. Publish the feature, transfer its ref to the canonical integration
clone, merge into clean/current beta, remove this dossier from beta, rerun
checks, push beta, read back the remote and apply focused security projection.

## Decision gates

- Integration: focused checks, baseline-failure reconciliation, semantic
  scenario review, and independent acceptance of the exact candidate.
- Activation: reviewed published beta, focused no-surprise sync plan, expected
  local symlink targets, and a fresh runtime specialist/reference load.
- Stable promotion: requires separate explicit user direction.
