# Bidirectional XSS path review integration dossier

- **Status:** review-ready
- **Owner:** Hermes (bugfix profile)
- **Branch:** `docs/xss-bidirectional-paths`
- **Base commit:** `48ed0e44b89284e3437f03c0beef691783c1eb7a`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-07
- **Owning feature branch/ref:** `docs/xss-bidirectional-paths`
- **Latest immutable recovery checkpoint:** `88c6b05`
- **Feature implementation commit(s):** `88c6b05`
- **Inspiration / canonical references:** XSS router, source-acquisition reference, impact-fit delivery lens, JS sink-site inventory.

## Intent

Permit source-first and sink-first XSS investigation without mistaking sink grouping for equivalent input paths. Keep coverage honest while avoiding another schema, scanner, percentage quota, or hard delivery gate.

## Implemented contract

The router explicitly supports tracing from either end. The existing source-acquisition reference groups shared downstream analysis but retains each ingress/filter/transform/consumer path separately, scopes negatives, and calls out unexamined/capped inventory at handoff. Attempts remain owned by `attempt-recording-policy`; static hints are not proof.

## Evidence and review

- Tests and commands: focused text-contract assertions PASS; `git diff --check` PASS. The available `policy_lint.py` validates the separate AI Policies repository, not BBH skill files; no applicable BBH policy linter was found.
- Independent review: read-only reviewer found no issues in the two XSS skill files; no live target action.
- Replay/cohort/fixture evidence: not applicable to prose-only guidance.
- Merge/ancestry evidence: branch begins at fetched `origin/beta` SHA above.

## Blockers and deferred work

None identified. Hoster rollout is a separate activation decision; no stable promotion implied.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-bidirectional-paths`
- **Latest immutable recovery checkpoint:** `88c6b05`
- **Feature implementation commit(s):** `88c6b05`
- **Exact resume point:** reconcile fetched beta, merge with dossier removed from beta, run post-merge checks.
- **Working-tree state at handoff:** clean after this handoff update is committed.

## Decision gates

- **Integration gate:** clean diff/checks, independent review, clean beta merge and post-merge checks.
- **Activation / cohort gate:** prove runtime projection resolves reviewed beta content before claiming active on Hoster.
- **Promotion gate:** stable requires separate explicit direction.

## Decision record

- 2026-10-07 — created from user-approved bidirectional and ingress-specific coverage direction.
- 2026-10-07 — independent review accepted the focused XSS change without findings; beta integration approved, Hoster activation separately gated.
