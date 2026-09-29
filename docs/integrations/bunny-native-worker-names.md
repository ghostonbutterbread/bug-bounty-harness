# Bunny native worker names — integration dossier

- **Status:** feature
- **Owner:** Hermes (bugfix profile)
- **Branch:** `feat/bunny-native-worker-names`
- **Base commit:** `ab15ea6ca26f602ef0ec2539b9e0f5ae86ed5e24`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-28
- **Owning feature branch/ref:** `feat/bunny-native-worker-names`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryushe follow-up in Bunny Discord thread; `skills/bunny/SKILL.md` and coordination policy.

## Intent

Name workers `bunny-hunter`, `bunny-recon`, `bunny-verifier`, or `bunny-reporter` in whichever harness runs Bunny; remove the special Claude dispatch paragraph. Preserve role packets and safety/evidence boundaries.

## Implemented contract

Native worker name where supported; generic agent type receives Bunny name in title/description and scoped packet otherwise. Bundled agent files remain portable role instructions and reporting test fixture, not required runtime projection. No harness-specific agent type, new tool implementation, live authorization, or external submission is implied.

## Evidence and review

- Tests and commands: pending focused tests, independent review, and integrated checks.
- Independent review: pending.
- Replay/cohort/fixture evidence: policy-text only; no live campaign.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

Native display names cannot be guaranteed in a harness lacking a naming API; packet/description records the role there. No other blocker identified.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/bunny-native-worker-names`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** test, review, integrate to beta, verify active projection.
- **Working-tree state at handoff:** intentionally uncommitted during implementation.

## Decision gates

- **Integration gate:** focused tests, independent review, policy alignment.
- **Activation / cohort gate:** active Bunny projection resolves to beta and loads revised text.
- **Promotion gate:** stable main only by separate owner direction.

## Decision record

- 2026-09-28 — feature branch from fetched beta; user requested harness-neutral worker names, without Claude-specific routing.
