# Bunny fetcher-family stewardship integration dossier

- **Status:** feature
- **Owner:** hermes
- **Branch:** feat/bunny-fetcher-family-steward
- **Base commit:** 224098257654940d53f004c1ee86f459debab461
- **Intended integration target:** beta
- **Last updated:** 2026-11-12
- **Owning feature branch/ref:** feat/bunny-fetcher-family-steward
- **Latest immutable recovery checkpoint:** 0247945b533829a3a36d6c99b580dac95856091d
- **Feature implementation commit(s):** 0247945b533829a3a36d6c99b580dac95856091d
- **Inspiration / canonical references:** `~/Shared/skill_seeds/2026-11-13-bunny-fetcher-family-steward.md` (Ghost review: promote the unique admission rule, not the body draft).

## Intent

Stop Bunny coordinators from minting a new hunter (new nickname, new Attempt
stream, new lease) for every remaining discriminator on the same fetch
implementation. Lease URL-fetch / SSRF / preview / ingest / webhook / oembed /
upload-from-url work by fetcher family. Keep one live steward per open family;
steer or successive-segment remaining lenses. Spawn only for a different
family, independent verification, or compaction rotation.

## Implemented contract

- `skills/bunny-collaborative/SKILL.md`: compact Fetcher-family stewardship
  subsection (explicit admission requirement); unused-fetcher catalogs assign
  unused families; a remaining lens is not a distinct responsibility.
- `skills/bunny-collaborative/references/fetcher-family.md`: family vs lens,
  coordinator admission rule, worker guidance. No program-specific fixtures
  and no SSRF technique.
- `skills/bunny/references/dispatch.md`: spawn gate before `bunny-hunter`.
- `skills/bunny-offhand/SKILL.md`: do not use a new offhand worker to skip an
  open family steward (dispatch.md is collaborative-only).
- Non-claims: no `hunt-orchestration-policy` edit; no new skill; no firsthand
  policy-load restatement; no `account-testing-policy` restatement.

## Evidence and review

- Tests and commands: `python3 -m unittest tests.test_bunny_skill -v` — 18
  passed, including `test_fetcher_family_steward_keeps_one_hunter_per_family`
  and `test_fetcher_family_reference_link_guard_rejects_a_broken_projection`.
  `git diff --check` clean.
- Independent review: not started.
- Replay/cohort/fixture evidence: not applicable; text contract only.
- Merge/ancestry evidence: based on `origin/beta` `22409825`. Local commit
  only; not pushed; not merged.

## Blockers and deferred work

- **Missing test or evidence:** independent review of the complete diff;
  runtime activation on Hoster/beta skill projection; no live Bunny dispatch
  was run.
- **Command / fixture / environment needed:** independent reviewer on this
  feature worktree; after merge, verify a fresh consumer loads the spawn gate
  and family subsection.
- **Trigger to run it:** review request from this task; activation after beta
  merge.
- **Why it blocks integration, activation, or promotion:** BBH policy changes
  merge to beta only after independent review. A local feature commit does not
  activate workers.
- **Next completion step / successor reference:** independent review, then
  merge to `beta` without this dossier.

## Interruption / resume handoff

- **Owning feature branch/ref:** feat/bunny-fetcher-family-steward
- **Latest immutable recovery checkpoint:** 0247945b533829a3a36d6c99b580dac95856091d
- **Feature implementation commit(s):** 0247945b533829a3a36d6c99b580dac95856091d
- **Exact resume point:** independent review of `0247945b` plus this dossier;
  do not merge to beta until that review accepts. Publish the feature ref for
  review after acceptance.
- **Working-tree state at handoff:** clean after the dossier commit.

## Decision gates

- **Integration gate:** independent review of the complete diff and test
  evidence; merge into a clean current beta worktree; drop this dossier from
  beta.
- **Activation / cohort gate:** Hoster/beta skill projection includes the new
  sentences; a fresh Bunny coordinator would apply the family→steward spawn
  gate.
- **Promotion gate:** not requested; do not promote to `main`.

## Decision record

- 2026-11-12 — implemented family-versus-lens admission contract on
  `feat/bunny-fetcher-family-steward`; tests green; awaiting independent review.
