# Bunny harness-native workers — integration dossier

- **Status:** review-ready
- **Owner:** Hermes (bugfix profile)
- **Branch:** `feat/bunny-harness-native`
- **Base commit:** `f6074b46058db1fa3f7848f667dfee319b1e35cf`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-28
- **Owning feature branch/ref:** `feat/bunny-harness-native`
- **Latest immutable recovery checkpoint:** `fa52f32`
- **Feature implementation commit(s):** `fa52f32`
- **Inspiration / canonical references:** Ryushe, Discord Bunny roles thread; `skills/bunny/SKILL.md`; `coordination` policy.

## Intent

Remove the Claude-only launch gate so Bunny uses the coordinator's current harness native subagents, retaining coordinator authority, role packets, scope/evidence boundaries, and optional Claude-specific role types.

## Implemented contract

Native subagent dispatch receives a scoped role packet in Hermes, Codex, Pi, or Claude Code. Claude role-specific files remain optional; generic native workers with full packets are acceptable. No new permission, live testing, harness switch, or external submission is implied.

## Evidence and review

- Tests and commands: `python3 -m unittest discover -s tests -p test_bunny_skill.py` (RED before policy edit; 4/4 GREEN afterward); `git diff --check` clean. No repository policy lint script found.
- Independent review: PASS on policy; reviewer reran Bunny (4/4), reporting (2/2), and skill (18/18) tests and `git diff --check`. Reviewer caught stale dossier metadata, corrected here.
- Replay/cohort/fixture evidence: not applicable; policy-text regression only.
- Merge/ancestry evidence: pending integration into `beta`.

## Blockers and deferred work

None identified. Runtime availability in other harnesses depends on their native subagent facility; the policy does not implement one.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/bunny-harness-native`
- **Latest immutable recovery checkpoint:** `fa52f32`
- **Feature implementation commit(s):** `fa52f32`
- **Exact resume point:** integrate reviewed change into `beta`, verify active projection.
- **Working-tree state at handoff:** clean after dossier correction commit.

## Decision gates

- **Integration gate:** focused tests, policy alignment, independent diff review.
- **Activation / cohort gate:** active Bunny projection resolves to beta and loads revised text.
- **Promotion gate:** stable main only by separate owner direction.

## Decision record

- 2026-09-28 — created feature branch from fetched beta; changed dispatch contract without changing live-action authority.
- 2026-09-28 — independent policy review passed, with stale dossier metadata corrected; integration accepted subject to beta ancestry and focused checks. No live dispatch test was performed; no harness implementation changed.
