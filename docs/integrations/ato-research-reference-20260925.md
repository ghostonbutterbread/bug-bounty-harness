# ATO source-grounded method atlas — integration dossier

- **Status:** review-ready
- **Owner:** Hermes / Kanban `t_4d9de8b8`
- **Branch:** `docs/ato-research-reference-20260925`
- **Base commit:** `9d228ceb5d23c8673633ea3cc230200db886dbcb`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-25
- **Owning feature branch/ref:** `docs/ato-research-reference-20260925`
- **Latest immutable recovery checkpoint:** `e7c75356999296a93b7b2f9d6336c0ceecc42931`
- **Feature implementation commit(s):** `e7c75356999296a93b7b2f9d6336c0ceecc42931`
- **Inspiration / canonical references:** OWASP WSTG/Cheat Sheets, NIST SP 800-63B-4, OAuth Security BCP, OIDC Core, SAML guidance, WebAuthn, pre-hijacking research; source URLs and claim mapping live in `skills/ato/references/methods.md`.

## Intent

Expand the ATO router's on-demand reference with comprehensively categorized, source-grounded owned-account hypothesis families. Do not change live-testing scope, encourage token guessing, or imply a hypothesis is a finding.

## Implemented contract

The `/ato` skill routes to a skill-local research atlas after fresh surface observation and before lane classification. The atlas presents claim/proof/binding/result framing, cross-channel identity failure modes, evidence thresholds, and primary-source links. Legacy repository-root prompts remain canonical and are explicitly located from the synced skill directory.

## Evidence and review

- Tests and commands: `sources.py render --replace-in skills/ato/references/methods.md`; `sources.py verify skills/ato/references/methods.md --min-coverage 0.5` passed (33/60 cited sentences, all 26 registered sources cited; 18 over-citation warnings reflect adjacent inline citations grouped by the validator's rough sentence splitter); `git diff --check` passed. Source URL and claim review sampled against standards; runtime skill load remains pending integration.
- Independent review: independent source/route audit accepted integration with no blockers (2026-09-25); sampled RFC 10017, OIDC, SAML, reset, invite and pre-hijacking claims; separately reran citation verification and diff check. Optional note: make symlink dereference explicit in a future wording pass; the existing “resolve” instruction is correct.
- Replay/cohort/fixture evidence: none; documentation only, no live target testing.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

None known. Source breadth is necessarily non-exhaustive; future methods should be added when observed target behavior warrants them. The citation linter's strict mode treats adjacent source brackets across multiple prose sentences on one Markdown bullet line as a single over-cited sentence. The non-strict verification passed; do not weaken the content merely to satisfy this line-splitting heuristic.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/ato-research-reference-20260925`
- **Latest immutable recovery checkpoint:** `e7c75356999296a93b7b2f9d6336c0ceecc42931` (reachable and an ancestor of this branch's tip)
- **Feature implementation commit(s):** `e7c75356999296a93b7b2f9d6336c0ceecc42931`
- **Exact resume point:** merge reviewed branch into clean `beta`, remove this temporary dossier from the merge result, verify citation source index and active runtime skill load, then push `origin/beta`.
- **Working-tree state at handoff:** clean after this dossier update is committed; the branch tip includes a later dossier-only handoff commit.

## Decision gates

- **Integration gate:** citation verification, independent review, clean beta and tested merge.
- **Activation / cohort gate:** runtime symlink resolves into merged beta and loads new reference.
- **Promotion gate:** no `main` promotion without separate explicit direction.

## Decision record

- 2026-09-25 — created task-owned feature worktree from current beta for online ATO research.
- 2026-09-25 — independent reviewer accepted the source-grounded reference and router; no blockers. Citation linter's strict over-citation warnings are a sentence-segmentation artifact, not unsupported sources. Approved beta integration after clean merge and verification; no main promotion.
