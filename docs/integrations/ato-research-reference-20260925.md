# ATO source-grounded method atlas — integration dossier

- **Status:** review-ready
- **Owner:** Hermes / Kanban `t_4d9de8b8`
- **Branch:** `docs/ato-research-reference-20260925`
- **Base commit:** `9d228ceb5d23c8673633ea3cc230200db886dbcb`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-25
- **Owning feature branch/ref:** `docs/ato-research-reference-20260925`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** OWASP WSTG/Cheat Sheets, NIST SP 800-63B-4, OAuth Security BCP, OIDC Core, SAML guidance, WebAuthn, pre-hijacking research; source URLs and claim mapping live in `skills/ato/references/methods.md`.

## Intent

Expand the ATO router's on-demand reference with comprehensively categorized, source-grounded owned-account hypothesis families. Do not change live-testing scope, encourage token guessing, or imply a hypothesis is a finding.

## Implemented contract

The `/ato` skill routes to a skill-local research atlas after fresh surface observation and before lane classification. The atlas presents claim/proof/binding/result framing, cross-channel identity failure modes, evidence thresholds, and primary-source links. Legacy repository-root prompts remain canonical and are explicitly located from the synced skill directory.

## Evidence and review

- Tests and commands: `sources.py render --replace-in skills/ato/references/methods.md`; `sources.py verify skills/ato/references/methods.md --min-coverage 0.5` passed (33/60 cited sentences, all 26 registered sources cited; 18 over-citation warnings reflect adjacent inline citations grouped by the validator's rough sentence splitter); `git diff --check` passed. Source URL and claim review sampled against standards; runtime skill load remains pending integration.
- Independent review: pending.
- Replay/cohort/fixture evidence: none; documentation only, no live target testing.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

None known. Source breadth is necessarily non-exhaustive; future methods should be added when observed target behavior warrants them. The citation linter's strict mode treats adjacent source brackets across multiple prose sentences on one Markdown bullet line as a single over-cited sentence. The non-strict verification passed; do not weaken the content merely to satisfy this line-splitting heuristic.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/ato-research-reference-20260925`
- **Latest immutable recovery checkpoint:** none yet (active work; commit before handoff)
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit the source-grounded reference and request independent source/route review, address blockers, then integrate into `beta`.
- **Working-tree state at handoff:** intentionally uncommitted research draft.

## Decision gates

- **Integration gate:** citation verification, independent review, clean beta and tested merge.
- **Activation / cohort gate:** runtime symlink resolves into merged beta and loads new reference.
- **Promotion gate:** no `main` promotion without separate explicit direction.

## Decision record

- 2026-09-25 — created task-owned feature worktree from current beta for online ATO research.
