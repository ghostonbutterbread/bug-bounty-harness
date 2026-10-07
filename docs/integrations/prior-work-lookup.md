# Compact prior-work lookup integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch / owning ref:** `feat/prior-work-lookup`
- **Base commit:** `815fcc9746835930dc9a653c0f63a63e66bfe938`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-07
- **Latest immutable recovery checkpoint:** `32a3f9154e57db6bd06e90fe270679c0cd0a7737`
- **Feature implementation commit(s):** `32a3f9154e57db6bd06e90fe270679c0cd0a7737`
- **Inspiration / canonical references:** Ryu's request for a bounded 'have we already confirmed/submitted this?' question after the default closed-finding exclusion; task `t_7818be03`.

## Intent

Avoid repeated proof without turning submitted findings into the default target queue or exposing full reports. A file/class pair is a precise available ledger key, not a semantic vulnerability identity or entire-route closure.

## Implemented contract

`me_ledger.py prior-work` takes program, lane, exact file and class. It returns only FID plus confirmed/submitted/duplicate flags for matching closed work, or an empty exact-match response. The agent chooses the next distinct question when its proposed proof is already present; it does not infer that all adjacent roles, consumers, or classes are exhausted. No bulk report contents, titles, payloads, or report references leave this command. Hunter Loop points to the ledger-owned command after current-surface selection.

## Evidence and review

- `python -m pytest -q agents/test_finding_visibility.py agents/test_me_ledger.py agents/test_ledger_v2.py agents/test_manual_hunter.py tests/test_ledger_skill_visibility.py`: 65 passed, 21 subtests after review correction; `git diff --check` clean.
- Real canonical-ledger integration test with a temporary storage root verifies submitted/confirmed flags, underscore-to-hyphen class normalization, and no private proof/report reference in the reply.
- Neighbor alignment: `agents/index.md` and `skills/hunter-loop/SKILL.md` prohibit broad historical target selection; `skills/ledger/SKILL.md` owns retrieval; `skills/manual-hunter/SKILL.md` owns operator submission state.
- Independent review: first review found a false negative for `dom_xss` versus canonical `dom-xss`; normalized query and stored class per Bounty Core's convention and added a real-ledger regression. Re-review pending.

## Blockers and deferred work

- Exact file/class matching does not detect semantically equivalent proofs on different paths or multiple distinct vulnerabilities sharing a file/class; no-match is not a global novelty claim. There is no automatic cross-store FID projection in this task.
- No main promotion or Hoster runtime rollout is implied by beta integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/prior-work-lookup`
- **Latest immutable recovery checkpoint:** `32a3f9154e57db6bd06e90fe270679c0cd0a7737`
- **Feature implementation commit(s):** `32a3f9154e57db6bd06e90fe270679c0cd0a7737`
- **Exact resume point:** reconcile independent review, compare to fresh beta, then integrate and verify local projection.
- **Working-tree state at handoff:** clean after this dossier checkpoint commit.

## Decision gates

- **Integration gate:** focused tests, independent review, clean current beta merge.
- **Activation / cohort gate:** local beta `bbh` command and fresh ledger skill readback; Hoster rollout separate.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-07 — created compact exact-match query, review pending.
