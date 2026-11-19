# ATO and reset guidance integration dossier

- **Status:** feature
- **Owner:** Hermes; Kanban `t_f8d68cfe`
- **Branch:** `feat/ato-reset-mentality-tf8d68cfe`
- **Base commit:** `c1cc1002e6561682d3f21b73182d0a4f36f4160a` (local beta contains fetched origin/beta)
- **Intended integration target:** `beta`
- **Owning feature branch/ref:** `feat/ato-reset-mentality-tf8d68cfe`
- **Latest immutable recovery checkpoint:** none yet; commit this dossier with the implementation.
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** `policy-authoring`, `/ato`, `/password-reset`, `/data-store-guidance`, `/attempt-recording-policy`.

## Intent and implemented contract

Make ATO teach curious authentication/authority reasoning and route to specialists; make password-reset expose concrete recovery techniques and route advanced parser ideation to its existing reference. Replace legacy class-specific evidence paths with canonical lane-owned stores. Preserve scope, owned fixtures, stop conditions, secrecy, proof standards and existing examples. No live traffic, user-profile changes, or main promotion.

## Evidence and review

- `/usr/bin/python3 -m pytest -q tests/test_password_reset_guidance.py`: 6 passed.
- `git diff --check`: passed before adding this dossier.
- Independent complete-diff review: pending.
- Offline behavioral consumer exercise and projected-reference route check: pending.
- Integration ancestry: base is local beta `c1cc1002`, ahead of fetched `origin/beta`; preserve all existing beta commits.

## Blockers and deferred work

- Missing evidence: independent review and an offline fresh-consumer exercise against the feature files. Run before beta integration; no live target needed.
- Runtime activation is separate from beta integration and must not be claimed without verified selected projection; remote deployment and push are not authorized by the request.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/ato-reset-mentality-tf8d68cfe`
- **Latest immutable recovery checkpoint:** pending implementation checkpoint commit.
- **Feature implementation commit(s):** pending.
- **Exact resume point:** commit candidate, perform independent review and offline consumer exercise, fix concrete findings, then reconcile beta.
- **Working-tree state at handoff:** intentionally uncommitted until candidate checkpoint.

## Decision gates

- **Integration:** focused tests, real route checks, independent review and clean beta comparison.
- **Activation:** verify the actual selected runtime projection; no implicit cross-host sync.
- **Promotion:** main/stable requires explicit owner direction.
