# ATO and reset guidance integration dossier

- **Status:** feature
- **Owner:** Hermes; Kanban `t_f8d68cfe`
- **Branch:** `feat/ato-reset-mentality-tf8d68cfe`
- **Base commit:** `c1cc1002e6561682d3f21b73182d0a4f36f4160a` (local beta contains fetched origin/beta)
- **Intended integration target:** `beta`
- **Owning feature branch/ref:** `feat/ato-reset-mentality-tf8d68cfe`
- **Latest immutable recovery checkpoint:** `23172c897a0e15362bbc8462bb4caf4367017f4d`
- **Feature implementation commit(s):** `92f50712e1a589c081ca79029306d182f0dd0d2e`, `23172c897a0e15362bbc8462bb4caf4367017f4d`
- **Inspiration / canonical references:** `policy-authoring`, `/ato`, `/password-reset`, `/data-store-guidance`, `/attempt-recording-policy`.

## Intent and implemented contract

Make ATO teach curious authentication/authority reasoning and route to specialists; make password-reset expose concrete recovery techniques and route advanced parser ideation to its existing reference. Replace legacy class-specific evidence paths with canonical lane-owned stores. Preserve scope, owned fixtures, stop conditions, secrecy, proof standards and existing examples. No live traffic, user-profile changes, or main promotion.

## Evidence and review

- `/usr/bin/python3 -m pytest -q tests/test_password_reset_guidance.py`: 6 passed.
- `git diff --check`: passed before adding this dossier.
- Independent complete-diff review: no live-safety regression; advanced-route negative test correction accepted on re-review. Dossier status corrected after re-review.
- Offline behavioral consumer exercise: two fictional recovery scenarios examined; routes, safety and unknowns checked. Six source-tree relative path checks passed. No real target traffic.
- Integration ancestry: base is local beta `c1cc1002`, ahead of fetched `origin/beta`; preserve all existing beta commits.

## Blockers and deferred work

- No known implementation blocker. Re-run focused checks on integrated beta; no live target needed.
- Runtime activation is separate from beta integration and must not be claimed without verified selected projection; remote deployment and push are not authorized by the request.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/ato-reset-mentality-tf8d68cfe`
- **Latest immutable recovery checkpoint:** `23172c897a0e15362bbc8462bb4caf4367017f4d`
- **Feature implementation commit(s):** `92f50712e1a589c081ca79029306d182f0dd0d2e`, `23172c897a0e15362bbc8462bb4caf4367017f4d`
- **Exact resume point:** reconcile current beta, integrate, remove this dossier from the integration target, and rerun focused checks.
- **Working-tree state at handoff:** checkpoint commit is recoverable; this decision record is committed separately.

## Decision gates

- **Integration:** focused tests, real route checks, independent review and clean beta comparison.
- **Activation:** verify the actual selected runtime projection; no implicit cross-host sync.
- **Promotion:** main/stable requires explicit owner direction.
