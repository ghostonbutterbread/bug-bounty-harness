# XSS mechanism ideation integration dossier

- **Status:** review-ready (corrected guidance accepted; dossier readback gate)
- **Owner:** Hermes / Kanban `t_e47a68ab`
- **Branch:** `feat/xss-idea-depth`
- **Base commit:** `ba398d92b05daf63406ba74b98c16a34d9e329de` (`origin/beta` at task start)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-20
- **Owning feature branch/ref:** `feat/xss-idea-depth`
- **Latest immutable recovery checkpoint:** `7273a774a73059151df48c92cde93d5756634536` (corrected implementation; current tip may have a later dossier-only update)
- **Feature implementation commit(s):** `639480ba23b2b490124b4866cd22a883be48412b`, `7273a774a73059151df48c92cde93d5756634536`
- **Inspiration / canonical references:** Advanced-XSS HEAD `7d529fe86fe8bdef73b393db9274e427cf637182`; DOMPurify README; PortSwigger historical mXSS write-up; existing XSS router and payload-engineering skill.

## Intent

Augment existing XSS methodology to produce non-equivalent ideas after a
sanitizer, URL, reparse or inert result; preserve lane proof, live testing and
ResearchMap ownership. Teach Ryushe through an explicit before/after and local
controlled fixture. No live target traffic or reproduction claims against
third-party programs.

## Implemented contract

Router and payload overlay conditionally load a compact mechanism-ideation
reference. It distinguishes nonmounted consumers, sanitizer/reparse mXSS,
fragment composition, URL check/parser differences, alternate consumers and
other structural/async routes with falsifying controls. Research routing uses an
exact observed edge rather than a generic bypass label. One local HTML fixture
shows post-text-encoding composition into an HTML attribute and two safe
negative controls; the learning note explains before/after and sample limits.

## Evidence and review

- Tests and commands: focused `python3 -m pytest -q tests/test_xss_mechanism_ideation.py tests/test_xss_gtm_skill.py` passed 4; first browser probe showed DOM attribute but asynchronous marker had not fired yet, corrected observer wait then isolated Chrome 150 fixture passed (individual branches false, joined true, safe sinks false, marker 1). The provisioner released the exact fixture browser and returned `state: stopped, status: released`. Checkout-local `.venv` installed via `./setup.sh --install-python-deps`; full `.venv/bin/python -m pytest -q tests` returned **300 passed, 2 failed, 190 subtests passed**. Unchanged beta base, run with the **same feature-venv interpreter** and baseline working directory, returned **297 passed, the same 2 failed, 190 subtests passed**. Both failures are pre-existing in `skills/stack-to-program/scripts/README.md`: missing Outputs/Mutates record and a lane-unsafe direct-Python example. No XSS-owned failure; do not patch unrelated source on this feature.
- Independent review: initial fresh reviewer verdict **MAJOR**: the mXSS branch
  conflated parser mutation with post-check composition. Corrected the
  definition and decision table, narrowed the historical patch claim, repaired
  cross-skill pointers, and added an opt-in browser regression. Fresh reviewer
  accepted the corrected XSS guidance and browser-test boundaries at
  `7273a77`; release was withheld only because this dossier still named the
  initial rather than latest implementation checkpoint. This dossier-only
  correction was read back at both checkpoint fields before integration.
- Browser regression: `XSS_FIXTURE_CDP_LAUNCH=<private task-owned receipt>
  .venv/bin/python -m pytest -q tests/test_xss_browser_fixture.py
  tests/test_xss_mechanism_ideation.py tests/test_xss_gtm_skill.py` returned
  **5 passed** (owned Chrome 150, only local `file:` fixture). Its exact lease
  was released and returned `state: stopped, status: released`; without the
  receipt the browser test skips rather than provisioning a browser.
- Replay/cohort/fixture evidence: bounded 12-stream/110-object recent XSS Attempts sample (40 canonical, 70 legacy omissions); summarized without secrets in `docs/xss-mechanism-ideation.md`. Local fixture only; no live replay.
- Merge/ancestry evidence: isolated branch started at beta `ba398d9`; merge and remote verification pending.

## Blockers and deferred work

- Full-suite green is blocked by the two verified pre-existing beta failures, not
  by this change; independent review accepted the XSS correction and observed
  the same two unchanged failures. A separate owner fixes those records; do not
  alter `stack-to-program` on this feature.
- A local fixture does not validate any third-party sanitizer, historical claim,
  or the scoped target behavior; those require the separate matching, authorized
  target-specific XSS lane and browser evidence.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/xss-idea-depth`
- **Latest immutable recovery checkpoint:** `7273a774a73059151df48c92cde93d5756634536` (corrected implementation commit)
- **Feature implementation commit(s):** `639480ba23b2b490124b4866cd22a883be48412b`, `7273a774a73059151df48c92cde93d5756634536`
- **Exact resume point:** verify this dossier-only correction and the clean
  branch; merge to beta after accepted review, remove dossier from beta, test,
  push and verify selected skill projection.
- **Working-tree state at handoff:** clean after dossier-only checkpoint

## Decision gates

- **Integration gate:** XSS guidance and browser regression accepted by fresh
  independent reviewer at corrected implementation commit. Two unchanged
  `stack-to-program` full-suite failures remain documented against the same
  beta base and interpreter; no XSS-owned failures. Dossier checkpoint corrected
  and read back before merge.
- **Activation / cohort gate:** merge/push beta, then verify selected skill
  projection and fresh resolver; do not equate feature branch with activation.
- **Promotion gate:** no stable/main change without explicit owner direction.

## Decision record

- 2026-10-20 — isolated feature created from current beta; bounded Attempts
  review and local browser composition proof informed the initial guidance.
- 2026-10-20 — implementation committed as `639480ba23b2b490124b4866cd22a883be48412b`;
  full suite matches two pre-existing beta failures; fresh review requested next.
- 2026-10-20 — initial independent review identified an mXSS/composition
  conflation; corrected and reproduced the optional browser regression. Fresh
  review of the corrected commit is the next gate.
- 2026-10-20 — fresh reviewer accepted corrected implementation at `7273a77`;
  blocked release only for stale dossier checkpoint. Updated checkpoint and
  implementation list here; unchanged beta suite failures remain deferred to
  their separate owner, not waived as a green suite.
