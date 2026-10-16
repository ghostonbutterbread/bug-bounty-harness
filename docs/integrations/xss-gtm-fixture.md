# XSS GTM fixture integration dossier

- **Status:** feature
- **Owner:** Hermes / Ryushe
- **Branch:** `feat/xss-gtm-fixture`
- **Base commit:** `5770784e1e07d990c4bb592fdad6217118222666`
- **Intended integration target:** `beta` (`origin/beta`)
- **Last updated:** 2026-10-16
- **Owning feature branch/ref:** `feat/xss-gtm-fixture`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Discord message `1560779508628594751`; `skills/xss/SKILL.md`; prior seed `2026-10-16-gtm-xss.md` (not canonical)

## Intent

Give XSS agents Ryushe's preconfigured GTM XSS container ID and a direct route from the XSS skill. Do not create GTM tags, access an account, or probe any live target in this change.

## Implemented contract

`xss-gtm` names `GTM-NRM7SMTK` and the corresponding script URL. The XSS router and registry expose it conditionally; selected XSS lane retains proof, safety, and reporting. User-reported payload contents are not independently verified by this source change.

## Evidence and review

- Tests and commands: focused `tests/test_xss_gtm_skill.py` plus three XSS route suites: 9 passed; `tests/test_skill_promotion_routes.py` and `tests/test_skill_triage_routes.py`: 16 passed / 10 subtests; `git diff --check` clean.
- Independent review: pending.
- Replay/cohort/fixture evidence: no live target or GTM container execution attempted.
- Merge/ancestry evidence: feature begins at fetched `origin/beta` `5770784e1e07d990c4bb592fdad6217118222666`.

## Blockers and deferred work

- No blocker for skill authoring; live fixture behavior is intentionally unverified until an authorized test context is selected. No account automation belongs to this change.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/xss-gtm-fixture`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** finish focused tests, independent review, and beta integration.
- **Working-tree state at handoff:** intentionally uncommitted feature files pending validation.

## Decision gates

- **Integration gate:** focused test, source diff review, beta compatibility, independent acceptance.
- **Activation / cohort gate:** beta skill projection verifies `xss-gtm` resolves and XSS pointer is present.
- **Promotion gate:** stable/main remains separate and not requested.

## Decision record

- 2026-10-16 — created from current fetched beta for a compact user-requested fixture skill.
