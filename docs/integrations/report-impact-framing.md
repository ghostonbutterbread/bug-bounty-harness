# Report impact framing integration dossier

- **Status:** review-ready
- **Owner:** Hermes, task `t_f90c97f6`
- **Branch:** `docs/report-impact-framing`
- **Base commit:** `8144a665adecc2313ce230c1057434e4650001bb`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-03
- **Owning feature branch/ref:** `docs/report-impact-framing`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryushe's report-stage and impact-framing conversation; `skills/security-reporting/SKILL.md`

## Intent

Clarify the existing three-stage report method without replacing the five-section submission or PoC style: lead with highest demonstrated impact, include proven consequences only when not encompassed by the lead, and retain exploratory angles in the rough report/evidence. No live finding edits or external submission.

## Implemented contract

`security-reporting` tells the writer how to frame Summary, Impact, and supporting evidence; its independent judge checks alignment with the PoC. One focused test guards the wording. No CLI or storage schema change.

## Evidence and review

- Tests and commands: `.venv/bin/python -m pytest -q tests/test_security_reporting_skill.py agents/test_finding_submission.py` — 14 passed, 41 subtests; `git diff --check` clean.
- Independent review: pending
- Replay/cohort/fixture evidence: not applicable; documentation-only
- Merge/ancestry evidence: pending

## Blockers and deferred work

- None known. Hoster activation needs the pushed beta commit, a safe remote sync plan, and runtime readback.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/report-impact-framing`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** test, commit, independent review, merge into beta, push and sync Hoster.
- **Working-tree state at handoff:** intentionally uncommitted while implementing

## Decision gates

- **Integration gate:** focused test, independent review, clean beta merge and retest.
- **Activation / cohort gate:** sync selected Hoster beta source and verify exact projected skill and launcher.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-03 — created on current `origin/beta`.
