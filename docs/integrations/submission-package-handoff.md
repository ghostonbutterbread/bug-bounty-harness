# Submission package handoff

- **Status:** feature
- **Owner:** Hermes bugfix
- **Branch:** feat/submission-package-handoff
- **Base commit:** 47b3aff
- **Intended integration target:** beta
- **Last updated:** 2026-10-29
- **Owning feature branch/ref:** feat/submission-package-handoff
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** ordinary hunt loaded `manual-hunter` and still wrote `SUBMISSION.md` instead of the report writer

## Intent

Point the finding-capture route at `bunny-report-and-triage` as the submission writer, and include a required standalone PoC in that same package. Do not add a second report writer or authorize live execution.

## Implemented contract

- After populated evidence, `manual-hunter` loads `bunny-report-and-triage` and, when a standalone PoC is needed, `triager-first-poc-authoring` plus `poc-tooling-policy`.
- `agents/index.md` uses the same package rule. Inline proof does not load the PoC authoring skill.
- Existing capture-before-escalation order stays intact.

## Evidence and review

- Tests and commands: `python3 -m pytest tests/test_security_reporting_skill.py tests/test_impact_escalation_routes.py -q`; `git diff --check`
- Independent review: pending
- Replay/cohort/fixture evidence: none; routing text only
- Merge/ancestry evidence: pending

## Blockers and deferred work

- **Missing test or evidence:** fresh Hoster agent reads the updated projected `manual-hunter`
- **Command / fixture / environment needed:** the runtime checkout behind the OMP skill symlink
- **Trigger to run it:** after reviewed beta contains this commit and that checkout is updated
- **Why it blocks integration, activation, or promotion:** it does not block the text change; it blocks claiming the live hunt route is updated
- **Next completion step / successor reference:** merge to beta, then update only the projected runtime checkout that agents resolve

## Interruption / resume handoff

- **Owning feature branch/ref:** feat/submission-package-handoff
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit, run the focused tests, review, then merge to beta
- **Working-tree state at handoff:** intentionally uncommitted until the implementation commit

## Decision gates

- **Integration gate:** focused tests and independent review, then merge to beta. Do not promote to main.
- **Activation / cohort gate:** OMP `manual-hunter` symlink content contains the submission-writer sentence
- **Promotion gate:** explicit owner direction only

## Decision record

- 2026-10-29 — created for the finding-capture submission package handoff.
