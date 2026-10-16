# Program severity scoring integration dossier

- **Status:** independently approved for beta integration; runtime activation pending
- **Owner:** Hermes bugfix subagent
- **Branch:** `fix/program-severity-scoring`
- **Base commit:** `ccdadc4e79152434c59cbebe467bd98cd0805819` (`origin/beta` fetched 2026-10-15)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Owning feature branch/ref:** `fix/program-severity-scoring`
- **Latest immutable recovery checkpoint:** `da8e4bfae7bbb1feb9eb63059366dcf176678177`
- **Feature implementation commit(s):** `da8e4bfae7bbb1feb9eb63059366dcf176678177`
- **Inspiration / canonical references:** PC-20261006-184020-439091b0; `skills/ledger/SKILL.md`; `SKILL_REGISTRY.md`; `agents/index.md`

## Intent

Repair the missing `program-severity-scoring` route from ledger without inventing program ratings. BBH owns its ledger workflow and skill registry; neither normalization nor the separate report-writing skill scores demonstrated impact.

## Implemented contract

Add a compact local skill for a confirmed finding: published program rules and caps first, delegated platform rubric second, CVSS only when required; use observed consequence, not class labels. Record source, rationale and constraint; if source/proof/conflict prevents a defensible rating, use `UNKNOWN` rather than a guessed P-tier. Registry resolves the existing ledger link; ledger text remains unchanged. No live target, program data, ledger writes or scoring algorithm.

## Evidence and review

- Tests and commands: `python3 -m pytest tests/test_program_severity_scoring_skill.py tests/test_ledger_skill_visibility.py tests/test_skill_command_lane_safety.py agents/test_me_ledger.py -q` (27 passed, 13 subtests); initial new tests red before skill. `git diff --cached --check` clean. YAML frontmatter parsed with PyYAML; description length 53.
- Independent review approved the four-file diff against fetched `origin/beta` at the feature base: 27 focused tests and 13 subtests, 41 manual-hunter tests and 13 subtests, three severity-normalization tests, frontmatter parsing, and `git diff --check` passed. No invented rating table or false P-tier mapping found. Reviewer changed no files.
- Replay/cohort/fixture evidence: content/route tests only; no real program rubric used.
- Merge/ancestry evidence: base fetched `origin/beta` at `ccdadc4`; no integration performed.

## Blockers and deferred work

- **Missing test or evidence:** Actual policy application to a specific program/finding.
- **Command / fixture / environment needed:** Published program brief/rubric and sanitized finding impact; compare source to selected rating.
- **Trigger to run it:** Authorized real finding scored through the ledger route.
- **Why it blocks integration, activation, or promotion:** It does not block this generic skill's local verification; it blocks claims of accuracy for any particular program rating.
- **Next completion step / successor reference:** Parent integrates to selected beta, verifies merged-tree checks and publishes, then refreshes the selected Hoster beta source and runs a focused profile sync/resolver check. Real program scoring stays with each finding owner.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/program-severity-scoring`
- **Latest immutable recovery checkpoint:** `da8e4bfae7bbb1feb9eb63059366dcf176678177`
- **Feature implementation commit(s):** `da8e4bfae7bbb1feb9eb63059366dcf176678177`
- **Exact resume point:** reconcile with current `origin/beta`, integrate independently reviewed code into a clean beta checkout, remove this temporary dossier, run merged-tree tests, publish and verify selected runtime skill projection. No real finding scoring is implied.
- **Working-tree state at handoff:** clean after dossier-only commit

## Decision gates

- **Integration gate:** independent review and current beta reconciliation by parent; not authorized here.
- **Activation / cohort gate:** selected runtime skill installation and fresh consumer lookup, not done here.
- **Promotion gate:** none; explicitly prohibited.

## Decision record

- 2026-10-15 — BBH owns ledger reference and registry; chose a narrow scoring skill rather than extending report-writing or normalization. No program-specific P-tier table.
- 2026-10-15 — independent review approved source-level beta integration with focused and neighboring suites; runtime discovery remains unverified.
