# Ledger impact-scoring fields integration dossier

- **Status:** review-ready
- **Owner:** Hermes (Ryushe-directed)
- **Branch:** `feat/ledger-impact-scoring`
- **Base commit:** `b64972ff76ab418c765ff7f44dc46e599fc05540` (beta tip, fetched)
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-17
- **Owning feature branch/ref:** `feat/ledger-impact-scoring` (worktree `~/projects/bbh-feat-ledger-impact`)
- **Latest immutable recovery checkpoint:** see decision record below
- **Feature implementation commit(s):** none yet (working tree verified, commit pending)
- **Inspiration / canonical references:** `security/program-severity-scoring` skill (severe fields: vulnerability_class, demonstrated_impact, severity, scoring_authority, severity_rationale, program_constraint); Ryu request: "instead of gating findings, use real-world scales".

## Intent

Ledger findings currently carry only an uppercased 6-value `severity` enum
(CRITICAL…UNKNOWN), and `review_tier: PENDING_REVIEW` effectively gates them.
Ryu wants findings self-classified by real-world scoring authority instead of
gated. This branch wires the existing `program-severity-scoring` skill's
output fields into the recording path so every ledger entry carries its
scoring evidence and is re-scoreable when program guidance changes.

Boundaries unchanged: severity enum values, dedupe identity, ledger schema
(new fields flow through `bounty_core.ledger._merge_extra_fields` — no
`bounty-core` change needed), FID lifecycle, review_tier semantics.

## Implemented contract

1. `me_ledger.py add` gains optional `--scoring-authority`,
   `--severity-rationale`, `--program-constraint`. Non-empty values are stored
   on the finding (and preserved through `ledger_add` via extra-field merge).
   Empty strings are omitted rather than stored.
2. `manual_hunter.py` finding-note parser accepts `Scoring Authority:`,
   `Severity Rationale:`, `Program Constraint:` fields (plus underscore
   aliases); values land on the finding dict and persist into the ledger and
   generated report.
3. `manual_hunter.py` hunt-prompt report template asks hunter agents for the
   three fields.
4. `skills/ledger/SKILL.md` gains a "Score before recording" step routing to
   the `program-severity-scoring` skill, with the `me_ledger add` command
   example showing the new flags.

Non-claims: no severity normalization changes (still `bounty_core`
CRITICAL…UNKNOWN with P1–P5 aliases); no retroactive migration of existing
UNKNOWN-severity entries; no gating removal in `review_tier` logic.

## Evidence and review

- Tests and commands:
  - `.venv/bin/python -m pytest agents/test_me_ledger.py agents/test_manual_hunter.py agents/test_ledger_v2.py agents/test_ledger_v2_compatibility_fixtures.py agents/test_finding_visibility.py -q` → 49 passed, 4 subtests.
  - New tests: `test_build_parser_add_accepts_scoring_fields`,
    `test_scoring_fields_are_parsed_into_the_finding`; extended
    `test_cmd_add_uses_adapter_functions_with_lane_and_family`.
  - Live smoke 1: `me_ledger.py add … --scoring-authority … --severity-rationale …`
    → `ledger.json` on disk contains `severity: HIGH`,
    `scoring_authority`, `severity_rationale`.
  - Live smoke 2: `manual_hunter.py --from-file` note with the three fields
    → ledger entry D01 carries all three fields; generated `REPORT.md` written.
- Independent review: pending (required before beta merge per repository policy).
- Replay/cohort/fixture evidence: covered by existing ledger_v2 fixture tests (unchanged).
- Merge/ancestry evidence: branch created from fetched `origin/beta`
  (`b64972f`); no upstream movement expected before review.

## Blockers and deferred work

None blocking review. Deferred (owner decision):

- Backfilling scoring fields for existing entries (e.g. superdrug D01,
  severity UNKNOWN, no rationale) — propose doing lazily on next sighting,
  not a migration script.
- Whether `manual_hunter` should *require* a scoring authority on CONFIRMED
  findings (currently optional to keep minimal-note tolerance).

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/ledger-impact-scoring`
- **Latest immutable recovery checkpoint:** none yet — commit before any pause.
- **Feature implementation commit(s):** none yet.
- **Exact resume point:** commit the staged change, then delegate release-gate
  review per `coding-agent-operations-policy`.
- **Working-tree state at handoff:** intentionally uncommitted (all edits
  verified by tests + two live smoke runs as of 2026-09-17).

## Decision gates

- **Integration gate:** independent review of diff + dossier, then merge into
  clean current `beta` worktree and push from there.
- **Activation / cohort gate:** after beta merge, sync-linked skill projection
  (`~/.hermes/synced-skills/ledger`) updates via normal aiskillsync flow; no
  separate activation step for the Python changes.
- **Promotion gate:** standard main promotion, not requested.

## Decision record

- 2026-09-17 — created; implementation verified in worktree (tests + smoke),
  commit pending.
