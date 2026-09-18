# Ledger severity normalization integration dossier

- **Status:** review-ready
- **Owner:** Hermes (Ryushe-directed)
- **Branch:** `feat/ledger-severity-normalization`
- **Base commit:** `8ac4be97dd0cd47ab582bf1768f2ce2620794408` (beta, fetched)
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-18
- **Owning feature branch/ref:** `feat/ledger-severity-normalization` (worktree `~/projects/bbh-feat-severity-normalize`)
- **Latest immutable recovery checkpoint:** none yet (commit pending)
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** `bounty_core.finding.normalize_severity` (P1–P5 + case-insensitive name aliases → canonical enum, unknown → UNKNOWN); Ryu request: agents can speak their platform's schema (P1, P0…) and the ledger translates it.

## Intent

`me_ledger.py add` stored severity as raw uppercase input: `P1` stayed
literally `"P1"` in ledger.json (only `bounty_core`'s internal normalize path
aliased it). Ryu wants agents to use whatever rating label their scoring
authority produced (P1/P2, lowercase words) and have the ledger normalize to
the canonical CRITICAL/HIGH/MEDIUM/LOW/INFO/UNKNOWN enum at write time.

Boundaries unchanged: `bounty_core` itself (its `normalize_severity` is
reused, not modified), dedupe identity, scoring-field behavior from
feat/ledger-impact-scoring, review_tier semantics.

## Implemented contract

1. `me_ledger.py` imports `normalize_severity` from `bounty_core.finding` and
   `cmd_add` applies it to `--severity` before building the finding dict.
2. Verified alias behavior (live, from the worktree venv):
   P1→CRITICAL, P2→HIGH, P3→MEDIUM, P4→LOW, P5→INFO, case-insensitive,
   full words accepted (`critical`→CRITICAL), garbage/empty→UNKNOWN.
   **P0→UNKNOWN** (not aliased upstream; see deferred work).
3. `skills/ledger/SKILL.md`: "Severity is normalized at write time" note —
   agents pass the platform's own label, never pre-convert by hand.
4. New regression test `test_cmd_add_normalizes_severity_aliases` covering
   P1/p2/P3/P4/critical/HIGH/bogus/empty through `cmd_add`.

Non-claims: manual_hunter's note parser keeps its own `_normalize_severity`
(SEVERITIES-set membership → UNKNOWN) — its input is the note template that
already asks for canonical values; changing it would alter a different
ingest path and is deferred.

## Evidence and review

- Tests and commands:
  - `.venv/bin/python -m pytest agents/test_me_ledger.py -q` → 9 passed, 8 subtests.
  - Focused suite: `agents/test_manual_hunter.py agents/test_ledger_v2.py
    agents/test_ledger_v2_compatibility_fixtures.py agents/test_finding_visibility.py -q`
    → 41 passed, 4 subtests.
  - Live CLI edge run (`/tmp/edge_ledger_norm.sh`): P1→CRITICAL stored;
    re-add deduped with rationale refresh; `SEVERE!!!`→UNKNOWN; `p0`→UNKNOWN.
- Independent review: pending (required before beta merge).
- Replay/cohort/fixture evidence: ledger_v2 fixtures unchanged and passing.
- Merge/ancestry evidence: branch from fetched beta tip `8ac4be9`.

## Blockers and deferred work

- **P0 handling (owner decision):** `bounty_core.normalize_severity` has no
  P0 alias → currently UNKNOWN. Many teams use P0 as top tier; Bugcrowd/H1
  top tier is P1/CRITICAL. Proposal: leave as UNKNOWN unless/until a real
  program uses P0-as-top, then alias in bounty_core (shared repo, separate
  slice). Ryu said "agents can say P1, P0" — if you want P0→CRITICAL now,
  it's a 1-line addition in bounty-core (beta), not this branch.
- **manual_hunter parser normalization:** same normalize call could apply at
  note-parse time; deferred to keep this slice minimal.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/ledger-severity-normalization`
- **Latest immutable recovery checkpoint:** none yet — commit before pause.
- **Feature implementation commit(s):** none yet.
- **Exact resume point:** commit, delegate release-gate review, merge to beta.
- **Working-tree state at handoff:** intentionally uncommitted (tests + live
  edge run verified 2026-09-18).

## Decision gates

- **Integration gate:** independent review PASS required before beta merge.
- **Activation / cohort gate:** skill text flows via aiskillsync projection;
  Python changes active on next agent run from beta checkout.
- **Promotion gate:** standard main promotion, not requested.

## Decision record

- 2026-09-18 — created; implementation verified (tests + live CLI edge run),
  commit pending.
