# Manual-hunter note template integration dossier

- **Status:** feature; awaiting parent review
- **Owner:** Hermes bugfix delegated implementation
- **Branch / owning ref:** `docs/manual-hunter-note-template`
- **Worktree:** `/home/ryushe/worktrees/bbh-manual-hunter-note-template`
- **Base commit:** `c39efdc93b2ae0f0c52fa83ba32bc327d33fe971` (`origin/beta`, fetched)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** none yet; implementation commit and branch tip to be supplied in handoff
- **Feature implementation commit(s):** pending
- **Inspiration:** `PC-20260914-221118-4041143b`, `PC-20260917-015305-acbfa385`; owning skill and `agents/manual_hunter.py` parser

## Intent and implemented contract

Document a sanitized `--from-file` note accepted by the current parser: explicit `File:` and `Description:` with optional `Class:`. The parser also supports fallback inference for unlabelled files and narrative descriptions; `Class:` omission emits a warning and can misclassify. No parser behavior or ledger records are changed. The documented synthetic example is not a finding or permission to ingest; the existing evidence gate remains authoritative.

## Evidence and review

- Source: `agents/manual_hunter.py` `FIELD_ALIASES`, `parse_text`, `_infer_class`, and `ingest_file`; direct validation requires a nonempty file and description, not a mandatory class.
- `python3 -m unittest agents.test_manual_hunter.ManualHunterTests.test_documented_from_file_note_parses_without_ingest -v`: 1 passed. The test parses the actual skill example via an uninitialized parser object, with explicit and inferred class cases; no ledger or ingest is invoked.
- Four focused parser tests (documented example, tolerant minimal note, class inferred/stated, missing file): 4 passed.
- `git diff --check`: passed.
- Independent review and beta integration: parent owns; not performed by this branch.

## Blockers and deferred work

None for parser-only validation. Parent should review the documentation/test diff against the fetched beta tip, integrate and remove this temporary dossier on beta. No runtime activation or live finding ingest is within this task.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/manual-hunter-note-template`
- **Latest immutable recovery checkpoint:** implementation commit to be reported in handoff
- **Exact resume point:** parent review and integration into `beta`; retire this dossier at merge
- **Working-tree state at handoff:** expected clean after commit

## Decision gates

- **Integration gate:** parent review and beta reconciliation/checks
- **Activation / cohort gate:** separate downstream skill projection, not claimed
- **Promotion gate:** no stable promotion requested

## Decision record

- 2026-10-15 — current parser contract verified and skill note template tested in isolation; parent review pending.
