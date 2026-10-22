# Program initializer full-recon integration dossier

- **Status:** feature
- **Owner:** Hermes delegated implementation
- **Branch / owning ref:** `feat/program-init-full-recon`
- **Base commit:** `95c073603582732f520c59d94d8f3b03a76dcedd` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-22
- **Latest immutable recovery checkpoint:** `331caa65f21737c89604b616a22f8fb06abbe775`
- **Feature implementation commit(s):** `331caa65f21737c89604b616a22f8fb06abbe775`
- **Inspiration / canonical references:** `scripts/program_init.py`, `agents/recon/full.py`, `skills/recon/SKILL.md`, `scripts/README.md`

## Intent

Preserve the basic initializer's create-only behavior and add an opt-in full plan-only handoff for independent collection, ordered JS→Katana endpoint extraction, API mapping, optional explicitly requested public docs, Recon Bus promotion and URL Ingest review. No target traffic or CLI subagent spawn.

## Implemented contract

`--mode basic` remains default. `--mode full` requires a platform scope source, nonempty saved scope and a web/API lane. `--include-docs` is full-only. Full writes a deterministic pending JSON packet to the selected lane's `recon/_meta/full-recon-handoff.json`, refreshing only that generated packet on rerun. Dry-run requires pre-existing saved scope and writes nothing. All stages require agent policy/scope/rate decisions and producer receipts; the packet is not a completion ledger. Recon-Ry remains owner of its stages and archive promotion; `agents/recon_full.py` remains plan-only.

## Evidence and review

- Tests: `python3 -m pytest tests/test_program_init.py tests/test_full_recon.py tests/test_recon_docs.py tests/test_recon_ry_snap_default.py -q` — 20 passed, 2026-10-22; `git diff --check` passed. CLI offline rejection of `--skip-scope --mode full --dry-run` returned the expected error.
- Independent review: pending parent review; no merge or push authorized by this task.
- Fixture: mocked platform pull and saved scope; deterministic rerun, docs opt-in, pending statuses, dependency order, missing scope and dry-run no-write checks.
- Merge/ancestry: branch created at the fetched `origin/beta` base; integration intentionally deferred.

## Blockers and deferred work

- **Missing evidence:** No live target execution, platform scope pull or subagent dispatch tested (intentionally forbidden for this task).
- **Command / fixture:** authorized program and its published rules, saved scope, approved rate budget and agent ownership receipts.
- **Trigger:** separate operator-approved live campaign after beta integration and policy review.
- **Why:** prevents claiming collection or promotion from an offline handoff.
- **Next step:** parent independently reviews diff/tests and determines integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/program-init-full-recon`
- **Latest immutable recovery checkpoint:** `331caa65f21737c89604b616a22f8fb06abbe775`
- **Feature implementation commit(s):** `331caa65f21737c89604b616a22f8fb06abbe775`
- **Exact resume point:** parent independently reviews tests and packet against policy; integrate only after a separate decision.
- **Working-tree state at handoff:** clean after commit expected.

## Decision gates

- **Integration gate:** independent review plus focused offline tests on current beta; no merge requested here.
- **Activation / cohort gate:** no target traffic or runtime activation in this change.
- **Promotion gate:** explicit owner decision, not implied by beta integration.

## Decision record

- 2026-10-22 — created feature handoff and offline test receipt; review pending.
