# Strict out-of-scope contract integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `fix/strict-outscope-contract`
- **Base commit:** `902b1c247ddfc58b234d79c4706ebdf805ee83fb`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-14
- **Owning feature branch/ref:** `fix/strict-outscope-contract`
- **Latest immutable recovery checkpoint:** `6109bc60147bf11ef27e319a86f7398d9d6c995b`
- **Feature implementation commit(s):** `82f23aa21d604036f94b4a0bbdf20f3065f31e62`, `6109bc60147bf11ef27e319a86f7398d9d6c995b`
- **Inspiration / canonical references:** `~/Shared/change_proposals/2026-09-14-claude-scope-puller-outscope-delimiter.md`

## Intent

Make generated `out-of-scope.txt` safe for strict line-based scope consumers without discarding platform exclusion information. Preserve the prior public Intigriti and Bugcrowd behavior.

## Implemented contract

`out-of-scope.txt` contains only strict host, wildcard-host, IP, or CIDR entries, one bare value per line. HTTP(S) path exclusions are conservatively represented by their host. Non-routable prose and the complete original records are retained in canonical `out-of-scope.json`. Canonical and legacy text files remain synchronized.

## Evidence and review

- Tests and commands: `PYTHONPATH=<worktree> python3 -m pytest -q agents/test_scope_puller_seed_files.py agents/test_scope_seed_files.py agents/test_scope_validator.py agents/test_recon_ry.py` (137 passed); `compileall`; `git diff --check`; corrected direct normalization smoke covers non-canonical IPv4/IPv6 CIDRs, uppercase HTTPS, and prose rejection. Live read-only Intigriti parse emitted 14 strict entries from 16 total exclusions and retained all 16 records in JSON.
- Independent review: initial review blocked CIDR canonicalization, case-insensitive URL normalization, comment-header compatibility, and stale dossier state; all four focused corrections are implemented and await fresh review.
- Replay/cohort/fixture evidence: test covers host, wildcard, URL-to-host, CIDR, prose exclusion omission from text, and prose retention in JSON.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** fresh independent review plus beta merge preflight.
- **Command / fixture / environment needed:** reviewer in this worktree; clean beta worktree.
- **Trigger to run it:** after implementation checkpoint.
- **Why it blocks integration, activation, or promotion:** shared scope output affects strict downstream filters.
- **Next completion step / successor reference:** commit, update recovery checkpoint, review, merge beta, then roll the clean selected beta checkout to Hoster.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/strict-outscope-contract`
- **Latest immutable recovery checkpoint:** `6109bc60147bf11ef27e319a86f7398d9d6c995b`
- **Feature implementation commit(s):** `82f23aa21d604036f94b4a0bbdf20f3065f31e62`, `6109bc60147bf11ef27e319a86f7398d9d6c995b`
- **Exact resume point:** obtain independent review of this current dossier-only handoff and the implementation through `6109bc60147bf11ef27e319a86f7398d9d6c995b`, then run the beta merge preflight if accepted.
- **Working-tree state at handoff:** clean after committing this dossier-only handoff.

## Decision gates

- **Integration gate:** fresh review accepted, beta merge preflight passes, and no dossier lands on beta.
- **Activation / cohort gate:** Hoster selected beta checkout contains the merged revision and passes a read-only smoke; no unrelated process restart.
- **Promotion gate:** beta only; main promotion is outside this task.

## Decision record

- 2026-09-14 — reviewer found CIDR, uppercase-URL, header, and dossier-state defects; implemented focused corrections and expanded the strict output fixture.
