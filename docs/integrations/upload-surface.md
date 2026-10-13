# Upload-surface integration dossier

- **Status:** review-ready
- **Owner:** Hermes / t_b1f7c842
- **Branch:** `feat/upload-surface-router-tb1f7c842`
- **Base commit:** `8725814f1fb5ff40d40992d0a5fbb9bca56815ba`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-13
- **Owning feature branch/ref:** `feat/upload-surface-router-tb1f7c842`
- **Latest immutable recovery checkpoint:** `919171b09989f4f3fba208bcf90d891e9242ec65`
- **Feature implementation commit(s):** `919171b09989f4f3fba208bcf90d891e9242ec65`
- **Inspiration / canonical references:** `~/Shared/skill_seeds/2026-10-13-upload-surface.md` (runtime block only); `skills/pfp/SKILL.md`.

## Intent

Promote the researched upload-surface lifecycle router into BBH and connect the existing PFP coordinator's concrete upload/parser lane. Preserve specialist ownership, program policy, owned-resource safety, and PFP's independent SSRF/IDOR/XSS/race lanes. Do not promote the seed-only anthology or private notes, and do not change live testing automation.

## Implemented contract

`skills/upload-surface/SKILL.md` traces file inputs through validation, derivatives, association, serving and cleanup, routes a concrete boundary to specialist skills, and gates live submissions by program/visibility policy. `references/public-cases.md` packages only the cited public examples, not the seed-only anthology or personal notes. `skills/pfp/SKILL.md` routes file-lifecycle questions here but retains avatar-specific direct specialist branches. `SKILL_REGISTRY.md` advertises the router. No live targets or new execution helper.

## Evidence and review

- Tests and commands: `PYTHONPATH=$PWD python3 -m unittest discover -s tests -p 'test_upload_surface_skill.py' -v` (4 passed); `git diff --check` (passed). YAML/frontmatter and citation/source equality checked in a separate read-only Python check.
- Independent review: pending.
- Merge/ancestry evidence: feature based on fetched `origin/beta` 8725814.

## Blockers and deferred work

None known. No live-target test is authorized or needed for a text-only router; runtime projection and fresh-session resolution still required.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/upload-surface-router-tb1f7c842`
- **Latest immutable recovery checkpoint:** `919171b09989f4f3fba208bcf90d891e9242ec65`
- **Feature implementation commit(s):** `919171b09989f4f3fba208bcf90d891e9242ec65`
- **Exact resume point:** independently review implementation commit, reconcile into beta, and project with Aiskillsync. Current branch tip will include a later dossier-only handoff commit.
- **Working-tree state at handoff:** clean after dossier-only commit.

## Decision gates

- **Integration gate:** independent review and source/route checks, then clean beta merge.
- **Activation / cohort gate:** focused Aiskillsync projection and read-only fresh-runtime load.
- **Promotion gate:** beta only; stable/master requires separate explicit direction.

## Decision record

- 2026-10-13 — created feature from current `origin/beta`; configured sync source is the separate `bbh-beta-integration` checkout, to update after beta push without touching unrelated worktrees.
- 2026-10-13 — implementation committed as `919171b09989f4f3fba208bcf90d891e9242ec65`; four focused offline tests passed; awaiting independent review.
