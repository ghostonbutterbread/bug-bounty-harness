# Bunny OMP worker routing integration dossier

- **Status:** feature; runtime inference and publication unverified
- **Owner:** Hermes
- **Branch:** `fix/bunny-omp-dynamic-model`
- **Base commit:** `69cec71186264b7495e949679efd5342a4f72ded`
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-05
- **Owning feature branch/ref:** `fix/bunny-omp-dynamic-model`
- **Latest immutable recovery checkpoint:** see first branch commit containing this dossier
- **Feature implementation commit(s):** see branch history
- **Inspiration / canonical references:** Bunny dispatch and OMP worker selection; installed OMP 18.16.0 source and `omp://task-agent-discovery.md`.

## Intent

Make the existing Bunny router tell OMP coordinators how a native named worker can receive an operator-selected model for one run, and how to avoid assuming the parent model or approval boundary. Preserve provider credential isolation, ordinary Bunny policies, operator choice, and global configuration.

## Implemented contract

The Bunny router conditionally loads an OMP-specific reference. It explains a trusted run-scoped `--config` `modelRoles` grant, exact named per-call selection, precedence of named frontmatter when no model is supplied, the OMP headless-child approval behavior, and verification of the actual route and approval gate. This is guidance, not code enforcing model selection or approval. It neither starts an agent nor changes OMP settings.

## Evidence and review

- `python3 -m unittest tests.test_bunny_skill -v`: 14 passed; a new focused contract assertion failed before the documentation and passed afterwards.
- Installed OMP source and disposable configuration loading support the documented `--config`, `modelRoles`, model grant and policy precedence; no inference was made.
- An independent review found omitted inherited-model and approval details; a separate focused re-review approved both corrections, with 14 tests passing. Review transcript: `deleg_3d9a8b0a` and `deleg_d4c955f1` in this Hermes session's delegation records.
- `git fetch origin beta`: current base matched `origin/beta` at branch creation and before checkpoint.
- Full test attempts: base-interpreter `unittest discover` ran 187 cases and failed with 38 missing-module errors; an isolated scratch venv was created from the repository-pinned `requirements.txt`. Repository-root `pytest -q -rs` stopped during collection because root `test_catalog.py` imports missing `bac_checks` (existing papercut `PC-20260829-003826-4da4517b`). With an owned `.venv` link to that isolated environment, `pytest tests -q -rs` reported **1957 passed, 2 failed, 3 skipped, 258 subtests passed**. Both failures are in `tests/test_skill_triage_routes.py` and independently reproduce on the unmodified `beta` checkout at the base SHA. The skipped browser fixture requires an explicit provisioner receipt.
- Policy alignment: Bunny owns the mode/model route; the new OMP reference is selected only for OMP and retains the existing provider, approval, scope, worker-lifetime and effective-model gates. No root-context changes. The BBH repository contains no policy-lint guide or lint command; run focused route/reference checks and flag that limit rather than claim policy lint passed.

## Blockers and deferred work

- **Missing test:** native OMP task child inference with a requested model and verified effective model/provider. The config overlay was loaded in a disposable fixture, not used for a model call.
- **Fixture needed:** an authorized, non-target local task with a valid operator-selected provider/model, trusted run-scoped overlay, registered named Bunny role, and verified non-bypassed parent task-approval boundary. Inspect child's own metadata and confirm its exit.
- **Trigger:** an operator-approved model smoke with the required parent approval boundary and valid provider route.
- **Effect:** blocks claiming real dynamic routing or an end-to-end worker fix, independently of whether the guidance is merged.
- **Activation:** merge reviewed changes to the clean named beta integration worktree, publish as authorized, then verify Hoster's actual configured source/projection and a fresh skill load; do not interrupt active workers. Codex role loading and `sync all` conflicts remain separate unresolved tasks in Kanban `t_05035b5e`.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/bunny-omp-dynamic-model`
- **Latest immutable recovery checkpoint:** see branch history containing this dossier
- **Feature implementation commit(s):** see branch history
- **Exact resume point:** inspect full-test result, compare fetched beta tip, review cumulative diff and dossier, then decide whether to integrate guidance separately while keeping end-to-end smoke open.
- **Working-tree state at handoff:** commit task-owned paths with this dossier; do not stage unrelated paths.

## Decision gates

- **Integration:** focused review and tests, complete applicable suite and policy-alignment checks; no implication of live inference.
- **Activation / cohort:** verify Hoster's actual source, new-session skill path and no disruption to existing processes.
- **Promotion:** explicit stable-lane user direction; not requested.

## Decision record

- 2026-11-05 — initial independent review blocked on parent approval and model inheritance; corrections independently re-reviewed and approved for those findings only. No end-to-end smoke or deployment claimed.
