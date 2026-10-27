# Bunny role-native pipeline

Status: implementation and incremental behavior trials in progress; not released.
Owner: Hermes / Kanban bug-bounty-harness t_8db7e67e.
Source: Discord thread 1564434386651193377, authorization 1564454258743582820.
Inspiration: user's MAPTA diagram reference; adapt operational coordination, not a new evidence store.

## Branch and scope

- Feature: `feat/bunny-pipeline`, worktree `/home/ryushe/worktrees/bbh-bunny-pipeline`.
- Base: `9e0702536791c49d38e9b5cc48442dea91e613ee` (fetched origin/beta).
- Intended integration target: `beta`, not main.
- Existing owner: `skills/bunny/` role definitions and `bunny-collaborative` behavior.
- No live target traffic, real account creation, external submission, global provider changes, or unattended scheduler in these trials.

## Incremental acceptance gates

1. Pi discovers and actually launches canonical hunter/recon/writer roles, with their required skill access; no generic implementation-worker substitution.
2. One canonical role set is usable through supported harness-native transports without manual reauthoring. State any untested harness explicitly.
3. Real recon writes a local-fixture observation through the existing MapStore; the hunter retrieves the returned reference and acknowledges pickup without parent evidence transcription.
4. The real coordinator resolves a synthetic operational prerequisite, coordinates conflicting ownership, and allows unrelated work to proceed.
5. Follow-up/resume retains the investigator and evidence; direct pushback is delivered to that hunter; independent verification checks an actual local-fixture candidate.

Each behavior gate uses real fresh orchestrator/child model runs on an explicitly synthetic local program. Fixtures are test inputs, not evidence of a real program vulnerability. Failed gates are repaired and rerun before proceeding. Source tests, model behavior, and runtime activation are separate receipts.

## Current implementation and evidence

- Added a Pi package manifest exporting the four existing role files; enabled their native advertised discovery.
- Test-first receipt: `tests/test_bunny_runtime_package.py` failed because the manifest was absent, then the package contract and existing Bunny tests passed (13 tests).
- This is structural evidence only. No Pi parent/child behavior gate has passed yet.
- Checkout environment installed through the repository setup entry point; pinned Bounty Core resolved from this feature checkout's `.venv`.

## Alignment preflight

Checked `AGENTS.md`, `agents/index.md`, `SCRIPT_POLICY.md`, Bunny router/modes, shared Coordination, Context-Efficient Coordination, Policy Authoring, Coding Policy, and Branch Lifecycle. Keep existing canonical evidence owners and scoped authority; no change to remote-pi peer-network policy, live scope, aggregate rate, manual approvals, or model routing. Native parent/child handoffs do not enable cross-campaign peer broadcasts. Preserve explicit offhand mode separately.

## Deferred verification / exact next step

Await bounded read-only Hoster Pi discovery (delegation `deleg_3420df22`). It establishes installed runtime launch/skill and supervisor-channel contracts. Next: exercise native role discovery and one real role launch in an isolated fixture/config using those supported interfaces. Do not claim a package manifest alone fixes runtime behavior. Next source step is the narrow Bunny dispatch reference plus tests based on that exercise.

Independent review, beta integration, and provider activation are pending. Existing runtime projections are untouched. Recovery checkpoint: pending initial feature commit; this dossier is committed with the initial package slice and test receipt. Before review replace this marker with the actual immutable implementation checkpoint and reconcile the feature tip.
