# Bunny role-native pipeline

Status: blocked at the first real-agent trial pending fresh execution approval; not released.
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
- Dispatch route now requires real named roles (or an actually loaded canonical role file on harnesses without a named selector), with readable selected skill paths. Focused package/router tests: 14 passed.
- Full `tests/` run: 365 passed, 1 skipped, 3 failed, with 196 subtests passed. All three failures reproduced on a clean detached worktree of the unchanged base using the same interpreter and base-first import path: stack-to-program script index missing Outputs/Mutates; its direct-checkout example rejected by lane-safety; upload-surface test expects stale wording. These are unrelated baseline issues, not excluded-and-called-green; no unrelated source was changed.
- Checkout environment installed through the repository setup entry point; pinned Bounty Core resolved from this feature checkout's `.venv`.

## Alignment preflight

Checked `AGENTS.md`, `agents/index.md`, `SCRIPT_POLICY.md`, Bunny router/modes, shared Coordination, Context-Efficient Coordination, Policy Authoring, Coding Policy, and Branch Lifecycle. Keep existing canonical evidence owners and scoped authority; no change to remote-pi peer-network policy, live scope, aggregate rate, manual approvals, or model routing. Native parent/child handoffs do not enable cross-campaign peer broadcasts. Preserve explicit offhand mode separately.

## Deferred verification / exact next step

Read-only Hoster discovery confirmed native named-role roots, clean custom-child prompts, and supervisor/follow-up/resume support. Delegation `deleg_c90a48b7` prepared the immutable candidate and a disposable RPC controller but did not execute the trial: tool approval was withdrawn when the approval prompt could not be completed before the turn ended. The receipt explicitly forbids retrying, rephrasing, or switching tools without fresh user consent. No remote staging, Pi coordinator, or child launch occurred. Correction to earlier progress wording: the trial was dispatched/prepared, not actually running.

Blocked receipt: `/home/ryushe/.hermes/cache/scratch/bunny-stage1-20261027T015526Z-dd31e4/receipt.json`. Local snapshot, manifest, and controller are retained there. After fresh explicit approval, inspect the prepared controller and resume the same stage; verify native role identities, actual skill reads, effective route, and terminal child states. Do not add the next stage until that gate passes.

Independent review, beta integration, and provider activation are pending. Existing runtime projections are untouched. Recovery implementation checkpoint: `e686d3139f9c16e167664fe227c4ec9857056810` on `feat/bunny-pipeline`, preceded by package slice `990e76214b4f43707111486766140270231966e3`; the current feature tip may include a later dossier-only checkpoint. Base and target are as recorded above.
