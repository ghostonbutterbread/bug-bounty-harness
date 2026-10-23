# Profile-local operational guidance reconciliation

- **Status:** feature; parent review and integration pending
- **Owner:** Hermes BBH canonicalization task `t_7478b065` (scoped subagent)
- **Branch:** `docs/local-operational-guidance`
- **Worktree:** `/home/ryushe/worktrees/bbh-local-operational-guidance`
- **Base commit:** `dd45b128dd61e9a1df91345803cd9924ddb1fa70` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-23
- **Owning feature branch/ref:** `docs/local-operational-guidance`
- **Latest immutable recovery checkpoint:** `5a31895a93eb1f80fcb455cac0cadca831ae6330`
- **Feature implementation commit(s):** `5a31895a93eb1f80fcb455cac0cadca831ae6330`
- **Inspiration / canonical references:** profile-local skills listed in audit below; `agents/index.md`, `skills/recon/`, `skills/js-hunt/`, `skills/coverage/`, `skills/hunter-loop/`.

## Intent and boundary

Audit seven local operational skill definitions against the existing BBH beta owners and migrate only distinct safe guidance. No new same-named skills, local archives, generated recon, live traffic, Hoster actions, init workflow edits, beta integration, or push. `t_1205ee4c` owns `scripts/program_init.py`, `skills/recon/` init handoffs and their tests; none are changed here.

## Source comparison and decisions

| Local source | Existing BBH owner / comparison | Decision |
| --- | --- | --- |
| profile `security/recon-automation` + `references/bbh-cron-pipeline.md` | `/bounty-tools/references/recon-maintenance-automation.md` already records proposed planner/reviewer/executor/postprocessor gates, candidate confinement, rate, queue, and no-scheduler status; `/recon` owns manual collection. | No duplicate. Defer local tool-specific Arjun/FFUF/Naabu prescriptions and semantic enrichment until an owning implementation/contract is reviewed. Avoid claiming scheduler exists. |
| profile `security/technology-led-bounty-hunt` | `/vulnerability-patch-research` already owns observed-component CVE/diff/target proof; program selection/first-party bounty verification belongs to `program-finder` and scope policies outside BBH. | Defer hosted-product candidate discovery/stack-to-program claims to those owners, not a second BBH target-selection skill. No live CVE campaign. |
| profile `security/static-security-signal-inventories` | `/js-pull` owns acquisition/analyzer; `/js-hunt` owns app-specific interpretation and deep trace. | Migrate distinct per-site signal interpretation, framework-specific search, and acquisition gap accounting into `/js-hunt/references/static-signal-review.md`; no scanner signatures or new CLI. |
| profile `security/scope-aware-recon` + `references/recon-ry-exact-url-queue.md` | `/recon` phase 2 and `/recon-ry` already warn current wrapper only validates hosts, not scheme/port/path, and detached queue is not request containment or aggregate rate guarantee. | Do **not** import the local checklist's claim that `exact-urls` root-only queue is safe or commands with raw identity headers; conflicts with canonical request-level gate. Structured scope pagination is a `pullscope` implementation concern requiring separate evidence/tests. |
| profile `security-coverage-stewardship` | `/coverage` and universal `agents/index.md` already distinguish discovery from assessment, exact evidence links, live vs static stores, and no automatic completed review; `/agent-audit` owns full-run audit. | No new watcher/backfill skill. Historical backfill across shared surface identities and retrospective-vs-contemporaneous adoption require separately scoped store-author review, not broad import. |
| default-profile `bug-bounty/training-lab-operations` + references | `/hunter-loop` already owns authorized disposable-lab completion and per-instance reset; active browser, vault, policy and credential workflows have separate owners. | Defer wholesale import: 727-line mixed benchmark/browser/auth material has duplicated and potentially conflicting browser/proxy fallback and seed handling; review by respective owners before extraction. No lab run. |
| default-profile `bug-bounty/portable-agent-coordination` + `references/portable-task-ledger.md` | `/hunter-loop` and `/hunt-orchestration` already own local Kanban/remote-native logs, leases, bounded packets, MapStore memory and synthesis. | Do not introduce a parallel portable shared task ledger or independent cross-host lock; coordinator-only leases and cross-host artifact storage need owner decision and implementation before promising distributed coordination. |

## Implemented contract

When `/js-hunt` consumes a static signature inventory it routes to an on-demand, BBH-owned reference. The agent distinguishes acquisition gaps from zero hits, individual sites from category counts, observed stack APIs from generic signatures, and review depth from candidate totals. Existing artifact, coverage, Attempts, MapStore and specialist owners remain authoritative. No runtime code changes or activation claim.

## Evidence and review

- Tests: `python3 -m pytest -q tests/test_js_hunt_skill.py tests/test_skill_promotion_routes.py tests/test_skill_triage_routes.py` → 22 passed, 10 subtests passed; `git diff --check` → clean.
- Independent review: parent will review before beta integration; no self-approval claimed.
- Replay/cohort/fixture evidence: prose-route assertions only; no target replay.
- Merge/ancestry evidence: branch from freshly fetched `origin/beta` at base above; parent to re-fetch/reconcile before integration.

## Blockers and deferred work

- **Missing evidence:** signal-analyzer signature and acquisition behavior for new patterns; **command/fixture:** owning `js_analyzer.py` tests plus positive/negative fixtures; **trigger:** a concrete analyzer change is requested; **why:** prose does not authorize altered scanner behavior; **next:** separate analyzer task.
- **Missing evidence:** Recon-Ry exact-origin/path request containment and effective rate across detached projects; **command/fixture:** upstream Recon-Ry and BBH wrapper integration tests; **trigger:** proposing exact-origin automated queue; **why:** host-only guard cannot prove request-level compliance; **next:** upstream tool owner and BBH wrapper task.
- **Missing evidence:** cross-host ledger atomic leases, secret-safe transfer and storage owner; **command/fixture:** no reviewed implementation yet; **trigger:** operator requests multi-host execution; **why:** a Markdown ledger is not distributed locking; **next:** separate coordination design.
- **Missing evidence:** browser/vault/policy compatibility of training-lab sketch; **command/fixture:** isolated fixture review by browser and lab policy owners; **trigger:** explicit lab-methodology migration request; **why:** conflicting fallback or auth guidance could change safety boundary; **next:** owner-specific review.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/local-operational-guidance`
- **Latest immutable recovery checkpoint:** `5a31895a93eb1f80fcb455cac0cadca831ae6330`
- **Feature implementation commit(s):** `5a31895a93eb1f80fcb455cac0cadca831ae6330`
- **Exact resume point:** parent review diff, compare current `origin/beta`, integrate without this temporary dossier, rerun focused tests.
- **Working-tree state at handoff:** clean after dossier-only handoff commit; check branch tip separately from implementation checkpoint.

## Decision gates

- **Integration gate:** parent independent review and current-beta reconciliation; no merge here.
- **Activation / cohort gate:** source beta merge, reviewed publication, sync, fresh runtime load all separate.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-23 — audit completed; only static-inventory application review selected for canonical migration; risky/conflicting drafts deferred.
