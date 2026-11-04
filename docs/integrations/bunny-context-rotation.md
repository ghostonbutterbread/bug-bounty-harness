# Bunny context rotation integration dossier

- **Status:** feature
- **Owner:** Hermes (Ryushe request)
- **Branch:** `feat/bunny-context-rotation`
- **Base commit:** `7b419467b08e07e7594a941378b5b7e9c6dd3b89`
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-04 UTC
- **Owning feature branch/ref:** `feat/bunny-context-rotation`
- **Latest immutable recovery checkpoint:** `bcdb4b54e7543460fba07ea8729a4358de254562`
- **Feature implementation commit(s):** `d81553e76a0aefcc1c364f7af98ed2ec2ab278b8`, `3ee424e7217f352e6cfff19db519a0469968e75d`, `bcdb4b54e7543460fba07ea8729a4358de254562`
- **Inspiration / canonical references:** Trello Bunny worker observed seven compactions across revived sessions; `skills/bunny-collaborative/SKILL.md`, `skills/bunny/references/dispatch.md`, `skills/hypothesis-ledger/SKILL.md`.

## Intent

Rotate collaborative hunter/recon workers after two or three native compactions without losing evidence, ownership, budgets, or private continuity. This is a coordinator/worker contract, not a harness-specific automatic monitor. It applies to collaborative mode only; offhand and other roles remain unchanged.

## Implemented contract

At the second observed compaction, prepare a handoff; at the third, finish the current safe checkpoint and rotate to a fresh same-role worker rather than sending another investigative turn. Count native events per worker session across revivals; unknown telemetry must not be treated as zero. Outgoing workers read back their own evidence. The coordinator verifies exact pointers, carries limits and pending ownership, preassigns a successor identity for an explicit private-branch delegation, confirms the old worker's exit, and admits a new worker with a separate Attempt stream. The successor ACKs referenced evidence and limits before receiving the surface. No duplicate evidence or concurrent browser control is implied. This guidance does not interrupt currently running workers and does not modify a model runtime.

## Evidence and review

- Focused tests: `UV_CACHE_DIR=<profile scratch>/uv-cache uv run --no-project --with pytest python -m pytest -q tests/test_bunny_runtime_package.py tests/test_bunny_skill.py tests/test_bunny_agent_sources.py` → 31 passed, 16 subtests passed.
- Structural check: `git diff --check` passed; frontmatter and dispatch link inspected.
- Installed beta venv's Bounty Core revision matches `requirements.txt` pin `6c36ee88a60073e1b687ec32deeade24ffafdd4f`; feature imports resolve from its worktree.
- Full suite attempt: root `pytest -q` fails collection on `test_catalog.py` (`bac_checks` absent); `pytest -q agents tests` timed out after 300s with unrelated early failures; `pytest -q -x agents tests` identifies baseline `agents/test_agent_context_routing.py::test_root_instructions_point_to_compact_agent_entry_card` expecting `/hypothesis-ledger` in unchanged `agents/index.md` (44 passed then failure). None is a passing full-suite receipt.
- Independent review: first read-only pass found private-branch ACK, browser-controller handoff, unknown-telemetry churn, and challenge-continuity gaps; those corrections are committed. Second pass found that `delegate` immediately transfers ledger ownership even without pickup ACK; corrected the recovery state and failure path. Final review pending.
- Replay/cohort/fixture: not yet exercised with fresh agents; policy-text tests do not prove automatic runtime enforcement.
- Merge/ancestry: branch created from fetched `origin/beta` above; not yet integrated.

## Blockers and deferred work

- **Missing test or evidence:** fresh-agent read/compaction→handoff→replacement behavior in an isolated non-target trial; full suite baseline failures.
- **Command / fixture / environment needed:** use an isolated harness trial with synthetic events/owned no-network data; establish a suite baseline on `beta` for unrelated routing assertion.
- **Trigger to run it:** before claiming active behavior or stable promotion; after independent review for integration decision.
- **Why it blocks integration, activation, or promotion:** no automatic enforcement claim is warranted from skill text alone; broad-suite failure is not attributable to this change but must be disclosed.
- **Next completion step / successor reference:** independent review of this branch and its evidence; beta integration only if review accepts the narrow policy contract, then provider-resolution verification.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/bunny-context-rotation`
- **Latest immutable recovery checkpoint:** `bcdb4b54e7543460fba07ea8729a4358de254562`
- **Feature implementation commit(s):** `d81553e76a0aefcc1c364f7af98ed2ec2ab278b8`, `3ee424e7217f352e6cfff19db519a0469968e75d`, `bcdb4b54e7543460fba07ea8729a4358de254562`
- **Exact resume point:** obtain final independent review, reconcile its findings, then decide beta integration.
- **Working-tree state at handoff:** clean after the dossier-only pointer commit.

## Decision gates

- **Integration gate:** focused checks, alignment with Bunny router/offhand/hypothesis-ledger, independent review, current beta reconciliation.
- **Activation / cohort gate:** selected provider resolves beta content and a fresh worker reads it; live Trello worker is not silently restarted.
- **Promotion gate:** separate explicit owner direction; no main update implied.

## Decision record

- 2026-11-04 — created a feature-branch guidance contract following a Trello audit; no runtime activation yet.
- 2026-11-04 — first independent review identified three medium and two low issues; revised the skill to address the ownership/telemetry/continuity gaps. Awaiting re-review.
- 2026-11-04 — second review identified immediate ledger ownership transfer on `delegate`; corrected the unacknowledged-pickup state and recovery condition. Awaiting final review.
