# Bunny context rotation integration dossier

- **Status:** feature
- **Owner:** Hermes (Ryushe request)
- **Branch:** `feat/bunny-context-rotation`
- **Base commit:** `7b419467b08e07e7594a941378b5b7e9c6dd3b89`
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-04 UTC
- **Owning feature branch/ref:** `feat/bunny-context-rotation`
- **Latest immutable recovery checkpoint:** `f7e718f2a1fb774479ffcc74aac6c53d2b4a9e92`
- **Feature implementation commit(s):** `d81553e76a0aefcc1c364f7af98ed2ec2ab278b8`, `3ee424e7217f352e6cfff19db519a0469968e75d`, `bcdb4b54e7543460fba07ea8729a4358de254562`
- **Inspiration / canonical references:** Trello Bunny worker observed seven compactions across revived sessions; `skills/bunny-collaborative/SKILL.md`, `skills/bunny/references/dispatch.md`, `skills/hypothesis-ledger/SKILL.md`.

## Intent

Rotate collaborative hunter/recon workers after two or three native compactions without losing evidence, ownership, budgets, or private continuity. This is a coordinator/worker contract, not a harness-specific automatic monitor. It applies to collaborative mode only; offhand and other roles remain unchanged.

## Implemented contract

At the second observed compaction, prepare a handoff; at the third, finish the current safe checkpoint and rotate to a fresh same-role worker rather than sending another investigative turn. Count native events per worker session across revivals; unknown telemetry must not be treated as zero. Outgoing workers read back their own evidence. The coordinator verifies exact pointers, carries limits and pending ownership, preassigns a successor identity for an explicit private-branch delegation, confirms the old worker's exit, and admits a new worker with a separate Attempt stream. The successor ACKs referenced evidence and limits before receiving the surface. No duplicate evidence or concurrent browser control is implied. This guidance does not interrupt currently running workers and does not modify a model runtime.

## Evidence and review

- Focused tests: the selected beta-worktree venv ran `python -m pytest -q tests/test_bunny_runtime_package.py tests/test_bunny_skill.py tests/test_bunny_agent_sources.py tests/test_security_reporting_skill.py` → 35 passed, 46 subtests passed. Independent reviewer reran the first three → 31 passed, 16 subtests; ledger tests → 10 passed.
- Structural check: `git diff --check` passed; frontmatter and dispatch link inspected.
- Test interpreter `/home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python` resolves the feature's `agents` package and installed Bounty Core revision `6c36ee88a60073e1b687ec32deeade24ffafdd4f`, matching this checkout's pin. A different venv at `~/projects/bug_bounty_harness/bbh-beta-integration/.venv` reports `9968eeb58ca902549097d8941875b0e01cfe0af2`; it was not the selected test interpreter. No dependency change is part of this feature.
- Full suite attempt: root `pytest -q` fails collection on `test_catalog.py` (`bac_checks` absent); `pytest -q agents tests` timed out after 300s with unrelated early failures; `pytest -q -x agents tests` identifies baseline `agents/test_agent_context_routing.py::test_root_instructions_point_to_compact_agent_entry_card` expecting `/hypothesis-ledger` in unchanged `agents/index.md` (44 passed then failure). None is a passing full-suite receipt.
- Independent review: first read-only pass found private-branch ACK, browser-controller handoff, unknown-telemetry churn, and challenge-continuity gaps; those corrections are committed. Second pass found that `delegate` immediately transfers ledger ownership even without pickup ACK; corrected the recovery state and failure path. Final independent pass found no material behavior issues; clarified the venv provenance above.
- Replay/cohort/fixture: a fresh-agent offline policy-comprehension trial correctly distinguished the second/third compaction, private ACK failure, browser ownership, confirmed exit, separate stream, and missing telemetry. It did not create native workers or exercise actual runtime compaction; policy-text tests and the trial do not prove automatic enforcement.
- Merge/ancestry: branch created from fetched `origin/beta` above; not yet integrated.

## Blockers and deferred work

- **Missing test or evidence:** real native compaction→handoff→replacement run with no target traffic, plus a passing full-suite baseline.
- **Command / fixture / environment needed:** an isolated native runner that emits synthetic compaction events and can safely spawn/stop fresh workers; baseline suite setup for unrelated routing assertion.
- **Trigger to run it:** before claiming runtime-enforced rotation or stable promotion, and when a native fixture is available.
- **Why it blocks integration, activation, or promotion:** does not block this reviewed guidance from beta integration; it blocks claims of automatic enforcement and stable promotion. Broad-suite failure is unrelated to the changed files but must be disclosed.
- **Next completion step / successor reference:** integrate reviewed guidance to beta, verify provider resolution, then exercise a native fixture before calling worker replacement automatic.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/bunny-context-rotation`
- **Latest immutable recovery checkpoint:** `f7e718f2a1fb774479ffcc74aac6c53d2b4a9e92`
- **Feature implementation commit(s):** `d81553e76a0aefcc1c364f7af98ed2ec2ab278b8`, `3ee424e7217f352e6cfff19db519a0469968e75d`, `bcdb4b54e7543460fba07ea8729a4358de254562`
- **Exact resume point:** record final decision, integrate this reviewed guidance into beta, then verify provider resolution.
- **Working-tree state at handoff:** dossier-only review receipt pending commit; policy/test tree clean.

## Decision gates

- **Integration gate:** focused checks, alignment with Bunny router/offhand/hypothesis-ledger, independent review, current beta reconciliation.
- **Activation / cohort gate:** selected provider resolves beta content and a fresh worker reads it; live Trello worker is not silently restarted.
- **Promotion gate:** separate explicit owner direction; no main update implied.

## Decision record

- 2026-11-04 — created a feature-branch guidance contract following a Trello audit; no runtime activation yet.
- 2026-11-04 — first independent review identified three medium and two low issues; revised the skill to address the ownership/telemetry/continuity gaps. Awaiting re-review.
- 2026-11-04 — second review identified immediate ledger ownership transfer on `delegate`; corrected the unacknowledged-pickup state and recovery condition. Awaiting final review.
- 2026-11-04 — final independent review found no material behavior issue. Clarified the exact selected test interpreter and bounded offline-trial limitations; accepted for beta guidance integration, not runtime auto-enforcement or stable promotion.
