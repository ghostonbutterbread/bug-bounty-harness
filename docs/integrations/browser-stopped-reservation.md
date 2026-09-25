# Stopped-profile reservation + offline fixture integration dossier

- **Status:** reconciled fixture-only feature checkpoint; no production consumer or activation
- **Owner / branch:** Hermes bugfix integration / `feat/browser-stopped-reservation`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/browser-stopped-reservation`
- **Reservation base:** fetched `origin/beta` `2d80b03af499a033a0b9a46c87b7e3a4eb61236c`
- **Reconciled beta tip:** fetched `origin/beta` `faa6163a0e7620af91818f05572c69de77bf2a70`, merged without rewriting history as `9efd9c2740cac56742480d4014370051ace2755a` (parents `a4b4ef5`, `faa6163`)
- **Clone-fixture base:** `3a25123903152994b9b431ac668c47ac3ad14e79`
- **Target:** `beta`, not merged or pushed; stable/production not authorized
- **Last updated:** 2026-09-25
- **Recovery checkpoint:** `9efd9c2740cac56742480d4014370051ace2755a` (history-preserving beta reconciliation); the dossier-only checkpoint containing this update is the current branch tip.
- **Implementation history:** reservation `0e943c0`, `71d378d`, `2bad39a`, `6400bb6`, `3f5ca5b7ce4a94069eb92d4ee7b4ae1de8d5d136`; offline helper and native fixture `9dfa0a4b71d15fc580eca97de6a82492e53b1163`, `6dc258c64abc537bab6ac4e4f22405614fd5fd6e`, `c5af3542ea5a2dd9c50a205dfcc3244f2fcd88e3`; integration merge `f5054ed` parents `3f5ca5b`, `c5af354`.
- **Inspiration:** clone branch's offline helper originated from isolated `feat/browser-offline-snapshot` tip `015ff42` (copied, not merged). The clone's original dossier remains as historical branch-local evidence; this is the single active integration handoff. Remove both temporary dossiers only during a future accepted merge cleanup on the beta target, not on this checkpoint.

## Intent and implemented contract

Combine independently reviewed *fixture-only* feasibility and inert reservation history without rewriting either. The canonical SQLite reservation binds exact fixture pool (`fixture`, `fixture.invalid`, `anon`), lease, manager/owner/control generation/root/unit/invocation/CDP and physical inode. Creation verifies stopped/terminal identity and historical physical aliases and serializes with canonical acquisition (`BEGIN IMMEDIATE`). Identical `reserved` retry is idempotent but cannot downgrade `copying` or `uncertain`. Cancellation requires untouched `reserved`, independently re-read manager/canonical/launch/stopped proof, matching unit invocation, exactly one `ActiveState=inactive` and one `LoadState=loaded` in successful systemd output, and matching physical/control identity; unknown, duplicate, malformed, extra, missing or changed evidence retains the fence. Manager `start`, `retire`, `release`, `sweep_rows` and canonical `acquire`, `transfer_managed_lease`, `release` reject the active reservation. No expiry, CLI, copy phase or production activation exists. The existing general `stopped()` interpretation remains unchanged; strict systemd proof is cancellation-only.

The offline helper accepts a proof reader, pins/checks physical source entries and excludes task-proxy/NSS material, but **does not itself provide a manager-held no-restart fence**. The opt-in disposable fixture separately demonstrates browser-native persistent HttpOnly cookie/localStorage success in physically distinct raw and filtered recipients, and probes session-only cookie loss; this is not a supported site/session contract. Raw comparison omits stale Singleton runtime artifacts. No live account, Blue profile, Hoster, real CA or client certificate was used.

## Evidence and review

- Prior independent reviews of reservation checkpoints found retry phase downgrade, incomplete cancellation identity, unit invocation drift, permissive nonzero `is-active`, then duplicate systemd property parsing; `71d378d`, `2bad39a`, `6400bb6`, `3f5ca5b` respectively addressed them. Final independent review approved **only** the inert reservation gate, with 90 focused tests and 41 subtests. The clone fixture's prior independent review approved **only** the controlled Chrome fixture (persistent login copied; session-only cookie lost locally), with 19 tests; neither approval covers integrated beta or production activation.
- Fresh `git fetch origin beta` yielded `2d80b03af499a033a0b9a46c87b7e3a4eb61236c`, already an ancestor of the reservation branch. Clone's three commits were merged `--no-ff` from separate local checkout; no textual conflict. Beta commits between `3a25123` and `2d80b03` include manual-hunter edits, Chromium GPU/launcher updates and a Bounty Core pin; no overlapping clone-fixture file changes, and beta's provisioner change is retained. No rebase or beta worktree modification.
- On 2026-09-25 another fetch confirmed `origin/beta` at `faa6163`; its five unique commits since `2d80b03` change only `skills/waf/SKILL.md` (four added lines). `git merge-tree` and the actual `--no-ff` merge showed no conflict with the browser fixture/provisioner/lease changes. Both parents remain reachable. No beta worktree edit or remote push.
- `python3 -m pytest -q agents/test_browser_stopped_reservation.py agents/test_browser_profile_lease.py agents/test_browser_manager_transfer_gate.py agents/test_browser_provisioner.py agents/test_browser_offline_snapshot.py` — **107 passed, 41 subtests passed** (71.13s).
- `BBH_STOPPED_CLONE_CANARY=1 python3 -m pytest -q -s agents/test_browser_stopped_clone_feasibility.py -k 'persistent-cookie'` — **1 passed, 1 deselected**, 36.49s; raw, filtered, source principals verified; CA trust untested.
- Earlier matching `-k 'session-only-cookie'` failed twice (139.96s: recipient verify `request` returned launch-failed/could not register owned browser; 80.28s: CDP `Page.navigate` timed out while checking an initially empty recipient). Those failures remain unexplained; the negative case did not reach auth comparison in either run. The first `-k persistent_cookie` selected no test (pytest exit 5); use the hyphenated ID.
- On reconciled merge `9efd9c2`, `python3 -m pytest -q agents/test_browser_stopped_reservation.py agents/test_browser_profile_lease.py agents/test_browser_manager_transfer_gate.py agents/test_browser_provisioner.py agents/test_browser_offline_snapshot.py` — **107 passed, 41 subtests passed** (67.03s).
- Serial native receipts on `9efd9c2`: `BBH_STOPPED_CLONE_CANARY=1 python3 -m pytest -q -s agents/test_browser_stopped_clone_feasibility.py -k 'persistent-cookie'` — **1 passed, 1 deselected** (32.03s), `raw=principal; filtered=principal; source=principal; CA trust=untested`; then same command with `-k 'session-only-cookie'` — **1 passed, 1 deselected** (30.70s), `source restart auth=False; raw/filtered recipient /me statuses=[401, 401]; CA trust=untested`. Private startup metadata under scratch `bbh-startup-evidence-r0403l2g` and `bbh-startup-evidence-ym9d35ip` records `fixture_failed=False`, `cleanup_verified=True` for each; profile material not inspected or retained in the dossier. These are local fixture results, not cross-version or real-session proof.
- Independent reviewer approved a fixture-only beta candidate conditional on reconciliation. The reconciled tree's diff and whitespace checks were clean; the final fetch still showed `origin/beta=faa6163` as an ancestor. This task does not integrate it into beta. No production copy consumer has been added.

## Blockers and deferred work

- **Intermittent native startup:** the fresh reconciled negative fixture passed, but the prior recipient registration and CDP navigation failures remain unexplained. Rerun both serial opt-in cases with sanitized private startup metadata on a new host/review cycle; if either fails, diagnose without dumping profile material and block beta integration. One green serial pair does not establish repeatability.
- **Manager-authoritative copy lifecycle:** no proof reader bound to the reservation or `copying`/`uncertain` recovery, durable completion, safe release, or crash/alias-swap race test. Trigger: separately reviewed manager+canonical consumer and disposal protocol; test real disposable browser copy interruption, restart, claim and filesystem alias changes. Without it, never activate production cloning.
- **Trust/session contract:** real CA import/trust, NSS client certificate behavior, browser-version-dependent session-cookie restoration, service workers/IndexedDB, SSO/device binding and site-specific authorization remain untested. Trigger: approved isolated HTTPS/proxy and site-specific fixtures; no claim of general auth portability.
- **Filesystem TOCTOU:** `browser_profile_lease.py` physical resolution and sweep may race alias replacement; an eventual copy consumer must pin/open identity at use and test alias swaps. Gate alone has no copy consumer.

## Interruption / resume handoff

- **Owner:** `feat/browser-stopped-reservation`; **immutable checkpoint:** `9efd9c2740cac56742480d4014370051ace2755a`; dossier-only handoff is committed at tip.
- **Exact resume:** verify fresh beta tip and reconcile again if it advances; inspect the combined diff and conditional review disposition, then decide separately whether fixture-only beta integration is appropriate. No automatic production/activation decision.
- **Working tree:** clean after dossier checkpoint (verify independently).

## Decision gates

- **Integration:** fixture-only candidate after conditional independent review and green reconciled local receipts; final integration decision and fresh beta-tip verification remain pending. No beta merge/push here.
- **Activation/cohort:** prohibited; manager consumer/recovery and site/trust contract absent.
- **Promotion:** prohibited.

## Decision record

- 2026-09-25 — merged reviewed fixture history into reservation feature, preserved fetched beta ancestor; positive native case green, negative case newly red under integrated tree. Keep the feature branch for diagnosis and review.
- 2026-09-25 — merged fresh `faa6163` beta history into feature, reran 107 focused tests/41 subtests and both native cases serially; negative now reaches auth comparison and shows `[401, 401]`. Retain unexplained intermittent startup risk and fixture-only boundary; do not activate or merge/push beta in this task.
