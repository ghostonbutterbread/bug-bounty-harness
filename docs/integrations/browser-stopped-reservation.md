# Stopped-profile reservation + offline fixture integration dossier

- **Status:** blocked feature checkpoint; fixture-only, no production consumer
- **Owner / branch:** Hermes bugfix integration / `feat/browser-stopped-reservation`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/browser-stopped-reservation`
- **Reservation base:** fetched `origin/beta` `2d80b03af499a033a0b9a46c87b7e3a4eb61236c`
- **Clone-fixture base:** `3a25123903152994b9b431ac668c47ac3ad14e79`
- **Target:** `beta`, not merged or pushed; stable/production not authorized
- **Last updated:** 2026-09-25
- **Recovery checkpoint:** `f5054edef7559453e73a48b793ebb090c25115bf` (two-parent fixture merge); the dossier-only checkpoint containing this update is the current branch tip.
- **Implementation history:** reservation `0e943c0`, `71d378d`, `2bad39a`, `6400bb6`, `3f5ca5b7ce4a94069eb92d4ee7b4ae1de8d5d136`; offline helper and native fixture `9dfa0a4b71d15fc580eca97de6a82492e53b1163`, `6dc258c64abc537bab6ac4e4f22405614fd5fd6e`, `c5af3542ea5a2dd9c50a205dfcc3244f2fcd88e3`; integration merge `f5054ed` parents `3f5ca5b`, `c5af354`.
- **Inspiration:** clone branch's offline helper originated from isolated `feat/browser-offline-snapshot` tip `015ff42` (copied, not merged). The clone's original dossier remains as historical branch-local evidence; this is the single active integration handoff. Remove both temporary dossiers only during a future accepted merge cleanup on the beta target, not on this checkpoint.

## Intent and implemented contract

Combine independently reviewed *fixture-only* feasibility and inert reservation history without rewriting either. The canonical SQLite reservation binds exact fixture pool (`fixture`, `fixture.invalid`, `anon`), lease, manager/owner/control generation/root/unit/invocation/CDP and physical inode. Creation verifies stopped/terminal identity and historical physical aliases and serializes with canonical acquisition (`BEGIN IMMEDIATE`). Identical `reserved` retry is idempotent but cannot downgrade `copying` or `uncertain`. Cancellation requires untouched `reserved`, independently re-read manager/canonical/launch/stopped proof, matching unit invocation, exactly one `ActiveState=inactive` and one `LoadState=loaded` in successful systemd output, and matching physical/control identity; unknown, duplicate, malformed, extra, missing or changed evidence retains the fence. Manager `start`, `retire`, `release`, `sweep_rows` and canonical `acquire`, `transfer_managed_lease`, `release` reject the active reservation. No expiry, CLI, copy phase or production activation exists. The existing general `stopped()` interpretation remains unchanged; strict systemd proof is cancellation-only.

The offline helper accepts a proof reader, pins/checks physical source entries and excludes task-proxy/NSS material, but **does not itself provide a manager-held no-restart fence**. The opt-in disposable fixture separately demonstrates browser-native persistent HttpOnly cookie/localStorage success in physically distinct raw and filtered recipients, and probes session-only cookie loss; this is not a supported site/session contract. Raw comparison omits stale Singleton runtime artifacts. No live account, Blue profile, Hoster, real CA or client certificate was used.

## Evidence and review

- Prior independent reviews of reservation checkpoints found retry phase downgrade, incomplete cancellation identity, unit invocation drift, permissive nonzero `is-active`, then duplicate systemd property parsing; `71d378d`, `2bad39a`, `6400bb6`, `3f5ca5b` respectively addressed them. Final independent review approved **only** the inert reservation gate, with 90 focused tests and 41 subtests. The clone fixture's prior independent review approved **only** the controlled Chrome fixture (persistent login copied; session-only cookie lost locally), with 19 tests; neither approval covers integrated beta or production activation.
- Fresh `git fetch origin beta` yielded `2d80b03af499a033a0b9a46c87b7e3a4eb61236c`, already an ancestor of the reservation branch. Clone's three commits were merged `--no-ff` from separate local checkout; no textual conflict. Beta commits between `3a25123` and `2d80b03` include manual-hunter edits, Chromium GPU/launcher updates and a Bounty Core pin; no overlapping clone-fixture file changes, and beta's provisioner change is retained. No rebase or beta worktree modification.
- `python3 -m pytest -q agents/test_browser_stopped_reservation.py agents/test_browser_profile_lease.py agents/test_browser_manager_transfer_gate.py agents/test_browser_provisioner.py agents/test_browser_offline_snapshot.py` — **107 passed, 41 subtests passed** (71.13s).
- `BBH_STOPPED_CLONE_CANARY=1 python3 -m pytest -q -s agents/test_browser_stopped_clone_feasibility.py -k 'persistent-cookie'` — **1 passed, 1 deselected**, 36.49s; raw, filtered, source principals verified; CA trust untested.
- Matching `-k 'session-only-cookie'` — **failed twice** (139.96s: recipient verify `request` returned launch-failed/could not register owned browser; 80.28s: CDP `Page.navigate` timed out while checking an initially empty recipient). The negative case did not reach its auth comparison in either fresh run. The first `-k persistent_cookie` selected no test (pytest exit 5); corrected to the actual hyphenated ID above. Prior clone-branch receipts remain evidence but do not substitute for a green integrated negative run.
- `git diff --check origin/beta...HEAD` was clean after the merge. Review staged dossier and final diff/secret scan before this checkpoint; no production copy consumer has been added.

## Blockers and deferred work

- **Fresh integrated negative fixture:** rerun the session-only opt-in fixture in a stable disposable local Chrome environment; diagnose bounded provisioner registration/CDP navigation failures using sanitized private startup metadata, never dump profile material. Trigger: host/native fixture readiness and a new integration review; command above with `-k 'session-only-cookie'`. Failure blocks a passing combined native receipt and beta integration decision.
- **Manager-authoritative copy lifecycle:** no proof reader bound to the reservation or `copying`/`uncertain` recovery, durable completion, safe release, or crash/alias-swap race test. Trigger: separately reviewed manager+canonical consumer and disposal protocol; test real disposable browser copy interruption, restart, claim and filesystem alias changes. Without it, never activate production cloning.
- **Trust/session contract:** real CA import/trust, NSS client certificate behavior, browser-version-dependent session-cookie restoration, service workers/IndexedDB, SSO/device binding and site-specific authorization remain untested. Trigger: approved isolated HTTPS/proxy and site-specific fixtures; no claim of general auth portability.
- **Filesystem TOCTOU:** `browser_profile_lease.py` physical resolution and sweep may race alias replacement; an eventual copy consumer must pin/open identity at use and test alias swaps. Gate alone has no copy consumer.

## Interruption / resume handoff

- **Owner:** `feat/browser-stopped-reservation`; **immutable checkpoint:** `f5054edef7559453e73a48b793ebb090c25115bf`; dossier-only handoff is committed at tip.
- **Exact resume:** investigate the failed integrated session-only native fixture, get independent review of combined diff and blocker disposition, then decide whether a fixture-only beta integration is appropriate. No automatic production/activation decision.
- **Working tree:** clean after dossier checkpoint (verify independently).

## Decision gates

- **Integration:** blocked pending fresh negative native fixture and combined review; no beta merge/push here.
- **Activation/cohort:** prohibited; manager consumer/recovery and site/trust contract absent.
- **Promotion:** prohibited.

## Decision record

- 2026-09-25 — merged reviewed fixture history into reservation feature, preserved fetched beta ancestor; positive native case green, negative case newly red under integrated tree. Keep the feature branch for diagnosis and review.
