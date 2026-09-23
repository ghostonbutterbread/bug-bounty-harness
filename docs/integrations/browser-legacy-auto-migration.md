# Legacy named-profile auto-slot integration dossier

- **Status:** feature checkpoint; local gates green, independent review pending
- **Owner:** Hermes builder subagent
- **Branch / owning ref:** `feat/browser-legacy-auto-migration`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/browser-legacy-auto-migration`
- **Base commit:** `af9dae91dfbddc0dae90ae17b3c3ed49a5f4a89d` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-23
- **Latest immutable recovery checkpoint:** `0b77bd5eef9390c7f6cfdc92ca057b9636d0edbf`
- **Feature implementation commit(s):** `83433f3ec18ea6eed25ef9bfb247617b98a5a890`, `0b77bd5eef9390c7f6cfdc92ca057b9636d0edbf`
- **Inspiration:** Ordinary Blue same-account/different-browser request; canonical SQLite lease conflict and legacy auth preservation.

## Intent and contract

On ordinary Blue-style requests, a stopped legacy browser is selected first, retaining its existing profile/auth without copying data. The manager requires every historical unkeyed row for that profile stopped, its unit inactive, recorded root/CDP terminal where observable, no SingletonLock and no exact profile process argument; missing launch receipts alone do not veto a genuinely quiescent stopped profile. A failed observable check blocks reuse without deleting the profile. After that first browser is running and healthy, the next owner may obtain a distinct auto slot when capacity and multiple-browser policy allow. Running legacy migration requires exact manager ownership and healthy root. All canonical historical unkeyed leases must match the exact domain/path, with no conflicting active lease. The marker is registered under SQLite `BEGIN IMMEDIATE`; the age sweep protects persistent unkeyed historical profile paths *before* selection (not disposable task-owned profiles). A manager-selected auto slot receives a 120-second one-use proof hashed in SQLite and passed to the lease subprocess via stdin. CLI flags plus a forged manager ID alone cannot confer automatic provenance; transfers retain the recorded provenance. This is a same-UID CLI contract, not a security boundary against arbitrary Python/SQLite access by that user. Legacy auth stays in place; the second profile needs its own authorized auth. Admission rejection does not register migration or acquire a lease.

The marker changes concurrency metadata, not files or credentials. Historical auth/session remains in the original legacy profile only. A second auto slot gets a new separate profile and must establish its own auth via ordinary authorized flow or seed; no live profile copying or concurrent on-disk access. This cannot promise website-level simultaneous sessions or an authenticated second browser.

## Evidence and review

- `python -m pytest -q --tb=short agents/test_browser_legacy_auto.py agents/test_browser_resources.py agents/test_browser_profile_lease.py agents/test_browser_selection.py agents/test_browser_provisioner.py` → **145 passed**. Synthetic Hoster-shaped stopped topology: two rows, absent launch receipt, 20 exact released leases, sweep retention, first legacy owner, second isolated auto; negative unit/profile lock and forged CLI proof/replay.
- `BBH_LOCAL_BROWSER_SMOKE=1 <scratch-venv>/bin/python -m pytest -q --tb=short agents/test_browser_lifecycle_systemd.py` → **3 passed**. Real disposable legacy→auto fixture started two Chromium roots with distinct profiles and legacy-only sentinel, then verified task-owned unit/root/CDP/process cleanup before profile deletion. Existing full lifecycle fixture also passed.
- Earlier heartbeat failure was fixture environment missing `httpx`: `activity_control` silently reported unavailable, watcher intentionally skipped renewal. Installed `pytest`, `websocket-client`, `aiohttp`, `httpx` in a disposable scratch venv; moved heartbeat observation before idle transition with a CDP activity event, without extending its wait. Earlier startup failure likewise lacked `aiohttp` for the pipe bridge. No project dependency declaration changed.
- `git diff --check` → clean. Independent review remains parent-owned. No Hoster mutation, merge, push or live account access.

## Blockers and deferred work

- **Remaining gate:** Parent independent review and Hoster read-only preflight of exact manager/lease/path data before any activation. Local disposable tests cannot establish actual Hoster unit/root/CDP state or last-release health.
- **Safe alternative if Hoster evidence disagrees:** Leave the old profile and exclusivity untouched; require manual inspection or authorized `--recover-profile` for an unhealthy canonical release. Do not synthesize missing launch receipts, reset lease metadata, copy the profile, or use direct CLI `--automatic-instance` to force migration.
- **Trigger:** Review this checkpoint against fetched `beta`, then inspect Hoster read-only. No live rollout in this task.
- **Next:** Parent-owned review/integration and separately authorized Hoster activation. No push, merge or Hoster mutation here.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/browser-legacy-auto-migration`
- **Latest immutable recovery checkpoint:** `d1de5c28327398e3605eccf9f8e029c95ac654da` (implementation and test checkpoint).
- **Feature implementation commit(s):** `83433f3`, `0b77bd5`, `d1de5c28327398e3605eccf9f8e029c95ac654da`.
- **Exact resume point:** Parent independent review against refreshed `beta`, then read-only Hoster preflight; do not mutate live accounts.
- **Working-tree state at handoff:** clean after checkpoint commit.

## Decision gates

- **Integration:** Parent independent review and real disposable fixture, reconcile latest fetched `beta`.
- **Activation:** Separate explicit Hoster rollout under runtime admission safeguards; preserve existing live browsers.
- **Promotion:** Separate owner decision after beta evidence.

## Decision record

- 2026-09-23 — branch-local checkpoint prepared; not integrated or activated.
