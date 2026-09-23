# Legacy named-profile auto-slot integration dossier

- **Status:** running-history reviewer blocker repaired and locally tested; independent re-review pending
- **Owner:** Hermes builder subagent
- **Branch / owning ref:** `feat/browser-legacy-auto-migration`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/browser-legacy-auto-migration`
- **Base commit:** `af9dae91dfbddc0dae90ae17b3c3ed49a5f4a89d` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-23
- **Previous immutable recovery checkpoint:** `cad9e5e` (stopped-path repair); running-history repair is the next feature checkpoint, verify with `git rev-parse HEAD`.
- **Feature implementation commit(s):** `83433f3`, `0b77bd5`, `d1de5c2`, `cad9e5e`; running-history gate at current feature tip.
- **Inspiration:** Ordinary Blue same-account/different-browser request; canonical SQLite lease conflict and legacy auth preservation.

## Intent and contract

On ordinary Blue-style requests, a stopped legacy browser is selected first, retaining its existing profile/auth without copying data. The manager requires every historical unkeyed row for that profile stopped, its unit inactive, recorded root/CDP terminal where observable, no SingletonLock and no exact profile process argument; missing launch receipts alone do not veto a genuinely quiescent stopped profile. A failed observable check blocks reuse without deleting the profile. After that first browser is running and healthy, the next owner may obtain a distinct auto slot when capacity and multiple-browser policy allow. Running legacy migration requires exact manager ownership and healthy root. All canonical historical unkeyed leases must match the exact domain/path, with no conflicting active lease. The marker is registered under SQLite `BEGIN IMMEDIATE`; the age sweep protects persistent unkeyed historical profile paths *before* selection (not disposable task-owned profiles). A manager-selected auto slot receives a 120-second one-use proof hashed in SQLite and passed to the lease subprocess via stdin. CLI flags plus a forged manager ID alone cannot confer automatic provenance; transfers retain the recorded provenance. This is a same-UID CLI contract, not a security boundary against arbitrary Python/SQLite access by that user. Legacy auth stays in place; the second profile needs its own authorized auth. Admission rejection does not register migration or acquire a lease.

The stopped first request now passes its manager row's lease ID, profile path, and former owner identity into canonical acquisition. Under the acquisition transaction, canonical history must identify that released lease with the same manager, domain, owner, and path; **every** historical unkeyed row for the account/domain must agree, including no null-domain ambiguity. The only accepted inherited path shapes are the canonical domain path and the historical pre-domain `<program>/web/browser-profiles/<alias>` path. No argument alone selects a path: a mismatch fails closed. The inherited path is stored on the new lease and used directly by Chromium, with no cookie copy, profile move, or auth material read. Active leases still arbitrate before inheritance, and the single-browser policy still blocks parallel auto slots.

The marker changes concurrency metadata, not files or credentials. Historical auth/session remains in the original legacy profile only. A second auto slot gets a new separate profile and must establish its own auth via ordinary authorized flow or seed; no live profile copying or concurrent on-disk access. This cannot promise website-level simultaneous sessions or an authenticated second browser.

Before registering a marker, selection now reconciles **every** historical unkeyed manager row, not only the latest row and canonical leases: all must refer to the selected legacy profile path, and any non-selected row must be stopped. A historical stopped former owner on that same path is valid; an older running different owner/run or stopped conflicting path blocks automatic migration without inserting the marker. Canonical SQLite still checks exact selected lease identity, ownership, manager, and complete canonical unkeyed history transactionally. Node-locked manager commands serialize selection against manager mutations; canonical acquisition remains the arbiter for racing peer claims.

## Evidence and review

- `python -m pytest -q --tb=short agents/test_browser_legacy_auto.py agents/test_browser_resources.py agents/test_browser_profile_lease.py agents/test_browser_selection.py agents/test_browser_provisioner.py` → **145 passed**. Synthetic Hoster-shaped stopped topology: two rows, absent launch receipt, 20 exact released leases, sweep retention, first legacy owner, second isolated auto; negative unit/profile lock and forged CLI proof/replay.
- `BBH_LOCAL_BROWSER_SMOKE=1 <scratch-venv>/bin/python -m pytest -q --tb=short agents/test_browser_lifecycle_systemd.py` → **3 passed**. Real disposable legacy→auto fixture started two Chromium roots with distinct profiles and legacy-only sentinel, then verified task-owned unit/root/CDP/process cleanup before profile deletion. Existing full lifecycle fixture also passed.
- Earlier heartbeat failure was fixture environment missing `httpx`: `activity_control` silently reported unavailable, watcher intentionally skipped renewal. Installed `pytest`, `websocket-client`, `aiohttp`, `httpx` in a disposable scratch venv; moved heartbeat observation before idle transition with a CDP activity event, without extending its wait. Earlier startup failure likewise lacked `aiohttp` for the pipe bridge. No project dependency declaration changed.
- `git diff --check` → clean. Independent review remains parent-owned. No Hoster mutation, merge, push or live account access.
- Repair rerun: `python -m pytest -q agents/test_browser_legacy_auto.py agents/test_browser_resources.py agents/test_browser_profile_lease.py agents/test_browser_selection.py agents/test_browser_provisioner.py` → **152 passed**. Seven new pre-domain scenarios cover exact first/second paths and conflicting history, null domain, wrong manager/owner, arbitrary path, and active conflict.
- `BBH_LOCAL_BROWSER_SMOKE=1 "$TMPDIR/browser-smoke-venv/bin/python" -m pytest -q agents/test_browser_lifecycle_systemd.py` → **3 passed**. The stopped legacy fixture now uses a real pre-domain profile, asserts first managed Chromium row still points to it, second row points elsewhere, sentinel stays in the original, and fixture units/roots/CDP are stopped before root removal. Initial default-interpreter full-fixture attempt had **1 failed, 2 passed** because `websocket` was absent; the disposable scratch venv (`pytest`, `websocket-client`, `aiohttp`, `httpx`) supplied fixture dependencies. Single pre-domain smoke also passed independently before this full run.
- Bounded reference impact: `browser_profile_lease.py` owns canonical acquired `profile_dir`; `browser_provisioner.py` owns stopped-row selection and CLI handoff. `chromium_test.py` retains direct standalone pre-domain and ephemeral defaults, but managed launches pass the acquired explicit profile path; its defaults are not selected here. Sweep recognizes both shapes. Existing README guidance remains compatible: new managed profiles still use domain directories; only verified historical stopped rows inherit pre-domain paths.
- Reviewer repros at `cad9e5e`: older running different-owner and older stopped conflicting-path manager rows both incorrectly yielded an auto key and marker despite exact canonical history. New parameterized negatives also cover older running same-agent/different-run identity and assert no marker or auto acquisition; all three failed before the repair and pass afterward. A stopped former owner on the same path remains allowed. Existing canonical two-contender race regression remains in `test_canonical_race_and_legacy_old_api_stay_exclusive`.
- Final `python -m pytest -q --tb=short agents/test_browser_legacy_auto.py agents/test_browser_resources.py agents/test_browser_profile_lease.py agents/test_browser_selection.py agents/test_browser_provisioner.py` → **156 passed** after the final gate edit; `git diff --check` clean. `BBH_LOCAL_BROWSER_SMOKE=1 /home/ryushe/.hermes/profiles/bugfix/cache/scratch/browser-smoke-venv/bin/python -m pytest -q --tb=short agents/test_browser_lifecycle_systemd.py` → **3 passed** with disposable Chromium/systemd fixtures before the final non-selected-state simplification. A subsequent full rerun was **2 passed, 1 failed**: `test_systemd_lifecycle_fixture` hit `sqlite3.OperationalError: database is locked` while polling task cleanup. No browser units/processes remained in a post-failure check; a targeted rerun of that test after the final edit → **1 passed**. Treat the intermittent fixture lock as review evidence, not a production gate failure or a claimed clean full rerun. Fixture teardown verifies units inactive/failed and process termination before removing test roots. Initial scratch venv lacked pytest; installed pytest/aiohttp/httpx/websocket-client in scratch, no repository dependency change. No Hoster mutation.

## Blockers and deferred work

- **Remaining gate:** Parent independent re-review and Hoster read-only preflight of exact manager/lease/path data before any activation. Local disposable tests cannot establish actual Hoster unit/root/CDP state or last-release health. This repair does not mutate Hoster, merge, or push.
- **Safe alternative if Hoster evidence disagrees:** Leave the old profile and exclusivity untouched; require manual inspection or authorized `--recover-profile` for an unhealthy canonical release. Do not synthesize missing launch receipts, reset lease metadata, copy the profile, or use direct CLI `--automatic-instance` to force migration.
- **Trigger:** Review this checkpoint against fetched `beta`, then inspect Hoster read-only. No live rollout in this task.
- **Next:** Parent-owned review/integration and separately authorized Hoster activation. No push, merge or Hoster mutation here.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/browser-legacy-auto-migration`
- **Previous immutable recovery checkpoint:** `cad9e5e` (before running-history repair); review current feature tip for the committed repair.
- **Feature implementation commit(s):** `83433f3`, `0b77bd5`, `d1de5c2`, `cad9e5e`, current feature tip (running-history repair).
- **Exact resume point:** Parent independent re-review against refreshed `beta`, then read-only Hoster preflight; do not mutate live accounts.
- **Working-tree state at handoff:** verify `git status --short` after repair commit.

## Decision gates

- **Integration:** Parent independent review and real disposable fixture, reconcile latest fetched `beta`.
- **Activation:** Separate explicit Hoster rollout under runtime admission safeguards; preserve existing live browsers.
- **Promotion:** Separate owner decision after beta evidence.

## Decision record

- 2026-09-23 — branch-local checkpoint prepared; not integrated or activated.
