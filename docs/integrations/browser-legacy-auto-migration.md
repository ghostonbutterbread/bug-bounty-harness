# Legacy named-profile auto-slot integration dossier

- **Status:** feature; fixture gate blocked
- **Owner:** Hermes builder subagent
- **Branch / owning ref:** `feat/browser-legacy-auto-migration`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/browser-legacy-auto-migration`
- **Base commit:** `af9dae91dfbddc0dae90ae17b3c3ed49a5f4a89d` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-23
- **Latest immutable recovery checkpoint:** pending this branch commit
- **Feature implementation commit(s):** pending
- **Inspiration:** Ordinary Blue same-account/different-browser request; canonical SQLite lease conflict and legacy auth preservation.

## Intent and contract

On a request for the same resolved account/domain, preserve the healthy running legacy owner's exact unkeyed profile and browser. After capacity admission and only under multiple-browser policy, the node-locked provisioner checks the manager projection against the exact active canonical lease, all historical unkeyed lease domains/paths, and legacy disk path; it registers a durable exact-path marker under SQLite `BEGIN IMMEDIATE`. Canonical acquire and transfer transactions exempt *only* the registered manager's `auto-` keyed slot from the matching active unkeyed legacy lock. All other keyed conflicts, explicit/unkeyed callers, a foreign manager, NULL-domain history, changed paths, unknown disk-only profiles, unhealthy/unregistered browsers, and single-browser policy remain conservative. A stopped legacy profile is preferred again when no automatic peer runs. The marker is idempotent; the legacy profile is retained by age sweep. Admission rejection does not register migration or acquire a lease.

The marker changes concurrency metadata, not files or credentials. Historical auth/session remains in the original legacy profile only. A second auto slot gets a new separate profile and must establish its own auth via ordinary authorized flow or seed; no live profile copying or concurrent on-disk access. This cannot promise website-level simultaneous sessions or an authenticated second browser.

## Evidence and review

- `python -m pytest -q agents/test_browser_legacy_auto.py agents/test_browser_resources.py agents/test_browser_profile_lease.py agents/test_browser_selection.py agents/test_browser_provisioner.py` → **142 passed** (final source state before dossier).
- `python -m pytest -rsq agents/test_browser_lifecycle_systemd.py` → one path check passed, real browser fixture skipped (opt-in).
- `BBH_LOCAL_BROWSER_SMOKE=1 <scratch-venv>/bin/python -m pytest -q agents/test_browser_lifecycle_systemd.py -k test_systemd_lifecycle_fixture` → failed at existing heartbeat assertion after successfully starting two isolated disposable browsers, distinct profiles/panes, and CDP evaluation. First attempt without scratch venv failed on missing `websocket-client`. Fixture teardown initially reported unverified root; exact recorded PIDs later absent, units inactive, CDP port closed, then disposable fixture root removed. Private evidence retained under scratch `bbh-startup-evidence-4dj8gurf`. Do not construe this as a green end-to-end migration test.
- `git diff --check` → clean.
- Independent review: pending parent reviewer.
- Feature/base comparison: worktree started clean at fetched `origin/beta` `af9dae9`.

## Blockers and deferred work

- **Missing evidence:** Disposable real browser *legacy-to-auto* two-request smoke, including canonical marker/path, exact retained legacy profile and auth sentinel, second isolated profile, release and endpoint/root verification. Existing opt-in fixture does not seed a legacy browser and currently fails its unrelated heartbeat assertion.
- **Command / fixture:** Extend the existing `agents/test_browser_lifecycle_systemd.py` disposable fixture (short physical scratch directory, task-owned systemd units, loopback-only content, exact cleanup); run with `BBH_LOCAL_BROWSER_SMOKE=1` in an environment with its test dependencies. Do not target live accounts or copy real profiles.
- **Trigger:** Parent review before integration/Hoster activation, after heartbeat fixture condition is diagnosed or isolated.
- **Why it blocks:** Deterministic SQLite/manager tests prove routing and policy; not actual Chromium startup and account-preserving two-browser lifecycle on intended host.
- **Next:** Independent diff review, disposable fixture fix/extension, then parent-owned integration/deployment decision. No push, merge, or Hoster activation here.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/browser-legacy-auto-migration`
- **Latest immutable recovery checkpoint:** pending commit; parent should read branch HEAD.
- **Feature implementation commit(s):** pending commit.
- **Exact resume point:** Review canonical conflict and manager marker semantics; run a disposable real migration fixture and inspect Hoster readiness without touching live accounts.
- **Working-tree state at handoff:** expected clean after commit.

## Decision gates

- **Integration:** Parent independent review and real disposable fixture, reconcile latest fetched `beta`.
- **Activation:** Separate explicit Hoster rollout under runtime admission safeguards; preserve existing live browsers.
- **Promotion:** Separate owner decision after beta evidence.

## Decision record

- 2026-09-23 — branch-local checkpoint prepared; not integrated or activated.
