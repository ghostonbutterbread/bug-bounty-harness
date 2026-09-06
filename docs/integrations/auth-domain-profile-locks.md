# Auth-domain profile locks integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `bug-bounty-harness/t_778adcb3-scope-persistent-auth-profile-locks-by-a`
- **Base commit:** `86db5055db1adfa13a45b7561a4b4644a881aaa4`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-06
- **Owning feature branch/ref:** `bug-bounty-harness/t_778adcb3-scope-persistent-auth-profile-locks-by-a`
- **Latest immutable recovery checkpoint:** `e591cae54981cb006a52ae01b2e349e5c42d3003` (implementation; the current tip will add this reviewed follow-up)
- **Feature implementation commit(s):** `e591cae54981cb006a52ae01b2e349e5c42d3003`
- **Inspiration / canonical references:** Discord thread `1546236602806964244`; `browser_profile_lease.py`; `browser_provisioner.py`

## Intent

Stop an active persistent browser lease for a color/account on one auth domain from blocking an independently authenticated domain. Preserve mutual exclusion for the same program, account, and auth domain without exposing session material or permitting automatic account substitution.

## Implemented contract

- `browser_profile_lease.py` accepts optional `--auth-domain` for `status` and `acquire`.
- A new lease is scoped to program, normalized auth domain, and resolved account; its persistent profile path includes the auth domain.
- With no explicit domain, the lease uses the account inventory's `auth_host_filter`; inventories without one retain the `legacy-global` scope.
- Existing lease rows that predate the new column have `NULL` `auth_domain`; an active such row safely blocks every requested domain for that account until released.
- `browser_provisioner.py` forwards `--auth-domain`, uses the lease-returned profile path, separates its browser records by domain, and accepts the resulting nested profile directory for bounded cleanup.
- Account selection, release ownership, profile-health gating, and secret redaction remain unchanged.

## Evidence and review

- Tests and commands: `python3 -m py_compile skills/chromium-test/scripts/browser_profile_lease.py skills/chromium-test/scripts/browser_provisioner.py`; `PYTHONPATH=. python3 -m pytest agents/test_browser_profile_lease.py agents/test_browser_provisioner.py -q` — 32 passed; `git diff --check`.
- Independent review: reviewer identified two high-severity domain-propagation gaps (status preflight and omitted-domain provisioner reuse). Both were fixed with focused regressions; no unresolved review findings remain.
- Replay/cohort/fixture evidence: focused temporary SQLite/inventory fixtures cover distinct-domain concurrency, legacy active migration fencing, provisioner forwarding, and nested-profile cleanup.
- Merge/ancestry evidence: branch is based on beta commit `86db5055db1adfa13a45b7561a4b4644a881aaa4`.

## Blockers and deferred work

- **Missing test or evidence:** no Hoster runtime invocation against the existing local lease database.
- **Command / fixture / environment needed:** Hoster profile host with a non-destructive status/acquire smoke using a test account and no concurrent production browser owner.
- **Trigger to run it:** before runtime activation on Hoster.
- **Why it blocks integration, activation, or promotion:** it does not block beta integration; runtime activation must confirm the installed source and migration behavior on the actual profile host.
- **Next completion step / successor reference:** activate the reviewed beta commit only after the profile-host smoke succeeds.

## Interruption / resume handoff

- **Owning feature branch/ref:** `bug-bounty-harness/t_778adcb3-scope-persistent-auth-profile-locks-by-a`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** apply independent-review findings, update this dossier with commit/test receipts, then merge into clean beta and remove this dossier from beta.
- **Working-tree state at handoff:** intentionally uncommitted (implementation and dossier awaiting review).

## Decision gates

- **Integration gate:** focused tests, syntax checks, diff check, and an independent review without unresolved material findings.
- **Activation / cohort gate:** actual profile host uses the integrated beta commit and passes a non-destructive domain-scoped smoke.
- **Promotion gate:** explicit Ryushe decision to promote beta to stable.

## Decision record

- 2026-09-06 — created and implemented auth-domain-scoped profile locks; focused test suite green; independent review pending.
