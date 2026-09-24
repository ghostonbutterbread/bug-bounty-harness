# Browser auth transfer authorization fence integration dossier

- **Status:** blocked foundation, not an activated transfer
- **Owner:** Hermes isolated coding subagent
- **Branch:** `feat/browser-auth-transfer-fence`
- **Base commit:** `313b2e8` (`origin/beta` fetched)
- **Intended integration target:** `beta`; no merge or push authorized here
- **Owning feature branch/ref:** `feat/browser-auth-transfer-fence`
- **Latest immutable recovery checkpoint:** see committed branch tip at handoff
- **Feature implementation commit(s):** see committed branch tip at handoff
- **Inspiration:** `browser-auth-transfer-attestation-review/docs/browser-auth-transfer-blocker.md` (`774edea`); `docs/browser-auth-clone-pool-spec.md` in the predecessor branch

## Intent and implemented contract

Canonical SQLite lease ownership is the only transaction boundary currently shared with low-level handoff and release. Added private `browser_transfer_identity` and `browser_transfer_grants` tables to the canonical DB; old rows do not acquire guessed attestation. `issue_transfer_grant(db_path, source, destination, ttl_seconds=30)` and `consume_transfer_grant(db_path, grant_id, source, destination)` are Python-only functions in `browser_profile_lease.py`, not CLI or HTTP routes. Both use `BEGIN IMMEDIATE`; grant is one-use, short-lived, mismatch burns it. A grant binds exact program/domain/account, both lease/owner/run/manager/profile paths, service units, process start/root, physical profile identities, and control/auth generations. Source/destination roots and physical profiles must differ. `revoke_transfer_identity(db_path, lease_id)` invalidates outstanding grants and private attestation. Canonical handoff and release revoke in their own transaction; provisioner revokes before both control rotation sites while holding node lock. Canonical row changes at redemption also deny, even if a revocation caller is missing.

**Critical trust limitation:** identity arguments are *not* proof and must never be accepted from an adapter, CLI, caller, or `/identity`. There is deliberately no production writer for the private identity rows, because neither the existing adapter nor the manager can currently attest auth generation and physical process/profile identity atomically. Only tests construct synthetic rows. All existing/normal browser rows fail closed. These functions are a private manager-bound contract for a successor manager integration, not a usable cross-process clone grant. A successful redemption is only a fence result at that instant; it is not authorization for asynchronous export or destination commit without new manager-controlled rechecks/fencing. No auth payload, cookie, localStorage, or public export/import route was added.

## Evidence and review

- RED: `python -m pytest agents/test_browser_auth_fence.py -q` failed with missing grant API before implementation (32 failures).
- GREEN: `python -m pytest agents/test_browser_auth_fence.py -q --tb=short` → 35 passed. Synthetic private-attestation fixtures cover legacy un-attested denial, one-use, 26 source/destination field mismatches, actual canonical handoff/release, status/generation invalidation, concurrent double redemption and handoff/redemption ordering.
- Existing suites: `python -m pytest agents/test_browser_profile_lease.py -q` → 18 passed; `python -m pytest agents/test_browser_provisioner.py -q` → 39 passed.
- Earlier combined suite attempt and one focused rerun timed out under simultaneous system load; subsequent separate receipts above succeeded.
- Independent review: not yet performed. No live Hoster/account mutation.

## Blockers and deferred work

- **Missing evidence:** trustworthy generation writer tied to adapter auth changes and control rotation, manager-derived live process/root/physical-profile verification, atomic source export/destination commit fences and browser-native app check. **Trigger:** successor adapter/manager implementation available. **Gate:** without it, no real row is eligible, no transfer endpoint is safe.
- **Missing test:** deterministic transfer-vs-handoff/release and rotation-vs-transfer race with actual manager row and adapter, plus disposable two-Chrome fixture and independent trust-boundary review. **Command/fixture:** successor focused integration suite and isolated two-Chrome fixture, not live Hoster. **Gate:** no beta integration/activation or pool claim on this checkpoint alone.
- **Missing integration receipt:** combined `python -m pytest agents/test_browser_auth_fence.py agents/test_browser_profile_lease.py agents/test_browser_provisioner.py -q` timed out under load; the three components passed separately. Re-run the combined suite before independent review if host contention clears.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/browser-auth-transfer-fence`
- **Latest immutable recovery checkpoint:** committed branch tip; report SHA in handoff
- **Exact resume point:** independent review and successor manager attestation design; rerun broad suite first.
- **Working-tree state at handoff:** intended clean committed checkpoint.

## Decision gates

- **Integration:** blocked pending complete regression and independent review; no beta merge.
- **Activation:** blocked until trusted live attestation and export/import transaction with fixture evidence.
- **Promotion:** separate explicit owner decision.

## Decision record

- 2026-09-24 — fail-closed authorization foundation only; no public transfer capability.
