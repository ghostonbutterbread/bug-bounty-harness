# Browser auth transfer authorization fence integration dossier

## Descendant checkpoint: manager attestation gate (not issuance)

- **Owning branch/worktree:** `feat/browser-auth-manager-attestation` at `browser-auth-manager-attestation`, descended from `feat/browser-auth-transfer-fence` `0f8deb3`; intended merge-back target is the fence feature branch, then separately reviewed `beta`. `origin/beta` was fetched and is at `7690fc0`; no beta merge/push or runtime activation was authorized.
- **Decision:** issuance is **not feasible** with the present architecture. The Unix `/identity` reports a process and CDP availability, not control generation or authenticated application state. `auth_resolver.run_auth_check` uses a separate HTTP cookie jar and seed, not the selected Chromium profile. Neither can mint a browser auth generation. The manager also has no authenticated profile-change notification. Old rows and newly launched rows remain without `browser_transfer_identity`.
- **Implemented gate:** private Python `browser_provisioner.manager_transfer_attestation_gate(source_lease_id, destination_lease_id)` takes only lease selectors (never caller-supplied identities). Under the node lock and canonical `BEGIN IMMEDIATE`, it requires exact live manager/canonical owner, program/domain/account, lease/profile/unit/CDP, active unit invocation, process PID/start/boot/node receipt, pipe-fenced mode, CDP health, and distinct physical profile identities. It returns only `auth-clone-unavailable` with a bounded non-secret reason; even a fully matched pair returns `attestation-hook-unavailable`. It does **not** write an identity, generation, or grant, and is not wired to CLI/HTTP/adapter.
- **Required successor interface before any writer:** a manager-owned, app-specific verification hook must run through the exact fenced browser and return a non-secret verified principal/domain result bound to the live adapter control generation and process/profile identity; the hook must identify which app auth transitions invalidate that generation, including logout, refresh, external profile mutation and manual UI changes. The manager must derive (not accept from the caller) the control generation from a trustworthy adapter source, bind it with process start/root/unit invocation and profile `(st_dev, st_ino)` under the node lock and canonical write transaction, and revoke on rotation/handoff/release/auth change. Before grant issuance or redemption, recheck live identities and generation; export/destination commit require their own synchronous fences. Do not use `auth_resolver` seed success or `/identity` availability as the hook. A separate ownership boundary is needed if untrusted local callers can write the canonical SQLite DB directly.
- **Evidence:** RED `python -m pytest agents/test_browser_manager_transfer_gate.py -q --tb=short` → four failures for missing manager gate; GREEN combined `python -m pytest agents/test_browser_manager_transfer_gate.py agents/test_browser_auth_fence.py agents/test_browser_profile_lease.py agents/test_browser_provisioner.py -q --tb=short` → 100 passed. Synthetic fixtures only; tests cover no self-attestation/receipt leakage, old/mismatched rows, handoff/release/rotation, missing/replaced manager/process/profile/CDP, and node-lock ownership race. No Hoster/account action.
- **Recovery checkpoint:** `a88d652934c21625274a2fd992bc7f71f44ce4b2` (implementation, tests, dossier); resume at app-native hook contract and independent review. Working tree clean at checkpoint.
- **Deferred verification:** implement and test the concrete app-native hook and generation invalidation, then rerun the combined command and an isolated two-Chrome fixture; independently review the full manager→canonical→adapter path before any beta integration. No export/import endpoint or live grant writer exists. This branch is a blocked, unactivated checkpoint.

- **Status:** blocked foundation, not an activated transfer
- **Owner:** Hermes isolated coding subagent
- **Branch:** `feat/browser-auth-transfer-fence`
- **Base commit:** `313b2e8` (`origin/beta` fetched)
- **Intended integration target:** `beta`; no merge or push authorized here
- **Owning feature branch/ref:** `feat/browser-auth-transfer-fence`
- **Latest immutable recovery checkpoint:** `8661c9b3f484f01b6c6152af1498e0db2063a927`
- **Feature implementation commit(s):** `8661c9b3f484f01b6c6152af1498e0db2063a927`
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
- **Prior checkpoint integration receipt:** predecessor combined run timed out under load; descendant combined suite passed (100 tests), as recorded above.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/browser-auth-transfer-fence`
- **Latest immutable recovery checkpoint:** `8661c9b3f484f01b6c6152af1498e0db2063a927` (implementation)
- **Feature implementation commit(s):** `8661c9b3f484f01b6c6152af1498e0db2063a927`
- **Exact resume point:** independent review and successor manager attestation design; rerun combined suite if host contention clears.
- **Working-tree state at handoff:** clean committed checkpoint.

## Decision gates

- **Integration:** blocked pending complete regression and independent review; no beta merge.
- **Activation:** blocked until trusted live attestation and export/import transaction with fixture evidence.
- **Promotion:** separate explicit owner decision.

## Decision record

- 2026-09-24 — fail-closed authorization foundation only; no public transfer capability.
