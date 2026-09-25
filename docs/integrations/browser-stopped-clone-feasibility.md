# Stopped-profile cloning feasibility — branch-local dossier

- **Status:** experiment; no production wiring or integration approval
- **Owner:** Hermes disposable browser fixture
- **Branch / worktree:** `feat/browser-stopped-clone-feasibility` / `browser-stopped-clone-feasibility`
- **Base commit:** `3a25123903152994b9b431ac668c47ac3ad14e79` (fetched `origin/beta`)
- **Intended integration target:** `beta`, only after separate review and decision; no merge/push authorized here
- **Last updated:** 2026-09-25
- **Owning feature branch/ref:** `feat/browser-stopped-clone-feasibility`
- **Latest immutable prior checkpoint:** `6dc258c64abc537bab6ac4e4f22405614fd5fd6e`; current negative-test checkpoint is this dossier's containing commit
- **Feature implementation commit(s):** `9dfa0a4b71d15fc580eca97de6a82492e53b1163` (initial implementation); negative-test checkpoint is this dossier's containing commit
- **Inspiration:** prior isolated `feat/browser-offline-snapshot` tip `015ff42`. Its `agents/browser_offline_snapshot.py` was copied unchanged; its synthetic tests were copied except for removing the legacy direct-Chrome localStorage canary and unused imports. The Git objects were not available in this beta-derived checkout. This does **not** imply that earlier branch was merged.

## Intent and implemented contract

Opt-in disposable loopback HTTP fixture, fixture-only manager database and three provisioner-owned isolated Chrome profiles. Separate persistent and session-only server-issued HttpOnly cookie cases plus origin localStorage establish an owned principal via browser-native `/me` fetch while the source is running. Verify empty recipients, exact release/root/CDP closure, no-restart copy boundary, raw regular-file copy (excluding Chrome's stale runtime Singleton artifacts), NSS/proxy-file-filtered offline snapshot, physical-directory distinction, two separately restarted recipients, and source preservation. The offline helper accepts a proof-reader but is not a manager no-restart fence; the fixture holds only a local procedural no-restart boundary. No production API, auth pooling, or live account is enabled.

## Evidence and review

- Command: `BBH_STOPPED_CLONE_CANARY=1 python -m pytest -q -s agents/test_browser_stopped_clone_feasibility.py`
- Synthetic helper tests: `python -m pytest -q agents/test_browser_offline_snapshot.py`
- Negative cases: session-only cookie without `Max-Age`/`Expires`, live source `/me` authenticated, source restarted and both physically distinct raw/filtered recipients returning `/me` 401 despite retained localStorage; active source terminal-proof refusal, stopped source with reappearing SingletonLock refusal, unsupported symlink/hardlink/snapshot rollback tests in helper suite.
- NSS comparison: synthetic `cert9.db`, `key4.db`, and task-proxy PEM marker are present in raw copy and absent in filtered copy. No real task CA or client certificate was provisioned; trust and client-certificate behavior are **untested**.
- Iteration finding: a session-only cookie disappeared on source restart; the positive fixture explicitly sets `Max-Age=3600` and tests source persistence before cloning. A raw `shutil.copytree` also failed on dangling Singleton links/socket left after verified Chrome stop; raw portable copy omits these exact runtime entries. This is not a byte-identical whole-tree clone.
- **Exact test receipts:** final opt-in real-Chrome fixture passed twice consecutively (`1 passed in 51.22s`; `1 passed in 44.80s`) and again after nonbehavioral cleanup (`1 passed in 33.43s`). The copied helper suite returned `17 passed, 1 deselected in 1.65s` before removal of its legacy direct-Chrome canary; after removal, `17 passed in 1.14s`. Fixture cleanup verified exact units, recorded process identities, CDP endpoints, and removal of its disposable root; only secret-free startup diagnostic metadata remains in private scratch.
- **Failure history:** during iteration, stopped source sometimes had zero persisted cookie rows and both cookie/localStorage checks failed after restart even though live `/me` passed. The final test checks on-disk cookie rows and verifies source restart before cloning, failing rather than treating transient memory auth as clone evidence. This intermittent persistence behavior is not explained and limits repeatability claims.
- **Current session-only negative receipt:** `BBH_STOPPED_CLONE_CANARY=1 python -m pytest -q -s agents/test_browser_stopped_clone_feasibility.py agents/test_browser_offline_snapshot.py` returned `19 passed in 94.48s` and, after explicit physical recipient-directory checks, `19 passed in 73.93s`; both printed `source restart auth=False; raw/filtered recipient /me statuses=[401, 401]`. Session-only auth loss is observed on this local Chrome/configuration, **not a cross-version guarantee**: Chrome session restoration and shutdown semantics can change the outcome. The test reports the actual statuses if restart preserves it rather than asserting universal loss. LocalStorage remained present in source and recipients. No browser flags were added for this negative case.
- Independent review: prior review blocked controlled-feasibility approval pending the negative session-cookie test; this branch now supplies that evidence but has not been re-reviewed or approved.
- Merge/ancestry evidence: branch based on fetched beta, no merge.

## Blockers and deferred work

- **Missing evidence:** real CA import/trust and NSS client-certificate authentication on destination. **Trigger:** deliberate isolated HTTPS/proxy fixture with provisioner-owned CA and certificate handling. **Gate:** no claim that omitted NSS state preserves TLS trust, client certificates, or production auth.
- **Missing evidence:** actual manager-held no-restart fence and supported real-site storage/session contract. **Trigger:** reviewed manager implementation and explicit approved site contract. **Gate:** no production activation or peer propagation from this fixture.
- **Unsupported states:** portability of session-only cookies across browser versions/configurations, device-bound/passkey credentials, token binding, service workers/IndexedDB-specific contracts, external SSO, server invalidation, and concurrent sessions are not proven. The current local negative test demonstrates session-only loss on this fixture only; a passing persistent-cookie case does not close these gaps.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/browser-stopped-clone-feasibility`
- **Latest immutable prior checkpoint:** `6dc258c64abc537bab6ac4e4f22405614fd5fd6e`; current negative-test checkpoint is this dossier's containing commit
- **Feature implementation commit(s):** `9dfa0a4b71d15fc580eca97de6a82492e53b1163` (initial implementation); negative-test checkpoint is this dossier's containing commit
- **Exact resume point:** independently review the negative receipt, intermittent persistent storage behavior and remaining manager/CA gaps; compare against fetched `origin/beta` (`2d80b03af499a033a0b9a46c87b7e3a4eb61236c`) before any integration decision. Do not merge or push beta without explicit authorization.
- **Working-tree state at handoff:** clean after the negative-test checkpoint commit (verify with `git status`).

## Decision gates

- **Integration gate:** separate independent review, no implicit beta merge.
- **Activation / cohort gate:** no production wiring, real CA/session contract and manager fence untested.
- **Promotion gate:** no stable or live-account activation.

## Decision record

- 2026-09-25 — created disposable-only test from fetched beta and isolated offline helper source.
