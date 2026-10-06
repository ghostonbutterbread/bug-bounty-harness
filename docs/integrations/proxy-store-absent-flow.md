# Proxy Store absent-flow integration dossier

- **Status:** review-ready
- **Owner:** Hermes bugfix task `t_083f0962`
- **Branch / owning ref:** `fix/proxy-store-absent-flow-20261006`
- **Base commit:** `edd1865d12c5814fea3eeb57ffcf52f916ff2304`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Latest immutable recovery checkpoint:** none yet (set after implementation commit)
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** `PC-20261006-035200-cc3d9b6a`, `skills/chromium-test/scripts/proxy_store.py:index_lane`.

## Intent and implemented contract

On current beta, `index-lane` without `--flow-file` and without lane state creates `Path("") == Path(".")`, passes `exists()`, creates the store DB, then raises `IsADirectoryError` when opening the directory. Verified against the current CLI under `/usr/bin/python3` with an offline scratch lane root. The fix detects an absent or non-file path before database access and returns its existing `missing-flow-file` status. The absent `flow_file` response is the honest empty string rather than `.`. An explicitly provided missing file path remains reported by path; no successful flow-indexing path is changed.

## Evidence and review

- RED: new absent-path regression first failed at the real directory opening; second directory-path regression failed the same way against the first partial fix.
- GREEN: `agents/test_proxy_store.py agents/test_mitm_lane.py` — 11 passed. Fresh scratch CLI with real installed mitmproxy returned `missing-flow-file` (exit 2), with no database created. `git diff --check` clean.
- Independent review: pending.
- Merge/ancestry: started at freshly fetched beta `edd1865d`; re-fetch/reconcile before integration.

## Blockers and deferred work

- **Missing operational evidence:** Fresh Hoster runtime command still needs verification after beta source activation. Use an offline isolated lane root and DB, not a live flow; trigger when Hoster's selected checkout contains the fix. No real captured flow is necessary for the absent-input contract.
- **Affected descendants:** beta is the owning integration lane. Do not promote to main without separate decision. The parallel task-MITM overflow feature does not touch Proxy Store indexing.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/proxy-store-absent-flow-20261006`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit implementation, record checkpoint, independent review, reconcile beta, integrate and verify.
- **Working-tree state at handoff:** changes pending first commit.

## Decision gates

- **Integration gate:** independent diff, source/CLI regression, fetched beta ancestry.
- **Activation gate:** selected Hoster checkout contains fix and isolated offline command confirms status; no live MITM flow touched.
- **Promotion gate:** separate main-lane decision.

## Decision record

- 2026-10-06 — verified still affecting current beta; implemented bounded input correction.
