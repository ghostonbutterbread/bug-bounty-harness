# MITM index interpreter papercut integration dossier

- **Status:** feature
- **Owner:** Hermes bugfix
- **Branch:** `fix/mitm-index-runtime-20261006`
- **Base commit:** `49399075619b7b12c680834951830412f2800701` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Owning feature branch/ref:** `fix/mitm-index-runtime-20261006`
- **Latest immutable recovery checkpoint:** `2c312aa685e317f3b1f265932d2af89e703ba5c4` on `fix/mitm-index-runtime-20261006`
- **Feature implementation commit(s):** `2c312aa685e317f3b1f265932d2af89e703ba5c4`
- **Inspiration / canonical references:** Shared PAPERCUTS.md `PC-20261005-203035-4b6c4b56`.

## Intent

Repair an observed offline indexing failure: the BBH checkout-local Python cannot import mitmproxy, while the `mitmdump` executable uses an interpreter that can. Do not install another dependency, change the listener transport, touch live browser/proxy state, or alter request storage behavior.

## Implemented contract

`mitm_lane.py index-store` invokes `proxy_store.py index-lane` under the interpreter named by the selected mitmdump executable, passing existing metadata and full-request policy through the CLI. It returns the store's JSON result; unexpected nonzero or non-JSON results produce a sanitized failure status rather than exposing flow content or raw stderr. Absent interpreter is explicit. The listener start/stop contract and separate `browser_provisioner.py` index path are unchanged.

## Evidence and review

- Reproduced at beta with its venv: `index-store` failed `ModuleNotFoundError: mitmproxy`; Hoster read-only inspection confirmed `/usr/bin/mitmdump` uses `/usr/bin/python3` and its BBH runtime venv lacks mitmproxy. This does not prove Hoster's active checkout is current or that a real flow has been indexed there.
- RED: new offline index-store regression failed on the missing import before implementation.
- GREEN: 19 passed in `agents/test_mitm_lane.py agents/test_proxy_store.py agents/test_hoster_mitm_lane.py` using the selected beta integration venv against the feature source; `git diff --check` clean.
- Independent read-only review of `2c312aa` approved the observed interpreter fix and privacy contract after rerunning 19 focused tests; the stale checkpoint text in this dossier was the only integration blocker and is corrected here. Optional end-to-end tests for metadata and packet-storage modes were exercised manually with synthetic flows, but are not new regressions in this commit.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- Hoster deployment and real flow indexing are not in scope; a source merge is not proof of runtime activation. Verify the Hoster checkout and a disposable offline flow before closing the Hoster papercut as operationally fixed.
- An adjacent missing-flow-path issue in `proxy_store.py` (empty path resolves to `.`) is separately logged as `PC-20261006-035200-cc3d9b6a`, not silently folded into this repair.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/mitm-index-runtime-20261006`
- **Latest immutable recovery checkpoint:** `2c312aa685e317f3b1f265932d2af89e703ba5c4` (implementation); the current dossier correction is committed separately after that checkpoint.
- **Feature implementation commit(s):** `2c312aa685e317f3b1f265932d2af89e703ba5c4`
- **Exact resume point:** reconcile the advanced `origin/beta`, rerun focused tests, review the reconciled tip, then integrate if approved.
- **Working-tree state at handoff:** committed implementation; dossier correction is a separate follow-up commit before reconciliation.

## Decision gates

- **Integration gate:** focused tests, independent review, clean beta merge and post-merge tests.
- **Activation / cohort gate:** not requested; Hoster runtime repair remains unverified.
- **Promotion gate:** no main/stable promotion.

## Decision record

- 2026-10-06 — reproduced interpreter mismatch, added failing regression, applied minimal subprocess runtime correction, validated focused suites.
- 2026-10-06 — independent review found no functional or privacy blocker; corrected the inaccurate uncommitted handoff before beta reconciliation.
