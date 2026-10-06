# MITM index interpreter papercut integration dossier

- **Status:** feature
- **Owner:** Hermes bugfix
- **Branch:** `fix/mitm-index-runtime-20261006`
- **Base commit:** `49399075619b7b12c680834951830412f2800701` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Owning feature branch/ref:** `fix/mitm-index-runtime-20261006`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Shared PAPERCUTS.md `PC-20261005-203035-4b6c4b56`.

## Intent

Repair an observed offline indexing failure: the BBH checkout-local Python cannot import mitmproxy, while the `mitmdump` executable uses an interpreter that can. Do not install another dependency, change the listener transport, touch live browser/proxy state, or alter request storage behavior.

## Implemented contract

`mitm_lane.py index-store` invokes `proxy_store.py index-lane` under the interpreter named by the selected mitmdump executable, passing existing metadata and full-request policy through the CLI. It returns the store's JSON result; unexpected nonzero or non-JSON results produce a sanitized failure status rather than exposing flow content or raw stderr. Absent interpreter is explicit. The listener start/stop contract and separate `browser_provisioner.py` index path are unchanged.

## Evidence and review

- Reproduced at beta with its venv: `index-store` failed `ModuleNotFoundError: mitmproxy`; Hoster read-only inspection confirmed `/usr/bin/mitmdump` uses `/usr/bin/python3` and its BBH runtime venv lacks mitmproxy. This does not prove Hoster's active checkout is current or that a real flow has been indexed there.
- RED: new offline index-store regression failed on the missing import before implementation.
- GREEN: 19 passed in `agents/test_mitm_lane.py agents/test_proxy_store.py agents/test_hoster_mitm_lane.py` using the selected beta integration venv against the feature source; `git diff --check` clean.
- Independent review: pending.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- Hoster deployment and real flow indexing are not in scope; a source merge is not proof of runtime activation. Verify the Hoster checkout and a disposable offline flow before closing the Hoster papercut as operationally fixed.
- An adjacent missing-flow-path issue in `proxy_store.py` (empty path resolves to `.`) is separately logged as `PC-20261006-035200-cc3d9b6a`, not silently folded into this repair.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/mitm-index-runtime-20261006`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** independent review, then beta reconciliation and integration only if approved.
- **Working-tree state at handoff:** active implementation; commit before pausing.

## Decision gates

- **Integration gate:** focused tests, independent review, clean beta merge and post-merge tests.
- **Activation / cohort gate:** not requested; Hoster runtime repair remains unverified.
- **Promotion gate:** no main/stable promotion.

## Decision record

- 2026-10-06 — reproduced interpreter mismatch, added failing regression, applied minimal subprocess runtime correction, validated focused suites.
