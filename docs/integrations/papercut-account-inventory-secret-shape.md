# Account inventory false secret-match repair

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `fix/papercut-account-inventory-secret-shape`
- **Base commit:** `4e005929127d05785e704847bc80486cbd0c6297`
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** `b329b73` (camelCase/plural follow-up; indexed assignment follow-up pending)
- **Feature implementation commit(s):** `e6bd8cf`, `b329b73` (indexed assignment follow-up pending)
- **Inspiration:** `PC-20261006-183024-3c2fa227`, `PC-20261006-190941-bdadb001`

## Intent and implemented contract

For only `notes`, `source`, `auth_refresh_hint`, and `auth_seed_ref`, allow non-secret prose and seed-reference filenames containing auth vocabulary. Reject recognizable secret assignments, JSON credential properties, Authorization/Cookie/Bearer headers and private-key blocks. All other inventory fields keep their existing conservative substring guard. Error messages identify the field but never echo values. This is a heuristic safety gate, not a proof that arbitrary input is non-secret; the skill still prohibits storing actual credentials. No real inventory read or write.

## Evidence and review

- RED: synthetic `add-account` rejected `.tokens.json` before saving; new JSON `access_token` and `client_secret` cases failed against initial shape pattern.
- GREEN: `python3 -m pytest -q agents/test_account_inventory.py` → 15 passed; test uses sandbox `HARNESS_SHARED_BASE` and synthetic values only.
- Independent review: initial security review BLOCK: camelCase and plural credential keys with assignments passed the first shape pattern. A second review BLOCK found indexed assignments such as `passwords["primary"] = ...` and `headers["Cookie"] = ...` passed. Follow-ups cover both classes and the benign "bearer of" prose case. Four new synthetic indexed-assignment cases were RED before the fix; `agents/test_account_inventory.py` now has 25 passing tests. Further independent re-review pending.
- Merge / ancestry evidence: pending.

## Blockers and deferred work

Security re-review required before integration. Assignment-like prose such as "password: not stored" remains conservatively rejected rather than risking low-entropy credential values. The guard is heuristic, not a sanitizer; stable promotion and runtime activation not requested.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/papercut-account-inventory-secret-shape`
- **Latest immutable recovery checkpoint:** `b329b73` (camelCase/plural follow-up; indexed assignment follow-up pending)
- **Feature implementation commit(s):** `e6bd8cf`, `b329b73` (indexed assignment follow-up pending)
- **Exact resume point:** Independently re-review indexed assignment coverage, reconcile beta, rerun focused suite, integrate only if safe.
- **Working-tree state at handoff:** clean after indexed-assignment follow-up commit.

## Decision gates

- **Integration gate:** independent security review plus focused tests, current beta reconciled.
- **Activation gate:** no runtime activation in task.
- **Promotion gate:** stable promotion separately authorized.

## Decision record

- 2026-10-08 — Reproduced broad substring false positives and added shape-based exception for bounded non-secret fields.
- 2026-10-08 — Initial reviewer found camelCase/plural credential assignments bypassed; follow-up covers the reported synthetic shapes.
- 2026-10-08 — Second reviewer found indexed credential assignments bypassed; follow-up covers secret-key array indexing and header dictionaries with assignment syntax.
