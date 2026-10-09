# Account inventory false secret-match repair

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `fix/papercut-account-inventory-secret-shape`
- **Base commit:** `4e005929127d05785e704847bc80486cbd0c6297`
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** `02f95e6` (plain authorization assignments; indexed/container follow-up pending)
- **Feature implementation commit(s):** `e6bd8cf`, `b329b73`, `06d85f0`, `37b5b38`, `02f95e6` (indexed/container follow-up pending)
- **Inspiration:** `PC-20261006-183024-3c2fa227`, `PC-20261006-190941-bdadb001`

## Intent and implemented contract

For only `notes`, `source`, `auth_refresh_hint`, and `auth_seed_ref`, allow non-secret prose and seed-reference filenames containing auth vocabulary. Reject recognizable secret assignments, JSON credential properties, Authorization/Cookie/Bearer headers and private-key blocks. All other inventory fields keep their existing conservative substring guard. Error messages identify the field but never echo values. This is a heuristic safety gate, not a proof that arbitrary input is non-secret; the skill still prohibits storing actual credentials. No real inventory read or write.

## Evidence and review

- RED: synthetic `add-account` rejected `.tokens.json` before saving; new JSON `access_token` and `client_secret` cases failed against initial shape pattern.
- GREEN: `python3 -m pytest -q agents/test_account_inventory.py` → 15 passed; test uses sandbox `HARNESS_SHARED_BASE` and synthetic values only.
- Independent review: initial review BLOCK found camelCase/plural assignments; second found indexed assignments; third found nested/empty brackets and percent-encoded query assignments. Post-reconciliation reviews found plain `Authorization = "Basic ..."`, then `authorization["default"] = ...`, encoded indexed authorization, and `headers = [(...)]` accepted in relaxed fields. Follow-ups cover each reported synthetic class with a shared indexed-key grammar and header container assignments. Each new case was RED before its fix; `agents/test_account_inventory.py` now has 35 passing synthetic tests. Further independent re-review pending.
- Merge / ancestry evidence: pending.

## Blockers and deferred work

Security re-review required before integration. Assignment-like prose such as "password: not stored" remains conservatively rejected rather than risking low-entropy credential values. The guard is heuristic, not a sanitizer; stable promotion and runtime activation not requested.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/papercut-account-inventory-secret-shape`
- **Latest immutable recovery checkpoint:** `02f95e6` (plain authorization assignments; indexed/container follow-up pending)
- **Feature implementation commit(s):** `e6bd8cf`, `b329b73`, `06d85f0`, `37b5b38`, `02f95e6` (indexed/container follow-up pending)
- **Exact resume point:** Independently re-review indexed authorization and header-container coverage against current beta, rerun focused suite, integrate only if safe.
- **Working-tree state at handoff:** clean after indexed-authorization/header-container follow-up commit.

## Decision gates

- **Integration gate:** independent security review plus focused tests, current beta reconciled.
- **Activation gate:** no runtime activation in task.
- **Promotion gate:** stable promotion separately authorized.

## Decision record

- 2026-10-08 — Reproduced broad substring false positives and added shape-based exception for bounded non-secret fields.
- 2026-10-08 — Initial reviewer found camelCase/plural credential assignments bypassed; follow-up covers the reported synthetic shapes.
- 2026-10-08 — Second reviewer found indexed credential assignments bypassed; follow-up covers secret-key array indexing and header dictionaries with assignment syntax.
- 2026-10-08 — Third reviewer found repeated/empty indexes and encoded query brackets bypassed; follow-up checks percent-decoded values and repeated indexing, and rejects header-map literals.
- 2026-10-08 — Post-reconciliation reviewer found plain `Authorization =` assignments passed; follow-up matches `:` and `=` assignment syntax in relaxed fields.
- 2026-10-08 — Re-review found indexed authorization and list-valued header assignments; follow-up unifies authorization with indexed secret keys and rejects header container assignments.
