# Auth-seed liveness metadata integration dossier

- **Status:** review-ready (review loop 1 fixes applied)
- **Owner:** Hermes (delegated subagent)
- **Branch:** `fix/auth-seed-liveness-metadata`
- **Worktree:** `/home/ryushe/worktrees/bbh-fix-auth-seed-liveness`
- **Base commit:** `85373a0058b38d05cc198c8097a1af3e4b1f4b91` (`origin/beta`); `origin/beta` `067f73cd` merged in as `00d4bf28` (no rebase)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-24
- **Owning feature branch/ref:** `fix/auth-seed-liveness-metadata`
- **Latest immutable recovery checkpoint:** the implementation commit named in
  the handoff (Git cannot embed a commit's own SHA; read `git log -1` on the
  branch and verify it is a descendant of the base)
- **Feature implementation commit(s):** `77c154d2` (initial); review-loop-1 fix commit follows the beta merge `00d4bf28`
- **Inspiration / canonical references:** papercuts PC-20261124-084457-704ab0ed
  and PC-20261124-055718-f99c12e5 (`~/Shared/PAPERCUTS.md`, HIGH);
  `skills/account-management/references/auth-seed-health.md`

## Intent

Workers learned an auth seed was dead only after setup plus live target
requests: seeds carried no capture time or verification record, an inventory
`auth_check` that hit a cached SPA shell returned 200 and read as live, and
seeds with no replayable auth material were listed as configured/ready. Make
capture and verification metadata visible at planning time, with no new live
probes and no secret values in any new field or output.

Unchanged: seed file format other than the added `captured_at`; the
Ryushe-proxy one-run refresh flow and its permission gates; browser-bound /
unknown session handling; lease availability; inventory schema version (new
fields are optional).

## Implemented contract

- `agents/auth_seed_health.py` (new, pure, no I/O): material counting
  (cookies with values, auth-like header names, declared
  `auth_check.required_header_names`), seed snapshot, liveness mapping
  (`passed→live`, `failed→expired`, `inconclusive/error→unknown`; check URL
  recorded as origin+path, query dropped), and `classify_seed` →
  `usable | unverified | stale | unusable | none` with reason codes.
  Old records/seeds without metadata classify as `unverified`, never `usable`.
  Freshness window = declared `auth_session_ttl_hours`, else 24h.
- `auth_resolver.py`:
  - writer adds `captured_at` (UTC) to refreshed seeds and writes the
    non-secret `auth_seed_status` projection to the inventory in the same
    update as `auth_seed_ref`;
  - a Ryushe-proxy refresh whose captured request has no replayable auth is
    refused (existing seed untouched);
  - `resolve` skips the liveness request for a material-less seed, treats a
    2xx cache hit (`cf-cache-status`/`x-cache`/`x-cache-status` HIT/STALE/
    UPDATING, `Age > 0`) or `text/html` body as `inconclusive`, records the
    result in `auth_seed_status` when a check ran (an `unknown` never
    overwrites a definitive `live`/`expired` for the same capture), and reports
    `auth_seed_usability`;
  - readiness: a seed without material is never `ready`; with no check URL or an
    inconclusive check, a seed with material is `ready` unless recorded
    `stale`/`unusable`; after a refresh, a re-check that `failed` is no longer
    reported `ready`. Inventory write failure is reported
    (`auth_seed_status_record`), not raised.
- `account_inventory.py`: `--auth-session-ttl-hours` (positive, finite);
  stderr warning when `--auth-check-url` is the site root or a static file;
  `show` prints `seed=<state>(<reasons>)`; repointing `--auth-seed-ref` to a
  different seed drops the previous seed's `auth_seed_status`.
- Seed writer (`write_auth_seed`) defaults `captured_at` to the write time and
  keeps a value already present in the data it is given.
- `browser_profile_lease.py`: account summaries (status/acquire) include
  `auth_seed_usability` from inventory metadata only; availability unchanged.
- `chromium_test.py`: account resolution includes `auth_seed_usability`; the
  auth fallback plan reports `needs-auth` (not `ready`) for a seed recorded
  `stale`/`unusable`; a launch-time refresh's usability supersedes the
  pre-refresh record. Launch gating is unchanged.

Non-claims: no app-specific auth-envelope parsing (a 200 JSON body with an
auth error still reads `live`); `failed` still maps 401/403 to `expired`
(a WAF 403 is indistinguishable here); planners that never call the resolver
see only what was last recorded.

## Evidence and review

- Tests (BBH `.venv` python, `PYTHONPATH=<worktree>:<worktree>/agents`,
  synthetic fixtures only; no bounty-core overlay was needed):
  - focused set (auth resolver ×2, account inventory, browser profile lease,
    chromium launcher, recon-ry ×6, skill hygiene): base `85373a00` 1420
    passed; branch 1472 passed (same files plus the new
    `agents/test_auth_seed_health.py` and added cases).
  - lease/provisioner consumers `test_browser_resources.py`,
    `test_browser_selection.py`: 25 failures on base and the identical 25
    failure IDs on branch, all pre-existing and unrelated
    (`PipeBrowser` has no `meaningful_count`; `'profile-unavailable' ==
    'reused'`; `browser_control.py` is untouched here).
    `test_browser_provisioner.py`: all passed on branch except the 25 above
    (none in this file); its final 21 node IDs passed on both base and branch.
  - remaining lease/launcher consumers (stop fence, stopped reservation,
    profile fallback review, lease recovery, startup diagnostics, legacy
    auto, program policy, startup safety, fallback sweep, lifecycle systemd):
    branch 227 passed, 7 skipped, 0 failed; base covered 8 of them in an
    interrupted run with no failures.
  - A single 48-file broad run was attempted on both lanes but could not finish
    within bounds on the loaded host (I/O-bound sqlite fsync); it was replaced
    by the bounded file groups above.
  - script-level smoke (direct `python <script>`, synthetic shared base, no
    network): material-less seed → `unusable`, no request sent; 33-day seed
    with 168h TTL → `stale`, not `ready`; no synthetic secret values in
    output or inventory.
  - pre-existing defect fixed in-scope: `agents/test_auth_resolver.py` run on
    its own failed on base (20 failed, `inventory_paths` not importable)
    because its loader relied on another test file putting the scripts
    directory on `sys.path`; the loader now inserts it.
- Independent review: not performed in this run; assigned to the parent/operator.
- Reference-impact audit: new import of `agents.auth_seed_health` from four
  skill scripts via `Path(__file__).resolve().parents[3]` (precedent:
  `browser_provisioner.py`, `hoster_mitm_lane.py`). All in-repo callers
  (`recon_ry.py`, `browser_provisioner.py`, `chromium_test.py`) invoke these
  scripts from their checkout; synced skill directories are symlinks into a
  checkout, so the root resolves.

## Review loop 1 (independent review: BLOCK on B1, B2)

- **B1 fixed:** `resolve` records a check result only when the checked URL and
  method equal the account's declared auth check after normalization
  (`is_declared_check`; scheme/host case, userinfo, query, and fragment
  ignored). A caller's one-off `--target-url` (for example `recon_ry.py`) is
  reported in `auth_check` and `auth_seed_status_record.check_result =
  "not-recorded:one-off-check-url"`, never saved. A 403 is recorded as
  `unknown` (WAF/bot ambiguity); 401 stays `expired`. Readiness for the run
  itself is unchanged from base (a failed check is not ready).
- **B2 fixed (chosen approach: file fingerprint fallback):** the snapshot
  records `seed_fingerprint` (`<mtime_ns>:<size>`). A saved result carries
  forward only when `captured_at` is set on both sides and equal, or, when
  neither side has `captured_at`, when both fingerprints are set and equal.
  A missing identity never matches. Chosen over "`captured_at` only" so a
  hand-replaced legacy seed is detected and the inventory projection is
  rewritten for inventory-only readers. Consequence: touching or re-syncing a
  legacy seed (new mtime) drops its saved result to `unverified` (fail-safe).
- **S1 fixed:** without a recordable check result, `resolve` still writes the
  seed snapshot when it differs from the stored projection (new capture, no
  replayable material), so lease summaries show `unusable`. The launcher also
  classifies the seed it already loads (`loaded_seed_usability`).
- **S2 fixed:** a fresh live check is evaluated before the declared-TTL age
  estimate.
- **Nits done:** N1 (`secret`, `passw` in the auth-header pattern), N3
  (stored check URL is scheme://host[:port]/path; the path equals the declared
  check URL already stored in the inventory, because only declared checks are
  recorded), N4 (refresh uses the proxied request's `source_time` as
  `captured_at` when parseable and not in the future), N6 (actionable error
  when `agents.auth_seed_health` cannot be imported).
- **Nits open (skipped to bound the loop):** N2 (doc line: localStorage-only
  `storage_state` seeds are unusable because BBH does not replay
  localStorage), N5 (inventory writes are unlocked read-modify-write;
  `account_inventory.py` has no flock pattern, so a lock would touch every
  writer and add a lock file in a synced folder; record in `BUGFIXES.md`),
  N7 (re-running `add-account` with a new `--auth-check-url` should clear the
  saved verification). Also observed, not fixed: re-running `add-account`
  without `--auth-check-url` replaces `auth_check` with `{"method": "GET"}`,
  dropping `required_header_names` (pre-existing; `BUGFIXES.md` candidate).
- **Receipts (focused suite: resolver ×2, health, inventory, lease, launcher,
  recon_ry ×6, skill hygiene; separate basetemps):** base `067f73cd` 1420
  passed; branch 1480 passed. Regressions added: one-off 401 then declared
  HTML check → ready; 403 → unknown; hand-replaced legacy seed after saved
  expiry → not stale; material-less seed persisted → unusable for
  inventory-only readers; launcher marks loaded empty seed unusable; fresh
  live outranks TTL; secret-named header counts as material.

## Blockers and deferred work

- **Missing evidence:** no live/Hoster smoke of `resolve` against a real
  program (prohibited for this change; synthetic only).
  - **Command:** `bbh skills/account-management/scripts/auth_resolver.py resolve --program <p> --account <alias>` on Hoster after beta activation.
  - **Trigger:** first authenticated run after this lands on the active beta checkout.
  - **Why:** confirms real inventories gain `auth_seed_status` and that real
    auth-check endpoints are not unexpectedly HTML/cached.
- **Deferred (outside BBH repo):** `program-auth-contract` skill's
  `references/auth-contract.md` should say the liveness check must
  discriminate auth state and should project `auth_session_ttl_hours`; route as
  a skill seed to Hermes.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/auth-seed-liveness-metadata`
- **Exact resume point:** independent review of the branch diff against
  `85373a00`, then merge into a clean current beta worktree.
- **Working-tree state at handoff:** clean after commit.

## Decision gates

- **Integration gate:** independent review accepts the readiness changes in
  `resolve` (material-less seeds never ready; inconclusive checks fall back to
  recorded state; failed post-refresh re-check not ready) and the inventory
  write on check.
- **Activation gate:** fast-forward of the Hoster beta checkout; no service restart needed.
- **Promotion gate:** beta→main only on explicit operator direction.

## Decision record

- 2026-11-24 — created; implementation committed review-ready on the feature branch.
- 2026-11-24 — review loop 1: B1/B2/S1/S2 and nits N1/N3/N4/N6 fixed; N2/N5/N7 open.
