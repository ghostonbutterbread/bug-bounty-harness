# Auth-seed liveness metadata integration dossier

- **Status:** review-ready
- **Owner:** Hermes (delegated subagent)
- **Branch:** `fix/auth-seed-liveness-metadata`
- **Worktree:** `/home/ryushe/worktrees/bbh-fix-auth-seed-liveness`
- **Base commit:** `85373a0058b38d05cc198c8097a1af3e4b1f4b91` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-24
- **Owning feature branch/ref:** `fix/auth-seed-liveness-metadata`
- **Latest immutable recovery checkpoint:** the implementation commit named in
  the handoff (Git cannot embed a commit's own SHA; read `git log -1` on the
  branch and verify it is a descendant of the base)
- **Feature implementation commit(s):** single commit on this branch
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
