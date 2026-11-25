# Browser recovery, unpacked extensions and stale legacy rows — integration dossier

- **Status:** review-ready
- **Owner:** Hermes subagent (browser-provisioner papercut cluster 2)
- **Branch:** `fix/browser-recovery-extension-stale-rows`
- **Base commit:** `origin/beta` `85373a00` (contains `fe07bd50` owner inference / PSI admission / `release-run`)
- **Intended integration target:** `beta` (after independent review; not merged here)
- **Last updated:** 2026-11-24
- **Owning feature branch/ref:** `fix/browser-recovery-extension-stale-rows`
- **Latest immutable recovery checkpoint:** the branch commit that adds this dossier
- **Feature implementation commit(s):** same commit
- **Inspiration / canonical references:** `~/Shared/PAPERCUTS.md`
  PC-20260907-210922-b259833e, PC-20261123-180615-59575c9a,
  PC-20261124-065810-babc0355; kanban `t_297ebf3e` (no age/idle retirement;
  fenced, verified stops only).

## Intent

Remove three agent-stranding blockers in `skills/chromium-test` without
weakening admission, ownership fencing or cleanup:

1. **Recover-profile deadlock.** A `needs-refresh` release made the account
   `account-unavailable`; the only advertised escape (`browser_profile_lease.py
   acquire --recover-profile`) produced a standalone lease that the provisioner
   then refused as `managed-by-provisioner`, so agents released it `healthy`
   (a lie) to get a browser.
2. **No unpacked-extension launch.** The launcher hard-codes
   `--disable-extensions`; request/start had no extension option.
3. **Stale legacy rows block named accounts program-wide.** Stopped rows whose
   units are gone and whose profile has no live process still made
   `legacy-profile-not-quiescent`/history mismatch refusals.

## Implemented contract

**Recovery.** The needs-refresh gate is unchanged. `account-unavailable` now
names the agent-usable path (`RECOVERY_NEXT`): repeat the same provisioner
request with `--recover-profile`. When that request finds the caller's own
standalone lease (same agent, run, account, domain, slot) that is active,
manager-less, `not-started`, with no CDP URL or unit, it is adopted (manager id
set under the canonical write lock) and launched; foreign, launched or
non-recovery leases are never adopted. Every pre-registration failure in
`start()` now releases with `health=None`, which preserves the prior released
health, so a failed recovery stays gated instead of becoming `healthy`. The
agent releases a repaired profile with the health it observed.

**Extensions.** `request`/`start` accept repeatable `--load-extension DIR`
(validated in `main()` before any state: absolute, existing directory,
`manifest.json` file, no comma; resolved and de-duplicated). The launcher
replaces `--disable-extensions` with `--disable-extensions-except=` and
`--load-extension=` for exactly those directories. No generic Chrome-flag
passthrough. The set is recorded in the launcher result, launch file, private
launch recipe and `safe()` receipt (path, manifest SHA-256, name/version/
manifest_version); `start` fails closed when the launcher result does not
confirm it; a running browser with another set is `locked/extension-mismatch`;
replacement and live transfer require an equal set; `resume` replays it.
Headless uses `--headless=new`, which loads extensions. Branded Google Chrome
137+ ignores `--load-extension`: the launcher refuses an automatically selected
binary whose `--version` identifies it (explicit `--chrome-binary` and
`CHROMIUM_TEST_CHROME` wrappers are not executed for this probe).

**Stale legacy rows (absence evidence only; nothing is stopped or edited).**
- `row_instance_key(row)`: a manager row whose record lacks `instance_key`
  (start interrupted before registration, or missing record) belongs to the slot
  its path names when the path is exactly
  `<…>/web/browser-instances/<domain>/<account>/<slot>`; otherwise it stays
  legacy. Used for latest-row selection, the unkeyed cohort and quiescence.
  `manager_legacy_profile` (sweep protection) deliberately still uses the record
  so the sweep stays conservative.
- `quiescent_legacy`: a `SingletonLock` is stale only if its `<host>-<pid>`
  target equals a recorded root `process_identity` of a row for the same
  physical profile, that identity is terminal on this host, and the PID does
  not exist. The `/proc/*/cmdline` reference check still runs afterwards.
- `browser_profile_lease` legacy inheritance: for a non-`legacy-global`
  domain, pre-domain (`auth_domain IS NULL`) history no longer constrains
  inheritance only when released/expired, no service unit, a different (or
  missing) physical directory, and any recorded CDP endpoint is not ready.
- Age/idle is never evidence. `browser_manager_row_repair.py` is unchanged;
  stopped rows are outside its scope and need no row edit.

Non-claims: no automatic retirement or stop of any resource; no change to
admission, PSI/swap gates, `fenced_stop_release`, or owner inference.

## Evidence and review

- **Hoster read-only evidence (2026-11-24).** `immutable`: 27 manager rows; 9
  profile dirs carry `SingletonLock`, and all 9 lock targets equal a recorded
  root identity whose PID no longer exists (new rule treats them as stale); 4
  records lack `instance_key`, 3 of them at slot-layout paths (now attributed to
  their slot), 1 remains legacy. Units `not-found`/`inactive`, canonical leases
  released. Script: read-only `sqlite3 mode=ro` + `readlink`/`/proc` checks.
- **Extension probe (offline, local).** Chrome for Testing 148.0.7778.96
  (`--headless=new`, `--no-sandbox` only because local AppArmor restricts user
  namespaces) loaded a probe MV3 extension (its page and `sw.js` worker
  present) even with `--disable-extensions` also present. `/usr/bin/google-chrome`
  showed only component extensions — consistent with branded 137+ ignoring the
  switch (branded version not recorded; treat as corroborating, not proof).
- **Focused regressions:** `agents/test_browser_recovery_extension_legacy.py`
  (40 tests): recovery guidance, adoption end-to-end through `start`, failed
  recovery stays gated, adoption exactness (foreign/launched/non-recovery);
  extension validation/refusals, launcher flags, branded refusal (auto vs
  explicit), CLI refusal before state, request forwarding, start record,
  fail-closed confirmation, resume replay, mismatch refusal; stale lock of a
  dead recorded root accepted, unknown/live/reused lock or a referencing process
  still blocks, interrupted-slot attribution, other-directory pre-instance rows
  still block, terminal pre-domain history of another directory accepted, and
  every missing proof still blocks. Copied onto unchanged base (36-test
  revision), 21 failed — every new-behaviour test — and the 15 fail-closed
  negative controls passed, as they should on base too.
- **Browser suite** (`agents/test_browser_*.py` + `test_chromium_test_launcher.py`,
  one pytest per module, BBH `.venv` Python 3.11, `PYTHONPATH=<wt>:<wt>/agents`,
  separate short `--basetemp`s): base 885 passed / 32 failed / 41 skipped
  (42 modules); branch 925 / 32 / 41 (43 modules, +40 new). Failure sets are
  identical: `test_browser_selection` 15, `test_browser_resources` 10,
  `test_browser_transfer_source_end_uncertainty` 6,
  `test_browser_transfer_end_uncertainty` 1 (pre-existing, `BUGFIXES.md`). The
  one branch-only break (`test_browser_startup_diagnostics` stub of
  `release_lease` without `**kw`) was fixed and the stub now asserts
  `health=None`. Base ran on `b3c6aced`; browser code and tests are identical
  between `b3c6aced` and `85373a00` (only `SKILL.md`/`BUGFIXES.md` differ there).
- **Docs checks:** `tests/test_skill_hygiene.py` (SKILL.md kept at its
  820-line budget), `test_script_policy.py`, `test_scratch_scripts.py`,
  `test_gate_route_negative_controls.py`, `test_bounty_storage_skill_contract.py`,
  `agents/test_shared_default_additional.py`: 68 passed on base and branch.
- **Independent review:** pending.

## Blockers and deferred work

- **Missing test or evidence:** a live Hoster recovery and extension launch
  through the managed unit (Playwright Chromium there) was not run.
  - **Command / fixture / environment needed:** after activation, a task-owned
    `request --headless --load-extension <dir>` and a `--recover-profile`
    request for a needs-refresh owned account on Hoster.
  - **Trigger to run it:** runtime-beta activation of this branch's merge.
  - **Why it blocks:** activation confidence only; offline coverage is complete.
  - **Next completion step:** the activating agent records the receipts here or
    in the merge note.
- Same-run proxy reuse keyed on `purpose` is recorded in `BUGFIXES.md` (not
  changed here).

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/browser-recovery-extension-stale-rows`
- **Latest immutable recovery checkpoint:** branch head
- **Exact resume point:** independent review, then merge to `beta` by the
  integrating agent.
- **Working-tree state at handoff:** clean

## Decision gates

- **Integration gate:** independent review of `start()` recovery adoption and
  the three absence-evidence rules; browser suite failures identical to base.
- **Activation / cohort gate:** Hoster runtime-beta live receipts above.
- **Promotion gate:** normal beta→main promotion.

## Decision record

- 2026-11-24 — created; review-ready on `85373a00`.
