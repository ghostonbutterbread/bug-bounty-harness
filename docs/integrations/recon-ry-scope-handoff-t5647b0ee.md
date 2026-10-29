# Recon-Ry scope handoff safety integration dossier

- **Status:** implementation checkpoint; independent review and integration pending
- **Task / owner:** t_5647b0ee / delegated BBH subagent; parent PC-20261029-173518-f2809a3c
- **Branch:** `fix/recon-ry-scope-handoff-t5647b0ee`
- **Worktree:** `/home/ryushe/worktrees/bbh-recon-ry-scope-handoff`
- **Fetched base:** `52252b96c6d6eb9ebd44f81b9646e6be3ab4214b` (original task fetch; no new network access authorized)
- **Intended integration target:** `origin/beta`; parent controls reconciliation and integration
- **Red checkpoint:** `620e321526b2fb2dcf63ef81e55198f3e7ae4493` (plus subsequent dossier-only checkpoint `0ec9f12`)
- **Implementation / green checkpoint:** `72241f1f996a2d1ce4ad927d6d82a9a78aed7b2e`; verify subsequent dossier-only commits and the current tip separately.
- **References:** BBH `AGENTS.md`; local Recon-Ry `6777eea`, `docs/defensive-maintenance.md` lines 18–42; separate validator fix `fix/scope-path-normalization` remains distinct and is not modified or merged here.

## Implemented contract

Before any child process or SSH, both `start` and `queue` pass through `validate_start_scope` and refuse the entire selected saved scope if any grant or exclusion has a scheme/origin, port, or raw/URL path restriction. This includes mixed wildcard scope and exclusions even when `--allow-unscoped` is supplied. CIDRs and host-only entries remain accepted under the prior checks; all previous URL-validation, profile, credential and wildcard gates remain. Diagnostics identify the saved restriction, explain the absence of request-level containment, and defer active coverage to a separately verified request-contained method. There is no attestation override in this wrapper. `status` and `ingest` are not Recon-Ry launches; ingest can independently probe promoted URLs and was not run live. `agents/recon/full.py` invokes the same wrapper; the two direct Recon-Ry command construction sites in BBH are `start_remote` and `queue_remote`.

## Evidence

- Original offline regression reproduced red: `/home/ryushe/projects/bug_bounty_harness/.venv/bin/python -m pytest -q tests/test_recon_ry_handoff_safety.py` at `0ec9f12` → **1 failed**, because a path exclusion was omitted and an exact launch was generated.
- Expanded offline test matrix runs real wrapper/validator logic against synthetic scope, denies socket creation and process launches, exercises exact credential resolver ordering, default `snap`, queue, allow-unscoped, wildcard mixed scope, URL/raw path grants/denies, scheme, and port; host-only dry runs and mocked SSH calls also preserve previous behavior. Regression tests detected accidental IPv6 CIDR refusal (3 failures) before correction.
- With a synthetic HOME and no network: `HOME="$TMPDIR/recon-ry-synthetic-home" /home/ryushe/projects/bug_bounty_harness/.venv/bin/python -m pytest -q tests/test_recon_ry_handoff_safety.py agents/test_recon_ry.py tests/test_recon_ry_scope_files.py tests/test_recon_ry_snap_default.py tests/test_scope_host_normalization.py tests/test_full_recon.py` → **129 passed, 1 skipped, 10 subtests passed**. The skipped test needs a local Recon-Ry checkout under HOME; a prior focused run with the normal HOME passed that offline parser test. Test environment imports the wrapper from this worktree, pytest/bounty_core from the existing main checkout venv; its pin has not been validated for this worktree.

## Residual risks and deferred coverage

This is a conservative interim gate, not universal egress confinement. Host-only allowed behavior is intentionally unchanged: host filters do **not** prove that redirects, browser subresources, nested parameter tools or resumed inputs cannot contact a denied or otherwise unauthorized host. Queue directly invokes Recon-Ry without generated scope files. Operators must assess those risks separately, not infer protection from a host deny or output filtering. This change defers all active coverage for mixed/restricted scopes, including otherwise host-wide components; no separately verified request-level confinement mechanism is assumed.

To lift the gate, Recon-Ry owners must demonstrate per-request containment for every enabled profile, including cross-host redirects and subresources, same-host disallowed scheme/port/path, nested consumers, and resumed input, using disposable synthetic loopback fixtures without real target data. Installed Hoster tool version/profile behavior remains unverified. Full repository suite is deferred because this task forbids network and real scope data; the focused synthetic suite above is the available verification.

## Next action and boundaries

Independent review must inspect branch diff and rerun offline tests; parent then fetches/reconciles `origin/beta` when network is authorized and resolves any conflict with the separate validator branch without conflating changes. Audit ancestor and descendant propagation before integration. No push, merge, runtime activation, target traffic, real scope data, or Hoster launch in this task.
