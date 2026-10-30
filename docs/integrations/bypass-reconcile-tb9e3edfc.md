# Bypass reconciliation integration dossier

- **Status:** blocked pending independent fresh review; candidate only, not release
- **Task:** `t_b9e3edfc`, delegated isolated bypass slice
- **Branch:** `fix/bypass-reconcile-tb9e3edfc-20261029`
- **Worktree:** `/home/ryushe/worktrees/bbh-bypass-reconcile-tb9e3edfc-20261029`
- **Fetched beta base / intended target:** `origin/beta` / `beta` at `533e87a28ab684b3206bb1318dfcc1f437dc78fc`
- **Source:** `0c9a870e6483d800a7803151dbfc4090075d95e0` on `fix/scope-consumer-deny-tb9e3edfc`; source/beta merge base `baebf7b90f86f12f553a9a455723f888296e4a2c`. This is a path extraction, not a merge or a claim that the divergent parent is reviewed.
- **Implementation checkpoint:** `cf376fd4cb2d039c135cc98b5703aa40088d3fc3`. Review exact current HEAD including subsequent fixes; this dossier cannot encode its own containing commit SHA.
- **Last updated:** 2026-10-29

## Intent and contract

Keep authorized bypass capability, with named-program saved-scope and exclusion enforcement before construction and for each cooperating client request and WAF retry. No-program mode remains explicitly unscoped, not authorized by this change. Conservative header routing defers uncertain forwarding/host overrides and rewrite paths; allowed same-authority/same-path probes remain. Redirect following is disabled at the guarded client. This is not a Python sandbox, does not enforce scope for independent clients or arbitrary routing semantics, and does not replace real program authorization, rate, ownership, or effects review. Encoded paths can be denied by the validator when exclusions make them ambiguous. See `TOOLS.md` for deliberate reporting/API compatibility changes and limitations.

Retain cancellation propagation and cleanup, per-attempt/outcome counts without claiming wire sends, WAF accounting and safe handling of summary-write failures, and incomplete race outcomes. Results retain useful typed CORS classifications and race aggregate evidence while withholding raw response evidence. Redaction is best-effort, not a universal secret detector; no exact replay/raw proof is claimed. WAF accounting semantics change for its shared API and persisted snapshot; external consumers are unknown.

## Source provenance and dependencies

The harness, redaction module, seven listed bypass-type files, interceptor, six new bypass test/plugin files and relevant `TOOLS.md` portions originated at `0c9a870`, with later compatibility fixes here; `tests/test_bypass_scope_consumer.py` extracts only three bypass test functions and their fixture/imports from its mixed `tests/test_scope_consumer_deny.py` (one parametrized for sweep and single). No source code from the divergent URL Ingest, recon, subdomain, XSS, unrelated docs or skills is imported. `agents/scope_validator.py`, `agents/attempts.py` and `requirements.txt` are unchanged from beta and byte-identical to the source commit. The redactor uses beta's `agents.attempts.redact_attempt_value` and the installed Bounty Core pinned by beta requirements; imports of these local modules were verified to resolve in this worktree. Core installed revision `6c36ee88a60073e1b687ec32deeade24ffafdd4f` matches the manifest; httpx 0.28.1, idna 3.18 and pytest 9.1.1 satisfy beta bounds. New checkout manifest timestamp is newer than the shared interpreter's venv configuration, so revision was checked rather than relying on mtime.

Scope policy difference vs beta: beta bypass previously allowed empty saved scope and checked only initial URLs; this candidate requires named-program grants/deny-wins and per-request checks, with the explicit no-program contract retained. Other beta consumers are untouched and may have different policies. Source and beta validator are identical, not a port of another validator. Bounded repository Python caller search found only bypass harness uses this WAF class directly; unknown external and dynamic callers remain. A `total_requests` field in `harness_core.py` and `run_campaign.py` belongs to a different component.

## Evidence and review

- Independent fresh local Hermes reviewer session `local-2675ef1684fdaf482f82700f9ac06dfc121e30bbfc842d29127ebf2fdadfb75e` **blocked** `cf376fd4cb2d039c135cc98b5703aa40088d3fc3`: JSON `total` was incorrectly documented as previously counting client calls, and importing the WAF module directly from `agents/` failed. Full independent suite was not run because the review instruction erroneously prohibited temporary fixture writes. A follow-up restored `total=len(results)` with the changed summary input explicitly documented, preserved the legacy import by locating the owning repository root, and added regressions. Both regressions failed before fixes; full suite including new import test passed afterward: **443 passed, 2 skipped, 10 subtests**. The import also passed in an isolated Python process from `agents/`, with `PYTHONPATH` removed and Python socket/DNS blocked. Fresh independent review of the complete current candidate is still required; allow temporary test files in task scratch, never real targets/data/network.

- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/tests:$PWD:$PWD/agents" /home/ryushe/projects/bug_bounty_harness/.venv/bin/python -m pytest -q tests/test_bypass_scope_consumer.py tests/test_bypass_review_io_race.py tests/test_bypass_cancellation_contract.py tests/test_bypass_request_scope.py tests/test_bypass_review_blockers.py tests/test_bypass_review_followup.py tests/test_waf_interceptor.py agents/test_scope_validator.py agents/test_scope_path_normalization.py tests/test_scope_host_normalization.py -p bbh_offline_guard -p no:cacheprovider -o faulthandler_timeout=60 --tb=short` — **442 passed, 2 skipped, 10 subtests passed**. Two skips: sync interface has no asyncio cancellation outcome (`tests/test_bypass_review_io_race.py:64`, independently confirmed with `-rs`).
- Synthetic `.example.test` inputs, mocks and HTTPX MockTransport only. Test plugin blocks Python socket connect/connect_ex/sendto/sendmsg, DNS lookups and `subprocess.Popen` during tests. It is not an OS sandbox, does not cover collection or native calls, and proves no live transport or real service behavior. No target data, live traffic, browser, or real user involved.
- Beta was fetched before worktree creation. No merge into beta, push, activation, Hoster operation, or closure. Prior review approved only the last source delta, not this reconciled candidate. **Fresh independent review of the exact candidate and its tests is required.**

## Changed file list

- `TOOLS.md`
- `agents/bypass_harness.py`, `agents/bypass_redaction.py`, `agents/waf_interceptor.py`
- `agents/bypass_types/__init__.py`, `cors.py`, `idor.py`, `race.py`, `ssti.py`, `traversal.py`, `xxe.py`
- `tests/bbh_offline_guard.py`, `tests/test_bypass_scope_consumer.py`, `tests/test_bypass_cancellation_contract.py`, `tests/test_bypass_request_scope.py`, `tests/test_bypass_review_blockers.py`, `tests/test_bypass_review_followup.py`, `tests/test_bypass_review_io_race.py`, `tests/test_bypass_waf_import_compat.py`
- `docs/integrations/bypass-reconcile-tb9e3edfc.md` (temporary; remove only at separately authorized integration)

## Blockers / handoff

1. Independent reviewer must inspect exact reconciled diff and dossier, check retained legitimate coverage, scope decisions, privacy, output/API compatibility, cancellation/accounting, WAF shared behavior and dependencies, and independently rerun the stated offline suite. Resolve findings on this branch, rerun and obtain a fresh review. No release without this gate.
2. Mocked client tests do not establish real HTTP/proxy routing semantics, raw proof capture, external API compatibility or runtime activation. Any later integration/activation requires explicit authorization and appropriate synthetic isolated fixture checks; no real target testing is authorized by this task.
3. Before any separately authorized integration fetch beta again, compare exact base and reconcile if advanced, rerun tests and review the actual resulting diff. Follow repository lifecycle and remove this temporary dossier from the integration target only then.

## Interruption / resume

- Owning branch and recovery checkpoint: implementation checkpoint `cf376fd4cb2d039c135cc98b5703aa40088d3fc3`; inspect `git rev-parse HEAD` on the branch named above for the subsequent review-fix checkpoint. Git cannot encode its own commit SHA in itself.
- Resume at independent review against `533e87a28ab684b3206bb1318dfcc1f437dc78fc`; inspect clean status, changed file list, actual current HEAD and any subsequent commits before review.
- Integration, activation, promotion and closure are all outside this delegation.
