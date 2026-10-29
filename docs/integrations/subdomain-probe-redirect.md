# Subdomain probe redirects — integration dossier

- **Status:** feature; independent review and integration pending
- **Owner:** delegated BBH task `t_f97c6d30`
- **Branch:** `fix/subdomain-probe-redirect`
- **Worktree:** `/home/ryushe/worktrees/bbh-subdomain-probe-redirect`
- **Base commit:** freshly fetched `origin/beta` `533e87a28ab684b3206bb1318dfcc1f437dc78fc`
- **Intended integration target:** `beta` (parent agent owns integration)
- **Last updated:** 2026-10-29
- **Owning feature branch/ref:** `fix/subdomain-probe-redirect`
- **Latest immutable recovery checkpoint:** `9d133fb0380b6439a05e739df31a0585954cdd4e`
- **Feature implementation commit(s):** `9d133fb0380b6439a05e739df31a0585954cdd4e`
- **Inspiration / canonical references:** independent synthetic reproduction, `agents/subdomain_agent.py`, HTTPX 0.28.1 redirect semantics, `httpx-redirect-observation`.

## Intent

Stop probe-stage automatic redirect following and persistence of sensitive redirect destinations and reflected redirect titles. Retain normal authorized subdomain probing, normal 200 title extraction and no-response HTTPS-to-HTTP fallback. Do not incorporate the separate scope-consumers branch or alter passive providers, local tools or takeover checking.

## Implemented contract

3xx responses are not followed or read; status is retained, title empty, content length zero, and a Location-bearing response records `[redacted]` rather than the Location or final URL. A response hook captures headers per request before HTTPX can parse malformed Location, with no shared hook mutation and request-local state removed after send. A response of any status prevents scheme fallback even if subsequent parsing or body decoding fails. Failures before headers permit HTTP fallback; errors are not printed. Normal non-3xx title and body length extraction remain. See `docs/subdomain-probe-redirects.md` for lost discovery and limitations; this is not general non-3xx content or network-egress sanitization.

## Evidence and review

- Baseline source was this worktree at `533e87a28ab684b3206bb1318dfcc1f437dc78fc`, HTTPX 0.28.1. A synthetic MockTransport returned 302 Location with a fake marker and a reflected final-page title. With connect/connect_ex/DNS patched to deny, `probe_all` issued 2 requests and `write_outputs` persisted the marker in both `title` and `redirect_url` in `scan_results.json`.
- Initial TDD regression failed at request count `2 != 1`, then passed. A later request-extension lifetime regression also failed first, then passed after clearing request state.
- Final offline focused suite: **78 passed, 22 subtests passed, 1 pre-existing `llm_harness.py` `datetime.utcnow` deprecation warning**. It covers 3xx variants, malformed Location and body, gzip, query/userinfo, errors and fallback, hook failure, cancellation, concurrent requests and closure, ordinary 200, all output files and mocked Recon Store input. Tests imported `agents/subdomain_agent.py` from this worktree and HTTPX 0.28.1 from the active Hermes Python environment. `bounty_core` was extracted from repository-pinned commit `6c36ee88a60073e1b687ec32deeade24ffafdd4f` into task scratch (not an editable installation).
- The final suite ran behind an inherited Linux seccomp filter denying socket and connect syscalls; an independently launched child confirmed `Operation not permitted`. Reproduce while scratch exists: `GUARD=/home/ryushe/.hermes/profiles/bugfix/cache/scratch/bbh-probe-offline; PYTHONPATH="$PWD:$GUARD/core" PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python "$GUARD/seccomp_run.py" python -c 'import sys; sys.path.append("/home/ryushe/.local/lib/python3.12/site-packages"); import pytest; raise SystemExit(pytest.main(["-q", "tests/test_subdomain_probe_redirect.py", "tests/test_scope_import_safety.py", "tests/test_scope_host_normalization.py"]))'`. Scratch is temporary; recreate filter and pinned dependency snapshot for later reruns.
- An earlier exploratory suite invocation using system pytest failed 10 tests due to missing `httpx` and `bounty_core`; its scope-import subprocesses replaced PYTHONPATH, so the Python-level socket guard was not inherited. The final kernel-filtered suite above resolved both issues. All test inputs were synthetic; no target or credential was used.
- Independent review: pending. Merge/ancestry: feature branched directly from fetched `origin/beta`; no integration performed. Lowest-owner/stable history is not resolved because `origin/main` is not present locally; stable changes and propagation are explicitly unauthorized in this task.

## Blockers and deferred work

- **Missing evidence:** fresh independent review of committed diff and offline test rerun, current beta reconciliation and integrated-tree checks.
- **Fixture/environment:** above synthetic tests and inherited network denial; pinned dependency snapshot. Trigger: parent agent proceeds with review/integration.
- **Gate:** blocks integration until review and reconciliation; activation and stable promotion separately unauthorized.
- **Next step:** parent reviews feature and dossier, fetches beta, reconciles if needed, runs offline checks and decides integration; remove branch dossier on integration under operations policy.
- **Deferred feature:** scope-aware redirect destination discovery needs a separate authorized design; no redirect targets are persisted here.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/subdomain-probe-redirect`
- **Latest immutable recovery checkpoint:** `9d133fb0380b6439a05e739df31a0585954cdd4e`
- **Feature implementation commit(s):** `9d133fb0380b6439a05e739df31a0585954cdd4e`
- **Exact resume point:** independent review of committed branch and parent-owned integration; no push.
- **Working-tree state at handoff:** intended clean after checkpoint and dossier update.

## Decision gates

- **Integration:** independent review, beta freshness and focused offline tests.
- **Activation / cohort:** not authorized; none performed.
- **Promotion:** stable not authorized; no propagation or closure.

## Decision record

- 2026-10-29 — isolated feature based on fetched beta; offline repair and evidence prepared for parent review.
