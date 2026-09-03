# XSS canary attribution dossier

- **Status:** implementation complete; awaiting independent review
- **Owner:** Hermes / BBH
- **Branch:** `fix/xss-canary-attribution`
- **Worktree:** `/home/ryushe/worktrees/bbh-xss-canary-attribution`
- **Base:** `eb22b08418a5f7ae71ad502c0693dcc426a0ec76`
- **Target:** `beta`
- **Kanban:** `bug_bounty_harness/t_b2b8c6a9`

## Contract

The XSS canary mapper must not count a query-wide echo, an old cached marker, or a WAF/access-blocked request as a parameter-level reflection. Each plan now creates a per-source random attempt nonce, embeds it in the canary and a cache-buster query field, preserves fetch-to-source identity, and writes explicit scan exclusions.

- Responses containing multiple known canaries without request provenance are `query_echo_ambiguous_multiple_canaries` and produce no sinks/edges.
- HTTP `403`/`429` responses are `inconclusive_waf_or_access_block`, not a negative reflection.
- A response with fetch/browser provenance must contain its requested source marker; mismatches are excluded.
- Single-marker imported response artifacts remain supported.

## Evidence

- Focused suite: `python3 -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q` — **15 passed**.
- Syntax and whitespace: `python3 -m py_compile skills/xss/scripts/xss_canary_mapper.py && git diff --check` — passed.
- Independent review identified one gap: imported 403/429 and browser navigation 403/429 could still produce sinks. The repair retains status codes and excludes these responses before marker scanning; the independent re-review reported no findings. Playwright is absent from the available test interpreter, so browser status propagation was source-reviewed rather than executed.
- Regressions cover repeated run ID/cache-buster, unbound multi-marker query echo, request/response marker mismatch, imported 403, and HTTP 403 inconclusive outcomes.

## Review and activation

An independent reviewer is examining the uncommitted diff. After findings are resolved, commit the focused repair, merge it into clean current `beta`, push `origin/beta`, and fast-forward the verified Hoster runtime checkout. Hoster activation requires a post-update source/commit check and a focused test or no-side-effect smoke there.

## Deferred

The checked-in mapper issues individual requests rather than batches; therefore there is no batch bisection retry implementation in this change. If a future runner adds batching, it must mark a whole-batch query echo ambiguous and isolate members before confirmation; it must never interpret a batch 403 as negative evidence.
