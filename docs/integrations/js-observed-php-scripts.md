# Browser-observed non-JS-suffix script inventory

- **Owner / Kanban:** Hermes / `t_73fe721b`
- **Feature branch / worktree:** `feat/js-observed-php-scripts` / `/home/ryushe/worktrees/bbh-js-observed-php-scripts`
- **Base / target:** `9c01786b363b5c75798c581cab2afa274f8afb33` / `beta`
- **Status:** independent cache-fix re-review accepted; ready for beta integration. This dossier is branch-local and excluded from the beta merge.

## Goal and boundaries

Admit an in-scope, explicitly listed script URL with a non-JS suffix such as `chunk.php` to `js_analyzer.py inventory` only with a matching browser/proxy observation: exact URL, loading page, saved request ID, `script`/`parser` initiator, GET method (if present), 2xx status, and JavaScript MIME. Require `--target-host`. Refetched or cached responses must independently be 2xx with JavaScript MIME before analysis. Existing `.js`/`.mjs`/`.cjs`/extensionless and HTML `--page` paths remain unchanged. No arbitrary PHP list fetch, no new live-target probe, and no claim that static source/sink hits prove XSS.

## Implementation and verification

- `agents/js_analyzer.py`: provenance-qualified input eligibility and response guard, with cached response metadata check and skipped-response diagnostic.
- `agents/test_js_analyzer.py`: positive PHP script inventory with paired source/sink seeds, parser/script initiators, input negatives, refetch HTML/error, valid cache and invalid cached HTML, missing target host.
- `skills/xss/references/source-acquisition.md`, `skills/js-pull/SKILL.md`, `prompts/js-playbook.md`: executable handoff and remaining evidence gap. `agents/test_xss_skill_clarity.py` updates the route contract.
- Initial implementation checkpoint: `a8b936bc8c26cefbc5118b90d159d3668d3892e1`. The first independent review found a **MAJOR** cache regression: a reused PHP script lost its 2xx/JavaScript ledger metadata on the next write, so run 3 skipped it. Corrected implementation checkpoint: `a96ab7d71dda752fbd17411d5780b8fac6817140`. Its three-run regression is RED on the prior tip and GREEN on this tip; the corrected run preserves status and MIME in metadata/ledger. The reviewer also identified an unchanged `--page` limitation (HTML `script[src]` is not proof of JS), now called out in the XSS reference and JS playbook. Independent narrow re-review **ACCEPTED** the corrected implementation: its four-run mocked probe preserved 200/JavaScript metadata and source/sink counts on runs 2–4 without a refetch, with no arbitrary/off-scope PHP fetch. Its broader focused selection: **439 passed**; `git diff --check`: clean. Beta integration still pending.
- After correction, focused XSS/JS/analyzer tests: **416 passed**; `git diff --check`: clean.
- Repository `tests/` with checkout-local `.venv`: **307 passed, 1 skipped, 2 failed**. Both failures are in unchanged `skills/stack-to-program/scripts/README.md` script-index/command-lane contracts; the same two selected tests also failed on unchanged beta `9c01786b363b5c75798c581cab2afa274f8afb33`. An earlier run without `.venv` had additional fixture-launch failures; the prescribed `./setup.sh --install-python-deps` resolved those.
- A combined `tests agents` foreground invocation reached the terminal's transport timeout without a verdict. The separate targeted selection above and `tests/` suite provide bounded results instead; no pass is claimed for that aborted invocation.

## Integration plan

Have an independent reviewer check feature diff, exact provenance and MIME/status guards, scope/rate/cache behavior, docs-to-code match, and tests. Resolve material findings, then merge reviewed content excluding this dossier into a clean current beta worktree; run integrated tests, push beta through the beta worktree, verify remote ref and local projections. Do not conflate this beta change with Hoster deployment.
