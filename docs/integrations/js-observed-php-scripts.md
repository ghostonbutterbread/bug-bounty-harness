# Browser-observed non-JS-suffix script inventory

- **Owner / Kanban:** Hermes / `t_73fe721b`
- **Feature branch / worktree:** `feat/js-observed-php-scripts` / `/home/ryushe/worktrees/bbh-js-observed-php-scripts`
- **Base / target:** `9c01786b363b5c75798c581cab2afa274f8afb33` / `beta`
- **Status:** implementation checkpoint; independent review pending. This dossier is branch-local and excluded from the beta merge.

## Goal and boundaries

Admit an in-scope, explicitly listed script URL with a non-JS suffix such as `chunk.php` to `js_analyzer.py inventory` only with a matching browser/proxy observation: exact URL, loading page, saved request ID, `script`/`parser` initiator, GET method (if present), 2xx status, and JavaScript MIME. Require `--target-host`. Refetched or cached responses must independently be 2xx with JavaScript MIME before analysis. Existing `.js`/`.mjs`/`.cjs`/extensionless and HTML `--page` paths remain unchanged. No arbitrary PHP list fetch, no new live-target probe, and no claim that static source/sink hits prove XSS.

## Implementation and verification

- `agents/js_analyzer.py`: provenance-qualified input eligibility and response guard, with cached response metadata check and skipped-response diagnostic.
- `agents/test_js_analyzer.py`: positive PHP script inventory with paired source/sink seeds, parser/script initiators, input negatives, refetch HTML/error, valid cache and invalid cached HTML, missing target host.
- `skills/xss/references/source-acquisition.md`, `skills/js-pull/SKILL.md`, `prompts/js-playbook.md`: executable handoff and remaining evidence gap. `agents/test_xss_skill_clarity.py` updates the route contract.
- Initial focused XSS/JS/analyzer tests: **416 passed**; `git diff --check`: clean. Full-suite and review receipts to follow.

## Integration plan

Have an independent reviewer check feature diff, exact provenance and MIME/status guards, scope/rate/cache behavior, docs-to-code match, and tests. Resolve material findings, then merge reviewed content excluding this dossier into a clean current beta worktree; run integrated tests, push beta through the beta worktree, verify remote ref and local projections. Do not conflate this beta change with Hoster deployment.
