# HackerOne structured-scope integration

- **Feature branch:** `fix/hackerone-structured-scope`
- **Base:** `origin/beta` at `dca21228fe895038efcd1df4c7cf6064f5d4d400`
- **Target:** `beta`
- **Implementation checkpoint:** `fe8c15bd4133f3ac63147ec0ca01019fa50b1145` (followed by `9358ea3a9d6833bf69e997922c8b6d0fc99aa13`, which preserves URL path boundaries when populating campaign host allow-lists)
- **Intent:** Replace HackerOne's client-rendered-page regex with its public structured-scope GraphQL response, preventing silently empty scopes and prose-derived campaign allow-lists.

## Contract

- Read a HackerOne team's public structured scopes, policy text, submission state, and bounty status from `https://hackerone.com/graphql`.
- Include only submission-eligible web hosts/URLs in `in-scope.txt`; retain all structured assets in `assets.json` and excluded assets separately. App-store, CIDR, hardware/model, smart-contract, executable, and source-code assets remain metadata rather than executable network seeds.
- Refuse to overwrite scope files with zero network assets.
- Prefer canonical pulled scope files over `scope.md` prose when deriving `ProgramConfig.scope_domains`.

## Evidence

- Focused regression suite: `PYTHONPATH="$PWD" python3 -m pytest agents/test_scope_puller_seed_files.py agents/test_scope_manager.py agents/test_scope_validator.py agents/test_scope_seed_files.py -q` — 11 passed.
- Syntax and whitespace: `python3 -m py_compile agents/scope_puller.py program_config.py`; `git diff --check` — passed.
- Public read-only smoke: Snapchat structured scope returned 32 domains, 1 URL, 6 excluded assets, and 4 asset groups. No scope files were written.

## Review and activation

- Independent review is pending before merge.
- After review, merge into clean current `beta`, push from the beta worktree, then fast-forward the actual Hoster runtime checkout only after preserving/handling any dirty runtime state and run the focused no-side-effect smoke there.
- No main promotion or runtime activation beyond that explicit Hoster validation is in scope.
