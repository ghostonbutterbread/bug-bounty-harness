# Recon-Ry wrapper custom header integration

- **Intent:** let agents pass repeatable `--header` values without replacing saved `urls.txt` or emptying `wild.txt`.
- **Branch / base / target:** `fix/recon-ry-custom-header` from `ea2869f07c2ed1dfc2d1f88c19346d81355d9919`; target `beta`.
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/.worktrees/recon-ry-custom-header`.
- **Contract:** generic headers, including Authorization and attribution headers, are staged with redacted metadata and forwarded to Recon-Ry while full saved-scope seeds remain intact. Account-resolved auth, explicit auth seed files, cookies, and exact-host profiles retain existing target narrowing.
- **Compatibility:** `--auth-header` remains an alias for `--header`.
- **Evidence:** implementation commit `57c6e2a`; `python3 -m pytest -q agents/test_recon_ry.py` passed (`17 passed`). Independent release review approved the commit and reran the isolated suite (`17 passed`) plus an eight-case seed/header matrix.
- **Provider dependency:** deploy reviewed Recon-Ry implementation commit `86c2e9f` on Hoster before exercising this wrapper behavior.
- **Activation boundary:** merge to BBH beta and Hoster runtime update are separate verified steps.
- **Next:** merge to current beta, push and read back beta, then deploy the provider and consumer revisions to Hoster and run non-network smoke checks.
