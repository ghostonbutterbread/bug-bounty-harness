# Recon-Ry wrapper custom header integration

- **Intent:** let agents pass repeatable `--header` values without replacing saved `urls.txt` or emptying `wild.txt`.
- **Branch / base / target:** `fix/recon-ry-custom-header` from `ea2869f07c2ed1dfc2d1f88c19346d81355d9919`; target `beta`.
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/.worktrees/recon-ry-custom-header`.
- **Contract:** generic headers, including Authorization and attribution headers, are staged with redacted metadata and forwarded to Recon-Ry while full saved-scope seeds remain intact. Account-resolved auth, explicit auth seed files, cookies, and exact-host profiles retain existing target narrowing.
- **Compatibility:** `--auth-header` remains an alias for `--header`.
- **Evidence:** `python3 -m pytest -q agents/test_recon_ry.py` passed (`17 passed`).
- **Provider dependency:** requires the reviewed Recon-Ry custom-header commit on Hoster.
- **Activation boundary:** merge to BBH beta and Hoster runtime update are separate verified steps.
- **Next:** independent review, commit, integrate to beta, push, then deploy provider and consumer commits to Hoster and run non-network smoke checks.
