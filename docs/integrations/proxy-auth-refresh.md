# Proxy auth refresh integration dossier

- **Task:** two-stage named-account proxy auth refresh
- **Branch / worktree:** `feat/proxy-auth-refresh` / `/home/ryushe/worktrees/bbh-proxy-auth-refresh`
- **Base / target:** `c1b30af` (`beta`) → `beta`
- **Intent:** make approved `ryushe-proxy` account refresh retrieve a selected request by opaque Caido ID after sanitized discovery, so restricted auth headers reach only the configured locked auth seed.
- **Contract:** list requests using non-secret account/color/host/path constraints; retrieve selected request IDs through `get_requests_by_ids`; verify configured required header names; preserve application headers except the existing replay denylist; never expose values in CLI metadata or write them to inventory/Git.
- **Activation boundary:** no scheduler/authenticated recon activation. A named account must pass its declared safe auth check after refresh.
- **Verification:** focused resolver unit tests, syntax/diff checks, live named-account source refresh proving metadata-only discovery and restricted ID retrieval, then a separately task-MITM-routed auth-check receipt.
- **Blocker / deferred test:** live profile check remains contingent on the program-declared endpoint matching an actual safe authenticated application route.
