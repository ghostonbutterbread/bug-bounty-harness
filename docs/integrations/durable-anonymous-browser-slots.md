# Durable anonymous browser slots

- **Task:** Allow program-scoped durable anonymous Chromium profiles (`anon`, `anon1`, `anon2`, and exact `anon<N>`) without representing them as account-inventory identities.
- **Branch / base / target:** `fix/durable-anonymous-browser-slots` / `5f4257cc675e7a167b42533b81b92174f8010481` (`beta`) / `beta`.
- **Implemented contract:** `browser_profile_lease.py status <program> --anonymous` lists available, locked, and released anonymous slots; an exact slot can be exclusively acquired, renewed, released, and reused through the existing provisioner. The stored browser profile remains program-scoped and persistent. Anonymous slots never look up an account record or auth seed. Legacy account lifecycle `live` remains accepted while inventory writers retain canonical `active`.
- **Evidence:** `uv run --with pytest python -m pytest agents/test_browser_profile_lease.py agents/test_browser_provisioner.py agents/test_chromium_test_launcher.py -q` — 60 passed. `python3 -m py_compile ...` and `git diff --check` passed. A local lease smoke demonstrated `anon2` acquire → lock → healthy release → availability.
- **Boundary:** No live browser or Hoster deployment was performed; Hoster remains execution-only and must fetch the reviewed beta commit before runtime use.
- **Next:** Review this feature branch, merge it into a clean current `beta`, rerun the focused tests from beta, then deploy the reviewed beta artifact to the desired browser node.
