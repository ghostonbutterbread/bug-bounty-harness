# Retained Proxy Store lease collision — partial repair

- **Status:** independently reviewed partial implementation; broader task remains open.
- **Owner:** task `t_226eb7ae`; parent retains integration authority.
- **Branch / worktree:** `fix/proxy-store-retained-lease-collision` / `/home/ryushe/worktrees/bbh-proxy-store-retained-lease-collision`.
- **Base commit:** `d0d42eedbadb3d39694d59283b5290588f22361c` (fetched `origin/beta`).
- **Intended integration target:** `beta`.
- **Last updated:** 2026-10-28.
- **Owning feature branch/ref:** `fix/proxy-store-retained-lease-collision`.
- **Latest immutable recovery checkpoint:** `ac3b12a46c64ce42f8ada26efc415d58b33198e8` on the owning branch, after merging beta `3fa84b824c9cbefbba2dcb0d09e3bb11b331c335`.
- **Feature implementation commit(s):** `b878d832222c8cd44fd309f709aa0e584518389b`.
- **Inspiration / canonical references:** retained rows conflict with `proxy_leases` unconditional unique port/lane and primary-key lease ID; `skills/chromium-test/scripts/proxy_store.py` owns standalone acquisition.

## Intent and implemented contract

Extend the existing indexed Proxy Store script and associated tests, not a new allocator. Standalone acquisition treats all retained rows as occupying their unique identities regardless of status/TTL; it skips occupied ports or reports the existing `no-free-port`, and reports `lease-unavailable` for a conflicting lane or lease ID when considering a free port. Existing ordering, release behavior, `BEGIN IMMEDIATE`, and schema are unchanged. Acquisition does not modify or reclaim retained leases. This does not prove shutdown or listener availability.

## Evidence and review

- RED before implementation: `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /usr/bin/python3 -m pytest agents/test_proxy_store.py -q -k 'retained_port or retained_identity or no_free_port_preserves' --tb=short --basetemp "$TMPDIR/proxy-store-red" -o cache_dir="$TMPDIR/proxy-store-pytest-cache"` — 9 failed from the expected SQLite uniqueness violations (including CLI), 25 deselected. To reconstruct RED, use these committed tests with the script from base commit, in a separate disposable checkout.
- Same focused command with `--basetemp "$TMPDIR/proxy-store-green"` after implementation: 9 passed, 25 deselected.
- Full Proxy Store suite, synthetic HOME and databases: `mkdir -p "$TMPDIR/proxy-store-synthetic-home"; chmod 700 "$TMPDIR/proxy-store-synthetic-home"; HOME="$TMPDIR/proxy-store-synthetic-home" PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /usr/bin/python3 -c 'import site,sys; site.addsitedir("/home/ryushe/.local/lib/python3.12/site-packages"); import pytest; sys.exit(pytest.main(sys.argv[1:]))' agents/test_proxy_store.py agents/test_proxy_store_default_path.py -q --basetemp "$TMPDIR/proxy-store-full" -o cache_dir="$TMPDIR/proxy-store-pytest-cache"` — 39 passed. The explicit site directory was necessary on this machine because the synthetic HOME hides user-installed pytest; use an equivalent installed pytest environment elsewhere.
- Explicit `importlib` source-path check loaded this worktree's `skills/chromium-test/scripts/proxy_store.py`; tests load the same checkout via `Path(__file__).resolve()` and CLI tests use its script directly.
- After beta reconciliation, parent ran `HOME="$TMPDIR" PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q agents/test_proxy_store.py agents/test_proxy_store_default_path.py` — 39 passed. Earlier run of only `agents/test_proxy_store.py` returned 34 passed; the difference is the five default-path tests.
- `git diff --check` passed. No real database, listener, service, or target was used.
- Independent release review approved partial beta integration at `ac3b12a46c64ce42f8ada26efc415d58b33198e8`: 39 tests passed; an additional synthetic 12-case retained-identity matrix and concurrent contenders demonstrated unique reservations in the standalone database. Schema, transaction and release semantics were preserved; broader cross-store issue remains open. Parent owns integration.

## Blockers and deferred work

- **Unsolved cross-store / legacy allocation issue:** `browser_provisioner.py:start_proxy` manages `task_proxies` separately; its standard-range selection checks task rows and open ports rather than standalone retained reservations, while the overflow fallback consults only active standalone leases. Standalone acquisition does not coordinate its transaction with the separate task-proxy store. Legacy reservations and allocation/start races across stores therefore remain possible. This patch does not fix or validate cross-store safety; the task stays open.
- **Missing evidence / next step:** a separately designed shared coordination and owner-fenced recovery approach, with deterministic synthetic two-allocator concurrent and legacy-reservation regressions covering both directions and no unsafe expiry reclamation. The exact test command depends on that successor design; use synthetic private DBs and mocked listeners only. Run when that design is implemented; do not activate or claim the broader issue resolved on this branch's evidence.
- **Integration gate:** independent review approved the partial fix; parent must fetch beta, integrate and rerun synthetic suite. Do not close the broader task or activate a runtime on this evidence.

## Interruption / resume handoff

- **Exact resume point:** fetch current beta, integrate reviewed partial fix, remove this dossier from the target, and rerun the synthetic suite without closing the underlying task.
- **Activation / promotion gate:** no activation or stable promotion authorized; outstanding cross-store work is not covered by this repair.
- **Decision record:** 2026-10-28 — scoped partial repair; broader allocator coordination and safe legacy recovery intentionally deferred.
