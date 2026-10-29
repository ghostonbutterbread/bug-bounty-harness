# Proxy Store query help integration dossier

- **Status:** independently reviewed; integration pending.
- **Owner:** Hermes bugfix, Kanban `t_5fdff9d8`.
- **Branch:** `fix/proxy-store-query-help`; worktree `/home/ryushe/worktrees/bbh-proxy-store-query-help`.
- **Base:** `6f34e62bcda278cba7d29d50916271f0b0c30171` (`origin/beta`).
- **Intended target:** `beta`; stable promotion and activation are separate.
- **Last updated:** 2026-10-28.
- **Recovery checkpoint:** `6e577963acb12dc799cce4e78b6732c8c9b49a1b`; implementation `ca460aad3c1649dd16c37665f21ddc05e152bb5d`.
- **Inspiration:** `PC-20261019-192049-a342d36f`.

## Intent and implemented contract

Fix `query --help` argparse formatting of literal percent signs in SQL LIKE examples. Escape percent signs in help strings only; displayed examples remain literal `%.example.com` and `/api/%`. No database, allocation, query semantics or runtime service behavior changes.

## Evidence and review

- RED: `PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q agents/test_proxy_store.py::test_query_help_displays_literal_sql_like_patterns_without_opening_db` failed with the observed `TypeError: must be real number, not dict` before the patch.
- GREEN: `HOME="$TMPDIR" PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q agents/test_proxy_store.py agents/test_proxy_store_default_path.py` returned 40 passed; the new test asserts both literal examples, exit 0 and that no DB is created.
- `git diff --check` passed; no real DB or service was touched. Independent release reviewer approved `6e577963acb12dc799cce4e78b6732c8c9b49a1b`, reproduced baseline TypeError, reran 40 tests, verified feature checkout source and instrumented zero SQLite calls on help.

## Blockers and deferred work

Integrated-tree tests are required before closure. Original Hoster runtime must be verified separately; no live activation implied. Separate cross-store reservation issues remain open.

## Interruption / resume handoff

- **Feature branch:** `fix/proxy-store-query-help`.
- **Recovery checkpoint:** `6e577963acb12dc799cce4e78b6732c8c9b49a1b`.
- **Exact resume:** fetch current beta, integrate reviewed feature and rerun tests; check affected runtime before closing papercut.
- **Working tree:** intended clean after initial commit.

## Decision gates

- **Integration:** fresh independent review, no beta drift, integrated tests.
- **Activation:** separate authorization and runtime verification.
- **Promotion:** stable changes need explicit authorization.

## Decision record

- 2026-10-28 — reproduced help crash, tested literal percent correction.
- 2026-10-28 — independent release review approved; integration pending.
