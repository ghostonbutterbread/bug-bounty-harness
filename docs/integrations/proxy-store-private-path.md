# Proxy-store private default path — integration dossier

- **Status:** independent review blocker repaired on feature branch; focused verification complete; re-review required before integration
- **Owner:** BBH proxy-store / Chromium Test script maintenance
- **Branch:** `fix/proxy-store-private-path-20261019`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness-proxy-store-private-path-20261019` (Hoster)
- **Base commit:** `9f56eb16d480eda212f7f76108a329d434aa9d9a` (`origin/beta` fetched 2026-10-19)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-19
- **Owning feature branch/ref:** `fix/proxy-store-private-path-20261019`
- **Latest immutable recovery checkpoint:** this feature commit (see Git history; self-SHA cannot be embedded)
- **Feature implementation commit(s):** this feature commit
- **Inspiration / canonical references:** PC-20261017-011032-3e67adf3; `skills/chromium-test/scripts/proxy_store.py`, `mitm_lane.py`, `browser_provisioner.py:task_proxy_finish`.

## Intent

The legacy default `~/.local/share/ghost/proxy-store/` can be an operator-created symlink into `/mnt/bounty/_ghost-state/proxy-store`. The private opener correctly rejects symlinks and unfenced writable ancestors. The first feature commit changed the default without preserving old indexed requests and leases; independent review found that a new empty DB could silently allocate ports occupied by old reservations. This correction blocks default-store use while the legacy entry exists, requires a frozen operator-controlled SQLite backup and verification, and leaves live state untouched.

## Implemented contract

`proxy_store.py` and standalone `mitm_lane.py index-store` default to `~/.local/state/ghost/proxy-store/proxy_store.sqlite`; `browser_provisioner.py` invokes `proxy_store.py index-lane` without `--db`. The default now hard-fails **before any command**, including reads and `lease-acquire`, whenever the old `~/.local/share/ghost/proxy-store` entry exists (regular directory, symlink, or dangling symlink). The same gate applies to explicit `--db` naming the new default and direct `connect()` callers. Explicit `--db` for other private paths remains available but never follows the legacy symlink. The private opener is unchanged. There is no automatic copy or lease release; fresh hosts without legacy state initialize privately. Detailed operator-only activation/migration and rollback gates are in `skills/chromium-test/scripts/README.md` under `Operator-only activation gate for legacy stores`.

## Evidence and review

- `./setup.sh --install-python-deps` could not run: `uv` missing on Hoster. A checkout-local `.venv` was created with `python3 -m venv .venv && .venv/bin/pip install 'pytest>=9,<10'` solely for focused tests; no dependency manifest changed. This is not a full runtime dependency installation.
- `.venv/bin/python -m pytest agents/test_proxy_store_default_path.py agents/test_proxy_store.py agents/test_mitm_lane.py agents/test_browser_provisioner.py -q --basetemp=/home/ryushe/.cache/bbh-proxy-store-safety-fixtures` — **80 passed** after review correction. First red-capable regression demonstrated a populated old DB's port 8081 was leased anew before the gate. After correction, old symlink, directory, and dangling symlink block all default commands before new DB mutation; explicit `--db` through old symlink remains rejected. An isolated frozen SQLite backup fixture transfers old request and lease rows, confirms old request visibility and that port 8081 remains unavailable after old-entry retirement. Finish/recover indexing remains green after simulated completed migration (legacy entry absent). No live DB or service touched.
- `git diff --check` — passed. Reference audit: tracked runtime references to legacy path are now only the guard, tests, documentation and historical dossier; `mitm_lane.py` uses the new default and `browser_provisioner.py` inherits it. `BUGFIXES.md:106` is historical evidence of a separate `/tmp` fence defect and remains untouched.
- Independent review: initial review blocked release on hidden legacy records/reservations. This correction is **not independently re-reviewed**; no merge/push/deployment performed.
- Merge/ancestry evidence: branched from `origin/beta` 9f56eb1; `git fetch origin beta` rerun before correction (still same base). Re-fetch and reconcile before independent review/integration.

## Blockers and deferred work

- **Missing test or evidence:** independent re-review of corrected gate and operator-only live migration/activation receipt. Fixture migration and port fencing are tested; no live operation was attempted.
- **Command / fixture / environment needed:** after independent acceptance, explicitly approved freeze of all old/new proxy-store writers on the affected host; use `skills/chromium-test/scripts/README.md` operator gate to take SQLite online backup, compare integrity/counts/active leases, preserve old DB, retire the old path, then verify new default `query` and `leases --active` before resuming task-owned recovery. This is not an unattended startup step.
- **Trigger to run it:** reviewed integration plus explicit operator authorization and a safe window with every indexer/allocator/finish/recover consumer fenced.
- **Why it blocks integration, activation, or promotion:** independent re-review blocks integration; operator freeze/migration blocks activation on hosts with legacy state. Live-effect/deployment claims require separate authorized verification.
- **Next completion step / successor reference:** fresh independent review of correction, deliberate beta integration with temporary dossier removed, integrated focused tests; later operator-controlled migration and activation.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/proxy-store-private-path-20261019`
- **Latest immutable recovery checkpoint:** feature commit containing this dossier (read feature branch tip)
- **Feature implementation commit(s):** feature branch tip
- **Exact resume point:** fresh independent review of the corrected branch diff and 80-test suite, then coordinate operator-frozen migration before any activation on a legacy-state host.
- **Working-tree state at handoff:** clean after correction commit.

## Decision gates

- **Integration gate:** fresh independent review of correction, fetched beta comparison, rerun focused checks on feature and integrated tree; remove temporary dossier from integration target.
- **Activation / cohort gate:** explicit operator freeze, SQLite backup and row/lease verification, old-entry retirement, new-default readback; never silently start with a second empty database.
- **Promotion gate:** separate stable direction review and approval.

## Decision record

- 2026-10-19 — independent review rejected silent default switch; added fail-closed legacy-entry guard and frozen operator migration runbook; 80 focused tests pass, no live migration or integration.
