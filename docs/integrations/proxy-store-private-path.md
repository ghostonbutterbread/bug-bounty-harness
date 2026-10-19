# Proxy-store private default path — integration dossier

- **Status:** feature; local verification complete, awaiting independent integration review
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

The legacy default `~/.local/share/ghost/proxy-store/` can be an operator-created symlink into `/mnt/bounty/_ghost-state/proxy-store`. The private opener correctly rejects symlinks and unfenced writable ancestors; task-proxy-finish then retains its reservation with `proxy-index-failed`. Select a separate direct local state path by default, without weakening `_open_private_parent`, following symlinks, or touching live stores, mounts, proxies, reservations, or services.

## Implemented contract

`proxy_store.py` and standalone `mitm_lane.py index-store` now default to `~/.local/state/ghost/proxy-store/proxy_store.sqlite`; `browser_provisioner.py` invokes `proxy_store.py index-lane` without `--db`, so finish/recover select that same path. Explicit `--db` remains available and subject to the existing owner, mode and no-symlink checks. Fresh default parent is created mode 0700, database mode 0600. Legacy share-path data is not migrated or merged automatically. This avoids a known symlink but fails closed if the *new* path itself is symlinked or insecure. No claim that live reservations were released.

## Evidence and review

- `./setup.sh --install-python-deps` could not run: `uv` missing on Hoster. A checkout-local `.venv` was created with `python3 -m venv .venv && .venv/bin/pip install 'pytest>=9,<10'` solely for focused tests; no dependency manifest changed. This is not a full runtime dependency installation.
- `.venv/bin/python -m pytest agents/test_proxy_store_default_path.py agents/test_proxy_store.py agents/test_mitm_lane.py agents/test_browser_provisioner.py -q --basetemp=/home/ryushe/.cache/bbh-proxy-store-safety-fixtures` — 74 passed. Regression creates legacy symlink into a group-writable fixture mount, invokes the real default CLI initialization, verifies new DB/private modes, no legacy mutation, and aligned standalone lane default. Negative case refuses a symlink at the new path. New parameterized finish/recover regression writes a real mitmproxy flow in an isolated fixture, runs the actual indexing subprocess at the new default (no `--db`), verifies a request in SQLite and reservation release; the old symlink target remains untouched. Existing finish/recover tests also cover retention and stop/conflict mechanics with mocked unit state.
- `git diff --check` — passed. Reference audit: tracked runtime references to legacy path were exactly `proxy_store.py` and `mitm_lane.py`; both updated. `BUGFIXES.md:106` is historical evidence of a separate `/tmp` fence defect and remains intentionally untouched. No live references found in the bounded repository search; `browser_provisioner.py` inherits the changed CLI default.
- Independent review: pending. This isolated feature branch is not integrated or deployed.
- Merge/ancestry evidence: branched from fetched `origin/beta` 9f56eb1; re-fetch and reconcile before review/integration.

## Blockers and deferred work

- **Missing test or evidence:** release of the retained live reservations; isolated real-flow indexing and release pass, but no live operation was attempted.
- **Command / fixture / environment needed:** review/merge into the selected `beta`, activate that checkout through the normal runtime lane procedure, then operator-run `task-proxy-recover --agent-id <owned-agent> --run-id <owned-run>` after verifying each reservation/browser/proxy state; query the new store and inspect finished reservation state. Obtain identities from the authorized operator, never infer from live state here.
- **Trigger to run it:** after reviewed integration and explicit activation approval, with known task-owned reservations and safe stop/recovery window.
- **Why it blocks integration, activation, or promotion:** does not block branch review; live-effect/deployment claims and real reservation release require runtime activation and authorized operator verification.
- **Next completion step / successor reference:** independent feature review, deliberate beta merge with this temporary dossier removed from beta, focused integrated tests, then separate approved rollout/recovery.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/proxy-store-private-path-20261019`
- **Latest immutable recovery checkpoint:** feature commit containing this dossier (read feature branch tip)
- **Feature implementation commit(s):** feature branch tip
- **Exact resume point:** fetch `origin/beta`, review the branch diff and test in worktree; do not touch live state until separate activation approval.
- **Working-tree state at handoff:** clean after commit.

## Decision gates

- **Integration gate:** independent review, fetched beta comparison, rerun focused checks on feature and integrated tree; remove temporary dossier from integration target.
- **Activation / cohort gate:** explicitly approved runtime checkout activation plus safe, task-owned recovery verification; no automatic migration of legacy database or reservations.
- **Promotion gate:** separate stable direction review and approval.

## Decision record

- 2026-10-19 — selected private local state default and kept strict opener; local regression and focused suites pass; feature handoff only, no merge/push/activation.
