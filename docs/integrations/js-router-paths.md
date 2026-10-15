# JS router path integration dossier

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `docs/js-router-paths`
- **Worktree:** `/home/ryushe/worktrees/bbh-js-router-paths`
- **Base commit:** `de82c81bb455e459888c20370ad1d61a84f59368` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commits:** none yet
- **Inspiration:** `PC-20260910-180201-1040cd76`, `PC-20260913-193206-1fa59327`.

## Intent and contract

Clarify BBH repository-root-relative JS references and use the existing `bbh` launcher form instead of implying scripts live under the skill directory. No target fetch, analyzer behavior, or runtime installation changes.

## Evidence and review

- Verified four referenced files exist under the fetched BBH root, not under `skills/js/`.
- `bbh agents/js_analyzer.py inventory --help` in the clean worktree could not run because that checkout lacks its local virtualenv; no analyzer invocation or target request was made. Static path/reference validation succeeded; runtime smoke remains deferred until a provisioned checkout.
- `git diff --check` clean.
- Independent review and merge pending.

## Blockers and deferred work

- **Missing evidence:** CLI smoke in a provisioned BBH checkout.
- **Command:** `bbh agents/js_analyzer.py inventory --help` after `./setup.sh --install-python-deps` in the selected checkout.
- **Trigger:** use a provisioned BBH beta runtime before claiming activation.
- **Scope:** docs reference correction can be reviewed/merged with static path checks; live activation is not claimed.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/js-router-paths`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commits:** none yet
- **Exact resume point:** commit, independent review, reconcile latest beta, integrate, verify resolved references from beta; close matching papercuts only after verification.
- **Working-tree state:** implementation and dossier uncommitted until checkpoint.

## Decision gates

- **Integration:** static references, review, clean beta merge.
- **Activation:** provisioned runtime CLI smoke before activation claim.
- **Promotion:** no stable promotion requested.

## Decision record

- 2026-10-15 — current router misanchors repository paths; minimal guidance patch, review pending.
