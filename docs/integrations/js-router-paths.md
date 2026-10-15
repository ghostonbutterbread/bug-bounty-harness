# JS router path integration dossier

- **Status:** independent re-review approved; reconciled with current beta, integration pending
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `docs/js-router-paths`
- **Worktree:** `/home/ryushe/worktrees/bbh-js-router-paths`
- **Base commit:** `de82c81bb455e459888c20370ad1d61a84f59368` (`origin/beta` at branch creation)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `40e60e7` (review follow-up; the subsequent beta merge and this dossier update are on the current branch tip)
- **Feature implementation commits:** `13889e83b5bce4e190c90d6a16693c3c4452ad47`, `40e60e7`.
- **Inspiration:** `PC-20260910-180201-1040cd76`, `PC-20260913-193206-1fa59327`.

## Intent and contract

Clarify BBH repository-root-relative JS references and use the existing `bbh` launcher form instead of implying scripts live under the skill directory. No target fetch, analyzer behavior, or runtime installation changes.

## Evidence and review

- Four referenced files exist under the fetched BBH root, not under `skills/js/`; the live offline-fanout command was updated after independent review.
- `./scripts/bbh --print-command agents/js_analyzer.py` selected this checkout's analyzer path. `python3 -m pytest tests/test_js_hunt_skill.py -q` passed 5/5 including a BBH-root reference regression.
- `git diff --check` clean.
- Initial independent review found one stale fanout reference, checkpoint inaccuracies, and ambient-launcher ambiguity. Independent re-review approved the corrected branch for reconciliation after 19 focused router/launcher tests and a no-conflict merge-tree check. Reconciled against fetched `origin/beta` `88c2df21e987f1e2548cb25e687f0302eaa1d9d9`; 19 tests and `git diff --check origin/beta...HEAD` passed. Clean beta integration and publication remain.

## Blockers and deferred work

- **Missing evidence:** CLI smoke in a provisioned BBH checkout.
- **Command:** `./scripts/bbh agents/js_analyzer.py inventory --help` after `./setup.sh --install-python-deps` in this checkout. Verify lane selection before relying on ambient `bbh`.
- **Trigger:** a provisioned BBH beta runtime before claiming activation.
- **Scope:** docs reference correction can be reviewed/merged with static path checks; live activation is not claimed. The ambient `bbh` currently selects a different checkout and the clean worktree lacks its own virtualenv.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/js-router-paths`
- **Latest immutable recovery checkpoint:** `40e60e7` (review follow-up; the subsequent beta merge and this dossier update are on the current branch tip)
- **Feature implementation commits:** `13889e83b5bce4e190c90d6a16693c3c4452ad47`, `40e60e7`.
- **Exact resume point:** integrate into clean beta, remove this temporary dossier, verify resolved references and focused tests from beta; close matching papercuts only after publication and read-back.
- **Working-tree state at handoff:** clean after dossier checkpoint commit.

## Decision gates

- **Integration:** static references, focused test, re-review, clean beta merge.
- **Activation:** provisioned runtime CLI smoke before activation claim.
- **Promotion:** no stable promotion requested.

## Decision record

- 2026-10-15 — initial router path guidance committed as `13889e83b5bce4e190c90d6a16693c3c4452ad47`.
- 2026-10-15 — independent review found one live reference and handoff gaps; patched fanout, added a regression, and corrected checkout-local launcher verification.
- 2026-10-15 — independent re-review approved for reconciliation. Merged fetched beta `88c2df2` without conflicts and reran 19 focused tests; runtime analyzer CLI smoke remains deferred to a provisioned checkout.
