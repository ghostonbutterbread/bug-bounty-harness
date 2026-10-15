# Chromium provisioner CLI guidance integration dossier

- **Status:** feature (parent review pending)
- **Owner:** Hermes bugfix subagent; parent owns integration
- **Branch / owning feature ref:** `docs/chromium-provisioner-cli-guidance`
- **Worktree:** `/home/ryushe/worktrees/bbh-chromium-provisioner-cli-guidance`
- **Base commit:** `de82c81bb455e459888c20370ad1d61a84f59368` (fetched `origin/beta` at branch creation)
- **Intended integration target:** `origin/beta` / local `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** pending first commit
- **Feature implementation commit(s):** pending first commit
- **Inspiration:** PC-20260928-175313-ee69bf62, PC-20260928-195534-bd7bcad5, PC-20260928-223031-a1b4997f, PC-20260928-223032-a3802a79, PC-20260927-231757-66683302

## Intent and implemented contract

Correct only Chromium Test's owning `SKILL.md` and `scripts/README.md` examples. The provisioner `request` parser supports `--task-owned`, not `--ephemeral-profile`; its `status` needs `--lease-id` and `--agent-id`; `release` additionally needs `--disposition` (`completed|handoff|cancelled`) and `--profile-health` (`healthy|needs-refresh|needs-cleanup|unknown`). Keep the launcher-only `--ephemeral-profile` example distinct from the provisioner. No code, live browser, Hoster, runtime projection, or papercut record changed.

## Evidence and review

- Source: `skills/chromium-test/scripts/browser_provisioner.py` parser at `main()`; checked `request/status/release --help` with local `python3` (help exits before allocation). Checkout has no `.venv`, so normal live `bbh` invocation was deliberately not attempted.
- Static parser-only AST probe truncated `main()` after `parse_args()` and checked four positive CLI shapes (named request, task-owned request, status, release) and four negative shapes (unsupported `--ephemeral-profile`, positional status program, release missing disposition, invalid health). All accepted/rejected as expected; no dispatcher reached.
- `git diff --check` passed. Bounded Chromium Test reference search found remaining `--ephemeral-profile` only in the internal `chromium_test.py` launcher example and parser, plus the skill's explicit warning; `browser_profile_lease.py status <program>` is a separate supported CLI.
- Independent review: parent pending. Live allocation explicitly out of scope.
- Merge/ancestry: branch created from fetched `origin/beta` `de82c81`; re-fetch and reconcile before integration.

## Blockers and deferred work

- No live acceptance attempted by design. Trigger only if parent authorizes a scoped runtime browser task; then use selected lane and browser-node preflight, not this documentation validation.
- Parent must independently review the diff and reconcile any advancing `origin/beta` before merge. Do not push, integrate, close papercuts, or project to Hoster from this branch.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/chromium-provisioner-cli-guidance`
- **Latest immutable recovery checkpoint:** pending first commit
- **Feature implementation commit(s):** pending first commit
- **Exact resume point:** parent review and beta reconciliation; no other edits expected.
- **Working-tree state at handoff:** clean after commit (to verify).

## Decision gates

- **Integration gate:** parent independent review and current beta reconciliation.
- **Activation / cohort gate:** not requested; live runtime remains unchanged.
- **Promotion gate:** not requested.

## Decision record

- 2026-10-15 — docs-only correction prepared; no live allocation.
