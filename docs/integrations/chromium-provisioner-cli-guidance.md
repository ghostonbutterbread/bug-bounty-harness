# Chromium provisioner CLI guidance integration dossier

- **Status:** independently reviewed; beta integration pending
- **Owner:** Hermes bugfix subagent; parent owns integration
- **Branch / owning feature ref:** `docs/chromium-provisioner-cli-guidance`
- **Worktree:** `/home/ryushe/worktrees/bbh-chromium-provisioner-cli-guidance`
- **Base commit:** `de82c81bb455e459888c20370ad1d61a84f59368` (fetched `origin/beta` at branch creation)
- **Intended integration target:** `origin/beta` / local `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `e776eb541227922d1f0f6826b0b18d18c6be1d91`
- **Feature implementation commit(s):** `8a9b961427c801dd9d4b7b0247f64f3779aff6e2`, `e776eb541227922d1f0f6826b0b18d18c6be1d91`
- **Inspiration:** PC-20260928-175313-ee69bf62, PC-20260928-195534-bd7bcad5, PC-20260928-223031-a1b4997f, PC-20260928-223032-a3802a79, PC-20260927-231757-66683302

## Intent and implemented contract

Correct only Chromium Test's owning `SKILL.md` and `scripts/README.md` examples. The provisioner `request` parser supports `--task-owned`, not `--ephemeral-profile`; its `status` needs `--lease-id` and `--agent-id`; `release` additionally needs `--disposition` (`completed|handoff|cancelled`) and `--profile-health` (`healthy|needs-refresh|needs-cleanup|unknown`). Remove an unsupported direct real-launch example from the skill, leaving direct launcher tests as implementation-only dry runs. No code, live browser, Hoster, runtime projection, or papercut record changed.

## Evidence and review

- Source: `skills/chromium-test/scripts/browser_provisioner.py` parser at `main()`; checked `request/status/release --help` with local `python3` (help exits before allocation). Checkout has no `.venv`, so normal live `bbh` invocation was deliberately not attempted.
- Static parser-only AST probe truncated `main()` after `parse_args()` and checked four positive CLI shapes (named request, task-owned request, status, release) and four negative shapes (unsupported `--ephemeral-profile`, positional status program, release missing disposition, invalid health). All accepted/rejected as expected; no dispatcher reached.
- `git diff --check` passed. Bounded Chromium Test reference search now finds `--ephemeral-profile` only in the skill's explicit negative guidance and internal parser; `browser_profile_lease.py status <program>` is a separate supported CLI.
- Independent review accepted changed provisioner examples but found a pre-existing direct launcher real-run example rejected by its own guard. Removed that block; fresh re-review approved the corrected branch. `agents/test_chromium_test_launcher.py` passes 51/51; eight parser-only shapes, compilation and `git diff --check` passed. Live allocation explicitly out of scope.
- Merge/ancestry: branch created from fetched `origin/beta` `de82c81`; re-fetched beta at `5993acc110972b2eae45b77a453ccb7ebb0e6b96` and merged it cleanly into the feature at `cfb6ebee8c1393e0db211f400b99df1977c207f3` (no Chromium Test overlap). Diff against `origin/beta` contains only two owning guidance files and this temporary dossier.

## Blockers and deferred work

- No live acceptance attempted by design. Trigger only if parent authorizes a scoped runtime browser task; then use selected lane and browser-node preflight, not this documentation validation.
- Reconcile beta again if it advances; merged-tree checks, remote read-back, and runtime projection remain pending.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/chromium-provisioner-cli-guidance`
- **Latest immutable recovery checkpoint:** `e776eb541227922d1f0f6826b0b18d18c6be1d91`
- **Feature implementation commit(s):** `8a9b961427c801dd9d4b7b0247f64f3779aff6e2`, `e776eb541227922d1f0f6826b0b18d18c6be1d91`
- **Exact resume point:** reconcile current beta, integrate, remove dossier, rerun focused checks, publish and verify remote beta.
- **Working-tree state at handoff:** clean after review-follow-up commit.

## Decision gates

- **Integration gate:** independent review passed; current beta reconciliation and merged-tree checks pending.
- **Activation / cohort gate:** not requested; live runtime remains unchanged.
- **Promotion gate:** not requested.

## Decision record

- 2026-10-15 — docs-only correction prepared; no live allocation.
- 2026-10-15 — review exposed unsupported internal real-launch example; removed it and reran 51 focused launcher tests. Re-review pending.
- 2026-10-15 — fresh independent re-review accepted the corrected branch; no live browser allocated.
