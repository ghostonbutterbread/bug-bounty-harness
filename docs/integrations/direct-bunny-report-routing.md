# Direct Bunny reporting route

- **Branch/worktree:** `fix/direct-bunny-report-routing` at `/home/ryushe/worktrees/bbh-direct-bunny-report-routing`
- **Base/intended target:** fetched BBH `origin/beta` `cc8ed9f8552922bc261a41807ad84fc9a3fe5926`
- **Owner intent:** Ryu wants agent entry pointers to load standalone `bunny-report-and-triage` directly. Keep `security-reporting` only as a deprecated compatibility pointer with an immediate redirect if accidentally loaded.
- **Scope:** change source-level BBH agent/skill registry pointers and fallback banner; preserve ledger, populated `EVIDENCE.md`, report registration, independent review, privacy/live-test gates, and older packet files. The separate Bunny skill remains the final FID report writer, not Bunny campaign orchestration.
- **Verification:** local routing tests 4 passed; combined focused suite 11 passed and 30 subtests. Independent read-only review ACCEPT on implementation `88ba10a`, using isolated environment from checkout manifest and pinned Bounty Core `9968eeb`: 99 reporting/routing tests and 43 subtests passed; `git diff --check` clean. Tracked reference audit found no active `security-reporting` load instruction in agent entrypoints. Expanded reviewer run had one pre-existing unchanged dependency test expecting old Bounty Core `54ac5e8` despite manifest pin `9968eeb`; do not call that expanded run passing. Beta merge/push and runtime projection remain pending.
- **Immutable implementation checkpoint:** `88ba10aa1f74b8d92b704b3d24a2c8232586113d` (the dossier-only handoff commit follows on the same branch).
- **Resume:** after source review, integrate beta; then dry-run the selected runtime projection and verify a fresh agent loads the direct route. Do not claim activation from a repository merge.
