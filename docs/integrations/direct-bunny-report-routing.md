# Direct Bunny reporting route

- **Branch/worktree:** `fix/direct-bunny-report-routing` at `/home/ryushe/worktrees/bbh-direct-bunny-report-routing`
- **Base/intended target:** fetched BBH `origin/beta` `cc8ed9f8552922bc261a41807ad84fc9a3fe5926`
- **Owner intent:** Ryu wants agent entry pointers to load standalone `bunny-report-and-triage` directly. Keep `security-reporting` only as a deprecated compatibility pointer with an immediate redirect if accidentally loaded.
- **Scope:** change source-level BBH agent/skill registry pointers and fallback banner; preserve ledger, populated `EVIDENCE.md`, report registration, independent review, privacy/live-test gates, and older packet files. The separate Bunny skill remains the final FID report writer, not Bunny campaign orchestration.
- **Verification:** `python3 -m unittest tests.test_security_reporting_skill -q` 4 passed; `python3 -m pytest -q agents/test_finding_submission.py agents/test_finding_report.py tests/test_security_reporting_skill.py` 11 passed and 30 subtests. `git diff --check` clean. Tracked reference audit finds no `security-reporting` load instruction in the five agent-facing entrypoints; only registry fallback remains. Independent review and beta projection still pending.
- **Resume:** after source review, integrate beta; then dry-run the selected runtime projection and verify a fresh agent loads the direct route. Do not claim activation from a repository merge.
