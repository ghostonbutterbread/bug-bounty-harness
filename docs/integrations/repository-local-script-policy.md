# Repository-local script policy integration

- **Intent:** Let the shared script manager defer repository structure to one
  repo-owned contract without creating one management skill per repository.
- **Base:** `origin/beta` at `5ef9b5b304fa3ce995e3700d32f3e7d4789539ee`.
- **Target:** `beta`.
- **Branch:** `feat/repository-local-script-policy`.
- **Contract:** `SCRIPT_POLICY.md` owns BBH placement, indexing, multiple-helper,
  and scripts-only maintenance boundaries; the root catalog links every
  skill-owned script index; policy and skill files remain outside script-agent
  authority.
- **Evidence:** `tests/test_script_policy.py` was created first and failed for the
  absent policy and five missing indexes before implementation. The policy and
  focused script suites now pass (`122 passed`), all newly indexed entrypoints
  pass bounded help/syntax smoke checks, and `git diff --check` passes.
- **Baseline drift:** The broader `tests/` suite reports `114 passed` with two
  failures that reproduce unchanged on `beta`: a Bounty Core pin expectation
  mismatch and a stale command inside an unrelated completed integration
  dossier. They are outside this change and were recorded as
  `PC-20260910-222417-7495b4bc`.
- **Activation:** Merge and push BBH beta, update the selected Hoster runtime-beta
  checkout, and verify repository files through the active checkout.
- **Review:** Initial independent review blocked on incomplete index records,
  filename-only tests, one undocumented legacy cross-skill import, conflicting
  `agents/` placement text, lane-unsafe verification commands, and an incomplete
  maintenance allowlist. The follow-up adds complete/nonstale record validation,
  verification-path checks, full records for every current skill script, an
  explicit compatibility exception, one placement owner, and root-catalog edit
  authority without policy-edit authority.
- **Next:** Obtain focused re-review, reconcile current `origin/beta`, then merge
  and remove this dossier from beta.
