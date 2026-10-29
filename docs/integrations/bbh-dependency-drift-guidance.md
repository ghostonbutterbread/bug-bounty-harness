# BBH dependency drift warning integration dossier

- **Status:** partial diagnostic improvement; independent release review pending.
- **Owner:** Hermes bugfix, task `t_4bf322c9`.
- **Branch/worktree:** `fix/bbh-dependency-drift-guidance`, `/home/ryushe/worktrees/bbh-dependency-drift-guidance`.
- **Base:** `6f34e62bcda278cba7d29d50916271f0b0c30171` (`origin/beta`); target `beta`.
- **Last updated:** 2026-10-28.
- **Recovery checkpoint / implementation:** `cf0e3c03b91ab711faedbf93ac50daa1f08005d6`.
- **Inspiration:** `PC-20261023-225539-746d33d4`; shared `coding-policy` dependency drift screen.

## Intent and implemented contract

The launcher warns on manifest versus site-packages mtime, which is a heuristic rather than proof. Current environment reports this warning although the installed bounty-core VCS commit matches the manifest pin; that single match cannot prove all dependencies are fresh. Keep the warning and suppression, stderr-only behavior, stdout/exit preservation, and existing checks. Clarify that the timestamp is a heuristic and direct the operator to compare installed dependencies including VCS revisions before reinstalling only if mismatched. This is a diagnostic improvement, not an automated complete dependency verification or a guarantee that a matching pin clears the warning.

## Evidence and review

- Active checkout manifest and installed `bounty-core` direct_url commit both `6c36ee88a60073e1b687ec32deeade24ffafdd4f`; warning was reproduced. Other dependencies were not claimed fresh.
- RED: targeted `tests/test_bbh_launcher.py::BbhLauncherTests::test_stale_venv_warns_on_stderr_and_preserves_stdout_and_exit` failed on missing heuristic explanation before production change.
- GREEN: `env PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q tests/test_bbh_launcher.py` returned 14 passed. `git diff --check` passed. No environment installation or service changes.
- Fresh independent review pending; evaluate if this partial explanation sufficiently addresses papercut or whether a safe complete comparison is necessary. Do not close an unresolved noisy-warning issue by claiming the heuristic is precise.

## Blockers and deferred work

Independent review, beta reconciliation, integrated tests and original runtime verification remain. No automated full manifest reconciliation was implemented. A matching single VCS pin is not sufficient evidence that all dependencies are current.

## Interruption / resume handoff

- **Branch:** `fix/bbh-dependency-drift-guidance`.
- **Recovery checkpoint:** `cf0e3c03b91ab711faedbf93ac50daa1f08005d6`.
- **Exact resume:** independent release review, fetch beta, integrate only if reviewer accepts proportional improvement, then verify actual selected launcher and determine papercut disposition.
- **Working tree:** intended clean after initial commit.

## Decision gates

- **Integration:** independent review, current beta ancestry, integrated tests.
- **Activation:** separate runtime verification; no reinstall authorized.
- **Stable:** explicit owner direction.

## Decision record

- 2026-10-28 — reproduced ambiguous warning; clarified heuristic and conditional remediation.
