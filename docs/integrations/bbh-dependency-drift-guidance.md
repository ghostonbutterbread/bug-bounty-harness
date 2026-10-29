# BBH dependency drift warning integration dossier

- **Status:** independent review approved reconciled feature `5e8be5acbf59eb01cbd50671d2155f9290ded9f9` for integration to exact beta `09172c72933b1c60cecf8980a41e16b39608ee96`; integrated tests and remote readback remain required.
- **Owner:** Hermes bugfix, task `t_4bf322c9`.
- **Branch/worktree:** `fix/bbh-dependency-drift-guidance`, `/home/ryushe/worktrees/bbh-dependency-drift-guidance`.
- **Base:** `6f34e62bcda278cba7d29d50916271f0b0c30171` (`origin/beta`); target `beta`.
- **Last updated:** 2026-10-29.
- **Recovery checkpoint:** `fd4b5f0bc87e053cb3cd7f8ae67306ca5f0999d3` (merge; this dossier update is a successor); implementation `cf0e3c03b91ab711faedbf93ac50daa1f08005d6`, review corrections `80967d8561d17afd05ceda08666ce9f6ce82d843`.
- **Inspiration:** `PC-20261023-225539-746d33d4`; shared `coding-policy` dependency drift screen.

## Intent and implemented contract

The launcher warns on manifest versus site-packages mtime, which is a heuristic rather than proof. Current environment reports this warning although the installed bounty-core VCS commit matches the manifest pin; that single match cannot prove all dependencies are fresh. Keep the warning and suppression, stderr-only behavior, stdout/exit preservation, and existing checks. Clarify that the timestamp is a heuristic and direct the operator to compare installed dependencies including VCS revisions before reinstalling only if mismatched. This is a diagnostic improvement, not an automated complete dependency verification or a guarantee that a matching pin clears the warning.

## Evidence and review

- Active checkout manifest and installed `bounty-core` direct_url commit both `6c36ee88a60073e1b687ec32deeade24ffafdd4f`; warning was reproduced. Other dependencies were not claimed fresh.
- RED: targeted `tests/test_bbh_launcher.py::BbhLauncherTests::test_stale_venv_warns_on_stderr_and_preserves_stdout_and_exit` failed on missing heuristic explanation before production change.
- GREEN: `env PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q tests/test_bbh_launcher.py` returned 14 passed. `git diff --check` passed. No environment installation or service changes.
- Independent review blocked `84b9c74`: warning lacked a usable VCS comparison, did not explain persistence, and used `./setup.sh` relative to an arbitrary cwd. Added selected-lane `bbh --root` remediation, persistent-warning explanation, and a BBH launcher guide with a read-only installed VCS revision check. Added targeted failing assertions before correcting the warning.
- After correction, launcher and lane-safety tests returned 16 passed. The documented read-only revision command ran against the actual selected checkout and returned `6c36ee88a60073e1b687ec32deeade24ffafdd4f`. Independent re-review pending; the original warning continues to appear after a valid comparison and the papercut must not be closed merely because the wording changed.
- Beta `379e8fcc1dfc89b967a4cc2b260a09b5c842efbb` was merged as `414655017b7821de42346a7fdb1c8eb6417ae68b`; the same 16 tests and diff check passed after reconciliation. Re-review the reconciled tip.
- Independent re-review blocked `0690b30`: source changes and 16 tests looked correct, but the reviewer could not execute the documented read-only revision command because tool approval timed out. Parent's earlier successful command is not an independent execution receipt. No bypass or retry of the blocked operation was attempted.
- Subsequent independent review of `1419b80c99a8cc6d2cf12797e8c661a326537f10`, as reported by the parent, executed the guide's exact read-only pin comparison and independently verified 16 focused tests. The comparison matched; integration was blocked pending reconciliation with advanced beta. This supersedes the earlier missing-command blocker, not the requirement to review the reconciled tip.
- Fetched `origin/beta` at `70edc5a8b9494df6b4b18a927d8cbb87e7d1fe94` and merged it into the feature as `fa475713e5212f5214c594fbdc596f022aa622f6` without conflict. The launcher dependency diagnostics and beta's parameter-mining documentation are both retained. `env PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q tests/test_bbh_launcher.py tests/test_skill_command_lane_safety.py` returned **16 passed**; `git diff --check origin/beta...HEAD` and `git diff --check` passed. The test environment's manifest matched this checkout; no installation was performed.
- Fetched `origin/beta` at `09172c72933b1c60cecf8980a41e16b39608ee96` and merged it without conflict as `fd4b5f0bc87e053cb3cd7f8ae67306ca5f0999d3`, preserving both dependency-warning work and beta's auth-contract changes. From this feature checkout, `env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD" /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q tests/test_bbh_launcher.py tests/test_skill_command_lane_safety.py` returned **16 passed in 0.53s**; `git diff --check` and `git diff --check 09172c72933b1c60cecf8980a41e16b39608ee96...HEAD` passed. The test and launcher resolved to this feature checkout; pytest came from the selected integration venv. The environment checkout and feature manifest Git blobs matched; the manifest was newer than site-packages, and the installed bounty-core VCS revision matched the manifest pin. That does not prove all dependencies are current. No install was performed.

## Blockers and deferred work

Fresh independent review approved the reconciled feature tip. Integrated tests and separate original runtime verification remain. No automated full manifest reconciliation was implemented; a matching single VCS pin is not sufficient evidence that all dependencies are current. The warning can remain noisy even after a valid comparison, so the original issue remains open.

## Interruption / resume handoff

- **Branch:** `fix/bbh-dependency-drift-guidance`.
- **Recovery checkpoint:** `fd4b5f0bc87e053cb3cd7f8ae67306ca5f0999d3` (reconciled merge; dossier-only successor must also be reviewed).
- **Exact resume:** refetch exact named beta before integration; merge the approved feature, retire this task-owned dossier from beta, run the integrated focused tests, and verify the named remote beta after push. Keep the noisy-warning papercut open until its full issue is actually resolved.
- **Working tree:** intended clean after the dossier checkpoint commit.

## Decision gates

- **Integration:** independent review, current beta ancestry, integrated tests.
- **Activation:** separate runtime verification; no reinstall authorized.
- **Stable:** explicit owner direction.

## Decision record

- 2026-10-28 — reproduced ambiguous warning; clarified heuristic and conditional remediation.
- 2026-10-28 — independent review blocked; added actionable selected-root diagnostics and persistent-warning disclosure, awaiting re-review.
- 2026-10-28 — independent re-review blocked because required read-only command approval timed out; no integration.
- 2026-10-29 — subsequent independent command and focused tests verified on the previous feature tip; merged fetched beta, reran focused tests, and deferred fresh independent review of the reconciled tip. No integration or activation.
- 2026-10-29 — reconciled freshly fetched beta `09172c72933b1c60cecf8980a41e16b39608ee96`, preserving auth-contract changes; focused tests passed. Fresh independent review and owner-controlled integration remain deferred.
- 2026-10-29 — fresh independent release review approved `5e8be5acbf59eb01cbd50671d2155f9290ded9f9` against fetched beta `09172c72933b1c60cecf8980a41e16b39608ee96`. Exact diff and merge ancestry preserve parameter-mining and Auth Contract; no overlapping changed worktrees observed. Feature tests: `env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD" /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q tests/test_bbh_launcher.py tests/test_skill_command_lane_safety.py` — 16 passed in 0.50s; both diff checks passed. From `/home/ryushe`, the exact guide's pip-free command with beta `scripts` on PATH returned installed bounty-core `6c36ee88a60073e1b687ec32deeade24ffafdd4f`, matching beta root's manifest. Selected root and diagnostic path were independent of cwd; feature launcher independently selected feature root. No other dependency freshness is asserted. Integrated tests and remote readback are required, and runtime activation remains separate.
