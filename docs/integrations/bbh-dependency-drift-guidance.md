# BBH dependency drift warning integration dossier

- **Status:** blocked; independent release re-review lacks required command execution.
- **Owner:** Hermes bugfix, task `t_4bf322c9`.
- **Branch/worktree:** `fix/bbh-dependency-drift-guidance`, `/home/ryushe/worktrees/bbh-dependency-drift-guidance`.
- **Base:** `6f34e62bcda278cba7d29d50916271f0b0c30171` (`origin/beta`); target `beta`.
- **Last updated:** 2026-10-28.
- **Recovery checkpoint:** `0690b30502ef06eeb695a110176f02a304a03e6f`; implementation `cf0e3c03b91ab711faedbf93ac50daa1f08005d6`, review corrections `80967d8561d17afd05ceda08666ce9f6ce82d843`.
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

## Blockers and deferred work

Missing independent evidence: execute the guide's read-only Bounty Core VCS revision command using a context where the approval gate permits it; compare output with the selected checkout's manifest, then re-review the exact feature tip. This blocks release. Integrated tests and original runtime verification also remain. No automated full manifest reconciliation was implemented; a matching single VCS pin is not sufficient evidence that all dependencies are current.

## Interruption / resume handoff

- **Branch:** `fix/bbh-dependency-drift-guidance`.
- **Recovery checkpoint:** `0690b30502ef06eeb695a110176f02a304a03e6f` (this blocker update will be a dossier-only successor).
- **Exact resume:** once independent command execution is approved, re-review exact feature tip; reconcile current beta, integrate only if approved, and verify selected launcher. Keep the noisy-warning papercut open until its full issue is actually resolved.
- **Working tree:** intended clean after initial commit.

## Decision gates

- **Integration:** independent review, current beta ancestry, integrated tests.
- **Activation:** separate runtime verification; no reinstall authorized.
- **Stable:** explicit owner direction.

## Decision record

- 2026-10-28 — reproduced ambiguous warning; clarified heuristic and conditional remediation.
- 2026-10-28 — independent review blocked; added actionable selected-root diagnostics and persistent-warning disclosure, awaiting re-review.
- 2026-10-28 — independent re-review blocked because required read-only command approval timed out; no integration.
