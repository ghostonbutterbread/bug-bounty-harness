# Manual hunter Markdown metadata integration dossier

- **Status:** reconciled feature; independent re-review approved
- **Owner:** parent task `t_14f68408`; delegated script-maintenance worker
- **Branch / owning ref:** `fix/manual-hunter-markdown-metadata`
- **Worktree:** `/home/ryushe/worktrees/bbh-manual-hunter-markdown-metadata`
- **Base commit:** `33ba01fa32613804697272ac5a502aecb7abee0b` (fetched `origin/beta`)
- **Intended integration target:** `beta` (parent owns release and integration)
- **Last updated:** 2026-10-28
- **Latest immutable recovery checkpoint:** `2ad81199c6330ecb94127477c509915178523b7b`
- **Feature implementation commit(s):** `307d52b27d3c4595681525748ad51c9196ec08b8`
- **Inspiration / canonical references:** `PC-20260825-225142-bf0e203f`; `agents/manual_hunter.py`, `agents/web_finding_identity.py`, `agents/test_manual_hunter.py`

## Intent and implemented contract

Extend the existing manual-hunter parser for synthetic Markdown file imports; do not create a new script or field. Strip only the label's closing marker in `**Label:** value`, preserving actual value formatting. Preserve existing plain labels, explicit review tiers and route-identity policy. Prefer an H1 heading over a derived description only when neither explicit title nor type exists; explicit title, then type retain precedence. The web route remains the normalized `file`/derived `asset`, not a new URL ledger field. No report-generation, edit-by-FID, or existing stored-finding migration is included.

## Evidence and review

Tests run from this worktree with `HOME="$TMPDIR"`; test cases additionally isolate HOME in a synthetic temporary directory. No live targets or real findings were used. Python: `/home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python`; imported `agents.manual_hunter` and `agents.web_finding_identity` resolved to this feature worktree. Its installed Bounty Core `direct_url.json` commit was `6c36ee88a60073e1b687ec32deeade24ffafdd4f`, matching `requirements.txt`; venv has no pip, but this pin verification establishes the installed revision.

Before production edits, run:

```sh
HOME="$TMPDIR" /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -q -p no:cacheprovider agents/test_manual_hunter.py -k 'test_from_file_markdown_class_is_stored_without_bold_markers or test_from_file_markdown_severity_is_normalized or test_from_file_heading_supplies_title_with_explicit_description'
```

Expected RED: **3 failed, 43 deselected**. Stored class was `**-idor` instead of `idor`, severity `UNKNOWN` instead of `HIGH`, and title was the description instead of the heading. Each test exercised `--from-file` through `main` and the synthetic ledger. After implementation, the same selection yielded **3 passed, 43 deselected**.

Final checks:

```sh
HOME="$TMPDIR" /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -q -p no:cacheprovider agents/test_manual_hunter.py -k 'test_from_file_markdown or test_from_file_heading_supplies_title or test_from_file_bold_metadata or test_markdown_preserves_plain_labels'
HOME="$TMPDIR" /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -q -p no:cacheprovider agents/test_manual_hunter.py
```

Results: **5 passed, 43 deselected**; **48 passed, 13 subtests passed**. The web end-to-end case verifies explicit URL route identity, query removal, existing asset projection, severity normalization and explicit title/type precedence. Existing suite covers hostname inference, prior heading behavior, FID edit and evidence/report handling. `git diff --check` passed before commit.

- **Independent review:** fresh reviewer found no blocking code defect on `db38788341bf88ad565a40ca025c854c06ee6d96`, independently reproduced the defect and passed 48 tests plus 13 subtests and synthetic edge cases. Reviewer required reconciliation after beta advanced. A second independent reviewer approved reconciled tip `2ad81199c6330ecb94127477c509915178523b7b`, confirmed ancestry and clean merge-tree, verified imports and matching dependency pin, and reran 48 tests plus 13 subtests.
- **Merge/ancestry:** merged fetched `origin/beta` `d0d42eedbadb3d39694d59283b5290588f22361c` into feature `20e356246b4b0ea79ac0697ca6bb2795d3170ca4`; the 48 tests plus 13 subtests passed again. `origin/master` at `7c2194a1eff3a100e53a90a9302980441f5f10e0` is an ancestor of beta but its parser differs materially; stable remains unmodified and requires separate authorization for promotion.

## Blockers and deferred work

- **Missing evidence:** integrated-tree test rerun; parent-owned integration gate.
- **Command/environment:** use the focused and full commands above in the feature worktree; confirm feature imports and Bounty Core pin in the chosen environment. Review diff for portable behavior and any changed beta tip.
- **Trigger:** before integrating into beta. Fetch the target, assess ancestry and reconcile if it advanced; re-run tests after any reconciliation.
- **Why it blocks closure:** beta integration and integrated-tree checks have not yet been performed.
- **Next step:** parent integrates and verifies beta. Do not automatically modify previously stored findings.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/manual-hunter-markdown-metadata`
- **Latest immutable recovery checkpoint:** `2ad81199c6330ecb94127477c509915178523b7b`; implementation `307d52b27d3c4595681525748ad51c9196ec08b8`.
- **Exact resume point:** fetch and verify beta, integrate reviewed feature, retire dossier from target, rerun tests and check runtime activation before closing the papercut.
- **Working-tree state at handoff:** intended clean after scoped commits.

## Decision gates

- **Integration:** parent-owned independent review, clean/reconciled target, and passing checks.
- **Activation:** not performed; requires explicit owner decision.
- **Promotion:** not authorized; stable ownership/propagation needs assessment by parent.

## Decision record

- 2026-10-28 — extended existing parser; recorded pre-edit RED and post-edit GREEN, awaiting independent review.
- 2026-10-28 — independent review found no code blocker; merged advanced beta and reran full manual-hunter test suite; re-review pending.
- 2026-10-28 — independent re-review approved reconciled tip; integration remains.
