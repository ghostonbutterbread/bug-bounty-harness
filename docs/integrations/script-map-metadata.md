# Script-map metadata exception

- Status: blocked for release; verified local partial documentation change.
- Owner/task: bugfix-profile delegated script-map alignment; parent owns Kanban/review.
- Worktree: `/home/ryushe/projects/.worktrees/bbh-script-map-metadata`
- Branch: `docs/script-map-metadata`
- Base: `7fb840d8493a53d1bccfd02e5407f92d3e0d7104` (fetched `beta` / `origin/beta`).
- Target: `beta`, only after parent independent review and resolving the blocker.

## Contract and changed boundary

User authorized a documentation-only exception: scripts-only maintenance may add
a script-map pointer to the owning main SKILL.md (no unrelated body edits), freely
maintain associated map/index entries in the existing docs/references/skill-local
README layout, and MUST update that map when creating a script.

Changed only SCRIPT_POLICY.md and its existing tests, plus this branch dossier.
Preserved script placement/catalog rules and normal branch/test/review/release
requirements. No runtime, scanner, security automation, or permission machinery.
Alignment checked canonical coding operations/proposal routing, Script Manager,
policy-authoring, installed branch-lifecycle, and root AGENTS.md.

## Verification

From this worktree: `PYTHONPATH="$PWD" python3 -m pytest tests/test_script_policy.py -q`
returned 23 passed. `git diff --check` passed. Tests use checkout-relative paths
and cover catalogs, linked indexes, records, and the clarified metadata boundary.
These checks do not prove cross-document alignment while AGENTS.md remains stale.

## Release blocker and exact resume point

The normal patch tool denied the AGENTS.md edit as a protected agent-instruction
write. No retry or alternate write path was attempted. Parent must obtain the
required approval and replace this final paragraph fragment in AGENTS.md:

```text
unavailable, use `coding-proposal-packets-policy`. If the needed change is a
skill or policy, write a skill seed instead of editing it here.
```

with:

```text
unavailable, use `coding-proposal-packets-policy`. The metadata-only exception in
`SCRIPT_POLICY.md` allows adding a script-map pointer to the main `SKILL.md` and
maintaining associated map/index entries; creating a script MUST update its map.
For other skill or policy changes, write a skill seed instead of editing here.
```

Then rerun the focused tests, inspect alignment with the other canonical owners,
and independently review before integration. No merge, push, stable promotion,
or runtime activation performed. Retain this blocked branch; remove the dossier
from the integration target only on acceptance. Recovery implementation checkpoint:
`0800efa1f4dce16618d13e08ebda86e9baaa8e89` on `docs/script-map-metadata`.
It contains the documentation/test changes; the subsequent dossier-only commit
records this immutable checkpoint. Verify that handoff-only range separately.

## Reconciled cleanup checkpoint

User now treats script discovery and canonical lifecycle migration as cohesive
work, but explicitly holds all pushes and deployments. Original base above is
historical, not the current remote. Fetched `origin/beta` advanced to `0d9231e`;
merged that upstream into this isolated feature without conflicts at immutable
reconciliation checkpoint `ee0102b5e93c2adfafc9db78ee0da7664fdfa701`.
This following dossier-only commit records the checkpoint. Relative to fetched
origin/beta the feature still changes only SCRIPT_POLICY.md, its focused tests,
and this dossier; upstream implementation work was preserved, not authored here.
The primary beta checkout was not changed.

Fresh isolated `PYTHONPATH="$PWD" python3 -m pytest tests/test_script_policy.py -q`:
23 passed. `git diff --check origin/beta..HEAD`: passed. AGENTS.md is unchanged;
no retry or alternate writer was used after the prior protected-file denial.
No fresh normal approval is available in this child. Parent must obtain that
approval and apply the exact fragment above before release.

Fresh combined independent review through Claude CLI failed before doing work
with HTTP 429/session limit, session `257d9ad2-082e-4d6e-86cd-4dcaa55ff11f`;
raw receipt `/home/ryushe/script-map-lifecycle-cleanup-review.json`. Parent must
supply/retry independent review after approved AGENTS alignment and rerun the
focused suite. Keep this feature/dossier intact until that gate completes.
No push, beta integration, protected-file write, or runtime sync is claimed.
