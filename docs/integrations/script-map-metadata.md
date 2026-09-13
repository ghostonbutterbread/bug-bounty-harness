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
