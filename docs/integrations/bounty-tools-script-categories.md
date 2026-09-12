# Bounty Tools Script Categories

## Intent

Clarify the BBH-local repository ownership decision requested in Discord message
`1547742715784208515`: named vulnerability/capability/program owners retain
their focused scripts, while abstract reusable bug bounty tooling without one of
those owners goes to category-based Bounty Tools storage.

## Branch and target

- Branch: `feat/bounty-tools-script-categories`
- Base: `origin/beta` at `12a6398`
- Target: `beta`

## Contract

- Class-specific helpers use `skills/<class>/scripts/`.
- Recon-specific helpers use `skills/recon/scripts/`.
- Program-specific helpers use their program skill's `scripts/` directory.
- Abstract reusable tools without an existing owner use
  `skills/bounty-tools/scripts/<category>/`.
- Bounty Tools forbids uncategorized top-level executables and `misc`, `general`,
  or `other` dumping grounds.
- Root `scripts/` remains for BBH infrastructure and cross-skill harness helpers.
- The parent Bounty Tools index links every populated category index.

No existing scripts are moved by this policy-only change.

## Evidence

- RED: `tests/test_script_policy.py` failed on missing routing language and the
  absent Bounty Tools category index.
- GREEN: `8 passed in 0.02s` for `tests/test_script_policy.py`.
- Compatible focused suite: `9 passed in 0.02s` for
  `tests/test_hoster_script_authority.py tests/test_script_policy.py`.

## Activation boundary

This branch changes BBH source policy and tests only. It does not activate until
reviewed, merged to `beta`, pushed, and rolled out to the BBH beta runtime.

## Review and next action

Initial independent review blocked release because the first test could accept
forbidden or malformed category names, substring-only/broken or stale category
links, uncategorized extensionless executables, and nested scripts outside the
category inventory. The regression now:

- recognizes executable-bit entrypoints as scripts;
- requires lowercase kebab-case names and rejects `misc`, `general`, and `other`;
- reconciles exact Markdown link targets against every category directory;
- rejects empty/stale categories; and
- rejects nested executable scripts.

Post-fix focused suite: `9 passed in 0.03s`. The first re-review found two
remaining parser bypasses: executable files named `test_*` were exempt and
noncanonical Markdown category links could evade catalog reconciliation. The
second correction now includes every Bounty Tools script regardless of filename,
normalizes an optional `./` prefix, compares every category-index link exactly,
and treats extensionless records as stale after removal. The focused suite
remains `9 passed in 0.03s`.

The final review found that general Markdown variants could still be silently
ignored by the catalog parser. The protected root policy now owns all category
norms and defines one canonical catalog-entry syntax; the editable Bounty Tools
README is discovery-only. Required ancestor catalog edits are explicitly within
the scripts-only lane, but normative prose remains protected. Fixture-based
regressions reject titled, angle-bracket, directory-only, and wrong-index links.
The focused suite now reports `13 passed in 0.19s`.

Pending final independent approval of the corrected tip. If accepted, record the
decision here, remove this dossier from the integration target during merge,
rerun the focused policy suite, push `beta`, verify the remote/runtime SHAs and
a fresh agent interpretation, then close the Kanban task.
