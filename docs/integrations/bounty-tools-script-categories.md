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

A later review found two final scope gaps: a blank Categories section could pass
without the mandated sentinel, and stale links outside the first Categories
section could evade validation. The parser now requires exactly one nonblank
Categories section and rejects category-index links anywhere outside it.
Permanent regressions cover blank, duplicate-section, and outside-section cases.
The focused suite now reports `16 passed in 2.57s`.

The next review found malformed directory-only and wrong-index links outside the
Categories section were not covered by the narrower `/README.md` check. The
catalog now permits no Markdown links outside its single Categories section;
the root policy pointer is plain code. Permanent regressions cover both malformed
forms before and after the section. The focused suite now reports
`20 passed in 0.04s`.

A further adversarial review showed that trying to partially parse arbitrary
Markdown creates endless alternate-link and heading variants. The catalog is
now deliberately a fixed-format inventory instead: an exact discovery preamble
followed only by the empty sentinel or canonical category rows. This removes
Markdown interpretation from the contract and rejects any extra prose, heading,
autolink, empty-label link, reference link, or shortcut-reference definition.
Permanent positive and negative controls cover the exact format. The focused
suite now reports `24 passed in 0.04s`.

## Final decision

Approved for `beta` integration by an independent no-edit review at candidate
checkpoint `444a182`. The reviewer reran the focused suite (`24 passed`) and an
additional 100 adversarial fixture checks covering fixed-format catalog inputs,
category naming, script placement, and complete/nonstale records. No security or
logic findings remained.

Next: merge the reviewed feature into current `beta` while removing this
branch-only dossier from the integration target; rerun the focused suite, push,
verify remote and Hoster runtime receipts plus a fresh-agent interpretation,
then close the Kanban task.
