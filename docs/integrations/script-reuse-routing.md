# Script reuse routing

Status: candidate for beta integration
Owner: Hermes / BBH
Feature: `docs/script-reuse-routing-tf40477dd`
Base: `origin/beta` at `73d83c730cef6343e0c61d5d0ddcc70a416490d3`
Target: `beta`

## Intent and contract

A Canva XSS campaign packet selected a run-local token scanner before checking the maintained JS source/sink inventory. Existing repository policy already favored reuse but was not at the packet decision point. This change makes the reuse/extend/new choice visible in the BBH entry card and Bunny coordinator route for specific script assignments, with a worker-side discovery choice for exploratory tasks. It clarifies the indexed home for recurring program-only helpers outside a program skill's responsibility, and gives an executable lookup through the selected lane profile. Program-lane code is distinct from BBH's lane-selected `bbh` launcher.

## Boundaries

No scanner implementation, target traffic, or runtime service changes. `SCRIPT_POLICY.md` remains the placement and maintenance owner. `agents/index.md` and `skills/bunny/SKILL.md` only route to it. No bulk migration of old scratch files.

## Verification and review

Initial route assertions and `git diff --check` passed. Independent review found two blockers: a premature coordinator gate for exploratory recon and missing executable program-index lookup. Both were corrected. The profile lookup resolved an existing program `scripts/` directory; the local index is not yet created (allowed until promotion). Independent re-review approved the corrected routes for beta integration and reran routing assertions and `git diff --check`. No runtime projection claimed. Compared with `script-manager`, `bounty-storage`, `skills/xss/scripts/README.md`, and `skills/bunny-collaborative/SKILL.md`; they continue to own their respective contracts.

## Activation and next action

Commit reviewed feature, merge into clean current beta worktree after re-fetch/retest, and verify runtime skill projection separately before claiming active Hoster behavior. Remove this temporary dossier from beta during integration; feature history retains it.
