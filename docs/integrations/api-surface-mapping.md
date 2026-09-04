# API surface mapping integration dossier

## Intent

Add a BBH-native `api-surface-mapping` skill that gives “map/test/compare the
API” a single adaptive entrypoint. It reconciles source-derived candidate APIs,
normal-flow task-MITM observations, cross-implementation and cross-surface
comparisons, and contract-behavior questions. It does not replace the existing
owner skills for endpoint contract writing, transport, or later active testing.

## Branch and target

- Feature branch: `bug-bounty-harness/t_e78c77a9-implement-adaptive-api-surface-mapping-s`
- Worktree: `/home/ryushe/projects/bug_bounty_harness/.worktrees/t_e78c77a9`
- Base: BBH `beta` at `6dea5c2`
- Intended integration target: `beta`
- Related policy-lane change: add a narrow router row on AI Policies
  `beta/grant-policies`; it is a separate repository commit.

## Implemented contract

- New `skills/api-surface-mapping/SKILL.md` owns API-wide operation/context
  mapping, provenance, adaptive lenses, artifact shape, and bounded handoffs.
- `analyze-endpoint` remains the canonical selected-operation contract writer;
  `proxy-routing-policy`, `js`, `live-map`, `parameter-mining`, and class owners
  retain their existing responsibilities.
- The skill treats source declarations, task-MITM runtime observations, and
  explicit Caido historical lookup as distinct evidence classes; it does not
  authorize Caido as active transport or persist credentials.
- The registry exposes `/api-surface-mapping <program> [--focus <lens>]`.

## Evidence

- Static skill/reference validation passed before and after independent-review
  repairs; focused repository/runtime projection validation remains pending.
- Independent review found and the branch repaired: mandatory JS/live-map loading,
  a competing run-local hypothesis file, missing Recon Bus promotion, an
  over-broad static-mapping router chain, missing JavaScript Lens, and stale
  dossier state. Narrow independent re-review approved all six repairs with no
  remaining actionable findings.
- No live target traffic is part of this implementation.

## Activation boundary

Do not call the skill active until the BBH feature has been reviewed and merged
into `beta`, the AI Policies router entry is committed on its beta lane, and the
selected security runtime projection resolves the new BBH skill without a
same-name shadow.

## Resume point

Run final static/reference checks and the focused Aiskillsync projection dry run;
commit this reviewed BBH feature, merge it into clean BBH `beta`, and commit the
narrow AI Policies routing row on `beta/grant-policies`. Then sync the selected
security profile, verify the runtime symlink/resolver, remove this branch-local
dossier from the integration target, and record commit/test/runtime receipts.
