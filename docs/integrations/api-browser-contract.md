# API browser-contract integration dossier

## Intent

Make live application testing browser-default while preserving direct HTTP for
small known-shape questions. Add an operation-scoped, documentation-first API
contract-discovery rule and a closest-normal-browser-flow recovery path when a
web-backed request's shape, values, or prerequisite state remain unclear.

## Branch and target

- Feature branch: `fix/api-browser-contract`
- Worktree: `/home/ryushe/projects/bug_bounty_harness/.worktrees/api-browser-contract`
- Base: BBH `beta` at `eefb8d4b2b47ef33565c71410df94d9efc213d04`
- Intended integration target: `beta`
- Related policy-lane change: `ai-policies` `beta/grant-policies`, updating the
  canonical `browser-session-policy` owner.

## Implemented contract

- `api-surface-mapping` now directs agents to use documentation only for the
  operation under test, then research first-party stack/client evidence if the
  needed contract remains uncertain.
- A web-backed operation whose shape, values, or prerequisites cannot be
  established reliably directs the agent to drive the closest normal browser
  flow through task MITM rather than guess from source evidence.
- No live target traffic, API enumeration, or new storage contract is added.

## Verification and next action

- Markdown/reference validation and targeted policy text inspection passed.
  Independent review found and repaired one wording ambiguity: both
  documentation and stack/client evidence are explicitly first-party. Narrow
  re-review found no actionable findings.
- Next: commit the feature, merge it into a clean current BBH `beta`
  worktree, remove this dossier from the integration target, and verify the
  runtime skill projection separately.
