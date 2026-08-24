# Manual Surface Review Integration Dossier

## Intent

Adopt the reviewed `manual-surface-review` seed as a BBH read-only synthesis
skill. It ranks current-run evidence for a human without adding a new canonical
finding store or starting live testing.

## Branch and target

- Feature branch: `docs/manual-surface-review`
- Worktree: `/home/ryushe/projects/bug_bounty_harness-manual-surface-review`
- Base: `6709a1de2c9fc39c3f52fba47ebf6e6a507bb826` (`beta`)
- Intended target: `beta`

## Implemented contract

- Adds `skills/manual-surface-review/SKILL.md` with `/manual` as the suggested
  user-facing alias.
- Uses current-run Attempts, reports, handoffs, sidecars, and scoped MapStore
  lookups as the default evidence boundary.
- Defines evidence thresholds, ranked tiers, action-card format, persistence
  routing, and policy-gated live follow-up.
- Updates `SKILL_REGISTRY.md` so the skill is discoverable and synced by the
  repository's existing `setup.sh --sync` workflow.

## Evidence

- Seed reviewed: `/home/ryushe/Shared/skill_seeds/2026-08-24-manual-surface-review.md`
- Repository instructions, existing skill shape, skill registry, and setup
  synchronization behavior inspected before implementation.
- Focused regression suite passed:
  `python3 -m unittest agents.test_manual_surface_review_skill agents.test_shared_skill_adoption`
  (4 tests).
- `./sync_skills.sh --dry-run --all` completed and included
  `skills/manual-surface-review` for the Claude, Codex, and Ghost destinations.

## Activation boundary

The repository change makes the skill available from canonical `skills/` after
sync. It does not execute the skill against a live program or alter active
runtime skill destinations.

## Verification and deferred work

Run focused repository checks for skill registration and content, then run the
skill sync from the feature worktree to verify provider copies. A live forward
test on a retained, authorized run remains deferred: it needs a concrete run ID
and evidence set, and must verify rank ordering without exposing sensitive data.
