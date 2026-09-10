# Deterministic Script Authority

## Intent

Make the deterministic-script contract apply across BBH rather than only to the
JavaScript lane. Agents should reuse documented automation for repeatable
mechanics without treating heuristic output as perfect, exhaustive, or a
replacement for source/evidence review.

## Ownership

- Branch: `fix/deterministic-script-authority`
- Base: `192d50efb6c8d0f260e40415d7e826d8b136f618`
- Target: `beta`
- Canonical contract: `docs/executable-harness-template.md`
- Template router: `SKILL_TEMPLATE.md`
- Script discovery index: `scripts/README.md`
- Companion proposals:
  `~/Shared/skill_seeds/2026-09-10-hoster-script-maintenance-lane.md` and
  `~/Shared/skill_seeds/2026-09-10-deterministic-script-authority.md`

## Contract

- Search documented BBH scripts and skill-owned helpers before creating another
  implementation.
- Put cross-skill CLIs in `scripts/`, one-skill helpers in
  `skills/<skill>/scripts/`, and established runtime modules in `agents/`.
- Document promoted scripts in the nearest `scripts/README.md` and invoke them
  through `bbh <repository-relative-path>`.
- Scripts own deterministic mechanics. Open-world regexes, signatures,
  classifiers, and hardcoded lists emit non-exhaustive seeds and unknowns, not
  negative conclusions.
- Consumers follow evidence beyond the script vocabulary. Script discoveries
  become maintained rules only with triggering evidence, a failing fixture, a
  generalized change, and review.
- Skill or policy improvements outside the authoring agent's authority become
  skill seeds rather than direct runtime edits.

## Evidence

- The existing Hoster maintenance seed was observed changing concurrently, so it
  was not overwritten. A separate `script_manager` seed now carries the
  deterministic-authority contract without colliding with that agent's
  contribution-lane work.
- All seven root scripts returned a successful `--help` smoke through the BBH
  beta virtual environment.
- Index validation found seven root scripts and seven matching documented
  records with no omissions.
- Focused root-script suites: `56 passed in 8.43s`.
- Independent review remains pending.

## Activation boundary

Repository guidance changes only. Merge to `beta`, push, update Hoster's clean
runtime source while preserving unrelated local modifications, and verify the
active projections. Existing sessions may retain already-loaded instructions;
new sessions and newly loaded skills receive the change.

## Next action

Verify the canonical contract and complete root script index, then request
independent review. The user declined a global `AGENTS.md` rule; keep ownership
in the executable template and proposed `script_manager` policy.
