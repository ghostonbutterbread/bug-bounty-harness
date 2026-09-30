# Bunny active checkpoints — integration dossier

- Status: implementation in progress
- Owner: Hermes; task `t_8db7e67e`; Discord thread `1554656393901113425`
- Branch/worktree: `feat/bunny-active-checkpoints` at `../bunny-active-checkpoints`
- Base: `f487c0a4f7bb3d634ab0fb60f8b3a52140c0f459` (`origin/beta`)
- Target: `beta`
- Intent: make opt-in Bunny coordinate evidence checkpoints and push back on a premature negative conclusion for 3–5 feedback turns, using research and creative in-scope lenses.
- Contract: coordinator retains ownership of the next decision; worker returns observed evidence and distinct next discriminator. The assertive vulnerability phrase is a motivational search stance, never evidence. Direct disproof or real blockers end the challenge early.
- Implementation: updated `skills/bunny/SKILL.md` and `skills/bunny/agents/bunny-hunter.md`; added focused contract test. No independent daemon or unattended timer is introduced; the current harness must expose interactable runs to steer mid-lane, otherwise Bunny chains bounded segments.
- Tests/review: `python3 -m unittest discover -s tests -p test_bunny_skill.py -v` passed 5/5; `git diff --check` clean. Independent read-only review found no concrete issues; reviewer explicitly noted text tests do not exercise a running coordinator.
- Policy alignment: compared `agents/index.md`, `hunt-orchestration-policy`, Bunny's role and scope boundaries, and `policy-authoring`. Bunny remains the opt-in owner; no change to authorization, rate, evidence, or verifier/reporting rules.
- Review decision: accept focused skill-contract change for beta; leave automated periodic scheduler/runner out of this change rather than misrepresenting guidance as implementation.
- Activation: this feature branch is not the active synced skill; beta integration and projection verification remain separate.
- Next: commit focused change, integrate reviewed feature into beta, rerun tests, verify active symlink, and retire this dossier from beta.
