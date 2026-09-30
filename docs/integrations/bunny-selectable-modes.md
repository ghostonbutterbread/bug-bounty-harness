# Bunny selectable modes — integration dossier

- Owner/status: Hermes, task `t_9889e3f5`; review pending.
- Branch/worktree: `feat/bunny-selectable-modes` at `../bunny-selectable-modes`.
- Base/target: `origin/beta` `0afc6960b2856ed3d16e77157170c615856c1e59` → `beta`.
- Intent: route opt-in Bunny to default collaboration, with an explicit offhand alternative. The former must be loaded by coordinator and workers; the latter only by coordinator, leaving workers ordinary.
- Contract: root owns shared scope/account/evidence boundaries; mode skills own distinct orchestration. Collaborative packets require child skill load, checkpoints, and evidence-responsive steering. Offhand packets do not require child mode load. No silent fallback; no claim of unattended transport.
- Changes: root mode router, `bunny-collaborative` and `bunny-offhand` subskills, role instructions, registry, focused tests.
- Verification: `python3 -m unittest discover -s tests -p test_bunny_skill.py -v` passed 6/6; `git diff --check` clean. Independent read-only review found no actionable findings, reran 8 Bunny/security-reporting tests and `git diff --check`, and noted live collaboration was not exercised.
- Policy alignment: root `bunny` remains the opt-in shared safety owner; collaborative and offhand skills own only their distinct dispatch/feedback modes. `agents/index.md`, `hunt-orchestration-policy`, and policy-authoring boundaries remain compatible.
- Review decision: accept this skill routing slice for beta, without representing the missing event runner as delivered.
- Boundary: this is a skill routing and agent contract release, not an implemented durable event bus, scheduler, or live end-to-end collaboration test. That remains task `t_8db7e67e`.
- Next: independent review, reconcile beta, merge, remove this dossier on beta, focused sync and runtime resolver verification.
