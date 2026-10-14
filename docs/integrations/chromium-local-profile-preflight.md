# Chromium local-profile preflight integration dossier

- **Status:** review-ready
- **Owner:** Hermes task `t_ccf1cf8e`
- **Branch:** `fix/chromium-local-profile-preflight`
- **Base commit:** `b96786f7358d17b994845057430ee126a39cb1fa`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-13
- **Owning feature branch/ref:** `fix/chromium-local-profile-preflight`
- **Latest immutable recovery checkpoint:** none yet; commit this branch before handoff
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Discord thread `1559668155721318492`; canonical `skills/chromium-test/SKILL.md` preflight section already in beta, but its `findmnt` output alone did not reject CIFS/SMB.

## Intent

Make the browser-node filesystem check an executable pass/fail gate before Chromium profile use, not a mount-printing suggestion. Keep large evidence on the bounty artifact store; preserve Hoster's ext4, provisioning, lease, and MITM workflows. No Hoster storage, provisioning, or lease implementation changes in this task.

## Implemented contract

The documented shell resolves an existing profile path or nearest existing ancestor, then accepts only known local filesystem types. It prints PASS and exits zero for accepted types; it prints FAIL to stderr and exits nonzero for CIFS/SMB, other unknown types, unresolved symlinks, and lookup failures. Existing named profiles use the recorded exact path before request. A provisional ancestor PASS for a fresh path is not final proof: start with `about:blank`, inspect the owner-recorded final path, then navigate to a target only after final PASS and normal MITM/CA readiness. Final FAIL requires exact-owner release and normal task-proxy finish. This is agent-facing guidance, not a new provisioner-side technical enforcement mechanism.

## Evidence and review

- Focused command: `PYTHONPATH="$PWD" /home/ryushe/projects/bug_bounty_harness/bbh-beta-integration/.venv/bin/python -m pytest -q agents/test_chromium_test_launcher.py` from this feature worktree: 51 passed. The preflight tests execute the exact skill snippet against local, CIFS, symlink, absent-root, unknown-filesystem, and lookup-failure fixtures. One test also checks a real local pytest path and the real `/mnt/bounty` CIFS mount when present.
- `git diff --check`: passed.
- Independent review: pending in pre-created child `t_456f552a` (also depends on Hoster safeguard task).
- Merge/ancestry evidence: feature starts at fetched `origin/beta` commit above; not integrated.

## Blockers and deferred work

- This task does not make the provisioner fail closed at its own launch boundary; a profile path that changes between preflight and launch could still race the agent-facing check. A separate code change and review would be needed for a technical guarantee. For the skill's safe workflow, unverified fresh paths use `about:blank` and final-path gating before target navigation.
- Do not activate a changed beta projection until the pre-created review and activation children complete. No live target or Hoster mutation is part of this skill task.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/chromium-local-profile-preflight`
- **Latest immutable recovery checkpoint:** none yet; replace after commit
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit scoped change and dossier, update checkpoint with real SHA, then complete this parent to release independent review.
- **Working-tree state at handoff:** intentionally uncommitted until the scoped change is committed.

## Decision gates

- **Integration gate:** pre-created independent review verifies documented fail behavior and branch diff, then beta integration through normal lane.
- **Activation / cohort gate:** separate child validates projection to intended Hermes profiles; this task does not activate.
- **Promotion gate:** no main promotion authorized.

## Decision record

- 2026-10-13 — strengthen existing canonical Chromium Test preflight rather than creating a second skill or changing the Hoster runtime.
