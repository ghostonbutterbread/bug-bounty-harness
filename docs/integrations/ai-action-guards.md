# AI action guards integration dossier

- Status: independent review accepted; local integration pending
- Owner: Hermes; Kanban `t_42923e0c`
- Owning feature branch/ref: `fix/ai-action-guards`
- Worktree: `~/worktrees/bbh-ai-action-guards`
- Base commit: `aa99c3e02e84f94ae8b9c6ec5626bea2abc11f8f`
- Intended integration target: `beta` (local only)
- Latest immutable recovery checkpoint: none yet; initial review is of the working diff
- Feature implementation commits: none yet

## Intent and implemented contract

Correct competing blanket AI action guards without weakening server-state or
other harm boundaries. BBH wrappers route through one shared reference to the
existing general/live/account/class policies. Normal already-permitted owned
application fixtures are distinct from pre-existing server files and shared
infrastructure. AI mediation and a lab label do not grant permission. Retain
unexpected-action stops, authorized callbacks, privacy, and evidence distinctions.
No exploit procedure, live target test, new tool capability, or automatic
escalation is added.

Canonical references checked: shared `general-security-testing-policy`,
`live-testing-policy`, `account-testing-policy`, `rce-validation`,
`attempt-recording-policy`, and AI Policies `root-context/AGENTS.md`;
BBH `agents/index.md`; affected AI entry skills and playbooks.
The shared policies remain unchanged; BBH only clarifies their application.

## Evidence and review

- RED: `python -m unittest discover -s tests -p test_ai_action_guards.py -v`
  failed because the common action-boundary reference did not exist.
- GREEN: the same command passed after the reference and its entry links landed.
- AI Policies repository lint (`scripts/policy_lint.py`) passed.
- `git diff --check` passed.
- Broad documentation check: `python -m unittest discover -s tests -p test_skill_command_lane_safety.py -v`
  has one pre-existing failure at `docs/integrations/broad-goal-map-reconciliation.md:24`.
  Reproduced the identical failure in the unchanged beta checkout. The other
  test in that module passes. No production behavior test is claimed.
- Independent read-only review: PASS; no blocking safety or policy-consistency
  findings. The reviewer inspected the actual staged candidate and compared the
  shared policy owners, verified host-state, cleanup, callback, lab, unexpected
  action, and evidence boundaries, and independently reran the focused test.
- Existing lane-safety tests run against the changed documentation: both passed.
  The all-canonical-skills check also passed. The unchanged full-documentation
  failure remains explicitly recorded above.
- All five changed skill headers parsed correctly. Added-line secret/contact
  heuristics found no matches; the complete task-owned staged diff was also
  manually reviewed. These are static checks, not runtime authorization proof.

## Blockers and deferred work

The pre-existing documentation-check defect is recorded in `BUGFIXES.md` and
left outside this change. Its owner should remove/repair the resolved dossier
and rerun the named check; this prevents claiming the entire documentation suite
is green, but is not an introduced AI-policy regression.

Full autonomous-agent behavior evaluation is not performed. A later evaluation
needs approved isolated fixtures and an explicit evaluation task; passing static
documentation checks is not proof of model behavior.

## Decision gates and resume

- Integration: independent review, scoped link/guard checks, clean exact diff,
  and a clean current beta worktree.
- Activation: no lane selector or remote runtime changes. Report local installed
  symlink resolution separately from source integration.
- Promotion: no stable merge, push, or remote deployment in this task.
- Exact next step: commit the reviewed change, record its immutable checkpoint,
  merge locally into beta, remove this temporary dossier from beta, and verify.
