# RCE and Ghost-local skill promotion dossier

- Status: feature (review pending)
- Owner/task: Hermes, `t_e6ec07ac`
- Worktree: `/home/ryushe/worktrees/bbh-rce-skill-promotion`
- Branch/ref: `feat/rce-skill-promotion`
- Base beta commit: `e6e12b4b64cab8af3e7939ee8e0d7099294f1f57`
- Intended integration target: `beta` (`origin/beta` after review)
- Latest immutable recovery checkpoint: `60682537754b6a1a78e8f6d34613d6a15422a0b6` (preceding implementation; current consumer-alignment correction pending commit)
- Implementation commits: `1852fe3178e47c0bd3a9747a13f0e121c119cd84`, `58c0376934239f78523246d9526bafd680614b64`, `60682537754b6a1a78e8f6d34613d6a15422a0b6`
- Source: nine Ghost-local skills named in the operator's Discord request (thread 1560716542101159957)

## Intent and contract

Promote the five RCE packets plus account-registry, blocker-first-analysis,
research-knowledge-management, and hunt-orchestration from Ghost-local Hermes
into BBH's canonical `skills/`. Add a substantive discoverable `rce` class entry
for the operator-requested why/where/how model, rather than treating
`rce-exploration` as an invisible parent. Package complete references. Preserve
AI Policies authority for scope, live testing, sidecar admission and account
behavior. BBH owns registry schema/migration details, blocked-test causal
interpretation, research corpus mechanics, and solo-hunter evidence/handoff.
Update the BBH registry, entry card, and upload route. No live target tests.

## Evidence and review

- `PYTHONPATH=. python3 -m pytest -q tests/test_skill_promotion_routes.py tests/test_bunny_skill.py tests/test_research_map.py tests/test_ai_action_guards.py tests/test_goal_router.py`: 21 passed, 36 subtests.
- `PYTHONPATH=. python3 -m pytest -q tests --ignore=tests/test_safety_incident.py`: 237 passed, 174 subtests with consumer-alignment correction.
- Unfiltered `tests`: 8 failures after initial placeholder path; placeholder corrected. Remaining 7 failures in `test_safety_incident.py` are reproduced unchanged on the beta integration base (missing checkout-local `.venv`, not a skill change). Exact deferred check: run `PYTHONPATH=. python3 -m pytest -q tests/test_safety_incident.py` after provisioning this checkout through `./setup.sh --install-python-deps`; compare with beta base. No waiver of application correctness.
- `PYTHONPATH=. python3 -m pytest -q tests/test_skill_command_lane_safety.py tests/test_migrated_skill_commands.py`: 3 passed, 62 subtests.
- Independent reviews of `1852fe3` and `58c0376`: first blocked on phantom auth loader and blocker gate, then on a blanket proxy exception, inconsistent RCE mapping route, research trigger and stale handoff. Corrected in `6068253`. A separate read-only review of `89b3541` blocked on account-registry text falsely claiming cross-consumer tombstone/schema checks and an `active`-only lease gate; the current correction labels those as migration targets and records the existing `live` exception. Fresh exact-tip review still required. Integration/remote runtime tests: pending.

## Decision and activation gates

Review source/routing and overlap boundaries; then merge into a clean current
beta worktree, excluding this temporary dossier from beta. Re-run focused and
baseline-aware full checks; push only from beta worktree after review. Source
merge/push is not activation: verify focused profile dry-run, link targets,
no-op repeat and fresh skill load on Ghost and Hoster before claiming either
runtime updated. Keep the Ghost-local copies until canonical links are verified;
retire local shadow copies only after complete-tree comparison and ownership check.

## Resume

If interrupted: inspect the current feature tip and verify its recorded
implementation SHA after the pending correction commit; refresh beta, then
obtain a new independent verdict on the corrected tip. The branch owns no
target traffic, secrets, or program data. The eventual implementation checkpoint
precedes any dossier-only handoff commit; reviewers must inspect both.
