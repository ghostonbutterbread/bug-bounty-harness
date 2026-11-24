# Integration dossier: feat/js-hunt-online-default

- Task: default JS hunts to online live validation with per-lead disposition
- Kanban: bug-bounty-harness `t_ad16cc17`
- Worktree: `~/worktrees/bbh-js-hunt-online-default`
- Branch: `feat/js-hunt-online-default`
- Base (origin/beta): `3f72ed81247d0eacb9b7d1e859c57a5ce20a4a2d`
- Implementation commit: `1b64266f` (recovery checkpoint; branch tip may carry a
  later dossier-only commit)
- Merge target: beta

## What changed

`/js-hunt` defaults to online: the review pass stays offline, then the parent
live-validates the selected leads and records a disposition for each, so leads
stop being left open. `--offline` (or an explicit offline/static request) keeps
the previous behavior. Collection-only is unchanged.

Files: `skills/js-hunt/SKILL.md`, new `skills/js-hunt/references/live-validation.md`,
`skills/js/SKILL.md`, `skills/js/references/analysis-lens.md`,
`skills/js/references/offline-fanout.md`, `skills/js-pull/SKILL.md`,
`prompts/js-playbook.md`, `tests/test_live_static_hunt_flow.py`,
`tests/skill_size_budget.json`.

## Tests

Focused: `tests/test_live_static_hunt_flow.py`, `tests/test_js_hunt_skill.py`,
`tests/test_js_analysis_routes.py`, `tests/test_jsluice_skill.py`,
`tests/test_skill_hygiene.py` — 33 passed.

Full suite: 2088 passed, 3 skipped, 269 subtests passed, 29 failed. All 29
failures reproduced on the untouched base worktree
(`bbh-proxy-fallback-beta-release-20261108`, which includes the 18 unpublished
local commits) or were caused by this worktree lacking a `.venv` (the suite
resolves its interpreter from the checkout's own venv). With the venv linked,
`tests/test_safety_incident.py` passed 11/11 here and on the base. No failure is
attributable to this change.

## Review

Independent review: pending.
