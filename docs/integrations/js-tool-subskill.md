# JSLuice tool sub-skill integration dossier

- **Status:** reviewed locally; independent review pending
- **Owner:** Hermes BBH skill task `t_b5b1d9a3`
- **Branch/worktree:** `docs/js-tool-subskill` at `/home/ryushe/projects/bbh-js-tool-subskill`
- **Base / target:** fetched `origin/beta` `ab49502beb1590e3a3a4ce200c09205148c74386` → `beta`
- **Implementation commit:** `4fc4aff048f101d5cf348b8b16d7ce95aed74f00`
- **Current reconciled feature tip:** `8c6d4bbb9a35cd1a341cd56c668403d6b0f82341`
- **Date:** 2026-10-07 UTC

## Intent and boundary

Ryu wants `/js` to describe available tools briefly and route agents to a focused sub-skill for deeper use. The preceding beta edit inlined JSLuice commands in the main skill. Move the tool-specific procedure to a standalone `/jsluice` skill, register it, and keep the main `/js` tool map short. This is skill and playbook guidance only: no BBH parser wrapper, new tool installation, Recon-Ry change, live request, or runtime activation.

## Implemented contract

`skills/js/SKILL.md` now summarizes BBH inventory and upstream JSLuice capabilities and points to `/jsluice`. `skills/jsluice/SKILL.md` owns modes, direct local-file commands, metadata/hash/provenance linkage, offline boundary, secret handling, and interpretation limits. `prompts/js-playbook.md` points to the focused skill rather than duplicating its procedure. `SKILL_REGISTRY.md` registers `/jsluice`. Primary source is BishopFox upstream CLI documentation and a locally built binary's help; no dependency on the abandoned enrichment branch.

## Evidence, blocker, next action

- `PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m pytest tests/test_jsluice_skill.py tests/test_script_policy.py tests/test_business_logic_skill.py -q -p no:cacheprovider` → 28 passed.
- Locally built upstream JSLuice against the synthetic local concatenation fixture: `urls` returned four JSONL records including `/api/accounts/EXPR/settings?view=full`; `secrets` exited 0 with no matches; `query -q '(string) @matches'` returned three string values. No target traffic. `git diff --check` passes.
- Beta advanced to `75497a447bd81fbafb3db837618fddf25d43bded` (report guidance only); merged it into the feature at `8c6d4bbb9a35cd1a341cd56c668403d6b0f82341` without conflict and reran the 28 focused tests: passed.
- Next: fetch beta again, obtain independent content review, record its verdict in this branch, and integrate only after passing. The shared local beta checkout is dirty and behind remote; do not touch or reconcile it. Stable promotion and runtime activation are separate decisions.
