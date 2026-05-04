---
name: appmap
description: Use when mapping a local application source tree or extracted binary source with /appmap to produce static AppMap artifacts and generated brainstorm specs before handing execution to zero_day_team or apk_team.
---
# AppMap

Map a local application and forge focused brainstorm specs from source/boundary/sink evidence.

## Invocation

```text
/appmap <program> <target_path> [--target-kind <kind>] [--focus rce] [--write-specs] [--output-root <path>]
```

Examples:

```text
/appmap canva /home/ryushe/Shared/binaries/canva/exe/input/app_asar --target-kind electron-exe --focus rce --write-specs
/appmap demo /path/to/source --focus rce
```

## Required Preflight

Read the playbook before running the mapper:

1. `$HARNESS_ROOT/prompts/appmap-playbook.md`
2. Existing target lane notes when the family/lane is obvious
3. Existing `brainstorm/spec.md` only for context; do not overwrite it from AppMap

## Canonical Files

- **Playbook:** `$HARNESS_ROOT/prompts/appmap-playbook.md`
- **Mapper:** `$HARNESS_ROOT/agents/app_mapper.py`
- **Default output:** `~/Shared/appmap/{program}/static/appmap/{run_id}/`
- **Generated specs:** `{output}/generated_specs/`
- **Agent contexts:** `{output}/agent_contexts/<hypothesis_id>-<candidate_id>-<agent_key>.json` when generated specs link hypotheses to candidates

## Responsibilities

- Run static AppMap against local source or extracted application code.
- Preserve AppMap artifacts: profile, architecture, surfaces, flows, candidates, rejected candidates, and summary.
- Generate parser-valid brainstorm specs when `--write-specs` is requested and candidates exist.
- Preserve candidate-isolated agent handoff contexts with only the linked map IDs, evidence snippets/files, active packs, and next steps.
- Ensure each AppMap hypothesis links to exactly one `appmap-C####` candidate and write one context packet per suggested agent.
- Keep packet `active_target_packs` candidate-evidence scoped so mixed targets do not leak unrelated framework context.
- Keep AppMap pre-runtime. Do not add or use `zero_day_team --appmap` integration from this skill.
- Hand generated specs to the normal team runtime only when the user explicitly asks to run hypotheses.

## Workflow

1. Resolve `program`, `target_path`, `target-kind`, `focus`, and output root.
2. Confirm `target_path` is a local directory. Do not run the target application.
3. Run:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 agents/app_mapper.py <program> <target_path> \
  --target-kind auto \
  --focus rce \
  --write-specs
```

4. Read `appmap_summary.md`, `architecture.md`, `candidates.jsonl`, `rejected_candidates.jsonl`, and generated `agent_contexts/*.json` when present.
5. Validate generated specs with `agents.brainstorm_spec.parse_brainstorm_spec` when present.
6. Report the output directory, candidate count, generated specs, and any no-candidate reason visible in rejected candidates.

## Runtime Handoff

AppMap stops after artifact and spec generation. If the user asks to run a generated spec, use the existing runtime explicitly:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 agents/zero_day_team.py <program> <target_path> \
  --brainstorm-spec <appmap-output>/generated_specs/rce-spec.md \
  --brainstorm-only
```

For AppMap-linked specs, normal brainstorm runtime handoff consumes `agent_contexts/*.json` automatically. The adapter matches `hypothesis_id`, `appmap-C####` candidate evidence, and `agent_key`, then uses the packet as the agent prompt context instead of the spec-wide mental model and impact primitives. Missing, duplicate, ambiguous, or multi-candidate linkage is a hard error.

Do not introduce a `zero_day_team --appmap` invocation here.

## Validation

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
python3 -m pytest agents/test_app_mapper.py -q
./sync_skills.sh --dry-run
```
