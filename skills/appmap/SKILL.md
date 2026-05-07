---
name: appmap
description: Use when mapping a local application source tree or extracted binary source with /appmap to produce static AppMap artifacts and generated brainstorm specs before handing execution to zero_day_team or apk_team.
---
# AppMap

Map a local application and forge focused brainstorm specs from source/boundary/sink evidence.

## Invocation

```text
/appmap <program> <target_path> [--target-kind <kind>] [--focus rce] [--write-specs] [--output-mode standalone|canonical] [--family <family>] [--lane <lane>] [--promote-to-brainstorm]
/appmap <program> <target_path> --research-mode local|web|hybrid [--research-query WORD [WORD ...]] [--research-seed <path>] [--research-online --research-source-url <https-url>]
/appmap --list-handoffs --brainstorm-root <brainstorm_root>
/appmap --campaign-status --brainstorm-root <brainstorm_root>
/appmap --validate-handoff <promoted_spec>
/appmap --plan-handoff <promoted_spec> [--brainstorm-hypothesis H001]
```

Examples:

```text
/appmap canva /home/ryushe/Shared/binaries/canva/exe/input/app_asar --target-kind electron-exe --focus rce --write-specs
/appmap canva /home/ryushe/Shared/binaries/canva/exe/input/app_asar --target-kind electron-exe --focus rce --write-specs --output-mode canonical --family binaries --lane exe
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
- **Research module:** `$HARNESS_ROOT/agents/appmap_research.py`
- **Default output:** `~/Shared/appmap/{program}/static/appmap/{run_id}/`
- **Canonical output:** `~/Shared/{family}/{program}/{lane}/appmap/{run_id}/`
- **Generated specs:** `{output}/generated_specs/`
- **Agent contexts:** `{output}/agent_contexts/<hypothesis_id>-<candidate_id>-<agent_key>.json` when generated specs link hypotheses to candidates
- **Run manifest:** `{output}/manifest.json`
- **Run index:** `~/Shared/{family}/{program}/{lane}/appmap/index.jsonl` for canonical runs

## Responsibilities

- Run static AppMap against local source or extracted application code.
- Preserve AppMap artifacts: profile, architecture, surfaces, flows, candidates, rejected candidates, and summary.
- Generate parser-valid brainstorm specs when `--write-specs` is requested and candidates exist.
- Preserve candidate-isolated agent handoff contexts with only the linked map IDs, evidence snippets/files, active packs, and next steps.
- Ensure each AppMap hypothesis links to exactly one `appmap-C####` candidate and write one context packet per suggested agent.
- Write `manifest.json` plus `appmap/index.jsonl` so future modules discover AppMap artifacts without reading findings ledgers.
- Promote generated specs/context packets into `brainstorm/` only when explicitly requested.
- During promotion, keep raw surfaces, flows, candidates, and rejected candidates in the AppMap run root.
- List, validate, and plan promoted handoffs with read-only CLI modes before runtime.
- Do not overwrite existing `brainstorm/spec.md` unless the user explicitly chooses that filename and allows overwrite.
- Keep packet `active_target_packs` candidate-evidence scoped so mixed targets do not leak unrelated framework context.
- Keep research no-network-by-default. Prefer `--research-mode local|web|hybrid` plus `--research-query WORD [WORD ...]`.
- Use `--research-mode local` for local `--research-seed` artifacts. Use `--research-mode hybrid` to process local seeds first and then explicit web sources only when `--research-online` and `--research-source-url` are present.
- Treat `--research-provider`, `--research-online`, and `--research-source-url` compatibility carefully: old provider flags still work, but docs and new commands should prefer mode/query.
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

For canonical lane storage:

```bash
python3 agents/app_mapper.py <program> <target_path> \
  --target-kind auto \
  --focus rce \
  --write-specs \
  --output-mode canonical \
  --family <family> \
  --lane <lane>
```

4. Read `appmap_summary.md`, `architecture.md`, `manifest.json`, `candidates.jsonl`, `rejected_candidates.jsonl`, and generated `agent_contexts/*.json` when present.
5. Validate generated specs with `agents.brainstorm_spec.parse_brainstorm_spec` when present.
6. If research is requested, prefer `--research-mode local --research-query <terms> --research-seed <path>`. Hybrid mode reads local seeds first and then fetches explicit HTTPS `--research-source-url` values only when `--research-online` is set; do not use search scraping, crawling, or target probing.
7. Promote only on request with `--promote-to-brainstorm`. Canonical mode defaults to `{lane_root}/brainstorm`; standalone mode needs `--brainstorm-root`.
8. For promoted specs, run `--list-handoffs`, `--validate-handoff`, or `--plan-handoff` as needed. These modes are read-only and must not write findings ledgers, raw map data, coverage, or reports.
9. Report the output directory, manifest/index, candidate count, generated specs, promoted handoff paths when any, validation counts/errors, planned runtime command, research mode/query/provider/network status, and no-candidate reasons visible in rejected candidates.

## Promotion

Default promotion writes a unique per-run handoff directory:

```text
~/Shared/{family}/{program}/{lane}/brainstorm/appmap-<run_id>-<focus>/rce-spec.md
```

This is `--promotion-layout flat` and remains the default for compatibility. Opt in to category layout with `--promotion-layout category` to write:

```text
~/Shared/{family}/{program}/{lane}/brainstorm/appmap-<run_id>/<focus>/rce-spec.md
```

It also copies matching context packets to the spec's sibling context directory:

```text
~/Shared/{family}/{program}/{lane}/brainstorm/appmap-<run_id>-<focus>/agent_contexts/
~/Shared/{family}/{program}/{lane}/brainstorm/appmap-<run_id>/<focus>/agent_contexts/
```

Promoted specs and packets keep pointers to the originating AppMap run. Existing `brainstorm/spec.md` remains untouched; `--promote-spec-name` chooses a filename inside the per-run promotion directory, and overwrite applies only there.

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

Promoted handoff discovery:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
python3 agents/app_mapper.py --list-handoffs --brainstorm-root ~/Shared/<family>/<program>/<lane>/brainstorm
```

Campaign status / operator view:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
python3 agents/app_mapper.py --campaign-status --brainstorm-root ~/Shared/<family>/<program>/<lane>/brainstorm
```

Promoted handoff validation:

```bash
python3 agents/app_mapper.py --validate-handoff <promoted-spec>
```

Planning prints the exact existing runtime command:

```bash
python3 agents/app_mapper.py --plan-handoff <promoted-spec> --brainstorm-hypothesis H001
```

The planned command must use `python3 agents/zero_day_team.py <program> <target_path> --brainstorm-spec <promoted-spec> --brainstorm-only` and must not include `--appmap`. Runtime defaults to one agent per hypothesis. If the user explicitly wants clustered execution for a reviewed AppMap campaign, pass `--brainstorm-cluster-size 2` (or another small value); clustering is only for assignments sharing the same focus files, source, and sink.

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
python3 -m pytest agents/test_app_mapper.py -q
./sync_skills.sh --dry-run
```
