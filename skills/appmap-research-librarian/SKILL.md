---
name: appmap-research-librarian
description: Use when creating a gated research campaign for AppMap where one agent scouts external sources, another validates them into structured technique packs, and AppMap later ingests only reviewed local seed data or explicit validated URLs.
---
# AppMap Research Librarian

Create an offline campaign workspace that bridges open-ended source research and deterministic AppMap ingest.

## Invocation

```text
/appmap-research-librarian init <program> --category <class> [--research-query WORD [WORD ...]] [--target-kind <kind>] [--focus rce]
/appmap-research-librarian validate <campaign_dir> [--seed <validated_seed.json>]
/appmap-research-librarian plan-appmap <campaign_dir> <target_path> [--write-specs] [--output-mode standalone|canonical] [--family <family>] [--lane <lane>] [--use-web-sources]
```

Examples:

```text
/appmap-research-librarian init canva --category electron-ipc --research-query electron rce --target-kind electron-exe
/appmap-research-librarian validate ~/Shared/appmap/canva/research-librarian/<run_id>
/appmap-research-librarian plan-appmap ~/Shared/appmap/canva/research-librarian/<run_id> /home/ryushe/Shared/binaries/canva/exe/input/app_asar --write-specs --output-mode canonical --family binaries --lane exe
```

## Required Preflight

Read the playbook first:

1. `$HARNESS_ROOT/prompts/appmap-research-librarian-playbook.md`
2. `$HARNESS_ROOT/prompts/appmap-playbook.md` when planning AppMap ingest
3. Existing target lane notes if a family/lane is obvious

## Canonical Files

- **Wrapper:** `$HARNESS_ROOT/agents/appmap_research_librarian.py`
- **Playbook:** `$HARNESS_ROOT/prompts/appmap-research-librarian-playbook.md`
- **Default campaigns:** `~/Shared/appmap/{program}/research-librarian/{run_id}/`
- **Scout brief:** `{campaign}/scout_brief.md`
- **Validator brief:** `{campaign}/validator_brief.md`
- **Scout source candidates:** `{campaign}/sources.todo.jsonl`
- **Validated seed:** `{campaign}/validated_research_seed.json`
- **Validation report:** `{campaign}/validation_report.json`
- **Planned AppMap command:** `{campaign}/plan_appmap_command.txt`

## Responsibilities

- Create a research campaign directory for a category/class.
- Generate a source-scout brief for a research agent.
- Generate a validator brief for a second agent that filters sources and writes structured seed data.
- Validate local seed JSON/JSONL without network access.
- Plan the AppMap ingest command.
- Keep AppMap deterministic: no search scraping, browser crawling, autonomous spidering, or target probing inside this wrapper.

## Workflow

1. Run `init` with the program and category/class.
2. Spawn or instruct a scout agent using `scout_brief.md`.
3. Put curated source candidates in `sources.todo.jsonl`.
4. Spawn or instruct a validator agent using `validator_brief.md`.
5. Validator writes `validated_research_seed.json` with cited `sources` and `technique_packs`.
6. Run `validate`; fix any `validation_report.json` errors. Planning requires at least one validated source and one validated technique pack.
7. Run `plan-appmap`; prefer local seed mode unless the user explicitly wants validated URL web mode.
8. Run the generated AppMap command only when the user asks to proceed.

## Safety

- This wrapper is offline by design.
- Research scouts may use their own allowed search/browser tools, but their output must be reviewed before AppMap sees it.
- Prefer `--research-mode local --research-seed <validated_seed>` for replayable campaigns.
- `--use-web-sources` plans `--research-mode web` only from validator-approved HTTPS source URLs.
