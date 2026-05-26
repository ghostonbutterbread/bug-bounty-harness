# Shared Skill Creator Playbook

This playbook keeps shared skills in the repo that owns them, then publishes them through `aiskillsync`.

## Project Resolution

Use `~/.config/aiskillsync/config.yaml` first:

- match by bridge name
- match by local path
- match by repo URL

If the project is not configured, inspect the requested local path or GitHub repo and ask Ryushe before adding it to aiskillsync.

## Repo Layout Detection

Look for:

- `skills/{name}/SKILL.md`
- `prompts/{name}-playbook.md`
- `docs/skill-tree-handoff-template.md` for router skills that hand off to child skills
- `SKILL_REGISTRY.md`
- `sync_skills.sh` or `setup.sh --sync`
- repo-specific `AGENTS.md`

Follow the repo's existing layout. For Bug Bounty Harness, use:

```text
skills/{skill-name}/SKILL.md
prompts/{skill-name}-playbook.md
SKILL_REGISTRY.md
```

If the skill is a router or starting point for several vulnerability lanes, use `docs/skill-tree-handoff-template.md` before writing. Keep the entry skill thin, put branch logic in a context pack, and require an evidence-backed handoff card before invoking child skills.

For skills that need findings, coverage, or prior-result context, point agents at `agents.ledger` as the harness adapter over Bounty Core. Do not add instructions that parse or rewrite `ledger.json` directly.

Default new router skills to ledger mode, but include an explicit no-ledger path. In no-ledger mode, agents should not read prior findings or write durable ledger/coverage state; they should still write local notes and handoff cards.

## Commit Rules

- Stage only files intentionally changed for the skill.
- Do not stage unrelated dirty files.
- Before committing, run:
  - frontmatter validation for touched `SKILL.md`
  - script tests or syntax checks for touched helper scripts
  - `git diff --check` for touched text files
- After committing, verify the commit hash with `git rev-parse --short HEAD`.

## Sync Rules

Prefer:

```bash
aiskillsync sync all --repo <bridge-name>
```

Use `--dry-run` first when destination conflicts are likely.

If a destination has a regular directory instead of the expected symlink, do not delete it automatically. Report the conflict and ask before adopting/replacing.
