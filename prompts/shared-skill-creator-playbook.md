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
- `SKILL_REGISTRY.md`
- `sync_skills.sh` or `setup.sh --sync`
- repo-specific `AGENTS.md`

Follow the repo's existing layout. For Bug Bounty Harness, use:

```text
skills/{skill-name}/SKILL.md
prompts/{skill-name}-playbook.md
SKILL_REGISTRY.md
```

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

