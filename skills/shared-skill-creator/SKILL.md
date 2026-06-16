---
name: shared-skill-creator
description: "Create or update shared skills in the correct project repo, then commit, push, and run aiskillsync when configured."
---

# Shared Skill Creator

Use when creating or updating a skill that should live in a project repository and be synced into provider skill directories.

## Invocation

```text
/shared-skill-creator <project> <skill-name> [intent...]
```

`<project>` can be a configured aiskillsync bridge name such as `bounty-harness` or `ai-policies`, a local repo path, or a GitHub repo URL.

## Required Preflight

1. Inspect `~/.config/aiskillsync/config.yaml`.
2. Resolve the project to the canonical repo path and `skills_path`.
3. Read the repo's routing docs, registry, and nearby skills:
   - `AGENTS.md` if present
   - `SKILL_REGISTRY.md` or equivalent if present
   - adjacent `skills/*/SKILL.md`
   - adjacent `prompts/*-playbook.md` when the repo uses playbooks
4. Check `git status --short --branch` and avoid unrelated dirty files.

## Workflow

1. Create or update `skills/{skill-name}/SKILL.md` using the local repo's skill layout.
2. Add supporting files only when needed:
   - `prompts/{skill-name}-playbook.md` for reusable methodology
   - `skills/{skill-name}/references/` for larger reference docs
   - `skills/{skill-name}/scripts/` for deterministic helpers
3. For web vulnerability, workflow, or endpoint-analysis skills, add a compact
   `## JavaScript Lens` section or explain why JavaScript evidence is not
   relevant. The lens should tell `/js` what to look for in bundles and when to
   hand evidence to this skill.
4. Update the repo's skill registry/index if one exists.
5. Validate frontmatter and any touched scripts/tests.
6. If the project is a GitHub repo:
   - stage only files touched for this skill
   - commit with a concise message
   - push the current branch
7. If the project is configured in aiskillsync:
   - run `aiskillsync sync all --repo <bridge-name>`
   - if destinations conflict, report the conflict and do not overwrite user-modified directories unless Ryushe approves adoption/replacement.
8. Report:
   - repo path
   - changed files
   - commit hash or reason no commit was made
   - push result
   - sync result

## Notes

- Keep `SKILL.md` lean. Move long technique docs into a playbook or references.
- Prefer symlink-based sync through `aiskillsync` over copying provider skills by hand.
- Do not commit secrets, credentials, cookies, tokens, private configs, or real sensitive files.
