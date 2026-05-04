---
name: brainstorm-spec
description: Use when creating, editing, summarizing, or importing a target-lane brainstorm spec with /brainstorm-spec so zero_day_team, apk_team, and future harness modules can consume hypothesis-driven dynamic agents.
---
# Brainstorm Spec

Create and maintain a durable `brainstorm/spec.md` for a target lane.

## Invocation

```text
/brainstorm-spec <program> [--family <family>] [--lane <lane>] [--target-kind <kind>] [--target-path <path>]
/brainstorm-spec <program> --add-hypothesis
/brainstorm-spec <program> --summarize-gaps
/brainstorm-spec <program> --from-report <report.md>
```

Examples:

```text
/brainstorm-spec canva --family binaries --lane exe --target-kind electron-exe
/brainstorm-spec canva --add-hypothesis
/brainstorm-spec canva --summarize-gaps
/brainstorm-spec canva --from-report /home/ryushe/Shared/binaries/canva/exe/reports/dormant/index.md
```

## Required Preflight

Read shared state before changing the brainstorm spec:

1. Existing `brainstorm/spec.md`, if present
2. `brainstorm/coverage.jsonl`, if present
3. Current confirmed and dormant reports for the target lane
4. `notes/summary.md`, `notes/observations.md`, `checklist.md`, and `todo.md` when they exist
5. `$HARNESS_ROOT/prompts/brainstorm-spec-playbook.md`

## Canonical Files

- **Playbook:** `$HARNESS_ROOT/prompts/brainstorm-spec-playbook.md`
- **Default lane spec:** `~/Shared/{family}/{program}/{lane}/brainstorm/spec.md`
- **Default coverage ledger:** `~/Shared/{family}/{program}/{lane}/brainstorm/coverage.jsonl`
- **Legacy web spec:** `$HARNESS_SHARED_BASE/{program}/brainstorm/spec.md` (read-only discovery/migration source only)
- **Parser/runtime module:** `$HARNESS_ROOT/agents/brainstorm_spec.py`

Use the existing target lane root when one is obvious from reports, team output, or the requested `--family`, `--lane`, or `--target-path`.
Do not create or update new specs under `$HARNESS_SHARED_BASE`; write to the lane-local `~/Shared/{family}/{program}/{lane}/brainstorm/` path unless the user explicitly overrides the spec path.

## Responsibilities

- Create the canonical `brainstorm/spec.md` if missing.
- Convert rough target ideas into structured hypotheses.
- Pull impact primitives from current dormant or confirmed reports.
- Summarize unresolved, blocked, retired, and tested hypotheses.
- Preserve human-written context and unknown sections when editing.
- Keep findings in the normal findings ledger; do not create a separate vulnerability ledger.
- Do not run high-volume security tools from this skill.

## Workflow

1. Resolve the lane root and spec path.
2. Read `$HARNESS_ROOT/prompts/brainstorm-spec-playbook.md`.
3. If the spec does not exist, create it from the playbook template.
4. For `--add-hypothesis`, ask for or infer the surface, entry point, expected chain, priority, suggested agents, tags, focus files, and evidence.
5. For `--from-report`, extract impact primitives and hypothesis candidates from the report, then add only source-backed entries.
6. For `--summarize-gaps`, use `BrainstormSpecStore.coverage_summary` or `summarize_coverage` to report authoritative statuses and outcomes from `coverage.jsonl`, then list remaining untested or blocked hypotheses.
7. Validate the spec with `BrainstormSpecStore.load` or `agents.brainstorm_spec.parse_brainstorm_spec` when possible.
8. Leave team execution to `zero_day_team --brainstorm-spec` or `apk_team --brainstorm-spec`.

## Runtime Handoff

When the user wants to run hypotheses, pass the spec to the team runtime instead of implementing execution here:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 agents/zero_day_team.py <program> <target> --brainstorm-spec <spec-path>

cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 agents/apk_team.py <program> <target> --brainstorm-spec <spec-path>
```

Use focused runtime flags only when explicitly requested:

```bash
--brainstorm-only
--brainstorm-hypothesis H001
```

## Validation

Lightweight validation:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
SPEC_PATH="PATH_TO_BRAINSTORM_SPEC" \
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
python3 - <<'PY'
import os
from agents.brainstorm_spec import BrainstormSpecStore

spec = BrainstormSpecStore.load(os.environ["SPEC_PATH"])
coverage = spec.path.with_name("coverage.jsonl")
summary = BrainstormSpecStore.coverage_summary(coverage, spec=spec)
print(f"loaded {len(spec.hypotheses)} hypotheses from {spec.path}")
print(f"status counts: {summary['counts_by_status']}")
print(f"outcome counts: {summary['counts_by_outcome']}")
PY
```

Do not move brainstorm code into `bounty_core` from this skill.
