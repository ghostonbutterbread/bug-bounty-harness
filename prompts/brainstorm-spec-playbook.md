# Brainstorm Spec Playbook

## Overview

Use this as a decision tree: resolve the target lane, read existing reports and coverage, capture the operator's target intuition, turn each idea into a structured hypothesis, then keep execution history in `brainstorm/coverage.jsonl` while findings continue through the normal ledger.

## Decision Tree

1. Resolve the program, family, lane, target kind, target path, and spec path.
2. If `brainstorm/spec.md` is missing, create it with metadata, target mental model, impact primitives, hypotheses, and coverage log sections.
3. If adding ideas, normalize each idea into one `HNNN` hypothesis with required fields.
4. If importing from a report, extract impact primitives first, then add only hypotheses that cite report evidence.
5. If summarizing gaps, compute coverage with `summarize_coverage` or `BrainstormSpecStore.coverage_summary` and list untested, blocked, and stale hypotheses.
6. Hand runtime execution to a team command with `--brainstorm-spec`; this playbook does not own agent execution.

## 1. Resolve The Lane

Prefer an existing target lane over inventing a new location.

Common layouts:

```text
~/Shared/{family}/{program}/{lane}/brainstorm/spec.md
```

The lane-local `~/Shared/{family}/{program}/{lane}/brainstorm/` path is the writable default for new work.
Treat `$HARNESS_SHARED_BASE/{program}/brainstorm/spec.md` as a legacy read-only discovery or migration source, not as a fallback write target.

Record these metadata fields when known:

- `Program`
- `Family`
- `Lane`
- `Target kind`
- `Target path`
- `Created`
- `Status`

If the lane is ambiguous, ask for the smallest missing detail needed to avoid writing the spec into the wrong root.

## 2. Create The Spec

Use this skeleton for new specs:

```markdown
# Brainstorm Spec: {Program} {Lane}

## Metadata
- Program: {program}
- Family: {family}
- Lane: {lane}
- Target kind: {target-kind}
- Target path: {target-path}
- Created: {YYYY-MM-DD}
- Status: active

## Target mental model
Describe how the target works from an attacker and user-workflow perspective.

## Impact primitives
### P001 - {impact primitive title}
- Source: {function, endpoint, file, feature, or report}
- Impact: {security consequence if reached}
- Evidence: {report path, FID, file path, or observed request}
- Status: active

## Hypotheses
### H001 - {hypothesis title}
- Status: untested
- Priority: medium
- Surface: {surface}
- Entry point: {attacker-controlled input or workflow}
- Expected chain: {source -> intermediate -> impact}
- Suggested agents:
  - {program}-{surface}-{class}
- Focus files:
  - {optional glob}
- Tags: {class}, {surface}, {technology}
- Evidence:
  - {report, FID, request, file, or note}
- Notes: {optional human context}

## Coverage log
| Hypothesis | Agent | Status | Result | Linked FIDs | Run ID | Notes |
|---|---|---|---|---|---|---|
```

Keep the markdown human-editable. Do not remove unknown sections or free-form analyst notes while adding structured fields.

## 3. Add Hypotheses

Each hypothesis must include:

- `Status`: `untested`, `queued`, `running`, `tested`, `blocked`, or `retired`
- `Priority`: `critical`, `high`, `medium`, or `low`
- `Surface`: broad target area such as `import-upload-render`, `ipc`, `deeplink`, `filesystem`, `api`, or `checkout`
- `Entry point`: how attacker-controlled input reaches the target
- `Expected chain`: source to intermediate step to impact primitive
- `Suggested agents`: one or more stable agent keys
- `Tags`: vulnerability class and target technology labels

Optional fields:

- `Focus files`
- `Evidence`
- `Notes`

Use stable agent keys with ASCII letters, digits, `_`, or `-`. Keep keys unique across active hypotheses.

## 4. Import From Reports

When using `--from-report`, read the report and extract:

- Confirmed or dormant impact primitives
- Entry points already described by the report
- Source-backed file paths, request paths, FIDs, or screenshots
- Chain assumptions that still need testing

Add report-backed material as `Impact primitives` when it is an impact layer, and as `Hypotheses` when it is an untested route to that impact. Do not invent evidence.

## 5. Summarize Gaps

When using `--summarize-gaps`, read both:

- `brainstorm/spec.md`
- `brainstorm/coverage.jsonl`

Use the parser summary API so statuses and outcomes match team runtime semantics:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
SPEC_PATH="/home/ryushe/Shared/binaries/canva/exe/brainstorm/spec.md" \
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
python3 - <<'PY'
import os
from agents.brainstorm_spec import BrainstormSpecStore

spec = BrainstormSpecStore.load(os.environ["SPEC_PATH"])
summary = BrainstormSpecStore.coverage_summary(
    spec.path.with_name("coverage.jsonl"),
    spec=spec,
)
print(summary["counts_by_status"])
print(summary["counts_by_outcome"])
PY
```

Report these categories from the summary:

- Untested hypotheses
- Blocked hypotheses and the missing prerequisite
- Tested hypotheses with no finding
- Hypotheses with raw findings pending review
- Hypotheses linked to promoted FIDs
- Suggested next runtime command, if one is obvious

JSONL coverage is authoritative for execution history. The markdown coverage table is operator-facing context and can lag behind.

## 6. Validate

Use the parser for lightweight validation when Python dependencies are available:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
SPEC_PATH="PATH_TO_BRAINSTORM_SPEC" \
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
python3 - <<'PY'
import os
from agents.brainstorm_spec import BrainstormSpecStore

spec = BrainstormSpecStore.load(os.environ["SPEC_PATH"])
print(f"{spec.path}: {len(spec.hypotheses)} hypotheses")
PY
```

Validation should catch malformed required fields, invalid statuses, invalid priorities, duplicate hypothesis IDs, and duplicate active suggested agent keys.

## 7. Handoff To Team Runtime

Brainstorm-spec work stops at the durable artifact and gap summary. Team runtime owns dynamic agent execution, coverage append events, finding metadata, review, and promotion.

Example handoff:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 agents/zero_day_team.py canva /home/ryushe/Shared/binaries/canva/exe/input/app_asar \
  --brainstorm-spec /home/ryushe/Shared/binaries/canva/exe/brainstorm/spec.md
```

Focused run:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 agents/zero_day_team.py canva /path/to/target \
  --brainstorm-spec /path/to/brainstorm/spec.md \
  --brainstorm-only \
  --brainstorm-hypothesis H001
```

Do not run high-volume scans or destructive tests from this playbook.
