# AppMap Playbook

## Overview

Use AppMap as a static pre-runtime step: map the application, preserve evidence-backed artifacts, and generate focused brainstorm specs. Execution remains owned by `zero_day_team --brainstorm-spec` or `apk_team --brainstorm-spec`.

## Decision Tree

1. Resolve the local target directory and target-kind hint.
2. Run static mapping with `agents/app_mapper.py`; do not launch the application.
3. Review architecture, surfaces, flows, candidates, and rejected candidates.
4. If a generated spec exists, validate it with the brainstorm spec parser.
5. Report the artifact root and the highest-signal candidate chains.
6. Hand off to team runtime only on explicit user request.

## 1. Resolve Inputs

Required:

- `program`: stable program name for generated metadata
- `target_path`: local directory containing source or extracted application files

Optional:

- `target-kind`: use `auto` unless the user gives a specific kind such as `electron-exe`
- `focus`: Phase 2 supports `rce`
- `output-root`: use only when the user wants a specific destination
- `run-id`: use for repeatable tests or comparison runs

If the target path is missing or ambiguous, ask before running the mapper.

## 2. Run The Mapper

Default command:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 agents/app_mapper.py <program> <target_path> \
  --target-kind auto \
  --focus rce \
  --write-specs
```

With an explicit target kind:

```bash
python3 agents/app_mapper.py canva /home/ryushe/Shared/binaries/canva/exe/input/app_asar \
  --target-kind electron-exe \
  --focus rce \
  --write-specs
```

## 3. Review Artifacts

Inspect:

- `target_profile.json`: detected kind, languages, frameworks, entrypoints
- `architecture.md`: human summary and top candidates
- `surfaces.jsonl`: normalized source, boundary, transform, and sink evidence
- `flows.jsonl`: source-to-sink chains
- `candidates.jsonl`: hypotheses eligible for spec generation
- `rejected_candidates.jsonl`: explicit reasons for discarded evidence
- `generated_specs/rce-spec.md`: parser-compatible brainstorm spec when candidates exist

A candidate should have a plausible attacker-controlled source, a trust boundary, a concrete sink, file evidence, and a question agents can answer.

## 4. Validate Specs

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
SPEC_PATH="PATH_TO_APPMAP/generated_specs/rce-spec.md" \
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
python3 - <<'PY'
import os
from agents.brainstorm_spec import parse_brainstorm_spec

spec = parse_brainstorm_spec(os.environ["SPEC_PATH"])
print(f"loaded {len(spec.hypotheses)} hypotheses from {os.environ['SPEC_PATH']}")
PY
```

If validation fails, fix the generated spec or mapper before handing it to a runtime.

## 5. Report Results

Include:

- Output directory
- Target kind and framework summary
- Surface, flow, candidate, and rejected counts
- Generated spec path, if present
- Top candidate source, boundary, sink, and file evidence
- Any reason no spec was generated

## 6. Runtime Handoff

Use a generated spec with existing team commands only when requested:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 agents/zero_day_team.py <program> <target_path> \
  --brainstorm-spec <appmap-output>/generated_specs/rce-spec.md \
  --brainstorm-only
```

AppMap does not own agent execution, findings review, coverage ledgers, or report promotion.
