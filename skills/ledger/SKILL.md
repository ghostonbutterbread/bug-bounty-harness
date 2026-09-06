---
name: ledger
description: Coordinate BBH findings, coverage, and durable hunt context.
---

# BBH Ledger

Use this skill for the Bug Bounty Harness ledger and its adjacent durable hunt
records. It owns finding deduplication, coverage coordination, and the
canonical artifact locations. It does not provide a general session briefing;
use the shared `atme` skill for a concise “what are we working on?” summary.

## When to Use

- A manual hunt needs its program/lane storage context.
- Before recording a candidate finding or marking a surface reviewed.
- When importing a real finding into BBH's report pipeline.
- When writing target-specific handoff, hypothesis, or timeline context.

Do not use this for a general conversational status update, non-BBH project
status, or to hand-edit generated ledgers.

## Resolve Context First

1. Start a hunt with the lane explicit:

   ```bash
   bbh agents/manual_hunter.py {program} --hunt --lane <web|api|apk|exe|mac>
   ```

   Completion: the command prints the resolved target context and writes the
   current lane's `context/` files.

2. Treat `context/target_profile.json` as the source of truth for the selected
   family, lane, and canonical roots. Read `context/me_context.md` for the
   human-oriented handoff.

3. Before taking a surface or class, inspect only the relevant coverage, shared
   brain, active claim, and run-control state. Do not select work merely because
   prior findings exist.

## Canonical Locations

```text
~/Shared/{family}/{program}/{lane}/
├── ledgers/ledger.json          # canonical v2 dedupe ledger
├── ledgers/findings.jsonl       # append-only finding stream, when present
├── ledgers/coverage.json        # reviewed surface/class state
├── ledgers/shared_brain/        # indexed target context
├── context/                     # target profile and handoff
├── notes/                       # timeline, hypotheses, handoffs, FAQ
└── reports/                     # raw inputs and generated canonical reports
```

Use the resolved root rather than constructing a legacy path. Web/API lanes use
`family=web_bounty` with `--lane web` or `--lane api`; binary lanes use
`family=binaries` with `--lane apk|exe|mac`.

## Record Findings and Coverage

Use the report pipeline for a real finding:

```bash
bbh agents/manual_hunter.py {program} --lane <web|api|apk|exe|mac> \
  --from-file /path/to/finding.md
```

For bounded coordination before a full report, use the ledger CLI:

```bash
bbh agents/me_ledger.py check \
  --program {program} --family <web_bounty|binaries> \
  --lane <web|api|apk|exe|mac> --file <relative/path> \
  --class-name <vuln-class>

bbh agents/me_ledger.py cover \
  --program {program} --family <web_bounty|binaries> \
  --lane <web|api|apk|exe|mac> --file <relative/path> \
  --class-name <vuln-class> --agent <agent>
```

Completion: the relevant command reports the selected lane and updates the
pipeline; never edit `ledger.json`, `coverage.json`, or generated indexes by
hand.

## Durable Hunt Notes

Keep reusable target knowledge in the resolved source/version root:

```text
<source-root>/.ghost/
├── INDEX.md
├── notes/{faq,timeline,hypotheses,handoffs}/
└── agents/<model>/<run-id>/
```

- Timeline: current-run checks and outcomes.
- Hypotheses: chain, status, evidence, and one next validation step.
- Handoffs: takeover-ready scope, lane, evidence, and blocker.
- FAQ: solved target-specific workflow facts, never secrets.

Submit findings through `manual_hunter.py`; use `me_ledger.py cover` only after
actual review; leave a handoff even when no finding was produced.

## Safety and Verification

- Always specify `--lane`; do not guess between web, API, and binary lanes.
- Prefer non-disruptive validation and ask before state-changing vendor actions.
- Keep credentials, cookies, tokens, and raw request/response dumps out of
  notes and reports.
- Before declaring completion, verify the lane-resolved command output and that
  the updated note/report is in the canonical root.
