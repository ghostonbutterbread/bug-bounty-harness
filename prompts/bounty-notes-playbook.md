# Bounty Notes Playbook

This playbook keeps bug bounty agents from treating every markdown file as the
same kind of memory. The goal is a navigable shared note layer plus clean machine
state for findings, coverage, URLs, and experiments.

Every durable note write should also leave an index trail. Agents should not
discover notes by reading every markdown file in the tree.

## Mental Model

Classify the material before writing:

- Raw or generated artifact: keep it in `working/scratch/<run-id>/`.
- Reusable target knowledge: write a small note under `notes/`.
- Testable idea: write or update `notes/hypotheses/<slug>.md`.
- Already-tested state: update coverage, URL review state, or hunter-memory.
- Reportable vulnerability: import through the finding/report pipeline.
- Next-agent context: write `notes/handoffs/<run-id>.md`.

Scratch is allowed to be messy. Durable notes should be short, linked, and useful
from Obsidian or a future agent prompt.

## Discovery Layer

The first stop for future agents is:

```text
notes/_index/
├── active.md
├── active.json
├── by-url.md
├── by-report.md
├── by-tag.md
└── notes.json
```

When Ryushe says "look at the notes for canva.com/endpoint", run:

```bash
python3 agents/bounty_notes.py search canva \
  --family web_bounty \
  --lane web \
  --url "canva.com/endpoint"
```

When Ryushe says "what were we last working on", read `notes/_index/active.md`.

When Ryushe gives a report/FID, run:

```bash
python3 agents/bounty_notes.py search <program> --report FID-123
```

## Directory Routing

Use the active lane root resolved by `/me` or Bounty Core:

```text
~/Shared/{family}/{program}/{lane}/
├── notes/
│   ├── index.md
│   ├── _index/
│   ├── faq/
│   ├── hypotheses/
│   ├── handoffs/
│   └── timeline/
├── working/scratch/
├── ledgers/
├── reports/
└── context/
```

For source-version collaboration notes, `/me` may also point to:

```text
<source-version-root>/.ghost/notes/
```

Use that path when the active task is tied to a specific extracted source or
binary version. Still keep canonical findings and coverage in the lane ledger.

## Note Types

### Timeline

Use for dated activity and decisions. Include what was checked, outcome, and
links to artifacts or ledger entries.

### Hypotheses

Use only for testable ideas, assumptions, or chains. Required fields:

```markdown
# <Short title>

Status: untested|testing|confirmed|rejected|blocked
Program: <program>
Family/Lane: <family>/<lane>
Agent/Run: <agent> / <run-id>
Updated: <ISO timestamp>

## Context
- Source files/endpoints reviewed:
- Related FIDs / coverage classes:

## Evidence
- What was observed:
- Commands or references:

## Next step
- One concrete validation step.
```

If a hypothesis becomes a real bug, import the finding and link the FID from the
hypothesis. If it fails, mark it `rejected` only for the exact context tested.

Use Obsidian links for cross-note navigation:

```markdown
Related investigation: [[timeline/2026-06-15]]
Related handoff: [[handoffs/20260615T190000Z-codex-avatar]]
Related report: [[../reports/findings/active/FID-123]]
```

The helper can add these links and refresh the machine index:

```bash
python3 agents/bounty_notes.py link <program> \
  --source hypotheses/avatar-metadata-reaches-admin-review.md \
  --target ../reports/findings/active/FID-123.md \
  --relationship report
```

### Handoffs

Use for takeover-ready summaries. A handoff should answer:

- What scope/lane/root was used?
- What was tested?
- What was learned?
- Which artifacts matter?
- What should the next agent do?
- What should the next agent avoid repeating?

### FAQ

Use for stable target facts future agents will repeatedly need, such as approved
helper scripts, source roots, browser/CDP ports, account aliases, non-secret
workflow facts, or recurring gotchas.

## Artifact Rules

Put raw/generated material in:

```text
working/scratch/<run-id>/
```

Examples:

- sanitized response JSON
- screenshots
- extracted snippets
- prompt bundles
- generated request templates
- temporary parser output

Do not paste huge artifacts into durable notes. Link the artifact path and
summarize why it matters.

Do not store raw secrets, cookies, authorization headers, tokens, credentials,
private config values, or full proxy dumps in notes. Store sanitized request
shape, response summary, and a local evidence reference instead.

## Interaction With Other Skills

- Use `/hunter-memory` for attempt-by-attempt learning, failed probes, and scoped
  claims during an experiment.
- Use `/url-ingest` for URL-level reviewed/deep-reviewed/dismissed state.
- Use `/me` and `me_ledger.py` for lane context and source/file coverage.
- Use `/findings`, `/manual_hunter`, or `/sync-reports` for vulnerabilities.
- Use `/brainstorm-spec` for structured hypothesis packs that feed teams.

`bounty-notes` does not replace those systems. It routes human-readable notes and
artifact references so the durable knowledge layer stays organized.

## Lookup Rules For Agents

Use these rules before opening random notes:

- URL or endpoint mentioned: search by `--url` first, then text search if no
  indexed match exists.
- "Last thing we tested" or "where were we": read `_index/active.md`.
- Finding/report mentioned: search by `--report`.
- Vulnerability class or area mentioned: search by `--tag`, then inspect matching
  hypotheses and handoffs.
- Hypothesis mentioned: open the hypothesis note, then follow its Obsidian links
  to timeline, artifacts, handoffs, and reports.
- If no match exists, create a new note with URL/tag/report metadata so the next
  agent does not hit the same ambiguity.

## Agent Exit Pattern

Before returning:

1. Write scratch artifacts into `working/scratch/<run-id>/`.
2. Promote only useful learning into `notes/` and include `--url`, `--tag`,
   `--report`, `--hypothesis`, or `--link` metadata where known.
3. Update or create hypotheses for promising ideas.
4. Add one handoff note.
5. Link any report/FID back to the hypothesis or investigation note.
6. Update ledgers for findings, coverage, or URL review as appropriate.
7. Mention the exact note paths in the final handoff.
