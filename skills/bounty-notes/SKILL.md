---
name: bounty-notes
description: Use when bug bounty agents need to write durable notes, hypotheses, handoffs, FAQs, or scratch artifact references without scattering markdown across working directories.
---

# Bounty Notes

Use this as the router for bug bounty note-taking. It tells agents where to put
temporary artifacts, durable knowledge, hypotheses, handoffs, and report-ready
material in the current program lane.

## Load Order

1. Resolve the active program, family, and lane from `/me`, `context/target_profile.json`,
   or the user request.
2. Read `prompts/bounty-notes-playbook.md`.
3. Use `agents/bounty_notes.py` for deterministic note and artifact writes.
4. Use specialist systems for their owned state:
   - Findings and report material: `manual_hunter.py` / `/findings`
   - Coverage and already-tested state: `me_ledger.py` / `coverage.json`
   - URL review state: `/url-ingest`
   - Attempt/claim memory for experiments: `/hunter-memory`

## Canonical Buckets

Default lane root:

`~/Shared/{family}/{program}/{lane}/`

Write to:

- `working/scratch/<run-id>/` for raw/generated artifacts, extracted JSON,
  screenshots, prompt bundles, and temporary logs.
- `notes/timeline/YYYY-MM-DD.md` for chronological activity and decisions.
- `notes/hypotheses/<slug>.md` for testable ideas or assumption chains.
- `notes/handoffs/<run-id>.md` for takeover-ready summaries.
- `notes/faq/<slug>.md` for stable solved target facts.
- `notes/index.md` for pointers to useful durable notes.

Do not write:

- Findings directly into final report directories. Import them through
  `manual_hunter.py`.
- Already-tested state as prose only. Mark coverage or URL review state in the
  appropriate ledger.
- Raw cookies, bearer tokens, API keys, credentials, private headers, or full
  proxy dumps into notes.

## Commands

Initialize notes for a lane:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
python3 agents/bounty_notes.py init <program> --family web_bounty --lane web
```

Write a hypothesis:

```bash
python3 agents/bounty_notes.py note <program> \
  --family web_bounty \
  --lane web \
  --bucket hypotheses \
  --title "Avatar metadata reaches admin review" \
  --status untested \
  --agent codex \
  --run-id <run-id> \
  --body "Check filename, EXIF, SVG title, moderation queue, and email render contexts."
```

Write a handoff:

```bash
python3 agents/bounty_notes.py note <program> \
  --family web_bounty \
  --lane web \
  --bucket handoffs \
  --title "<run-id>" \
  --slug "<run-id>" \
  --agent codex \
  --run-id <run-id> \
  --body-file /tmp/handoff.md
```

Store artifacts under scratch:

```bash
python3 agents/bounty_notes.py artifact <program> \
  --family web_bounty \
  --lane web \
  --run-id <run-id> \
  --agent codex \
  --source /tmp/sanitized-response.json \
  --note "Sanitized baseline response shape"
```

## Exit Checklist

Before an agent finishes:

1. Put raw/generated material in `working/scratch/<run-id>/`.
2. Promote reusable learning into `notes/`.
3. Add or update each promising hypothesis in `notes/hypotheses/`.
4. Add a handoff under `notes/handoffs/`.
5. Import real findings through the finding pipeline.
6. Mark coverage or URL review state in the right ledger.
