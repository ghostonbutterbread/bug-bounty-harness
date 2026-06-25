---
name: bounty-notes
description: Use when bug bounty agents need durable hunt narrative: timeline, decisions, hypotheses, handoffs, blockers, FAQs, next-agent guidance, or sanitized artifact references.
---

# Bounty Notes

Bounty Notes is the human investigation journal. It answers: "What happened in
this hunt, what did we decide, and what should the next agent do?"

It is not the primary app-memory store. If a note describes what an app, URL,
endpoint, parameter, auth flow, or defense actually does, write that observation
to `/map-store` first, then link or summarize it here when it affects the hunt.

## Fast Routing

- URL/app/surface behavior -> `/map-store`.
- Timeline, decisions, hypotheses, handoffs, blockers, next-agent guidance,
  report-polish notes -> `/bounty-notes`.
- Bulk URL queue/review state -> `/url-ingest`.
- Already-tested coverage -> `me_ledger.py` / coverage ledgers.
- Concrete findings and proof packets -> `manual_hunter.py` / `/findings`.

If both are true, split it: factual behavior in `/map-store`, hypothesis or
handoff here, linked by full URL and shared tags.

## Canonical Buckets

Default lane root: `~/Shared/{family}/{program}/{lane}/`

- `notes/timeline/YYYY-MM-DD.md` - chronology and decisions
- `notes/hypotheses/<slug>.md` - testable ideas or assumption chains
- `notes/handoffs/<run-id>.md` - takeover-ready summaries
- `notes/faq/<slug>.md` - stable solved target facts
- `notes/_index/` and `notes/index.md` - generated lookup/pointers
- `working/scratch/<run-id>/` - raw/generated run-local artifacts

Do not leave reusable hunt knowledge only in ad hoc scratch notes.

## Commands

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
python3 agents/bounty_notes.py init <program> --family web_bounty --lane web
python3 agents/bounty_notes.py note <program> --family web_bounty --lane web --bucket hypotheses --title "Title" --status untested --agent codex --run-id <run-id> --url "https://target.example/path" --tag xss --body "Hypothesis..."
python3 agents/bounty_notes.py artifact <program> --family web_bounty --lane web --run-id <run-id> --agent codex --source /tmp/sanitized.json --note "Sanitized baseline"
python3 agents/bounty_notes.py search <program> --family web_bounty --lane web --url "target.example/path"
python3 agents/bounty_notes.py link <program> --family web_bounty --lane web --source hypotheses/example.md --target ../reports/findings/active/FID-123.md --relationship report
```

Open `references/bounty-notes-reference.md` for examples, load order, artifact
rules, and the exit checklist.
