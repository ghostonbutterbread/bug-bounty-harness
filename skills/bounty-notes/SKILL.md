---
name: bounty-notes
description: "Use when bug bounty agents need durable hunt narrative: timeline, decisions, hypotheses, handoffs, blockers, FAQs, next-agent guidance, or sanitized artifact references."
---

# Bounty Notes

Bounty Notes is the human investigation journal. It answers: "What happened in
this hunt, what did we decide, and what should the next agent do?"

It is not the primary app-memory store. If a note describes what an app, URL,
endpoint, parameter, auth flow, or defense actually does, write that observation
to `/map-store` first, then link or summarize it here when it affects the hunt.

Bounty Notes may point to verbose artifacts, but it should not become the only
place where tested endpoint state or deductions live. If a Markdown or JSON
probe summary says what was tried, what response was observed, why a hypothesis
was killed, or which condition gates further testing, promote the factual part
to `/map-store` and use Bounty Notes only for the hunt narrative, handoff, or
next-step decision.

Exact payload and probe history belongs in attempts folders, not directly in
Bounty Notes. Use Bounty Notes to explain why the agent kept pressure, pivoted,
paused, or killed a hypothesis, then link the MapStore entry and attempts
artifact.

## Fast Routing

- URL/app/surface behavior -> `/map-store`.
- Timeline, decisions, hypotheses, handoffs, blockers, next-agent guidance,
  report-polish notes -> `/bounty-notes`.
- Bulk URL queue/review state -> `/url-ingest`.
- Already-tested coverage -> `me_ledger.py` / coverage ledgers.
- Exact payload/probe attempts -> `agent_shared/attempts/<vuln-class>/<surface>/<run-id>/`
  with MapStore pointers.
- Concrete findings and proof packets -> `manual_hunter.py` / `/findings`.

If both are true, split it: factual behavior in `/map-store`, hypothesis or
handoff here, linked by full URL and shared tags.

## MapStore vs Bounty Notes

- `/map-store`: structured memory for URL/domain/surface/app facts, including
  positive and negative test outcomes, parser behavior, auth gates, reusable
  deductions, and artifact pointers.
- `/bounty-notes`: human-readable hunt narrative, chronology, why a path was
  prioritized or paused, what a future agent should do next, and links to the
  MapStore entries or sanitized artifacts.

Before finishing, check whether every artifact-backed conclusion has a
corresponding MapStore entry at the right scope. A note can say "we paused video
export until an account with create_video is available"; MapStore should say the
specific endpoint returned `ACL_PERMISSION_DENIED`, which variants were tested,
and what evidence file contains the proof.

## Canonical Buckets

Default lane root: `~/Shared/{family}/{program}/{lane}/`

- `notes/timeline/YYYY-MM-DD.md` - chronology and decisions
- `notes/hypotheses/<slug>.md` - testable ideas or assumption chains
- `notes/handoffs/<run-id>.md` - takeover-ready summaries
- `notes/faq/<slug>.md` - stable solved target facts
- `notes/_index/` and `notes/index.md` - generated lookup/pointers
- `agent_shared/attempts/<vuln-class>/<surface>/<run-id>/` - exact payload/probe
  attempts, transformations, evidence, block reasons, and next mutations
- `working/scratch/<run-id>/` - durable-but-unpublished quick notes and
  sanitized artifacts promoted from `~/workdir/`
- `scripts/` - reusable program-specific helper scripts, PoCs, repro tools, or
  retest utilities

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
